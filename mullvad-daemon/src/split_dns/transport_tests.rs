use super::*;

use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{Arc, Mutex},
};

use hickory_net::{
    runtime::{TokioHandle, TokioRuntimeProvider, TokioTime, iocompat::AsyncIoTokioAsStd},
    tcp::TcpStream as DnsTcpStream,
    xfer::DnsStreamHandle,
};
use hickory_proto::{
    op::{Edns, Query, SerialMessage},
    rr::{DNSClass, Name, RData, Record, RecordType, rdata::NULL},
};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

#[test]
fn section_wire_bound_counts_questions_and_all_record_sections() {
    let counts = HeaderCounts {
        queries: 2,
        answers: 3,
        authorities: 4,
        additionals: 5,
    };
    assert_eq!(minimum_section_bytes(counts), 142);
}

#[test]
fn decode_accepts_minimum_wire_question_and_opt() {
    let mut request = Message::query();
    request.add_query(Query::query(Name::root(), RecordType::A));
    request.edns = Some(Edns::new());
    let bytes = request.to_vec().unwrap();
    assert_eq!(bytes.len(), 12 + 5 + 11);
    assert_eq!(decode_message(&bytes).unwrap(), request);
}

/// Records the exact resolver passed to both Hickory injection seams. Production
/// must replace the fixture runtime with its grant/carrier-bound implementation.
#[derive(Clone, Default)]
struct FixtureRuntime {
    inner: TokioRuntimeProvider,
    calls: Arc<Mutex<Vec<(Protocol, SocketAddr)>>>,
}

impl RuntimeProvider for FixtureRuntime {
    type Handle = TokioHandle;
    type Timer = TokioTime;
    type Udp = UdpSocket;
    type Tcp = AsyncIoTokioAsStd<TcpStream>;

    fn create_handle(&self) -> Self::Handle {
        self.inner.create_handle()
    }

    fn connect_tcp(
        &self,
        server: SocketAddr,
        bind: Option<SocketAddr>,
        timeout: Option<Duration>,
    ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Tcp>>>> {
        self.calls.lock().unwrap().push((Protocol::Tcp, server));
        self.inner.connect_tcp(server, bind, timeout)
    }

    fn bind_udp(
        &self,
        local: SocketAddr,
        server: SocketAddr,
    ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Udp>>>> {
        self.calls.lock().unwrap().push((Protocol::Udp, server));
        self.inner.bind_udp(local, server)
    }
}

fn question() -> Message {
    let mut message = Message::query();
    message.metadata.recursion_desired = true;
    message.metadata.checking_disabled = true;
    let mut query = Query::query(
        Name::from_ascii("_matrix-fed._tcp.My-Matrix-Server.com.").unwrap(),
        RecordType::SRV,
    );
    query.set_query_class(DNSClass::CH);
    message.add_query(query);
    let mut edns = Edns::new();
    edns.set_dnssec_ok(true).set_max_payload(4096);
    message.set_edns(edns);
    message
}

fn response(request: Message, large: bool) -> Message {
    let mut response = request.into_response();
    response.metadata.authoritative = true;
    response.metadata.authentic_data = true;
    response.add_answer(Record::from_rdata(
        Name::from_ascii("_matrix-fed._tcp.My-Matrix-Server.com.").unwrap(),
        741,
        RData::Unknown {
            code: RecordType::Unknown(65400),
            rdata: NULL::with(if large {
                vec![42; 8192]
            } else {
                vec![0, 255, 1, 128, 42]
            }),
        },
    ));
    response.add_authority(Record::from_rdata(
        Name::from_ascii("home.").unwrap(),
        830,
        RData::Unknown {
            code: RecordType::Unknown(65401),
            rdata: NULL::with(vec![9, 8, 7]),
        },
    ));
    response.add_additional(Record::from_rdata(
        Name::from_ascii("outside.example.").unwrap(),
        901,
        RData::Unknown {
            code: RecordType::Unknown(65402),
            rdata: NULL::with(vec![3, 2, 1]),
        },
    ));
    response
}

async fn udp_fixture(large: bool) -> (SocketAddr, tokio::task::JoinHandle<Message>) {
    udp_fixture_reply(move |request| response(request, large)).await
}

async fn udp_fixture_reply(
    reply: impl FnOnce(Message) -> Message + Send + 'static,
) -> (SocketAddr, tokio::task::JoinHandle<Message>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer = socket.local_addr().unwrap();
    let job = tokio::spawn(async move {
        let mut bytes = vec![0; u16::MAX as usize];
        let (length, client) = socket.recv_from(&mut bytes).await.unwrap();
        let request = Message::from_vec(&bytes[..length]).unwrap();
        let reply = reply(request.clone()).to_vec().unwrap();
        assert_eq!(socket.send_to(&reply, client).await.unwrap(), reply.len());
        request
    });
    (peer, job)
}

async fn tcp_fixture(large: bool) -> (SocketAddr, tokio::task::JoinHandle<Message>) {
    tcp_fixture_reply(move |request| response(request, large)).await
}

async fn tcp_fixture_reply(
    reply: impl FnOnce(Message) -> Message + Send + 'static,
) -> (SocketAddr, tokio::task::JoinHandle<Message>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let peer = listener.local_addr().unwrap();
    let job = tokio::spawn(async move {
        let (socket, client) = listener.accept().await.unwrap();
        let (mut stream, mut sender) = DnsTcpStream::from_stream(AsyncIoTokioAsStd(socket), client);
        let incoming = stream.next().await.unwrap().unwrap();
        let request = incoming.to_message().unwrap();
        sender
            .send(SerialMessage::new(
                reply(request.clone()).to_vec().unwrap(),
                client,
            ))
            .unwrap();
        // Polling Hickory drives its queued length-prefixed reply. Closing the
        // client after reception releases this fixture naturally.
        while let Some(next) = stream.next().await {
            next.unwrap();
        }
        request
    });
    (peer, job)
}

#[tokio::test]
async fn hickory_udp_and_tcp_exchange_preserve_complete_message() {
    for protocol in [Protocol::Udp, Protocol::Tcp] {
        let (peer, server) = match protocol {
            Protocol::Udp => udp_fixture(false).await,
            Protocol::Tcp => tcp_fixture(false).await,
        };
        let runtime = FixtureRuntime::default();
        let request = question();
        let received = exchange(
            runtime.clone(),
            peer,
            protocol,
            Duration::from_secs(3),
            request.clone(),
        )
        .await
        .unwrap();
        let expected = response(request.clone(), false);
        assert_eq!(received.metadata.id, request.metadata.id);
        assert_eq!(received.clone().into_message(), expected);
        assert_eq!(received.as_buffer(), expected.to_vec().unwrap());
        assert_eq!(Message::from_vec(received.as_buffer()).unwrap(), expected);
        assert_eq!(received.answers[0].ttl, 741);
        assert!(received.metadata.authentic_data);
        assert!(received.metadata.checking_disabled);
        assert!(received.edns.as_ref().unwrap().flags().dnssec_ok);
        drop(received);
        let mut sent = tokio::time::timeout(Duration::from_secs(4), server)
            .await
            .unwrap()
            .unwrap();
        sent.metadata.id = request.metadata.id;
        assert_eq!(sent, request);
        assert_eq!(*runtime.calls.lock().unwrap(), vec![(protocol, peer)]);
    }
}

#[tokio::test]
async fn partial_ordinary_udp_and_tcp_preserve_original_bytes_and_response() {
    for protocol in [Protocol::Udp, Protocol::Tcp] {
        let (peer, server) = match protocol {
            Protocol::Udp => udp_fixture(true).await,
            Protocol::Tcp => tcp_fixture(true).await,
        };
        let mut request = question();
        request.metadata.id = 65432;
        let bytes = request.to_vec().unwrap();
        let received = exchange_bytes(
            FixtureRuntime::default(),
            peer,
            protocol,
            Duration::from_secs(3),
            bytes.clone(),
        )
        .await
        .unwrap();
        assert_eq!(
            received.as_buffer(),
            response(request, true).to_vec().unwrap()
        );
        let sent = tokio::time::timeout(Duration::from_secs(4), server)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            sent.to_vec().unwrap(),
            bytes,
            "Ordinary ID, flags, questions and options must not be rewritten"
        );
    }
}

#[tokio::test]
async fn hickory_tcp_preserves_large_response() {
    let (peer, server) = tcp_fixture(true).await;
    let mut request = question();
    request.edns.as_mut().unwrap().set_max_payload(16384);
    let received = exchange(
        FixtureRuntime::default(),
        peer,
        Protocol::Tcp,
        Duration::from_secs(3),
        request.clone(),
    )
    .await
    .unwrap();
    let expected = response(request, true);
    assert_eq!(received.into_message(), expected);
    tokio::time::timeout(Duration::from_secs(4), server)
        .await
        .unwrap()
        .unwrap();
}

/// Addendum 01: the injected Hickory datagram primitive must not inherit the
/// UdpClientStream convenience client's 4096-byte receive ceiling.
#[tokio::test]
async fn hickory_udp_preserves_large_edns_response() {
    let (peer, server) = udp_fixture(true).await;
    let mut request = question();
    request.edns.as_mut().unwrap().set_max_payload(16384);
    let result = exchange(
        FixtureRuntime::default(),
        peer,
        Protocol::Udp,
        Duration::from_secs(3),
        request.clone(),
    )
    .await;
    let received = result.unwrap();
    assert!(received.as_buffer().len() > 8192);
    assert_eq!(received.into_message(), response(request, true));
    tokio::time::timeout(Duration::from_secs(4), server)
        .await
        .unwrap()
        .unwrap();
}

#[derive(Clone, Copy)]
enum InvalidReply {
    Peer,
    Id,
    Question,
    MissingQuestion,
    ExtraQuestion,
    NotResponse,
    Opcode,
    Truncated,
    Garbage,
    TrailingBytes,
}

async fn invalid_udp_fixture(invalid: InvalidReply) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer = socket.local_addr().unwrap();
    let job = tokio::spawn(async move {
        let mut buffer = vec![0; MAX_MESSAGE_BYTES];
        let (length, client) = socket.recv_from(&mut buffer).await.unwrap();
        let request = Message::from_vec(&buffer[..length]).unwrap();
        let mut answer = response(request, false);
        match invalid {
            InvalidReply::Id => answer.metadata.id = answer.metadata.id.wrapping_add(1),
            InvalidReply::Question => {
                answer.queries[0] =
                    Query::query(Name::from_ascii("wrong.home.").unwrap(), RecordType::A)
            }
            InvalidReply::MissingQuestion => answer.queries.clear(),
            InvalidReply::ExtraQuestion => answer.queries.push(Query::query(
                Name::from_ascii("extra.home.").unwrap(),
                RecordType::A,
            )),
            InvalidReply::NotResponse => answer.metadata.message_type = MessageType::Query,
            InvalidReply::Opcode => answer.metadata.op_code = OpCode::Update,
            _ => (),
        }
        let mut bytes = answer.to_vec().unwrap();
        match invalid {
            InvalidReply::Truncated => {
                bytes.pop();
            }
            InvalidReply::Garbage => bytes = vec![255; 13],
            InvalidReply::TrailingBytes => bytes.push(42),
            _ => (),
        }
        if matches!(invalid, InvalidReply::Peer) {
            let wrong = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            wrong.send_to(&bytes, client).await.unwrap();
        } else {
            socket.send_to(&bytes, client).await.unwrap();
        }
    });
    (peer, job)
}

#[tokio::test]
async fn hickory_udp_rejects_spoofed_identity_and_incomplete_messages() {
    for invalid in [
        InvalidReply::Peer,
        InvalidReply::Id,
        InvalidReply::Question,
        InvalidReply::MissingQuestion,
        InvalidReply::ExtraQuestion,
        InvalidReply::NotResponse,
        InvalidReply::Opcode,
        InvalidReply::Truncated,
        InvalidReply::Garbage,
        InvalidReply::TrailingBytes,
    ] {
        let (peer, server) = invalid_udp_fixture(invalid).await;
        let runtime = FixtureRuntime::default();
        let result = exchange(
            runtime.clone(),
            peer,
            Protocol::Udp,
            Duration::from_secs(3),
            question(),
        )
        .await;
        if matches!(
            invalid,
            InvalidReply::Truncated | InvalidReply::Garbage | InvalidReply::TrailingBytes
        ) {
            assert!(matches!(result, Err(ExchangeError::Malformed)));
        } else {
            assert!(matches!(result, Err(ExchangeError::Identity)));
        }
        assert_eq!(*runtime.calls.lock().unwrap(), vec![(Protocol::Udp, peer)]);
        server.await.unwrap();
    }
}

#[tokio::test]
async fn hickory_home_silence_has_no_retry_or_other_resolver() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer = socket.local_addr().unwrap();
    let runtime = FixtureRuntime::default();
    let result = exchange(
        runtime.clone(),
        peer,
        Protocol::Udp,
        Duration::from_millis(100),
        question(),
    )
    .await;
    assert!(
        matches!(result, Err(ExchangeError::Io(ref error)) if error.kind() == io::ErrorKind::TimedOut)
    );
    assert_eq!(*runtime.calls.lock().unwrap(), vec![(Protocol::Udp, peer)]);
    let mut bytes = [0; 4096];
    socket.try_recv_from(&mut bytes).unwrap();
    assert_eq!(
        socket.try_recv_from(&mut bytes).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
}

#[tokio::test]
async fn hickory_update_and_transfer_operations_do_not_open_sockets() {
    let runtime = FixtureRuntime::default();
    let peer = "127.0.0.1:53".parse().unwrap();
    let mut update = question();
    update.metadata.op_code = OpCode::Update;
    let mut axfr = question();
    axfr.queries[0] = Query::query(Name::from_ascii("home.").unwrap(), RecordType::AXFR);
    let mut ixfr = question();
    ixfr.queries[0] = Query::query(Name::from_ascii("home.").unwrap(), RecordType::IXFR);
    for request in [update, axfr, ixfr] {
        assert!(matches!(
            exchange(
                runtime.clone(),
                peer,
                Protocol::Udp,
                Duration::from_secs(1),
                request
            )
            .await,
            Err(ExchangeError::Unsupported)
        ));
    }
    assert!(runtime.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn hickory_all_normal_types_reach_the_requesting_transport_intact() {
    use super::super::fixture;
    for protocol in [Protocol::Udp, Protocol::Tcp] {
        for kind in [
            RecordType::A,
            RecordType::AAAA,
            RecordType::SRV,
            RecordType::HTTPS,
            RecordType::SVCB,
            RecordType::TXT,
            RecordType::MX,
            RecordType::CNAME,
            RecordType::Unknown(65400),
        ] {
            let reply = move |request: Message| {
                fixture::answer(&request, fixture::Role::Home, fixture::Protocol::Tcp).unwrap()
            };
            let (peer, server) = match protocol {
                Protocol::Udp => udp_fixture_reply(reply).await,
                Protocol::Tcp => tcp_fixture_reply(reply).await,
            };
            let mut request = question();
            request.queries[0] = Query::query(
                Name::from_ascii("nonce.my-matrix-server.com.").unwrap(),
                kind,
            );
            let response = exchange(
                FixtureRuntime::default(),
                peer,
                protocol,
                Duration::from_secs(3),
                request.clone(),
            )
            .await
            .unwrap();
            assert_eq!(response.queries, request.queries);
            assert_eq!(response.metadata.id, request.metadata.id);
            assert_eq!(response.answers[0].record_type(), kind);
            assert_eq!(response.answers[0].ttl, fixture::TTL);
            assert_eq!(
                response.clone().into_message(),
                Message::from_vec(response.as_buffer()).unwrap()
            );
            tokio::time::timeout(Duration::from_secs(3), server)
                .await
                .unwrap()
                .unwrap();
        }
    }
}

fn sized_response(request: Message, size: usize) -> Message {
    let mut answer = response(request, false);
    let RData::Unknown { rdata, .. } = &answer.answers[0].data else {
        unreachable!()
    };
    let overhead = answer.to_vec().unwrap().len() - rdata.anything.len();
    answer.answers[0].data = RData::Unknown {
        code: RecordType::Unknown(65400),
        rdata: NULL::with(vec![42; size - overhead]),
    };
    assert_eq!(answer.to_vec().unwrap().len(), size);
    answer
}

#[tokio::test]
async fn hickory_udp_protocol_max_and_tcp_full_framing_limit_are_not_shortened() {
    for (protocol, size) in [(Protocol::Udp, 65507), (Protocol::Tcp, 65535)] {
        let reply = move |request| sized_response(request, size);
        let (peer, server) = match protocol {
            Protocol::Udp => udp_fixture_reply(reply).await,
            Protocol::Tcp => tcp_fixture_reply(reply).await,
        };
        let mut request = question();
        request.edns.as_mut().unwrap().set_max_payload(u16::MAX);
        let received = exchange(
            FixtureRuntime::default(),
            peer,
            protocol,
            Duration::from_secs(3),
            request.clone(),
        )
        .await
        .unwrap();
        assert_eq!(received.as_buffer().len(), size);
        assert_eq!(
            received.as_buffer(),
            sized_response(request, size).to_vec().unwrap()
        );
        tokio::time::timeout(Duration::from_secs(3), server)
            .await
            .unwrap()
            .unwrap();
    }
}
