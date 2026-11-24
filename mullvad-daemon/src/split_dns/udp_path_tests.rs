use super::super::home_path::PathFuture;
use super::*;
use hickory_proto::{
    op::Query,
    rr::{Name, RecordType},
};
use std::{
    io,
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering::SeqCst},
    },
};
use talpid_netstack::buffer_budget::BufferBudget;

struct State {
    live: tokio::sync::watch::Sender<bool>,
    active: AtomicUsize,
    protocols: Mutex<Vec<Protocol>>,
    contexts: Mutex<Vec<u64>>,
    truncate: bool,
    pending: bool,
    deny: bool,
    answer_bytes: AtomicUsize,
}

struct Path(Arc<State>);
struct Lease {
    state: Arc<State>,
    protocol: Protocol,
}

impl Path {
    fn new(truncate: bool, pending: bool, deny: bool) -> Self {
        Self(Arc::new(State {
            live: tokio::sync::watch::channel(true).0,
            active: AtomicUsize::new(0),
            protocols: Mutex::new(Vec::new()),
            contexts: Mutex::new(Vec::new()),
            truncate,
            pending,
            deny,
            answer_bytes: AtomicUsize::new(0),
        }))
    }
}

impl HomeDnsPath for Path {
    fn authorize(
        &self,
        input: &DnsInput,
        _: SocketAddr,
        protocol: Protocol,
    ) -> Result<Box<dyn HomeDnsQuery>, ExchangeError> {
        self.0.protocols.lock().unwrap().push(protocol);
        self.0.contexts.lock().unwrap().push(input.scope().id());
        if self.0.deny || !*self.0.live.borrow() {
            return Err(ExchangeError::Closed);
        }
        self.0.active.fetch_add(1, SeqCst);
        Ok(Box::new(Lease {
            state: self.0.clone(),
            protocol,
        }))
    }
    fn close(&self) -> PathFuture<'_, io::Result<()>> {
        self.0.live.send_replace(false);
        Box::pin(async { Ok(()) })
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        self.state.active.fetch_sub(1, SeqCst);
    }
}

impl HomeDnsQuery for Lease {
    fn current(&self) -> bool {
        *self.state.live.borrow()
    }
    fn retired(&self) -> PathFuture<'_, ()> {
        Box::pin(async move {
            let mut live = self.state.live.subscribe();
            while *live.borrow_and_update() {
                if live.changed().await.is_err() {
                    break;
                }
            }
        })
    }
    fn exchange(
        &self,
        _: Duration,
        message: Message,
    ) -> PathFuture<'_, Result<DnsResponse, ExchangeError>> {
        Box::pin(async move {
            if self.state.pending && (!self.state.truncate || self.protocol == Protocol::Tcp) {
                return std::future::pending().await;
            }
            let mut response = message.into_response();
            let length = self.state.answer_bytes.load(SeqCst);
            if length != 0 {
                response.add_answer(hickory_proto::rr::Record::from_rdata(
                    response.queries[0].name().clone(),
                    741,
                    hickory_proto::rr::RData::Unknown {
                        code: RecordType::Unknown(65400),
                        rdata: hickory_proto::rr::rdata::NULL::with(vec![42; length]),
                    },
                ));
            }
            response.metadata.truncation = self.state.truncate && self.protocol == Protocol::Udp;
            DnsResponse::from_buffer(response.to_vec().unwrap())
                .map_err(|_| ExchangeError::Malformed)
        })
    }
}

fn query() -> UdpQuery {
    query_for_family(false)
}

fn query_for_family(ipv6: bool) -> UdpQuery {
    let mut request = Message::query();
    request.add_query(Query::query(
        Name::from_ascii("nonce.home.").unwrap(),
        RecordType::A,
    ));
    let (client, resolver) = if ipv6 {
        ("[fdf0:ce4a:801d::172:27:1:1]:49152", "[fd00::53]:53")
    } else {
        ("172.27.1.1:49152", "10.64.0.1:53")
    };
    let client: SocketAddr = client.parse().unwrap();
    let resolver: SocketAddr = resolver.parse().unwrap();
    let context = DnsInput::for_test(
        mullvad_types::settings::local_network_access::split_dns::SuffixMatcher::compile(["home"])
            .unwrap(),
        talpid_lan_forwarder::ReceiveScope::new(
            client.ip(),
            resolver.ip(),
            &BufferBudget::new(1024),
        )
        .unwrap(),
    );
    let UdpDecision::Intercept(query) = inspect(
        Some(&context),
        &[resolver.ip()],
        client,
        resolver,
        &request.to_vec().unwrap(),
    ) else {
        panic!("Home query");
    };
    *query
}

#[tokio::test]
async fn split_dns_udp_path_retains_both_transport_leases_through_reply_retries() {
    for truncate in [false, true] {
        let path = Path::new(truncate, false, false);
        let budget = BufferBudget::new(256 * 1024);
        let query = query();
        let context_id = query.context.scope().id();
        let reply = query
            .answer(Some(&path), Duration::from_secs(1), true, 65507, &budget)
            .await
            .unwrap();
        assert_eq!(path.0.active.load(SeqCst), if truncate { 2 } else { 1 });
        assert_eq!(
            *path.0.contexts.lock().unwrap(),
            vec![context_id; if truncate { 2 } else { 1 }]
        );
        assert!(budget.used() > usize::from(u16::MAX));
        for _ in 0..2 {
            let result = reply
                .with_current(|source, destination, bytes| {
                    assert_eq!(source, "10.64.0.1:53".parse().unwrap());
                    assert_eq!(destination, "172.27.1.1:49152".parse().unwrap());
                    assert_eq!(
                        Message::from_vec(bytes).unwrap().metadata.response_code,
                        ResponseCode::NoError
                    );
                    Err::<(), _>(io::ErrorKind::WouldBlock)
                })
                .unwrap();
            assert_eq!(result, Err(io::ErrorKind::WouldBlock));
            assert_eq!(path.0.active.load(SeqCst), if truncate { 2 } else { 1 });
        }
        drop(reply);
        assert_eq!(path.0.active.load(SeqCst), 0);
        assert_eq!(budget.used(), 0);
    }
}

#[tokio::test]
async fn split_dns_udp_path_revoked_reply_never_calls_an_emitter() {
    let path = Path::new(true, false, false);
    let budget = BufferBudget::new(256 * 1024);
    let reply = query()
        .answer(Some(&path), Duration::from_secs(1), true, 65507, &budget)
        .await
        .unwrap();
    path.close().await.unwrap();
    assert!(
        reply
            .with_current(|_, _, _| panic!("stale reply emitted"))
            .is_err()
    );
    assert_eq!(path.0.active.load(SeqCst), 2);
    drop(reply);
    assert_eq!(budget.used(), 0);
    assert_eq!(path.0.active.load(SeqCst), 0);
}

#[tokio::test]
async fn split_dns_udp_path_unavailable_or_denied_produces_only_servfail() {
    let path = Path::new(false, false, true);
    let budget = BufferBudget::new(256 * 1024);
    for selected in [None, Some(&path as &dyn HomeDnsPath)] {
        let reply = query()
            .answer(selected, Duration::from_secs(1), true, 65507, &budget)
            .await
            .unwrap();
        reply
            .with_current(|_, _, bytes| {
                assert_eq!(
                    Message::from_vec(bytes).unwrap().metadata.response_code,
                    ResponseCode::ServFail
                );
            })
            .unwrap();
        assert_eq!(path.0.active.load(SeqCst), 0);
        drop(reply);
        assert_eq!(budget.used(), 0);
    }
    assert_eq!(*path.0.protocols.lock().unwrap(), [Protocol::Udp]);
}

#[tokio::test]
async fn split_dns_udp_path_unfunded_reply_cannot_authorize_or_exchange() {
    let path = Path::new(false, false, false);
    assert!(
        query()
            .answer(
                Some(&path),
                Duration::from_secs(1),
                true,
                65507,
                &BufferBudget::new(0)
            )
            .await
            .is_err()
    );
    assert!(path.0.protocols.lock().unwrap().is_empty());
    assert_eq!(path.0.active.load(SeqCst), 0);
}

#[tokio::test]
async fn split_dns_udp_path_cancelled_exchange_refunds_and_retires_every_lease() {
    for truncate in [false, true] {
        let path = Path::new(truncate, true, false);
        let budget = BufferBudget::new(256 * 1024);
        {
            let waiting = query().answer(Some(&path), Duration::from_secs(1), true, 65507, &budget);
            tokio::pin!(waiting);
            assert!(futures::poll!(waiting.as_mut()).is_pending());
            assert_eq!(path.0.active.load(SeqCst), if truncate { 2 } else { 1 });
        }
        assert_eq!(path.0.active.load(SeqCst), 0);
        assert_eq!(budget.used(), 0);
    }
}

#[tokio::test]
async fn split_dns_udp_path_retirement_wakes_a_silent_exchange_without_an_emission() {
    for truncate in [false, true] {
        let path = Path::new(truncate, true, false);
        let budget = BufferBudget::new(256 * 1024);
        {
            let waiting =
                query().answer(Some(&path), Duration::from_secs(60), true, 65507, &budget);
            tokio::pin!(waiting);
            assert!(futures::poll!(waiting.as_mut()).is_pending());
            path.close().await.unwrap();
            assert!(
                tokio::time::timeout(Duration::from_secs(1), waiting)
                    .await
                    .unwrap()
                    .is_err()
            );
        }
        assert_eq!(path.0.active.load(SeqCst), 0);
        assert_eq!(budget.used(), 0);
    }
}

struct RacingPath {
    original: Path,
    tcp_started: Arc<AtomicUsize>,
}
struct FreshTcp(Arc<AtomicUsize>);

impl HomeDnsPath for RacingPath {
    fn authorize(
        &self,
        input: &DnsInput,
        client: SocketAddr,
        protocol: Protocol,
    ) -> Result<Box<dyn HomeDnsQuery>, ExchangeError> {
        if protocol == Protocol::Udp {
            return self.original.authorize(input, client, protocol);
        }
        // A policy replacement races between the consumer's currentness check
        // and obtaining TCP authority. The successor must never perform I/O.
        self.original.0.live.send_replace(false);
        Ok(Box::new(FreshTcp(self.tcp_started.clone())))
    }
    fn close(&self) -> PathFuture<'_, io::Result<()>> {
        self.original.close()
    }
}

impl HomeDnsQuery for FreshTcp {
    fn current(&self) -> bool {
        true
    }
    fn retired(&self) -> PathFuture<'_, ()> {
        Box::pin(std::future::pending())
    }
    fn exchange(
        &self,
        _: Duration,
        _: Message,
    ) -> PathFuture<'_, Result<DnsResponse, ExchangeError>> {
        Box::pin(async {
            self.0.fetch_add(1, SeqCst);
            Err(ExchangeError::Closed)
        })
    }
}

#[tokio::test]
async fn split_dns_udp_path_tc_cannot_cross_into_successor_authority() {
    let path = RacingPath {
        original: Path::new(true, false, false),
        tcp_started: Arc::new(AtomicUsize::new(0)),
    };
    let budget = BufferBudget::new(256 * 1024);
    assert!(
        query()
            .answer(Some(&path), Duration::from_secs(1), true, 65507, &budget)
            .await
            .is_err()
    );
    assert_eq!(path.tcp_started.load(SeqCst), 0);
    assert_eq!(path.original.0.active.load(SeqCst), 0);
    assert_eq!(budget.used(), 0);
}

fn capture_input(
    query: &UdpQuery,
    receiver: &mut PacketReceiver,
) -> (talpid_lan_forwarder::ReceiveScope, CompletedDatagram) {
    let scope = query.context.scope().clone();
    let wire = talpid_lan_forwarder::packet::udp_reply(
        talpid_lan_forwarder::Flow {
            source: query.resolver,
            destination: query.client,
            transport: talpid_lan_forwarder::Transport::Udp,
        },
        &query.request.to_vec().unwrap(),
    )
    .unwrap();
    let input = receiver.ingest(&scope, &wire).unwrap().unwrap();
    (scope, input)
}

fn capture_owner(
    _query: &UdpQuery,
    buffers: &BufferBudget,
) -> talpid_types::relay_flow::RelayCaptureOwner {
    use talpid_types::relay_flow::{RelayCaptureGeneration, RelayCaptureOwner, RelaySources};
    let sources = RelaySources {
        ipv4: Some("172.27.1.1".parse().unwrap()),
        ipv6: Some("fdf0:ce4a:801d::172:27:1:1".parse().unwrap()),
    };
    RelayCaptureOwner::with_identity(
        RelayCaptureGeneration::fresh().unwrap(),
        "dns-test",
        None,
        sources,
        1280,
        buffers,
    )
    .unwrap()
}

#[tokio::test]
async fn split_dns_udp_output_home_bytes_reach_native_consumer_through_checked_sink() {
    for ipv6 in [false, true] {
        for truncate in [false, true] {
            let path = Path::new(truncate, false, false);
            path.0.answer_bytes.store(12000, SeqCst);
            let buffers = Arc::new(BufferBudget::new(32 * 1024 * 1024));
            let mut query = query_for_family(ipv6);
            let mut edns = hickory_proto::op::Edns::new();
            edns.set_max_payload(16000);
            query.request.set_edns(edns);
            let client = query.client;
            let resolver = query.resolver;
            let owner = capture_owner(&query, &buffers);
            let capture = owner.capability();
            let sink = capture.sink().unwrap();
            let mut receiver = PacketReceiver::new(buffers.clone(), 1280).unwrap();
            let (_scope, input) = capture_input(&query, &mut receiver);
            let reply = query
                .answer(
                    Some(&path),
                    Duration::from_secs(1),
                    true,
                    65487,
                    buffers.as_ref(),
                )
                .await
                .unwrap();
            let expected = reply.with_current(|_, _, bytes| bytes.to_vec()).unwrap();
            let mut output = reply
                .into_output(&mut receiver, input, buffers.as_ref(), capture)
                .unwrap();
            assert_eq!(
                output
                    .write_output(&sink, |_| Err(io::ErrorKind::WouldBlock.into()))
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::WouldBlock
            );
            assert_eq!(path.0.active.load(SeqCst), if truncate { 2 } else { 1 });
            let mut consumer = PacketReceiver::new(buffers.clone(), 1280).unwrap();
            let scope = talpid_lan_forwarder::ReceiveScope::new(
                resolver.ip(),
                client.ip(),
                buffers.as_ref(),
            )
            .unwrap();
            let mut received = 0;
            let mut fragments = 0;
            while output.has_output() {
                assert!(
                    output
                        .write_output(&sink, |packet| {
                            fragments += 1;
                            if let Some(complete) = consumer.ingest(&scope, packet).unwrap() {
                                let parsed = complete.packet().unwrap();
                                assert_eq!(parsed.flow.source, resolver);
                                assert_eq!(parsed.flow.destination, client);
                                assert_eq!(parsed.payload, expected);
                                let message = decode_message(parsed.payload).unwrap();
                                assert_eq!(message.answers[0].ttl, 741);
                                assert!(!message.metadata.truncation);
                                received += 1;
                            }
                            assert_eq!(path.0.active.load(SeqCst), if truncate { 2 } else { 1 });
                            Ok(packet.len())
                        })
                        .unwrap()
                );
            }
            assert!(fragments > 1);
            assert_eq!(received, 1);
            assert_eq!(path.0.active.load(SeqCst), 0);
        }
    }
}

#[tokio::test]
async fn split_dns_udp_output_revocation_discards_tail_and_refunds_home_storage() {
    for capture_loss in [false, true] {
        let path = Path::new(true, false, false);
        path.0.answer_bytes.store(12000, SeqCst);
        let buffers = Arc::new(BufferBudget::new(32 * 1024 * 1024));
        let mut query = query();
        let mut edns = hickory_proto::op::Edns::new();
        edns.set_max_payload(16000);
        query.request.set_edns(edns);
        let owner = capture_owner(&query, &buffers);
        let capture = owner.capability();
        let sink = capture.sink().unwrap();
        let mut receiver = PacketReceiver::new(buffers.clone(), 1280).unwrap();
        let (_scope, input) = capture_input(&query, &mut receiver);
        let reply = query
            .answer(
                Some(&path),
                Duration::from_secs(1),
                true,
                65507,
                buffers.as_ref(),
            )
            .await
            .unwrap();
        let mut output = reply
            .into_output(&mut receiver, input, buffers.as_ref(), capture)
            .unwrap();
        assert!(output.write_output(&sink, |bytes| Ok(bytes.len())).unwrap());
        assert!(output.has_output());
        let funded = buffers.used();
        assert!(
            output
                .write_output(&sink, |_| Err(io::ErrorKind::WouldBlock.into()))
                .is_err()
        );
        if capture_loss {
            owner.retire();
        } else {
            path.close().await.unwrap();
        }
        let result = output.write_output(&sink, |_| panic!("stale authority reached sink"));
        if capture_loss {
            assert!(result.is_err());
        } else {
            assert!(!result.unwrap());
        }
        assert!(!output.has_output());
        assert_eq!(path.0.active.load(SeqCst), 0);
        assert!(buffers.used() < funded);
    }
}

#[tokio::test]
async fn split_dns_udp_output_cannot_emit_through_another_capture_sink_or_tuple() {
    for mismatch in ["sink", "tuple", "message"] {
        let path = Path::new(false, false, false);
        let buffers = Arc::new(BufferBudget::new(32 * 1024 * 1024));
        let query = query();
        let owner = capture_owner(&query, &buffers);
        let capture = owner.capability();
        let other = capture_owner(&query, &buffers);
        let other_sink = other.capability().sink().unwrap();
        let mut receiver = PacketReceiver::new(buffers.clone(), 1280).unwrap();
        let mut input_query = UdpQuery {
            context: query.context.clone(),
            client: query.client,
            resolver: query.resolver,
            request: query.request.clone(),
            error: None,
        };
        if mismatch == "tuple" {
            input_query.client.set_port(49153);
        }
        if mismatch == "message" {
            input_query.request.metadata.id ^= 1;
        }
        let (_scope, input) = capture_input(&input_query, &mut receiver);
        let reply = query
            .answer(
                Some(&path),
                Duration::from_secs(1),
                true,
                65507,
                buffers.as_ref(),
            )
            .await
            .unwrap();
        let output = reply.into_output(&mut receiver, input, buffers.as_ref(), capture);
        if mismatch != "sink" {
            assert!(matches!(output, Err(IpError::Malformed)));
        } else {
            let mut output = output.unwrap();
            assert!(
                output
                    .write_output(&other_sink, |_| panic!("successor sink"))
                    .is_err()
            );
            assert!(!output.has_output());
        }
        assert_eq!(path.0.active.load(SeqCst), 0);
    }
}

#[tokio::test]
async fn split_dns_udp_output_unavailable_home_servfail_reaches_native_consumer() {
    let buffers = Arc::new(BufferBudget::new(32 * 1024 * 1024));
    let query = query();
    let owner = capture_owner(&query, &buffers);
    let capture = owner.capability();
    let sink = capture.sink().unwrap();
    let mut receiver = PacketReceiver::new(buffers.clone(), 1280).unwrap();
    let (_scope, input) = capture_input(&query, &mut receiver);
    let reply = query
        .answer(None, Duration::from_secs(1), true, 65507, buffers.as_ref())
        .await
        .unwrap();
    let mut output = reply
        .into_output(&mut receiver, input, buffers.as_ref(), capture)
        .unwrap();
    assert!(
        output
            .write_output(&sink, |bytes| {
                let parsed = talpid_lan_forwarder::packet::parse(bytes).unwrap();
                let response = decode_message(parsed.payload).unwrap();
                assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
                assert_eq!(
                    response.queries[0].name(),
                    &Name::from_ascii("nonce.home.").unwrap()
                );
                Ok(bytes.len())
            })
            .unwrap()
    );
    assert!(!output.has_output());
}

#[tokio::test]
async fn split_dns_udp_output_sink_family_loss_discards_without_a_write() {
    use talpid_types::relay_flow::{RelayCaptureGeneration, RelaySources};
    let path = Path::new(false, false, false);
    let buffers = Arc::new(BufferBudget::new(32 * 1024 * 1024));
    let query = query_for_family(true);
    let owner = capture_owner(&query, &buffers);
    let capture = owner.capability();
    let old = capture.sink().unwrap();
    let mut receiver = PacketReceiver::new(buffers.clone(), 1280).unwrap();
    let (scope, input) = capture_input(&query, &mut receiver);
    let reply = query
        .answer(
            Some(&path),
            Duration::from_secs(1),
            true,
            65487,
            buffers.as_ref(),
        )
        .await
        .unwrap();
    let mut output = reply
        .into_output(&mut receiver, input, buffers.as_ref(), capture.clone())
        .unwrap();
    owner.suspend_sink(&old).unwrap();
    let new = owner
        .bind_sink(
            RelayCaptureGeneration::fresh().unwrap(),
            "dns-next",
            None,
            RelaySources {
                ipv4: Some("172.27.1.1".parse().unwrap()),
                ipv6: None,
            },
            1280,
            buffers.as_ref(),
        )
        .unwrap();
    assert!(scope.current() && capture.current());
    assert!(
        !output
            .write_output(&new, |_| panic!("absent source family reached sink"))
            .unwrap()
    );
    assert!(!output.has_output());
    assert_eq!(path.0.active.load(SeqCst), 0);
}
