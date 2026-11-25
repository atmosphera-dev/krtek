use super::super::home_path::PathFuture;
use super::*;
use hickory_proto::{
    op::{DnsResponse, Edns, Query},
    rr::{Name, RData, Record, RecordType, rdata::A},
};
use mullvad_types::settings::local_network_access::split_dns::SuffixMatcher;
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use talpid_netstack::buffer_budget::BufferBudget;
use talpid_types::relay_flow::{RelayCaptureGeneration, RelayCaptureOwner, RelaySources};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Home {
    calls: Arc<AtomicUsize>,
    live: Arc<AtomicBool>,
    fail: bool,
    on_exchange: Option<Arc<dyn Fn() + Send + Sync>>,
}
impl HomeDnsPath for Home {
    fn authorize(
        &self,
        _: &DnsInput,
        _: SocketAddr,
        protocol: Protocol,
    ) -> Result<Box<dyn HomeDnsQuery>, ExchangeError> {
        assert_eq!(protocol, Protocol::Tcp);
        self.calls.fetch_add(1, SeqCst);
        if self.fail {
            return Err(ExchangeError::Closed);
        }
        Ok(Box::new(Home {
            calls: self.calls.clone(),
            live: self.live.clone(),
            fail: false,
            on_exchange: self.on_exchange.clone(),
        }))
    }
    fn close(&self) -> PathFuture<'_, io::Result<()>> {
        Box::pin(async { Ok(()) })
    }
}
impl HomeDnsQuery for Home {
    fn current(&self) -> bool {
        self.live.load(SeqCst)
    }
    fn retired(&self) -> PathFuture<'_, ()> {
        Box::pin(std::future::pending())
    }
    fn exchange(
        &self,
        _: Duration,
        message: Message,
    ) -> PathFuture<'_, Result<DnsResponse, ExchangeError>> {
        Box::pin(async move {
            if let Some(on_exchange) = &self.on_exchange {
                on_exchange();
            }
            let mut reply = message.into_response();
            reply.add_answer(Record::from_rdata(
                reply.queries[0].name().clone(),
                741,
                RData::A(A("10.77.10.1".parse().unwrap())),
            ));
            DnsResponse::from_buffer(reply.to_vec().unwrap()).map_err(|_| ExchangeError::Malformed)
        })
    }
}
fn query(name: &str, id: u16) -> Vec<u8> {
    let mut message = Message::query();
    message.metadata.id = id;
    message.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
    message.to_vec().unwrap()
}
fn session(
    resolver: SocketAddr,
    buffers: &dyn RelayBufferAllocator,
) -> (RelayCaptureOwner, Arc<Session>) {
    let source = SocketAddr::new(
        if resolver.is_ipv4() {
            "127.0.0.1".parse().unwrap()
        } else {
            "::1".parse().unwrap()
        },
        49900,
    );
    let capture = RelayCaptureOwner::with_identity(
        RelayCaptureGeneration::fresh().unwrap(),
        "dns-tcp",
        None,
        RelaySources {
            ipv4: source.is_ipv4().then(|| "127.0.0.1".parse().unwrap()),
            ipv6: source.is_ipv6().then(|| "::1".parse().unwrap()),
        },
        1280,
        buffers,
    )
    .unwrap();
    let sink = capture.capability().sink().unwrap();
    let scope = ReceiveScope::new(source.ip(), resolver.ip(), buffers).unwrap();
    let session = Arc::new(Session {
        system: None,
        partial: false,
        live: AtomicBool::new(true),
        flow: Flow {
            source,
            destination: resolver,
            transport: talpid_lan_forwarder::Transport::Tcp,
        },
        input: DnsInput::for_test(SuffixMatcher::compile(["home"]).unwrap(), scope),
        capture: capture.capability(),
        sink,
        replies: Mutex::new(Replies {
            end: 0,
            pending: LinkedList::new(),
        }),
        _storage: buffers.try_reserve(1024 * 1024).unwrap(),
    });
    (capture, session)
}

#[test]
fn split_dns_tcp_review_empty_writes_ignore_backpressure() {
    use futures::io::AsyncWrite;

    let buffers = BufferBudget::new(4096);
    let (mut stream, _peer) = ServiceStream::pair(&buffers, 1).unwrap();
    assert_eq!(stream.try_write(b"x").unwrap(), 1);
    let mut io = CodecIo(stream);
    let cx = &mut Context::from_waker(futures::task::noop_waker_ref());
    assert!(Pin::new(&mut io).poll_write(cx, b"x").is_pending());
    assert!(matches!(
        Pin::new(&mut io).poll_write(cx, b""),
        Poll::Ready(Ok(0))
    ));
    assert!(matches!(
        Pin::new(&mut io).poll_write_vectored(cx, &[std::io::IoSlice::new(b"")]),
        Poll::Ready(Ok(0))
    ));
}

#[tokio::test]
async fn split_dns_tcp_hickory_partial_frames_alternate_home_ordinary_home_both_families() {
    for ipv6 in [false, true] {
        let listener = tokio::net::TcpListener::bind(if ipv6 { "[::1]:0" } else { "127.0.0.1:0" })
            .await
            .unwrap();
        let resolver = listener.local_addr().unwrap();
        let expected = query("ordinary.example.", 777);
        let golden = expected.clone();
        let peer = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut length = [0; 2];
            socket.read_exact(&mut length).await.unwrap();
            let mut bytes = vec![0; usize::from(u16::from_be_bytes(length))];
            socket.read_exact(&mut bytes).await.unwrap();
            assert_eq!(
                bytes, golden,
                "Ordinary must retain the complete original wire message and ID"
            );
            let reply = decode_message(&bytes)
                .unwrap()
                .into_response()
                .to_vec()
                .unwrap();
            // Independent test wire generator deliberately segments both prefix
            // bytes and the body. Product framing is Hickory on both legs.
            for byte in (reply.len() as u16).to_be_bytes().into_iter().chain(reply) {
                socket.write_all(&[byte]).await.unwrap();
                tokio::task::yield_now().await;
            }
            bytes
        });
        let buffers = Arc::new(BufferBudget::new(32 * 1024 * 1024));
        let (capture, session) = session(resolver, &*buffers);
        let attempt = capture.open_attempt(&*buffers).unwrap();
        attempt.activate().unwrap();
        let home = Arc::new(Home {
            calls: Arc::default(),
            live: Arc::new(AtomicBool::new(true)),
            fail: false,
            on_exchange: None,
        });
        let registry = Arc::new(Registry::default());
        let (client, codec) = ServiceStream::pair(&*buffers, 1).unwrap();
        let worker = tokio::spawn(serve(
            session.clone(),
            codec,
            home.clone(),
            registry.clone(),
            buffers.clone(),
        ));
        let (mut reader, mut writer) = futures::io::AsyncReadExt::split(CodecIo(client));
        let mut coalesced = Vec::new();
        let requests = [
            query("first.home.", 777),
            expected.clone(),
            query("last.home.", 777),
        ];
        for bytes in &requests {
            coalesced.extend((bytes.len() as u16).to_be_bytes());
            coalesced.extend(bytes);
        }
        let client = async {
            let write = async {
                futures::io::AsyncWriteExt::write_all(&mut writer, &coalesced)
                    .await
                    .unwrap();
                futures::io::AsyncWriteExt::close(&mut writer)
                    .await
                    .unwrap();
            };
            let read = async {
                let mut replies = Vec::new();
                for _ in 0..3 {
                    let mut prefix = [0; 2];
                    futures::io::AsyncReadExt::read_exact(&mut reader, &mut prefix)
                        .await
                        .unwrap();
                    let mut bytes = vec![0; usize::from(u16::from_be_bytes(prefix))];
                    futures::io::AsyncReadExt::read_exact(&mut reader, &mut bytes)
                        .await
                        .unwrap();
                    replies.push(decode_message(&bytes).unwrap());
                }
                replies
            };
            let (_, replies) = futures::join!(write, read);
            replies
        };
        let replies = tokio::time::timeout(Duration::from_secs(3), client)
            .await
            .unwrap();
        for ((home_reply, reply), request) in
            [true, false, true].into_iter().zip(replies).zip(requests)
        {
            assert_eq!(reply.metadata.id, 777);
            assert_eq!(reply.queries, decode_message(&request).unwrap().queries);
            assert_eq!(reply.answers.len(), usize::from(home_reply));
            if home_reply {
                assert_eq!(reply.answers[0].ttl, 741);
            }
        }
        assert_eq!(home.calls.load(SeqCst), 2);
        assert_eq!(peer.await.unwrap(), expected);
        let ordinary = session
            .replies
            .lock()
            .unwrap()
            .pending
            .iter()
            .find_map(|reply| match &reply.guard {
                Some(Guard::Ordinary(socket)) => Some(socket.clone()),
                _ => None,
            })
            .unwrap();
        assert!(registry.owns(ordinary.flow));
        attempt.retire();
        assert!(!ordinary.current());
        assert_eq!(
            registry.route(ordinary.flow),
            Some(false),
            "retired own packets must be consumed, not re-intercepted or routed into a successor"
        );
        assert!(!session.current());
        drop(reader);
        drop(writer);
        let _ = tokio::time::timeout(Duration::from_secs(1), worker)
            .await
            .unwrap()
            .unwrap();
    }
}

#[tokio::test]
async fn split_dns_tcp_unavailable_home_is_servfail_without_ordinary_capability() {
    let buffers = Arc::new(BufferBudget::new(32 * 1024 * 1024));
    let (_capture, session) = session("127.0.0.1:53".parse().unwrap(), &*buffers);
    let home = Arc::new(Home {
        calls: Arc::default(),
        live: Arc::new(AtomicBool::new(true)),
        fail: true,
        on_exchange: None,
    });
    let (client, codec) = ServiceStream::pair(&*buffers, 3).unwrap();
    let worker = tokio::spawn(serve(session, codec, home.clone(), Arc::default(), buffers));
    let (mut client, mut sender) =
        TcpStream::from_stream(CodecIo(client), "127.0.0.1:53".parse().unwrap());
    let mut request = decode_message(&query("unreachable.home.", 904)).unwrap();
    request.set_edns(Edns::new());
    let mut mixed = request.clone();
    mixed.metadata.id += 1;
    mixed.add_query(Query::query(
        Name::from_ascii("outside.example.").unwrap(),
        RecordType::A,
    ));
    for (request, code) in [
        (request, ResponseCode::ServFail),
        (mixed, ResponseCode::FormErr),
    ] {
        sender
            .send(SerialMessage::new(
                request.to_vec().unwrap(),
                "127.0.0.1:53".parse().unwrap(),
            ))
            .unwrap();
        let response = tokio::time::timeout(Duration::from_secs(1), client.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let bytes = response.into_parts().0;
        let response = decode_message(&bytes).unwrap();
        assert_eq!(response.metadata.response_code, code);
        assert_eq!(response.metadata.id, request.metadata.id);
        assert_eq!(response.metadata.message_type, MessageType::Response);
        if code == ResponseCode::FormErr {
            assert!(response.queries.is_empty());
            assert_eq!(&bytes[4..6], &[0, 0]);
        } else {
            assert_eq!(response.queries, request.queries);
        }
        assert_eq!(response.edns.unwrap().max_payload(), 1232);
    }
    assert_eq!(home.calls.load(SeqCst), 1);
    drop(client);
    drop(sender);
    assert!(
        tokio::time::timeout(Duration::from_secs(1), worker)
            .await
            .unwrap()
            .unwrap()
            .is_ok()
    );
}

#[tokio::test]
async fn split_dns_tcp_review_retired_home_fails_only_a_current_session() {
    let resolver = "127.0.0.1:53".parse().unwrap();
    for revoke_input in [false, true] {
        let buffers = Arc::new(BufferBudget::new(32 * 1024 * 1024));
        let (_capture, session) = session(resolver, &*buffers);
        let live = Arc::new(AtomicBool::new(true));
        let scope = session.input.scope().clone();
        let home = Arc::new(Home {
            calls: Arc::default(),
            live: live.clone(),
            fail: false,
            on_exchange: Some(Arc::new(move || {
                live.store(false, SeqCst);
                if revoke_input {
                    scope.revoke();
                }
            })),
        });
        let (client, codec) = ServiceStream::pair(&*buffers, 1024).unwrap();
        let worker = tokio::spawn(serve(
            session.clone(),
            codec,
            home.clone(),
            Arc::default(),
            buffers,
        ));
        let (mut client, mut sender) = TcpStream::from_stream(CodecIo(client), resolver);
        let wire = query("retiring.home.", 951);
        let request = decode_message(&wire).unwrap();
        sender.send(SerialMessage::new(wire, resolver)).unwrap();
        let response = tokio::time::timeout(Duration::from_secs(1), client.next())
            .await
            .unwrap();
        assert_eq!(home.calls.load(SeqCst), 1);
        if revoke_input {
            assert!(response.is_none(), "revoked input received a reply");
        } else {
            let (bytes, _) = response
                .expect("current session must receive SERVFAIL")
                .unwrap()
                .into_parts();
            let reply = decode_message(&bytes).unwrap();
            assert_eq!(reply.metadata.response_code, ResponseCode::ServFail);
            assert_eq!(reply.metadata.id, 951);
            assert_eq!(reply.queries, request.queries);
            assert!(reply.answers.is_empty());
            assert!(
                session.current(),
                "synthetic failure must not retain the retired lease"
            );
        }
        drop(client);
        drop(sender);
        let result = tokio::time::timeout(Duration::from_secs(1), worker)
            .await
            .unwrap()
            .unwrap();
        if revoke_input {
            assert!(matches!(result, Err(ExchangeError::Closed)));
        } else {
            result.unwrap();
        }
    }
}

#[test]
fn split_dns_tcp_reply_guard_lives_until_ack_and_revocation_cannot_revive() {
    let buffers = BufferBudget::new(32 * 1024 * 1024);
    let (_capture, session) = session("127.0.0.1:53".parse().unwrap(), &buffers);
    let live = Arc::new(AtomicBool::new(true));
    session
        .retain(
            8,
            Some(Guard::Home(Arc::new(Home {
                calls: Arc::default(),
                live: live.clone(),
                fail: false,
                on_exchange: None,
            }))),
            &buffers,
        )
        .unwrap();
    let (stream, _peer) = ServiceStream::pair(&buffers, 32).unwrap();
    let mut app = Application {
        stream,
        session: session.clone(),
        read: 10,
    };
    app.queued_output(1);
    assert_eq!(session.replies.lock().unwrap().pending.len(), 1);
    live.store(false, SeqCst);
    app.queued_output(0);
    live.store(true, SeqCst);
    assert!(
        !app.current(),
        "same-looking authority cannot resurrect queued bytes"
    );
    assert_eq!(session.replies.lock().unwrap().pending.len(), 1);
}

#[test]
fn split_dns_tcp_socket_context_observes_coalesced_suspend_resume_without_revoking_local() {
    use talpid_types::relay_flow::RelayTargetId;
    let buffers = BufferBudget::new(32 * 1024 * 1024);
    let (capture, session) = session("127.0.0.1:53".parse().unwrap(), &buffers);
    let capability = capture.capability();
    assert!(capability.socket_context(RelayTargetId::MULLVAD).is_none());
    let attempt = capture.open_attempt(&buffers).unwrap();
    assert!(capability.socket_context(RelayTargetId::MULLVAD).is_none());
    attempt.activate().unwrap();
    let context = capability.socket_context(RelayTargetId::MULLVAD).unwrap();
    assert!(context.current());
    capture.suspend_sink(&session.sink).unwrap();
    capture.resume_sink(&session.sink).unwrap();
    // Deliberately no intermediate observation: checking only the final sink
    // would revive old kernel I/O after a capture-loss interval.
    assert!(
        !context.current(),
        "capture suspension must irreversibly retire old socket context"
    );
    assert!(
        context
            .with_current(|| panic!("old socket syscall"))
            .is_err()
    );
    assert!(capability.current());
    assert!(
        attempt.capability().current(),
        "Local/ordinary packet continuity is unchanged"
    );
    let fresh = capability.socket_context(RelayTargetId::MULLVAD).unwrap();
    assert!(fresh.current());
    attempt.retire();
    assert!(!fresh.current());
    assert!(capability.socket_context(RelayTargetId::MULLVAD).is_none());
}

#[test]
fn split_dns_tcp_ack_releases_only_the_completed_reply_guards() {
    let buffers = BufferBudget::new(32 * 1024 * 1024);
    let (_capture, session) = session("127.0.0.1:53".parse().unwrap(), &buffers);
    for size in [8, 18] {
        session.retain(size, None, &buffers).unwrap();
    }
    let (stream, _peer) = ServiceStream::pair(&buffers, 32).unwrap();
    let mut app = Application {
        stream,
        session: session.clone(),
        read: 30,
    };
    app.queued_output(21);
    assert_eq!(session.replies.lock().unwrap().pending.len(), 2);
    app.queued_output(20);
    assert_eq!(session.replies.lock().unwrap().pending.len(), 1);
    app.queued_output(0);
    assert!(session.replies.lock().unwrap().pending.is_empty());
}

#[tokio::test]
async fn split_dns_partial_ambiguous_tcp_each_message_is_servfail_or_lockdown_drop() {
    for ipv6 in [false, true] {
        for lockdown in [false, true] {
            let buffers = Arc::new(BufferBudget::new(32 * 1024 * 1024));
            let resolver = if ipv6 { "[::1]:53" } else { "127.0.0.1:53" }
                .parse()
                .unwrap();
            let (_capture, mut session) = session(resolver, &*buffers);
            let (system, platform, _unused_capture, _scope) =
                super::super::system::tests::fixture();
            platform.ambiguous.store(true, SeqCst);
            platform.lockdown.store(lockdown, SeqCst);
            let mutable = Arc::get_mut(&mut session).unwrap();
            mutable.partial = true;
            mutable.system = Some(Arc::new(system));
            let home = Arc::new(Home {
                calls: Arc::default(),
                live: Arc::new(AtomicBool::new(true)),
                fail: false,
                on_exchange: None,
            });
            let (client, codec) = ServiceStream::pair(&*buffers, 128).unwrap();
            let worker = tokio::spawn(serve(
                session.clone(),
                codec,
                home.clone(),
                Arc::default(),
                buffers,
            ));
            let (mut client, mut sender) = TcpStream::from_stream(CodecIo(client), resolver);
            for (id, name) in [
                (901, "first.home."),
                (902, "ordinary.example."),
                (903, "last.home."),
                (904, "another.example."),
            ] {
                sender
                    .send(SerialMessage::new(query(name, id), resolver))
                    .unwrap();
            }
            for id in if lockdown {
                vec![901, 903]
            } else {
                vec![901, 902, 903, 904]
            } {
                let response = tokio::time::timeout(Duration::from_millis(500), client.next())
                    .await
                    .expect("each allowed TCP message must fail fast")
                    .unwrap()
                    .unwrap();
                let response = decode_message(&response.into_parts().0).unwrap();
                assert_eq!(response.metadata.id, id);
                let is_home = id == 901 || id == 903;
                assert_eq!(
                    response.metadata.response_code,
                    if is_home {
                        ResponseCode::NoError
                    } else {
                        ResponseCode::ServFail
                    }
                );
                assert_eq!(response.answers.len(), usize::from(is_home));
            }
            assert!(
                tokio::time::timeout(Duration::from_millis(50), client.next())
                    .await
                    .is_err(),
                "no extra or denied Ordinary reply"
            );
            assert_eq!(home.calls.load(SeqCst), 2);
            assert_eq!(platform.prepares.load(SeqCst), 0);
            platform.lockdown.store(true, SeqCst);
            if !lockdown {
                assert!(
                    !session.current(),
                    "queued ambiguity reply retains OS guard"
                );
                platform.lockdown.store(false, SeqCst);
                assert!(!session.current());
            }
            drop(client);
            drop(sender);
            let _ = tokio::time::timeout(Duration::from_secs(1), worker)
                .await
                .unwrap()
                .unwrap();
        }
    }
}
