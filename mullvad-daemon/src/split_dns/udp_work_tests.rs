use super::super::{
    home_path::{HomeDnsQuery, PathFuture},
    transport::{Protocol, decode_message},
    udp::{UdpDecision, inspect},
};
use super::*;
use hickory_proto::{
    op::{DnsResponse, Edns, Message, Query, ResponseCode},
    rr::{Name, RecordType},
};
use mullvad_types::settings::local_network_access::split_dns::SuffixMatcher;
use std::{
    net::SocketAddr,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst},
};
use talpid_lan_forwarder::{Flow, ReceiveScope, Transport, packet};
use talpid_netstack::buffer_budget::BufferBudget;
use talpid_types::relay_flow::{RelayCaptureGeneration, RelayCaptureOwner, RelaySources};

#[derive(Default)]
struct Path {
    active: Arc<AtomicUsize>,
    calls: Arc<AtomicUsize>,
    revoked: Arc<AtomicBool>,
    closing: tokio::sync::Notify,
    hold_close: AtomicBool,
}
struct Lease {
    path: Arc<Path>,
    client: SocketAddr,
}
impl HomeDnsPath for Arc<Path> {
    fn authorize(
        &self,
        client: SocketAddr,
        _: Protocol,
    ) -> Result<Box<dyn HomeDnsQuery>, ExchangeError> {
        self.calls.fetch_add(1, SeqCst);
        self.active.fetch_add(1, SeqCst);
        Ok(Box::new(Lease {
            path: self.clone(),
            client,
        }))
    }
    fn close(&self) -> PathFuture<'_, io::Result<()>> {
        self.revoked.store(true, SeqCst);
        Box::pin(async move {
            if self.hold_close.load(SeqCst) {
                self.closing.notified().await;
            }
            Ok(())
        })
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        self.path.active.fetch_sub(1, SeqCst);
    }
}
impl HomeDnsQuery for Lease {
    fn current(&self) -> bool {
        !self.path.revoked.load(SeqCst)
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
            if self.client.port() == 49000 {
                return std::future::pending().await;
            }
            let mut reply = message.into_response();
            if self.client.port() == 49001 {
                reply.add_answer(hickory_proto::rr::Record::from_rdata(
                    reply.queries[0].name().clone(),
                    741,
                    hickory_proto::rr::RData::Unknown {
                        code: RecordType::Unknown(65400),
                        rdata: hickory_proto::rr::rdata::NULL::with(vec![42; 8000]),
                    },
                ));
            }
            DnsResponse::from_buffer(reply.to_vec().unwrap()).map_err(|_| ExchangeError::Malformed)
        })
    }
}

struct Fixture {
    buffers: Arc<BufferBudget>,
    path: Arc<Path>,
    capture: RelayCaptureOwner,
    receiver: PacketReceiver,
    work: HomeUdpWork,
}
impl Fixture {
    fn new(home: bool) -> Self {
        let buffers = Arc::new(BufferBudget::new(32 * 1024 * 1024));
        let path = Arc::new(Path::default());
        let capture = RelayCaptureOwner::with_identity(
            RelayCaptureGeneration::fresh().unwrap(),
            "dns-work",
            None,
            RelaySources {
                ipv4: Some("172.27.1.1".parse().unwrap()),
                ipv6: None,
            },
            1280,
            &*buffers,
        )
        .unwrap();
        let receiver = PacketReceiver::new(buffers.clone(), 1280).unwrap();
        let work = HomeUdpWork::new(
            home.then(|| Arc::new(path.clone()) as Arc<dyn HomeDnsPath>),
            capture.capability(),
            buffers.clone(),
            buffers.clone(),
        );
        Self {
            buffers,
            path,
            capture,
            receiver,
            work,
        }
    }
    fn input(&mut self, port: u16) -> (UdpQuery, ReceiveScope, CompletedDatagram) {
        let client = SocketAddr::new("172.27.1.1".parse().unwrap(), port);
        let resolver = "10.64.0.1:53".parse::<SocketAddr>().unwrap();
        let mut request = Message::query();
        request.metadata.id = port;
        request.add_query(Query::query(
            Name::from_ascii("nonce.home.").unwrap(),
            RecordType::A,
        ));
        let mut edns = Edns::new();
        edns.set_max_payload(16000);
        request.set_edns(edns);
        let bytes = request.to_vec().unwrap();
        let matcher = SuffixMatcher::compile(["home"]).unwrap();
        let UdpDecision::Intercept(query) =
            inspect(Some(&matcher), &[resolver.ip()], client, resolver, &bytes)
        else {
            panic!("Home query");
        };
        let scope = ReceiveScope::new(client.ip(), resolver.ip(), &*self.buffers).unwrap();
        let wire = packet::udp_reply(
            Flow {
                source: resolver,
                destination: client,
                transport: Transport::Udp,
            },
            &bytes,
        )
        .unwrap();
        let input = self.receiver.ingest(&scope, &wire).unwrap().unwrap();
        (*query, scope, input)
    }
    fn submit(&mut self, port: u16) -> ReceiveScope {
        let (query, scope, input) = self.input(port);
        self.work
            .submit(query, input, Duration::from_secs(1), true, 65507)
            .unwrap();
        scope
    }
    async fn ready(&mut self) {
        tokio::time::timeout(Duration::from_secs(1), self.work.wait())
            .await
            .unwrap();
        self.work.process(&mut self.receiver);
    }
}

#[tokio::test]
async fn split_dns_udp_work_tcp_input_cannot_obtain_home_udp_authority() {
    let mut fixture = Fixture::new(true);
    let (query, scope, mut original) = fixture.input(49001);
    let flow = original.packet().unwrap().flow;
    let mut wire = original.pop_original().unwrap().unwrap().to_vec();
    // Independent test-only wire generator: retain the same DNS payload/tuple
    // but supply a complete, checksum-valid TCP segment rather than UDP.
    wire.splice(20..28, [0; 20]);
    let length = wire.len() as u16;
    wire[2..4].copy_from_slice(&length.to_be_bytes());
    wire[9] = 6;
    wire[10..12].fill(0);
    wire[20..22].copy_from_slice(&flow.source.port().to_be_bytes());
    wire[22..24].copy_from_slice(&flow.destination.port().to_be_bytes());
    wire[24..28].copy_from_slice(&1234u32.to_be_bytes());
    wire[28..32].copy_from_slice(&5678u32.to_be_bytes());
    wire[32] = 0x50;
    wire[33] = 0x10;
    wire[34..36].copy_from_slice(&4096u16.to_be_bytes());
    let checksum = |bytes: &[u8]| {
        let mut sum: u32 = bytes
            .chunks(2)
            .map(|bytes| u32::from(u16::from_be_bytes([bytes[0], *bytes.get(1).unwrap_or(&0)])))
            .sum();
        while sum >> 16 != 0 {
            sum = (sum & 65535) + (sum >> 16);
        }
        !(sum as u16)
    };
    let mut pseudo = wire[12..20].to_vec();
    pseudo.extend([0, 6]);
    pseudo.extend(((wire.len() - 20) as u16).to_be_bytes());
    pseudo.extend(&wire[20..]);
    wire[36..38].copy_from_slice(&checksum(&pseudo).to_be_bytes());
    let header = checksum(&wire[..20]);
    wire[10..12].copy_from_slice(&header.to_be_bytes());
    let input = fixture.receiver.ingest(&scope, &wire).unwrap().unwrap();
    assert_eq!(input.packet().unwrap().flow.transport, Transport::Tcp);
    assert!(
        fixture
            .work
            .submit(query, input, Duration::from_secs(1), true, 65507)
            .is_err()
    );
    assert_eq!(fixture.path.calls.load(SeqCst), 0);
    fixture.work.close().await.unwrap();
}

#[tokio::test]
async fn split_dns_udp_work_silent_home_does_not_block_sibling_or_repeat_completion() {
    let mut f = Fixture::new(true);
    let _silent = f.submit(49000);
    let _ready = f.submit(49002);
    assert_eq!(
        f.path.calls.load(SeqCst),
        0,
        "ingest must not poll upstream"
    );
    f.ready().await;
    assert_eq!(f.path.calls.load(SeqCst), 2);
    let sink = f.capture.capability().sink().unwrap();
    assert!(
        f.work
            .write_output(&sink, |bytes| {
                let packet = packet::parse(bytes).unwrap();
                assert_eq!(packet.flow.destination.port(), 49002);
                assert_eq!(decode_message(packet.payload).unwrap().metadata.id, 49002);
                Ok(bytes.len())
            })
            .unwrap()
    );
    assert!(!f.work.has_output());
    assert!(futures::poll!(Box::pin(f.work.wait())).is_pending());
    assert_eq!(f.path.calls.load(SeqCst), 2);
    f.work.close().await.unwrap();
    assert_eq!(f.path.active.load(SeqCst), 0);
}

#[tokio::test]
async fn split_dns_udp_work_cancellation_safe_wait_and_packet_fairness_reach_consumer() {
    let mut f = Fixture::new(true);
    let _large = f.submit(49001);
    let _small = f.submit(49002);
    // Dropping a ready wait future cannot consume either completion.
    assert!(futures::poll!(Box::pin(f.work.wait())).is_ready());
    f.ready().await;
    let sink = f.capture.capability().sink().unwrap();
    assert_eq!(
        f.work
            .write_output(&sink, |_| Err(io::ErrorKind::WouldBlock.into()))
            .unwrap_err()
            .kind(),
        io::ErrorKind::WouldBlock
    );
    assert_eq!(f.path.active.load(SeqCst), 2);
    let mut consumer = PacketReceiver::new(f.buffers.clone(), 1280).unwrap();
    let scope = ReceiveScope::new(
        "10.64.0.1".parse().unwrap(),
        "172.27.1.1".parse().unwrap(),
        &*f.buffers,
    )
    .unwrap();
    let mut delivered = Vec::new();
    let mut writes = 0;
    while f.work.has_output() {
        assert!(
            f.work
                .write_output(&sink, |bytes| {
                    writes += 1;
                    if let Some(complete) = consumer.ingest(&scope, bytes).unwrap() {
                        let packet = complete.packet().unwrap();
                        let message = decode_message(packet.payload).unwrap();
                        if message.metadata.id == 49001 {
                            assert_eq!(message.answers[0].ttl, 741);
                        }
                        delivered.push((message.metadata.id, writes));
                    }
                    Ok(bytes.len())
                })
                .unwrap()
        );
    }
    assert_eq!(
        delivered[0],
        (49002, 2),
        "small sibling precedes remaining fragments"
    );
    assert_eq!(delivered[1].0, 49001);
    assert!(writes > 2);
    assert_eq!(f.path.active.load(SeqCst), 0);
    assert!(futures::poll!(Box::pin(f.work.wait())).is_pending());
}

#[tokio::test]
async fn split_dns_udp_work_policy_and_capture_retirement_cancel_pending_and_ready() {
    for capture in [false, true] {
        let mut f = Fixture::new(true);
        let silent = f.submit(49000);
        let ready = f.submit(49001);
        f.ready().await;
        assert_eq!(f.path.active.load(SeqCst), 2);
        let before = f.buffers.used();
        if capture {
            f.capture.retire();
        } else {
            silent.revoke();
            ready.revoke();
        }
        f.work.revalidate();
        assert_eq!(f.path.active.load(SeqCst), 0);
        assert!(f.work.pending.is_empty());
        assert!(!f.work.has_output());
        assert!(f.buffers.used() < before);
    }
}

#[tokio::test]
async fn split_dns_udp_work_missing_home_servfail_is_still_policy_bound() {
    for revoke in [false, true] {
        let mut f = Fixture::new(false);
        let scope = f.submit(49002);
        f.ready().await;
        let sink = f.capture.capability().sink().unwrap();
        if revoke {
            scope.revoke();
        }
        let mut writes = 0;
        assert_eq!(
            f.work
                .write_output(&sink, |bytes| {
                    writes += 1;
                    let packet = packet::parse(bytes).unwrap();
                    assert_eq!(
                        decode_message(packet.payload)
                            .unwrap()
                            .metadata
                            .response_code,
                        ResponseCode::ServFail
                    );
                    Ok(bytes.len())
                })
                .unwrap(),
            !revoke
        );
        assert_eq!(writes, usize::from(!revoke));
        assert_eq!(f.path.calls.load(SeqCst), 0);
    }
}

#[tokio::test]
async fn split_dns_udp_work_refuses_wrong_input_and_unfunded_job_before_authorization() {
    for unfunded in [false, true] {
        let mut f = Fixture::new(true);
        let (query, _scope, input) = f.input(49002);
        let (_, _other_scope, other) = f.input(49003);
        if unfunded {
            f.work.buffers = Arc::new(BufferBudget::new(0));
        }
        assert!(
            f.work
                .submit(
                    query,
                    if unfunded { input } else { other },
                    Duration::from_secs(1),
                    true,
                    65507
                )
                .is_err()
        );
        assert_eq!(f.path.calls.load(SeqCst), 0);
        assert!(f.work.pending.is_empty());
    }
}

#[tokio::test]
async fn split_dns_udp_work_close_retains_join_owner_across_cancellation() {
    let mut f = Fixture::new(true);
    let _scope = f.submit(49000);
    assert!(futures::poll!(Box::pin(f.work.wait())).is_pending());
    assert_eq!(f.path.active.load(SeqCst), 1);
    f.path.hold_close.store(true, SeqCst);
    assert!(futures::poll!(Box::pin(f.work.close())).is_pending());
    assert_eq!(f.path.active.load(SeqCst), 0);
    let (query, _scope, input) = f.input(49002);
    assert!(matches!(
        f.work
            .submit(query, input, Duration::from_secs(1), true, 65507),
        Err(IpError::Stale)
    ));
    f.path.hold_close.store(false, SeqCst);
    f.work.close().await.unwrap();
}
