//! Partial Ordinary must traverse the production capture and system I/O owners.
use super::*;
use std::sync::atomic::AtomicBool;
use talpid_tunnel::android_frontend::{CaptureHandover, SystemDnsSnapshot};

struct SystemPlatform {
    packet: Arc<PacketPlatform>,
    checks: AtomicUsize,
    prepares: AtomicUsize,
    ambiguous: AtomicBool,
    lockdown: AtomicBool,
}

impl FrontendPlatform for SystemPlatform {
    fn system_dns(&self) -> Option<SystemDnsSnapshot> {
        if self.ambiguous.load(SeqCst) {
            return None;
        }
        Some(SystemDnsSnapshot {
            token: 7,
            dns_servers: vec!["127.77.10.54".parse().unwrap()],
            interface_index: 1,
        })
    }
    fn system_dns_current(&self, token: i64) -> bool {
        self.checks.fetch_add(1, SeqCst);
        token == 7 && !self.ambiguous.load(SeqCst) && !self.lockdown.load(SeqCst)
    }
    fn system_dns_failure_token(&self) -> i64 {
        self.checks.fetch_add(1, SeqCst);
        if self.ambiguous.load(SeqCst) && !self.lockdown.load(SeqCst) {
            8
        } else {
            0
        }
    }
    fn prepare_system_dns(&self, _: i32, token: i64) -> io::Result<()> {
        assert_eq!(token, 7);
        self.prepares.fetch_add(1, SeqCst);
        Ok(())
    }
    fn open(
        &self,
        generation: i64,
        config: &CaptureConfig,
    ) -> io::Result<talpid_tunnel::tun_provider::AppliedTun> {
        self.packet.open(generation, config)
    }
    fn handover(&self, _: i64, _: i64, _: &CaptureConfig) -> CaptureHandover {
        unreachable!()
    }
    fn capture_feed(&self) -> Arc<CaptureNetworkFeed> {
        self.packet.capture_feed()
    }
    fn capture_format(
        &self,
        fd: BorrowedFd<'_>,
    ) -> io::Result<talpid_tunnel::android_frontend::CaptureFormat> {
        self.packet.capture_format(fd)
    }
    fn interface_name(&self, fd: BorrowedFd<'_>) -> io::Result<String> {
        self.packet.interface_name(fd)
    }
    fn expectation(&self, _: &CaptureConfig, _: String) -> io::Result<CaptureExpectation> {
        unreachable!()
    }
    fn bind(&self, _: i64, _: &str) -> io::Result<bool> {
        unreachable!()
    }
    fn closed(&self, generation: i64) -> io::Result<()> {
        self.packet.closed(generation)
    }
}

#[tokio::test]
async fn split_dns_live_partial_ordinary_udp_reaches_system_and_original_client() {
    let platform = Arc::new(SystemPlatform {
        packet: platform(),
        checks: AtomicUsize::new(0),
        prepares: AtomicUsize::new(0),
        ambiguous: AtomicBool::new(false),
        lockdown: AtomicBool::new(false),
    });
    let resolver: SocketAddr = "127.77.10.54:53".parse().unwrap();
    let server = UdpSocket::bind(resolver).await.unwrap();
    let (mut owner, peer) = start_partial(platform.clone(), resolver).await;
    let input = request("fresh.ordinary.test.", 702, resolver);
    peer.send(&input).await.unwrap();
    let observed = tokio::time::timeout(Duration::from_secs(1), async {
        let mut bytes = vec![0; 65535];
        let (length, client) = server.recv_from(&mut bytes).await.unwrap();
        bytes.truncate(length);
        assert_eq!(bytes, packet::parse(&input).unwrap().payload);
        let mut response = crate::split_dns::decode_message(&bytes)
            .unwrap()
            .into_response();
        response.add_answer(Record::from_rdata(
            response.queries[0].name().clone(),
            741,
            RData::A(A("10.77.10.54".parse().unwrap())),
        ));
        let response = response.to_vec().unwrap();
        server.send_to(&response, client).await.unwrap();
        let reply = capture_reply(&peer).await;
        let reply = packet::parse(&reply).unwrap();
        assert_eq!(reply.flow.source, resolver);
        assert_eq!(reply.flow.destination, "172.27.1.1:49900".parse().unwrap());
        assert_eq!(reply.payload, response);
    })
    .await;
    owner.stop().await.unwrap();
    assert!(
        observed.is_ok(),
        "Partial Ordinary did not return: lockdown checks={}, preparations={}",
        platform.checks.load(SeqCst),
        platform.prepares.load(SeqCst)
    );
    assert_eq!(platform.prepares.load(SeqCst), 1);
    assert!(platform.checks.load(SeqCst) > 1);
}

async fn start_partial(
    platform: Arc<SystemPlatform>,
    resolver: SocketAddr,
) -> (managed_platform::PlatformOwner, UnixDatagram) {
    let buffers = DeliveryBuffers::new();
    let mut policy = policy();
    policy.split_dns.enabled = true;
    policy.split_dns.suffixes = vec!["home".into()];
    policy.split_dns.home_resolver = Some("10.77.10.53".parse().unwrap());
    policy.split_dns.local_rule_id = Some(policy.rules[0].id);
    policy.rules[0]
        .cidrs
        .push("10.77.10.53/32".parse().unwrap());
    assert!(policy.validate().is_ok());
    let authority = Arc::new(DeliveryAuthority::new(
        &policy,
        Arc::new(|_, _| panic!("Ordinary must not acquire Home authority")),
    ));
    let broker = AttachmentBroker::new(
        buffers._application.clone(),
        buffers._capture.clone(),
        buffers._control.clone(),
    )
    .unwrap();
    broker.set_mode(AttachmentMode::ManagedRequired).unwrap();
    let config = DeliveryConfig::Partial(talpid_tunnel::tun_provider::PartialConfig {
        routes: vec![format!("{}/32", resolver.ip())],
        dns_servers: vec![resolver.ip()],
        excluded_packages: vec![],
    });
    authority.install(config.authority(&broker));
    let mut owner = managed_platform::PlatformFactory(platform.clone())
        .start(config, authority, buffers.local.clone(), broker)
        .unwrap();
    bounded(owner.ready()).await.unwrap();
    let peer =
        UnixDatagram::from_std(platform.packet.peer.lock().unwrap().take().unwrap()).unwrap();
    (owner, peer)
}

#[tokio::test]
async fn split_dns_partial_ambiguous_udp_reactor_returns_to_client_only_when_os_allows() {
    let resolver: SocketAddr = "127.77.10.55:53".parse().unwrap();
    let server = UdpSocket::bind(resolver).await.unwrap();
    for lockdown in [false, true] {
        let platform = Arc::new(SystemPlatform {
            packet: platform(),
            checks: AtomicUsize::new(0),
            prepares: AtomicUsize::new(0),
            ambiguous: AtomicBool::new(true),
            lockdown: AtomicBool::new(lockdown),
        });
        let (mut owner, peer) = start_partial(platform.clone(), resolver).await;
        let input = request("ambiguous.ordinary.test.", 703, resolver);
        peer.send(&input).await.unwrap();
        let observed = tokio::time::timeout(Duration::from_millis(500), capture_reply(&peer)).await;
        // Join on negative/red outcomes as well; never leave the reactor running.
        owner.stop().await.unwrap();
        if lockdown {
            assert!(observed.is_err(), "lockdown must drop");
        } else {
            let bytes =
                observed.expect("ambiguity must return SERVFAIL to the actual capture client");
            let packet = packet::parse(&bytes).unwrap();
            assert_eq!(packet.flow.source, resolver);
            assert_eq!(packet.flow.destination, "172.27.1.1:49900".parse().unwrap());
            let response = crate::split_dns::decode_message(packet.payload).unwrap();
            assert_eq!(response.metadata.id, 703);
            assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
            assert_eq!(
                response.queries,
                crate::split_dns::decode_message(packet::parse(&input).unwrap().payload)
                    .unwrap()
                    .queries
            );
        }
        assert_eq!(platform.prepares.load(SeqCst), 0);
        assert!(platform.checks.load(SeqCst) > 0);
        let mut unexpected = [0; 512];
        assert!(
            tokio::time::timeout(Duration::from_millis(50), server.recv_from(&mut unexpected))
                .await
                .is_err()
        );
    }
}
