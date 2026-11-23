//! Partial Ordinary must traverse the production capture and system I/O owners.
use super::*;
use talpid_tunnel::android_frontend::{CaptureHandover, SystemDnsSnapshot};

struct SystemPlatform {
    packet: Arc<PacketPlatform>,
    checks: AtomicUsize,
    prepares: AtomicUsize,
}

impl FrontendPlatform for SystemPlatform {
    fn system_dns(&self) -> Option<SystemDnsSnapshot> {
        Some(SystemDnsSnapshot {
            token: 7,
            dns_servers: vec!["127.77.10.54".parse().unwrap()],
            interface_index: 1,
        })
    }
    fn system_dns_current(&self, token: i64) -> bool {
        self.checks.fetch_add(1, SeqCst);
        token == 7
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
    });
    let resolver: SocketAddr = "127.77.10.54:53".parse().unwrap();
    let server = UdpSocket::bind(resolver).await.unwrap();
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
        routes: vec!["127.77.10.54/32".into()],
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
    // Join even on red, so a timeout cannot hide the failed boundary.
    owner.stop().await.unwrap();
    assert!(
        observed.is_ok(),
        "Partial Ordinary did not return: lockdown checks={}, preparations={}",
        platform.checks.load(SeqCst),
        platform.prepares.load(SeqCst),
    );
    assert_eq!(platform.prepares.load(SeqCst), 1);
    assert!(platform.checks.load(SeqCst) > 1);
}
