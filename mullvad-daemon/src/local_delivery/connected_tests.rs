//! Exercise the daemon's actual configuration, classifier and authority through
//! the production capture actor, with real packet and physical socket consumers.
use super::*;
use crate::local_network::ConnectContinuation;
use crate::local_network::TunnelPhase;
use std::{
    os::fd::{AsRawFd, BorrowedFd, OwnedFd},
    path::PathBuf,
};
use talpid_tunnel::android_frontend::{
    CaptureConfig, FrontendOwner, FrontendPlatform, FrontendState,
};
use talpid_types::capture_network::{
    CaptureExpectation, CaptureNetworkFeed, CaptureNetworkObservation, CapturePrefix,
};
use talpid_types::local_network::{LocalPhysicalAddress, LocalPhysicalNetwork};
use tokio::net::UnixDatagram;

struct PacketPlatform {
    feed: Arc<CaptureNetworkFeed>,
    expected: Mutex<Option<CaptureExpectation>>,
    opened: Mutex<Vec<talpid_tunnel::tun_provider::TunConfig>>,
    application_coverage: Mutex<Vec<Vec<String>>>,
    peer: Mutex<Option<std::os::unix::net::UnixDatagram>>,
    descriptors: Mutex<Vec<DescriptorEpoch>>,
    starts: AtomicUsize,
    releases: AtomicUsize,
    completed_releases: Mutex<Vec<i64>>,
    released: tokio::sync::Notify,
    fail_release: AtomicBool,
    retain_handover: AtomicBool,
    delayed_completion: Mutex<Option<oneshot::Sender<(i64, CaptureNetworkObservation)>>>,
    authority: Mutex<Option<Arc<DeliveryAuthority>>>,
    generation: std::sync::atomic::AtomicI64,
    physical: (SocketAddr, SocketAddr),
}

struct DescriptorEpoch {
    generation: i64,
    descriptor: PathBuf,
    identity: PathBuf,
    peer: PathBuf,
}

impl PacketPlatform {
    fn descriptor_closed(&self, generation: i64) -> bool {
        let descriptors = self.descriptors.lock().unwrap();
        let Some(epoch) = descriptors
            .iter()
            .find(|epoch| epoch.generation == generation)
        else {
            // A pre-establish failure can owe platform release without having
            // returned a descriptor at all.
            return true;
        };
        match std::fs::read_link(&epoch.descriptor) {
            Ok(identity) => identity != epoch.identity,
            Err(error) => {
                assert_eq!(error.kind(), io::ErrorKind::NotFound, "{error}");
                true
            }
        }
    }

    // A Unix datagram peer's send error need not coincide with descriptor close.
    // Match this peer to the actual owned fd and its exact release record.
    fn peer_closed(&self, peer: &std::os::unix::net::UnixDatagram) -> bool {
        let identity = std::fs::read_link(format!("/proc/self/fd/{}", peer.as_raw_fd())).unwrap();
        let generation = self
            .descriptors
            .lock()
            .unwrap()
            .iter()
            .find(|epoch| epoch.peer == identity)
            .expect("peer belongs to an issued descriptor epoch")
            .generation;
        self.completed_releases
            .lock()
            .unwrap()
            .contains(&generation)
            && self.descriptor_closed(generation)
    }
}

impl FrontendPlatform for PacketPlatform {
    fn handover(
        &self,
        _: i64,
        generation: i64,
        config: &CaptureConfig,
    ) -> talpid_tunnel::android_frontend::CaptureHandover {
        if self.retain_handover.load(SeqCst) {
            return talpid_tunnel::android_frontend::CaptureHandover {
                descriptor: Err(io::Error::other("before establish")),
                predecessor_retained: true,
            };
        }
        talpid_tunnel::android_frontend::CaptureHandover {
            descriptor: self.open(generation, config),
            predecessor_retained: false,
        }
    }
    fn capture_format(
        &self,
        _: BorrowedFd<'_>,
    ) -> io::Result<talpid_tunnel::android_frontend::CaptureFormat> {
        talpid_tunnel::android_frontend::CaptureFormat::from_flags(0x1001)
    }
    fn open(
        &self,
        generation: i64,
        config: &CaptureConfig,
    ) -> io::Result<talpid_tunnel::tun_provider::AppliedTun> {
        self.application_coverage
            .lock()
            .unwrap()
            .push(match config {
                CaptureConfig::Partial(config) => config.excluded_packages.clone(),
                _ => config.secured_config().unwrap().excluded_packages.clone(),
            });
        if let Some(config) = config.secured_config() {
            self.opened.lock().unwrap().push(config.clone());
        }
        let (capture, peer) = std::os::unix::net::UnixDatagram::pair()?;
        capture.set_nonblocking(true)?;
        peer.set_nonblocking(true)?;
        let descriptor = PathBuf::from(format!("/proc/self/fd/{}", capture.as_raw_fd()));
        self.descriptors.lock().unwrap().push(DescriptorEpoch {
            generation,
            identity: std::fs::read_link(&descriptor)?,
            descriptor,
            peer: std::fs::read_link(format!("/proc/self/fd/{}", peer.as_raw_fd()))?,
        });
        *self.peer.lock().unwrap() = Some(peer);
        self.generation.store(generation, SeqCst);
        self.starts.fetch_add(1, SeqCst);
        Ok(OwnedFd::from(capture).into())
    }
    fn capture_feed(&self) -> Arc<CaptureNetworkFeed> {
        self.feed.clone()
    }
    fn interface_name(&self, _: BorrowedFd<'_>) -> io::Result<String> {
        Ok("tun-owned".into())
    }
    fn expectation(
        &self,
        config: &CaptureConfig,
        interface: String,
    ) -> io::Result<CaptureExpectation> {
        let config = config.secured_config().expect("secured test capture");
        let routes = config
            .routes
            .iter()
            .map(|prefix| CapturePrefix {
                address: prefix.network(),
                prefix_length: i16::from(prefix.prefix()),
            })
            .collect::<Vec<_>>();
        let expected = CaptureExpectation::requested(
            interface,
            1000,
            33,
            &config.addresses,
            &routes,
            &config
                .dns_servers
                .clone()
                .unwrap_or_else(|| config.gateways()),
            config.mtu,
        )
        .unwrap();
        *self.expected.lock().unwrap() = Some(expected.clone());
        Ok(expected)
    }
    fn bind(&self, generation: i64, _: &str) -> io::Result<bool> {
        let expected = self.expected.lock().unwrap().clone().unwrap();
        let observation = CaptureNetworkObservation {
            network_handle: generation << 32,
            network: format!("net-{generation}"),
            interface_name: expected.interface_name,
            owner_uid: expected.owner_uid,
            routes: expected.routes,
            addresses: expected.addresses,
            dns_servers: expected.dns_servers,
            mtu: expected.mtu,
            fresh: true,
            lost: false,
            api_level: 33,
        };
        if let Some(delayed) = self.delayed_completion.lock().unwrap().take() {
            delayed
                .send((generation, observation))
                .map_err(|_| io::Error::other("delayed completion receiver closed"))?;
            Ok(true)
        } else {
            Ok(self
                .feed
                .publish(self.feed.registration(), generation, observation))
        }
    }
    fn closed(&self, generation: i64) -> io::Result<()> {
        assert!(
            self.descriptor_closed(generation),
            "platform release preceded exact descriptor closure for epoch {generation}"
        );
        self.releases.fetch_add(1, SeqCst);
        let result = if self.fail_release.load(SeqCst) {
            Err(io::Error::other("test platform retains capture"))
        } else {
            self.completed_releases.lock().unwrap().push(generation);
            Ok(())
        };
        self.released.notify_one();
        result
    }
}

struct PacketFactory(Arc<PacketPlatform>);
struct PacketOwner {
    owner: FrontendOwner,
    authority: Arc<DeliveryAuthority>,
    state: watch::Receiver<FrontendState>,
    open: bool,
}
impl FrontendFactory for PacketFactory {
    type Owner = PacketOwner;
    fn supported(&self) -> bool {
        true
    }
    fn start(
        &self,
        config: DeliveryConfig,
        authority: Arc<DeliveryAuthority>,
        buffers: Arc<dyn RelayBufferAllocator>,
        broker: AttachmentBroker,
    ) -> io::Result<Self::Owner> {
        let updates = authority.subscribe();
        *self.0.authority.lock().unwrap() = Some(authority.clone());
        let mtu = config.mtu();
        let frontend = config.into_frontend(authority.clone());
        let forward_authority = Arc::new(LoopbackAuthority {
            authority: authority.clone(),
            peer: Some(self.0.physical),
        });
        let forwarder = Forwarder::with_mtu(forward_authority, buffers, usize::from(mtu))
            .map_err(|_| io::Error::other("test budget full"))?;
        let owner = FrontendOwner::start(self.0.clone(), frontend, forwarder, updates, broker)?;
        Ok(PacketOwner {
            state: owner.state(),
            owner,
            authority,
            open: true,
        })
    }
}
impl DeliveryOwner for PacketOwner {
    fn handover(&mut self, config: DeliveryConfig) -> io::Result<()> {
        self.owner
            .handover(config.into_frontend(self.authority.clone()))
    }
    fn retry_handover_release(&mut self) -> io::Result<()> {
        self.owner.retry_handover_release()
    }
    async fn ready(&mut self) -> io::Result<()> {
        self.owner.ready().await
    }
    async fn stop(&mut self) -> io::Result<()> {
        self.owner.stop().await
    }
    fn retry_release(&mut self) -> io::Result<()> {
        self.owner.retry_release()
    }
    fn state(&self) -> OwnerState {
        match *self.state.borrow() {
            FrontendState::Running => OwnerState::Running,
            FrontendState::Failed => OwnerState::Failed,
            FrontendState::Stopped => OwnerState::Stopped,
        }
    }
    fn release_failed(&self) -> bool {
        self.owner.release_failed()
    }
    async fn changed(&mut self) {
        if self.open {
            self.open = self.state.changed().await.is_ok();
        } else {
            std::future::pending().await
        }
    }
}

fn physical_snapshot() -> LocalNetworkSnapshot {
    let observed = observation();
    LocalNetworkSnapshot {
        sequence: 9,
        observer_running: true,
        local_ready: true,
        fine_ready: true,
        background_ready: true,
        location_enabled: true,
        location_allowed: true,
        networks: observed
            .networks
            .into_iter()
            .map(|network| LocalPhysicalNetwork {
                network_handle: network.handle,
                transport: 1,
                capabilities_fresh: true,
                links_fresh: true,
                blocked: false,
                interface_index: network.interface_index,
                addresses: network
                    .addresses
                    .into_iter()
                    .map(|address| LocalPhysicalAddress {
                        prefix: LocalPhysicalPrefix {
                            address: address.prefix.ip(),
                            prefix_length: i16::from(address.prefix.prefix()),
                        },
                        usable: true,
                    })
                    .collect(),
                routes: network.routes,
                ssid_hex: network.ssid.map(|ssid| ssid.encoded_bytes()),
            })
            .collect(),
    }
}

async fn capture_reply(peer: &UnixDatagram) -> Vec<u8> {
    let mut bytes = vec![0; 65575];
    let count = bounded(peer.recv(&mut bytes)).await.unwrap();
    bytes.truncate(count);
    bytes
}

#[tokio::test]
async fn daemon_route_handover_retains_the_partial_grant_and_same_physical_tcp_stream() {
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let physical = (tcp.local_addr().unwrap(), udp.local_addr().unwrap());
    let physical_task = tokio::spawn(async move {
        let (mut stream, _) = tcp.accept().await.unwrap();
        for nonce in [
            b"before".as_slice(),
            b"routes",
            b"secured",
            b"exclusions",
            b"partial",
        ] {
            let mut bytes = vec![0; nonce.len()];
            stream.read_exact(&mut bytes).await.unwrap();
            assert_eq!(bytes, nonce);
            stream.write_all(&bytes).await.unwrap();
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(30), tcp.accept())
                .await
                .is_err()
        );
    });
    let platform = Arc::new(PacketPlatform {
        feed: CaptureNetworkFeed::new(43),
        expected: Mutex::new(None),
        opened: Mutex::new(Vec::new()),
        application_coverage: Mutex::new(Vec::new()),
        peer: Mutex::new(None),
        descriptors: Mutex::new(Vec::new()),
        starts: AtomicUsize::new(0),
        releases: AtomicUsize::new(0),
        completed_releases: Mutex::new(Vec::new()),
        released: tokio::sync::Notify::new(),
        fail_release: AtomicBool::new(false),
        retain_handover: AtomicBool::new(false),
        delayed_completion: Mutex::new(None),
        authority: Mutex::new(None),
        generation: 0.into(),
        physical,
    });
    let authority = authority();
    authority.update(&policy(), Some(observation()));
    let buffers = DeliveryBuffers::new();
    let broker = broker();
    let mut delivery = Delivery::new(
        PacketFactory(platform.clone()),
        authority.clone(),
        buffers.local.clone(),
        broker.clone(),
    );
    delivery
        .maintain_config(Some(DeliveryConfig::Partial(
            vec!["10.0.2.2/32".into()].into(),
        )))
        .await;
    bounded(delivery.changed()).await;
    let mut peer = UnixDatagram::from_std(platform.peer.lock().unwrap().take().unwrap()).unwrap();
    let local = flow(Transport::Tcp, 45901);
    let grant = authority.authorize(local).unwrap();
    let session = broker.snapshot().session_generation;
    assert_eq!(
        grant.generation, session,
        "Partial uses the real logical session"
    );
    peer.send(&tcp_packet(local, 100, 0, 2, &[])).await.unwrap();
    let syn = capture_reply(&peer).await;
    assert_eq!(syn[33] & 0x12, 0x12);
    let mut ack = u32::from_be_bytes(syn[24..28].try_into().unwrap()).wrapping_add(1);
    let mut sequence = 101;
    let mut request = None;
    for (index, nonce) in [
        b"before".as_slice(),
        b"routes",
        b"secured",
        b"exclusions",
        b"partial",
    ]
    .into_iter()
    .enumerate()
    {
        if index != 0 {
            drop(request.take());
            let mut config = match index {
                1 => DeliveryConfig::Partial(
                    vec!["10.0.2.2/32".into(), "172.16.0.0/16".into()].into(),
                ),
                2 | 3 => {
                    let mut config = assigned_config();
                    config.addresses = vec![
                        "172.27.1.1".parse().unwrap(),
                        "fdf0:ce4a:801d::172:27:1:1".parse().unwrap(),
                    ];
                    config.mtu = 1280;
                    if index == 3 {
                        config.dns_servers = Some(vec!["10.64.0.2".parse().unwrap()]);
                        config
                            .excluded_packages
                            .push("unrelated.excluded.app".into());
                    }
                    request = Some(broker.request_capture(config).unwrap());
                    DeliveryConfig::Secured {
                        broker: broker.clone(),
                        request: broker.pending_request().unwrap(),
                    }
                }
                _ => DeliveryConfig::Partial(vec!["10.0.2.2/32".into()].into()),
            };
            if index == 1 {
                platform.fail_release.store(true, SeqCst);
            }
            if index == 2 {
                // Retry the retained predecessor within this same live owner,
                // then fail establish before any OS switch. Neither may revoke
                // the Partial grant or the already connected physical stream.
                let previous = delivery.applied_config().unwrap();
                platform.fail_release.store(false, SeqCst);
                platform.retain_handover.store(true, SeqCst);
                delivery.maintain_config(Some(config.clone())).await;
                bounded(async {
                    while delivery.pending.is_some() {
                        delivery.changed().await;
                    }
                })
                .await;
                assert!(delivery.failed(), "failed establish was not reported");
                assert!(
                    delivery.ready(),
                    "proven rollback lost the working predecessor"
                );
                assert!(delivery.applied_config().unwrap().same_capture(&previous));
                assert!(authority.current(&grant));
                assert!(
                    !delivery.release_failed(),
                    "exact predecessor release did not recover: owner {:?}, releases {}, broker {:?}",
                    delivery.owner_state(),
                    platform.releases.load(SeqCst),
                    broker.snapshot()
                );
                platform.retain_handover.store(false, SeqCst);
                assert!(
                    bounded(request.as_mut().unwrap().configured())
                        .await
                        .is_err()
                );
                let projection = config.router_config().unwrap().clone();
                drop(request.take());
                request = Some(broker.request_capture(projection).unwrap());
                config = DeliveryConfig::Secured {
                    broker: broker.clone(),
                    request: broker.pending_request().unwrap(),
                };
            }
            delivery.maintain_config(Some(config.clone())).await;
            assert!(
                authority.current(&grant),
                "configuration change revoked the retained Local grant"
            );
            bounded(async {
                while !delivery
                    .applied_config()
                    .as_ref()
                    .is_some_and(|applied| applied.same_capture(&config))
                {
                    delivery.changed().await;
                }
            })
            .await;
            if let Some(request) = request.as_mut() {
                bounded(request.configured()).await.unwrap();
            }
            peer = UnixDatagram::from_std(platform.peer.lock().unwrap().take().unwrap()).unwrap();
            assert!(authority.current(&grant));
            assert_eq!(broker.snapshot().session_generation, session);
        }
        peer.send(&tcp_packet(local, sequence, ack, 0x18, nonce))
            .await
            .unwrap();
        let mut received = vec![];
        while received.len() < nonce.len() {
            let bytes = capture_reply(&peer).await;
            let payload = packet::parse(&bytes).unwrap().payload;
            received.extend_from_slice(payload);
            ack = ack.wrapping_add(payload.len() as u32);
        }
        assert_eq!(received, nonce);
        sequence += nonce.len() as u32;
        peer.send(&tcp_packet(local, sequence, ack, 0x10, &[]))
            .await
            .unwrap();
        if index == 1 {
            bounded(async {
                while !delivery.release_failed() {
                    delivery.changed().await;
                }
            })
            .await;
            assert!(
                authority.current(&grant),
                "failed predecessor cleanup revoked Local"
            );
            assert!(delivery.ready(), "cleanup failure stopped the current sink");
            assert_eq!(platform.starts.load(SeqCst), 2);
        }
    }
    bounded(physical_task).await.unwrap();
    delivery.stop().await.unwrap();
    assert!(!authority.current(&grant));
    assert_eq!(platform.starts.load(SeqCst), 5);
    assert_eq!(platform.releases.load(SeqCst), 7);
}

#[tokio::test]
async fn managed_capture_delivers_local_nonces_and_never_relays_denied_local() {
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let physical = (tcp.local_addr().unwrap(), udp.local_addr().unwrap());
    let hits = Arc::new(AtomicUsize::new(0));
    let tcp_hits = hits.clone();
    let tcp_task = tokio::spawn(async move {
        let (mut stream, _) = tcp.accept().await.unwrap();
        let nonce = b"assigned-tcp-consumer";
        let mut bytes = vec![0; nonce.len()];
        stream.read_exact(&mut bytes).await.unwrap();
        assert_eq!(bytes, nonce);
        tcp_hits.fetch_add(1, SeqCst);
        stream.write_all(&bytes).await.unwrap();
    });
    let udp_hits = hits.clone();
    let udp_task = tokio::spawn(async move {
        let mut bytes = [0; 128];
        let (count, source) = udp.recv_from(&mut bytes).await.unwrap();
        assert_eq!(&bytes[..count], b"assigned-udp-consumer");
        udp_hits.fetch_add(1, SeqCst);
        udp.send_to(&bytes[..count], source).await.unwrap();
        // Remain a real bound peer for the denied cases, so absence of delivery
        // is not merely the absence of a listener.
        let denied =
            tokio::time::timeout(Duration::from_millis(400), udp.recv_from(&mut bytes)).await;
        assert!(denied.is_err(), "denied local packet hit the physical peer");
    });
    let platform = Arc::new(PacketPlatform {
        feed: CaptureNetworkFeed::new(41),
        expected: Mutex::new(None),
        opened: Mutex::new(Vec::new()),
        application_coverage: Mutex::new(Vec::new()),
        peer: Mutex::new(None),
        descriptors: Mutex::new(Vec::new()),
        starts: AtomicUsize::new(0),
        releases: AtomicUsize::new(0),
        completed_releases: Mutex::new(Vec::new()),
        released: tokio::sync::Notify::new(),
        fail_release: AtomicBool::new(false),
        retain_handover: AtomicBool::new(false),
        delayed_completion: Mutex::new(None),
        authority: Mutex::new(None),
        generation: 0.into(),
        physical,
    });
    let feed = LocalNetworkFeed::new(31);
    assert!(feed.publish(31, physical_snapshot()));
    let mut runtime = LocalNetworkRuntime::with_factory(
        &policy(),
        Some(feed.clone()),
        PacketFactory(platform.clone()),
        Arc::new(|_, _| Ok(())),
    );
    let broker = runtime.broker();
    broker.set_mode(AttachmentMode::ManagedRequired).unwrap();
    let mut request = broker
        .request_target_capture(
            assigned_config(),
            talpid_tunnel::tun_provider::transport::router_config(
                &assigned_config(),
                policy()
                    .announced_routes()
                    .iter()
                    .map(|route| route.network())
                    .collect(),
            ),
        )
        .unwrap();
    // The real actor's startup can await its callback without holding the daemon.
    tokio::time::timeout(
        Duration::from_millis(100),
        runtime.update(&policy(), TargetState::Secured, TunnelPhase::Connecting),
    )
    .await
    .unwrap();
    assert_eq!(
        runtime.status().forwarding,
        ForwardingAvailability::PausedWhileConnected
    );
    bounded(runtime.notifications().1).await;
    runtime.owner_changed(&policy(), TargetState::Secured, TunnelPhase::Connecting);
    let receipt = bounded(request.configured()).await.unwrap();
    let mut pair = broker.acquire(&receipt).unwrap();
    let peer = UnixDatagram::from_std(platform.peer.lock().unwrap().take().unwrap()).unwrap();
    let mut public = flow(Transport::Udp, 45000);
    public.source.set_ip(fixed_config().addresses[0]);
    public.destination = "1.1.1.1:443".parse().unwrap();
    let public_bytes = udp_packet(public, b"ordinary-raw");
    peer.send(&public_bytes).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(30), pair.receive.recv())
            .await
            .is_err()
    );
    assert_eq!(runtime.status().forwarding, ForwardingAvailability::Active);
    assert!(
        runtime
            .status()
            .rules
            .iter()
            .all(|rule| rule.state == RuleState::Forwarding)
    );
    let mut tcp_flow = flow(Transport::Tcp, 45001);
    tcp_flow.source.set_ip(public.source.ip());
    peer.send(&tcp_packet(tcp_flow, 100, 0, 2, &[]))
        .await
        .unwrap();
    let syn = capture_reply(&peer).await;
    assert_eq!(syn[33] & 0x12, 0x12);
    let ack = u32::from_be_bytes(syn[24..28].try_into().unwrap()).wrapping_add(1);
    let nonce = b"assigned-tcp-consumer";
    peer.send(&tcp_packet(tcp_flow, 101, ack, 0x18, nonce))
        .await
        .unwrap();
    let mut received = vec![];
    while received.len() < nonce.len() {
        let bytes = capture_reply(&peer).await;
        received.extend_from_slice(packet::parse(&bytes).unwrap().payload);
    }
    assert_eq!(received, nonce, "complete TCP echo at the capture consumer");
    let mut udp_flow = flow(Transport::Udp, 45002);
    udp_flow.source.set_ip(public.source.ip());
    peer.send(&udp_packet(udp_flow, b"assigned-udp-consumer"))
        .await
        .unwrap();
    loop {
        let bytes = capture_reply(&peer).await;
        let parsed = packet::parse(&bytes).unwrap();
        if parsed.flow.transport == Transport::Udp {
            assert_eq!(parsed.payload, b"assigned-udp-consumer");
            break;
        }
    }
    assert_eq!(hits.load(SeqCst), 2);
    assert!(
        !pair.control.current(),
        "Local authentication accidentally activated ordinary traffic"
    );
    pair.control.activate().unwrap();
    bounded(pair.receive.recv())
        .await
        .unwrap()
        .handoff(|bytes| assert_eq!(bytes, public_bytes))
        .unwrap();
    runtime
        .internal_update(&policy(), TargetState::Secured, TunnelPhase::Connected)
        .await;
    assert_eq!(runtime.status().forwarding, ForwardingAvailability::Active);
    peer.send(&public_bytes).await.unwrap();
    bounded(pair.receive.recv())
        .await
        .unwrap()
        .handoff(|bytes| assert_eq!(bytes, public_bytes))
        .unwrap();
    let mut unmet = policy();
    unmet.rules[0].ssid_ids = vec![SsidIdentity::from_bytes(b"other".to_vec()).unwrap()];
    runtime
        .update(&unmet, TargetState::Secured, TunnelPhase::Connected)
        .await;
    peer.send(&udp_packet(udp_flow, b"denied-condition"))
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(80), pair.receive.recv())
            .await
            .is_err()
    );
    feed.close();
    runtime
        .update(&policy(), TargetState::Secured, TunnelPhase::Connected)
        .await;
    assert!(
        runtime
            .status()
            .rules
            .iter()
            .all(|rule| rule.state != RuleState::Forwarding)
    );
    peer.send(&udp_packet(udp_flow, b"denied-observer"))
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(80), pair.receive.recv())
            .await
            .is_err()
    );
    assert!(pair.control.current());
    peer.send(&public_bytes).await.unwrap();
    bounded(pair.receive.recv())
        .await
        .unwrap()
        .handoff(|bytes| assert_eq!(bytes, public_bytes))
        .unwrap();
    assert_eq!(
        platform.starts.load(SeqCst),
        1,
        "conditions and physical loss do not replace capture"
    );
    runtime.suspend();
    assert!(
        !pair.control.current(),
        "ordinary authority revoked before stop"
    );
    runtime.observe_transport(
        &mut ConnectContinuation::default(),
        TunnelPhase::Disconnected,
    );
    runtime.stop().await.unwrap();
    assert_eq!(platform.releases.load(SeqCst), 1);
    bounded(tcp_task).await.unwrap();
    bounded(udp_task).await.unwrap();
    assert_eq!(hits.load(SeqCst), 2);
}

#[tokio::test]
async fn assigned_config_handover_retains_local_sources_and_joined_shutdown() {
    let platform = Arc::new(PacketPlatform {
        feed: CaptureNetworkFeed::new(42),
        expected: Mutex::new(None),
        opened: Mutex::new(Vec::new()),
        application_coverage: Mutex::new(Vec::new()),
        peer: Mutex::new(None),
        descriptors: Mutex::new(Vec::new()),
        starts: AtomicUsize::new(0),
        releases: AtomicUsize::new(0),
        completed_releases: Mutex::new(Vec::new()),
        released: tokio::sync::Notify::new(),
        fail_release: AtomicBool::new(false),
        retain_handover: AtomicBool::new(false),
        delayed_completion: Mutex::new(None),
        authority: Mutex::new(None),
        generation: 0.into(),
        physical: (
            "127.0.0.1:9".parse().unwrap(),
            "127.0.0.1:9".parse().unwrap(),
        ),
    });
    let feed = LocalNetworkFeed::new(32);
    assert!(feed.publish(32, physical_snapshot()));
    let mut runtime = LocalNetworkRuntime::with_factory(
        &policy(),
        Some(feed),
        PacketFactory(platform.clone()),
        Arc::new(|_, _| Ok(())),
    );
    let broker = runtime.broker();
    broker.set_mode(AttachmentMode::ManagedRequired).unwrap();
    let target = assigned_config();
    let projected =
        talpid_tunnel::tun_provider::transport::router_config(&target, broker.local_routes());
    let mut first_request = broker.request_target_capture(target, projected).unwrap();
    runtime
        .update(&policy(), TargetState::Secured, TunnelPhase::Connecting)
        .await;
    bounded(runtime.notifications().1).await;
    let first = bounded(first_request.configured()).await.unwrap();
    let session = broker.snapshot().session_generation;
    let first_pair = broker.acquire(&first).unwrap();
    first_pair.control.activate().unwrap();
    runtime.owner_changed(&policy(), TargetState::Secured, TunnelPhase::Connected);
    let authority = platform.authority.lock().unwrap().clone().unwrap();
    let mut old_flow = flow(Transport::Udp, 45010);
    old_flow.source.set_ip(fixed_config().addresses[0]);
    let old_grant = authority.authorize(old_flow).unwrap();

    let mut replacement = assigned_config();
    replacement.addresses = vec![
        "10.64.9.8".parse().unwrap(),
        "fc00:bbbb:bbbb:bb01::8".parse().unwrap(),
    ];
    replacement.dns_servers = Some(vec!["10.64.0.2".parse().unwrap()]);
    replacement.routes.push("10.0.2.2/32".parse().unwrap());
    replacement.mtu = 1420;
    replacement.excluded_packages = vec!["test.excluded".into()];
    platform.fail_release.store(true, SeqCst);
    first_pair.control.detach();
    first_request.transport_joined();
    let projected =
        talpid_tunnel::tun_provider::transport::router_config(&replacement, broker.local_routes());
    let mut second_request = broker
        .request_target_capture(replacement.clone(), projected.clone())
        .unwrap();
    runtime
        .update(&policy(), TargetState::Secured, TunnelPhase::Connected)
        .await;
    bounded(runtime.notifications().1).await;
    let second = bounded(second_request.configured()).await.unwrap();
    assert_ne!(first.generation(), second.generation());
    assert!(!first.current(), "old sink receipt must stay stale");
    let second_pair = broker.acquire(&second).unwrap();
    second_pair.control.activate().unwrap();
    bounded(async {
        while !runtime.failed() {
            runtime.notifications().1.await;
        }
    })
    .await;
    runtime.owner_changed(&policy(), TargetState::Secured, TunnelPhase::Connected);
    assert!(runtime.has_owner());
    assert_eq!(runtime.status().forwarding, ForwardingAvailability::Failed);
    assert!(
        authority.current(&old_grant),
        "sink cleanup does not retire eligible Local authority"
    );
    assert!(!first_pair.control.current());
    assert_eq!(broker.snapshot().session_generation, session);
    assert_eq!(platform.starts.load(SeqCst), 2);
    assert!(broker.pending_request().is_none());
    let release_count = platform.releases.load(SeqCst);
    runtime
        .internal_update(&policy(), TargetState::Secured, TunnelPhase::Connected)
        .await;
    assert_eq!(
        platform.releases.load(SeqCst),
        release_count,
        "internal wake cannot retry release"
    );
    assert!(
        second_pair.control.current(),
        "cleanup failure retains the configured successor"
    );
    assert!(
        !platform
            .completed_releases
            .lock()
            .unwrap()
            .contains(&(first.generation() as i64))
    );
    platform.fail_release.store(false, SeqCst);
    runtime
        .update(&policy(), TargetState::Secured, TunnelPhase::Connected)
        .await;
    bounded(runtime.notifications().1).await;
    runtime.owner_changed(&policy(), TargetState::Secured, TunnelPhase::Connected);
    assert_eq!(runtime.status().forwarding, ForwardingAvailability::Active);
    assert!(authority.current(&old_grant));
    assert_eq!(broker.snapshot().session_generation, session);
    assert_eq!(
        platform.starts.load(SeqCst),
        2,
        "release retry cannot reopen the sink"
    );
    assert!(
        platform
            .completed_releases
            .lock()
            .unwrap()
            .contains(&(first.generation() as i64))
    );
    let mut new_flow = old_flow;
    new_flow.source.set_ip(replacement.addresses[0]);
    assert!(
        authority.authorize(new_flow).is_err(),
        "target assignment cannot become a Local source"
    );
    let new_grant = authority.authorize(old_flow).unwrap();
    let observed = platform.expected.lock().unwrap().clone().unwrap();
    assert_eq!(
        observed
            .addresses
            .iter()
            .map(|p| p.address)
            .collect::<Vec<_>>(),
        projected.addresses
    );
    assert_eq!(
        observed.dns_servers,
        replacement.dns_servers.clone().unwrap()
    );
    assert_eq!(observed.mtu, Some(1420));
    assert_eq!(
        platform.opened.lock().unwrap().last(),
        Some(&projected),
        "exact config including routes/exclusions reaches platform"
    );
    drop(first_request);
    assert!(
        second_pair.control.current(),
        "old request Drop cannot retire the successor"
    );

    platform.fail_release.store(true, SeqCst);
    runtime.begin_shutdown();
    assert!(!authority.current(&new_grant));
    assert!(!second_pair.control.current());
    runtime.observe_transport(
        &mut ConnectContinuation::default(),
        TunnelPhase::Disconnected,
    );
    assert!(runtime.shutdown().await.is_err());
    assert!(runtime.has_owner());
    assert_eq!(platform.starts.load(SeqCst), 2);
    platform.fail_release.store(false, SeqCst);
    runtime.shutdown().await.unwrap();
    assert!(!runtime.has_owner());
    assert!(broker.snapshot().closed);
}

fn release_fixture() -> (
    Delivery<PacketFactory>,
    Arc<PacketPlatform>,
    AttachmentBroker,
) {
    let platform = Arc::new(PacketPlatform {
        feed: CaptureNetworkFeed::new(44),
        expected: Mutex::new(None),
        opened: Mutex::new(Vec::new()),
        application_coverage: Mutex::new(Vec::new()),
        peer: Mutex::new(None),
        descriptors: Mutex::new(Vec::new()),
        starts: AtomicUsize::new(0),
        releases: AtomicUsize::new(0),
        completed_releases: Mutex::new(Vec::new()),
        released: tokio::sync::Notify::new(),
        fail_release: AtomicBool::new(false),
        retain_handover: AtomicBool::new(false),
        delayed_completion: Mutex::new(None),
        authority: Mutex::new(None),
        generation: 0.into(),
        physical: (
            "127.0.0.1:9".parse().unwrap(),
            "127.0.0.1:9".parse().unwrap(),
        ),
    });
    let broker = broker();
    broker.set_mode(AttachmentMode::ManagedRequired).unwrap();
    let delivery = Delivery::new(
        PacketFactory(platform.clone()),
        authority(),
        DeliveryBuffers::new().local.clone(),
        broker.clone(),
    );
    (delivery, platform, broker)
}

#[tokio::test]
async fn shutdown_failure_is_observable_without_external_events() {
    use futures::{FutureExt, StreamExt};
    for queued_connect in [false, true] {
        let mut h = Handover::new(policy());
        h.connect_endpoint().await;
        let broker = h.runtime.broker();
        let platform = h.platform.clone();
        let generation = platform.generation.load(SeqCst);
        let request = h.request.take().unwrap();
        let transport = h.transport.take().unwrap();
        if queued_connect {
            h.continuation.connect();
            assert_eq!(
                h.runtime
                    .continue_connect(&mut h.continuation)
                    .map(|_| "Connect"),
                Some("Connect")
            );
        }
        // The daemon's input is closed; the physical feed is never republished.
        let (input, mut events) = futures::channel::mpsc::unbounded::<crate::InternalDaemonEvent>();
        drop(input);
        assert!(events.next().await.is_none());
        platform.fail_release.store(true, SeqCst);
        let before = platform.releases.load(SeqCst);
        let (complete, joined) = oneshot::channel();
        {
            let shutdown = h.runtime.shutdown_with_transport(async move {
                joined.await.map_err(io::Error::other)?;
                drop(transport);
                request.transport_joined();
                Ok(())
            });
            tokio::pin!(shutdown);
            assert!(shutdown.as_mut().now_or_never().is_none());
            assert!(broker.snapshot().closed);
            assert!(!broker.snapshot().ordinary_ready);
            assert_eq!(platform.releases.load(SeqCst), before);
            assert!(
                !platform.descriptor_closed(generation),
                "closed before actual transport join"
            );
            complete.send(()).unwrap();
            assert!(
                bounded(shutdown).await.is_err(),
                "release failure was hidden by an event wait"
            );
        }
        assert!(
            h.runtime.has_owner(),
            "failed shutdown discarded recovery owner"
        );
        assert!(platform.descriptor_closed(generation));
        assert_eq!(platform.releases.load(SeqCst), before + 1);
        assert!(
            !platform
                .completed_releases
                .lock()
                .unwrap()
                .contains(&generation)
        );
        platform.fail_release.store(false, SeqCst);
        bounded(h.runtime.shutdown_with_transport(async { Ok(()) }))
            .await
            .unwrap();
        assert!(!h.runtime.has_owner());
        assert_eq!(platform.releases.load(SeqCst), before + 2);
        assert_eq!(
            platform
                .completed_releases
                .lock()
                .unwrap()
                .iter()
                .filter(|g| **g == generation)
                .count(),
            1
        );
        h.runtime
            .shutdown_with_transport(async { Ok(()) })
            .await
            .unwrap();
        assert_eq!(platform.releases.load(SeqCst), before + 2);
        assert_eq!(
            h.phase,
            TunnelPhase::Connected,
            "resource join fabricated public Disconnected"
        );
    }
}

fn fixed_config() -> talpid_tunnel::tun_provider::TunConfig {
    let mut config = assigned_config();
    config.addresses = vec![
        "172.27.1.1".parse().unwrap(),
        "fdf0:ce4a:801d::172:27:1:1".parse().unwrap(),
    ];
    config.mtu = 1280;
    config
}

#[tokio::test]
async fn production_factory_mtu_changes_preserve_local_session_and_cancelled_target_is_not_loss() {
    use talpid_tunnel::android_frontend::{CaptureFormat, CaptureHandover};
    struct Deferred {
        platform: Arc<PacketPlatform>,
        defer: AtomicBool,
        entered: tokio::sync::Notify,
    }
    impl FrontendPlatform for Deferred {
        fn open(
            &self,
            g: i64,
            c: &CaptureConfig,
        ) -> io::Result<talpid_tunnel::tun_provider::AppliedTun> {
            self.platform.open(g, c)
        }
        fn handover(&self, old: i64, g: i64, c: &CaptureConfig) -> CaptureHandover {
            self.platform.handover(old, g, c)
        }
        fn capture_format(&self, fd: BorrowedFd<'_>) -> io::Result<CaptureFormat> {
            self.platform.capture_format(fd)
        }
        fn capture_feed(&self) -> Arc<CaptureNetworkFeed> {
            self.platform.capture_feed()
        }
        fn interface_name(&self, fd: BorrowedFd<'_>) -> io::Result<String> {
            self.platform.interface_name(fd)
        }
        fn expectation(&self, c: &CaptureConfig, i: String) -> io::Result<CaptureExpectation> {
            self.platform.expectation(c, i)
        }
        fn bind(&self, g: i64, i: &str) -> io::Result<bool> {
            if self.defer.load(SeqCst) {
                self.entered.notify_one();
                Ok(true)
            } else {
                self.platform.bind(g, i)
            }
        }
        fn closed(&self, g: i64) -> io::Result<()> {
            self.platform.closed(g)
        }
    }
    let (_, platform, broker) = release_fixture();
    let deferred = Arc::new(Deferred {
        platform: platform.clone(),
        defer: AtomicBool::new(false),
        entered: tokio::sync::Notify::new(),
    });
    let factory = super::super::managed_platform::PlatformFactory(deferred.clone());
    let buffers = DeliveryBuffers::new();
    let auth = authority();
    auth.update(
        &policy(),
        Some(NetworkObservation::from(&physical_snapshot())),
    );
    let mut delivery = Delivery::new(factory, auth.clone(), buffers.local.clone(), broker.clone());
    let projected = |mtu: u16, dual: bool| {
        let mut target = assigned_config();
        target.mtu = mtu;
        if !dual {
            target.addresses.truncate(1);
            target.ipv6_gateway = None;
            target.routes.retain(ipnetwork::IpNetwork::is_ipv4);
        }
        talpid_tunnel::tun_provider::transport::router_config(
            &target,
            vec!["10.0.2.2/32".parse().unwrap()],
        )
    };
    let mut session = None;
    let mut grant = None;
    for (mtu, dual) in [
        (576, false),
        (1380, true),
        (1220, false),
        (u16::MAX, true),
        (68, false),
        (1280, true),
    ] {
        let old = broker.snapshot().capture_generation;
        delivery
            .maintain_config(Some(DeliveryConfig::Router(projected(mtu, dual))))
            .await;
        bounded(delivery.changed()).await;
        auth.endpoint(true);
        if let Some(expected) = session {
            assert_eq!(broker.snapshot().session_generation, Some(expected));
        } else {
            session = broker.snapshot().session_generation;
            grant = Some(auth.authorize(flow(Transport::Udp, 45980)).unwrap());
        }
        assert!(broker.snapshot().capture_ready && auth.current(grant.as_ref().unwrap()));
        assert_eq!(
            platform.expected.lock().unwrap().as_ref().unwrap().mtu,
            Some(i32::from(mtu))
        );
        if let Some(old) = old {
            bounded(async {
                loop {
                    let changed = platform.released.notified();
                    if platform
                        .completed_releases
                        .lock()
                        .unwrap()
                        .contains(&(old as i64))
                    {
                        break;
                    }
                    changed.await;
                }
            })
            .await;
            bounded(delivery.changed()).await;
        }
    }
    deferred.defer.store(true, SeqCst);
    let mut cancelled = broker.request_capture(projected(1220, false)).unwrap();
    delivery
        .maintain_config(Some(DeliveryConfig::Secured {
            broker: broker.clone(),
            request: broker.pending_request().unwrap(),
        }))
        .await;
    bounded(deferred.entered.notified()).await;
    cancelled.cancel();
    let generation = platform.generation.load(SeqCst);
    assert!(platform.bind(generation, "tun-owned").unwrap());
    bounded(delivery.changed()).await;
    assert!(
        cancelled.configured().await.is_err(),
        "cancelled target acquired readiness"
    );
    assert_eq!(broker.snapshot().session_generation, session);
    assert!(broker.snapshot().capture_ready && auth.current(grant.as_ref().unwrap()));
    cancelled.transport_joined();
    deferred.defer.store(false, SeqCst);
    delivery.stop().await.unwrap();
    assert!(broker.snapshot().session_generation.is_none());
    for invalid in [0, 67] {
        let factory = super::super::managed_platform::PlatformFactory(deferred.clone());
        let attempt = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            factory.start(
                DeliveryConfig::Router(projected(invalid, false)),
                authority(),
                buffers.local.clone(),
                broker.clone(),
            )
        }));
        assert!(attempt.is_ok(), "configuration panicked");
        assert_eq!(
            attempt.unwrap().err().unwrap().kind(),
            io::ErrorKind::InvalidInput
        );
    }
}

#[tokio::test]
async fn pending_successor_defers_actual_fd_release_before_daemon_ready() {
    let (mut delivery, platform, broker) = release_fixture();
    delivery
        .maintain_config(Some(DeliveryConfig::Partial(
            vec!["10.0.2.2/32".into()].into(),
        )))
        .await;
    bounded(delivery.changed()).await;
    let old_peer = platform.peer.lock().unwrap().take().unwrap();
    let mut request = broker.request_capture(fixed_config()).unwrap();
    delivery
        .maintain_config(Some(DeliveryConfig::Secured {
            broker: broker.clone(),
            request: broker.pending_request().unwrap(),
        }))
        .await;
    bounded(request.configured()).await.unwrap();
    assert!(matches!(delivery.pending, Some(Readiness::Handover { .. })));
    let peer = platform.peer.lock().unwrap().take().unwrap();
    delivery.defer_release();
    let stopped = bounded(delivery.stop()).await;
    assert_eq!(
        peer.send(b"pending-held")
            .expect("pending successor fd released before TSM join"),
        12
    );
    assert_eq!(stopped.unwrap_err().kind(), io::ErrorKind::WouldBlock);
    assert!(delivery.has_owner());
    delivery.transport_joined();
    bounded(delivery.stop()).await.unwrap();
    assert!(platform.peer_closed(&old_peer));
    assert!(platform.peer_closed(&peer));
    assert_eq!(platform.releases.load(SeqCst), 2);
}

#[tokio::test]
async fn applied_successor_acknowledges_retained_predecessor_before_stop() {
    let (mut delivery, platform, broker) = release_fixture();
    let mut first = broker.request_capture(fixed_config()).unwrap();
    let first_pending = broker.pending_request().unwrap();
    delivery
        .maintain_config(Some(DeliveryConfig::Secured {
            broker: broker.clone(),
            request: first_pending.clone(),
        }))
        .await;
    let receipt = bounded(first.configured()).await.unwrap();
    let pair = broker.acquire(&receipt).unwrap();
    bounded(delivery.changed()).await;
    let old_peer = platform.peer.lock().unwrap().take().unwrap();
    delivery.defer_release();
    first.cancel();
    let mut config = fixed_config();
    config.dns_servers = Some(vec!["10.64.0.2".parse().unwrap()]);
    let mut second = broker.request_capture(config).unwrap();
    let next = DeliveryConfig::Secured {
        broker: broker.clone(),
        request: broker.pending_request().unwrap(),
    };
    delivery.maintain_config(Some(next.clone())).await;
    bounded(second.configured()).await.unwrap();
    bounded(delivery.changed()).await;
    assert!(delivery.applied_config().unwrap().same_capture(&next));
    let peer = platform.peer.lock().unwrap().take().unwrap();
    assert_eq!(old_peer.send(b"predecessor-held").unwrap(), 16);
    assert_eq!(platform.releases.load(SeqCst), 0);
    drop(pair);
    first.transport_joined();
    assert!(
        !first_pending.release_ready(),
        "transport join bypassed the TSM stage"
    );
    assert_eq!(old_peer.send(b"predecessor-held").unwrap(), 16);
    assert_eq!(platform.releases.load(SeqCst), 0);
    delivery.transport_joined();
    bounded(delivery.stop()).await.unwrap();
    assert!(first_pending.release_ready());
    assert!(platform.peer_closed(&old_peer));
    assert!(platform.peer_closed(&peer));
    assert_eq!(platform.releases.load(SeqCst), 2);
}

struct Handover {
    runtime: LocalNetworkRuntime<PacketFactory>,
    physical_feed: Arc<LocalNetworkFeed>,
    platform: Arc<PacketPlatform>,
    continuation: ConnectContinuation,
    policy: LocalNetworkAccess,
    target: TargetState,
    phase: TunnelPhase,
    transport: Option<talpid_tunnel::packet_attachment::TransportPair>,
    request: Option<talpid_tunnel::packet_attachment::ConfigurationRequest>,
    commands: Vec<&'static str>,
}

#[tokio::test]
async fn status_revisions_follow_rule_status_not_covered_route_edits() {
    use mullvad_types::settings::local_network_access::status::{InactiveReason, RuleState};

    let mut h = Handover::new(policy());
    h.continuation.connect();
    assert_eq!(h.admit().await, Some("Connect"));
    h.connect_endpoint().await;
    let before = h.runtime.status().clone();
    let generation = h.runtime.broker().snapshot().capture_generation;
    let starts = h.platform.starts.load(SeqCst);
    h.policy.rules[0]
        .cidrs
        .push("10.0.2.99/32".parse().unwrap());
    let covered = h.runtime.update(&h.policy, h.target, h.phase).await;
    assert!(
        covered.is_none(),
        "Unchanged semantic status is not republished"
    );
    assert_eq!(h.runtime.status(), &before);
    assert_eq!(h.platform.starts.load(SeqCst), starts);
    assert_eq!(h.runtime.broker().snapshot().capture_generation, generation);

    let mut added = h.policy.rules[0].clone();
    added.id = "00000000-0000-0000-0000-000000000002".parse().unwrap();
    h.policy.rules.push(added);
    let added = h
        .runtime
        .update(&h.policy, h.target, h.phase)
        .await
        .expect("Adding a rule row must publish even when capture is reused");
    assert_eq!(added.revision, before.revision + 1);
    assert_eq!(added.rules.len(), 2);
    for (status, rule) in added.rules.iter().zip(&h.policy.rules) {
        assert_eq!(status.id, rule.id);
        assert_eq!(status.state, RuleState::Forwarding);
    }
    h.policy.rules[1].enabled = false;
    let disabled = h
        .runtime
        .update(&h.policy, h.target, h.phase)
        .await
        .expect("Changed rule state must publish independently of capture reuse");
    assert_eq!(disabled.revision, added.revision + 1);
    assert_eq!(disabled.rules[0].state, RuleState::Forwarding);
    assert_eq!(
        disabled.rules[1].state,
        RuleState::Inactive(InactiveReason::RuleOff)
    );
    h.policy.rules.pop();
    let removed = h
        .runtime
        .update(&h.policy, h.target, h.phase)
        .await
        .expect("Removing a rule row must publish");
    assert_eq!(removed.revision, disabled.revision + 1);
    assert_eq!(removed.rules, before.rules);
    assert_eq!(h.platform.starts.load(SeqCst), starts);
    assert_eq!(h.runtime.broker().snapshot().capture_generation, generation);
    h.close().await;
}

#[tokio::test]
async fn second_settings_reconnect_cannot_close_queued_target_admission() {
    use talpid_tunnel::tun_provider::transport::ManagedTun;

    for admit_before_second in [false, true] {
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let physical = (tcp.local_addr().unwrap(), udp.local_addr().unwrap());
        let tcp_task = tokio::spawn(async move {
            let (mut stream, tuple) = tcp.accept().await.unwrap();
            for index in 0..4 {
                let mut bytes = [0; 8];
                stream.read_exact(&mut bytes).await.unwrap();
                assert_eq!(bytes.as_slice(), format!("{index:08}").as_bytes());
                assert_eq!(stream.peer_addr().unwrap(), tuple);
                stream.write_all(&bytes).await.unwrap();
            }
            assert!(
                tokio::time::timeout(Duration::from_millis(30), tcp.accept())
                    .await
                    .is_err(),
                "Local TCP was reopened"
            );
        });
        let udp_task = tokio::spawn(async move {
            let mut tuple = None;
            for index in 0..4 {
                let mut bytes = [0; 128];
                let (count, source) = udp.recv_from(&mut bytes).await.unwrap();
                assert_eq!(&bytes[..count], format!("{index:08}").as_bytes());
                assert_eq!(*tuple.get_or_insert(source), source);
                udp.send_to(&bytes[..count], source).await.unwrap();
            }
        });
        let mut h = Handover::unstarted_with_physical(policy(), physical);
        h.observe(TunnelPhase::Disconnected);
        h.continuation.connect();
        assert_eq!(h.admit().await, Some("Connect"));
        h.connect_endpoint().await;
        let broker = h.runtime.broker();
        let session = broker.snapshot().session_generation;
        let authority = h.platform.authority.lock().unwrap().clone().unwrap();
        let local = flow(Transport::Tcp, 45994);
        let udp_flow = flow(Transport::Udp, 45995);
        let grant = authority.authorize(local).unwrap();
        let peer = |h: &Handover| {
            UnixDatagram::from_std(
                h.platform
                    .peer
                    .lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .try_clone()
                    .unwrap(),
            )
            .unwrap()
        };
        peer(&h)
            .send(&tcp_packet(local, 100, 0, 2, &[]))
            .await
            .unwrap();
        let syn = capture_reply(&peer(&h)).await;
        let mut ack = u32::from_be_bytes(syn[24..28].try_into().unwrap()).wrapping_add(1);
        let mut sequence = 101;

        for index in 0..4 {
            if index == 1 {
                let old = h.transport.take().unwrap();
                let old_request = h.request.take().unwrap();
                let cleanup = broker.transport_cleanup();
                let old_attempt = old.control.capability();
                let mut old_packet = old_attempt
                    .packet(
                        talpid_types::relay_flow::RelayBuffer::copy_from(
                            b"stale-final-write",
                            broker.application_buffers().as_ref(),
                        )
                        .unwrap(),
                    )
                    .unwrap();
                // The first settings reconnect uses the same dispatch boundary
                // as the daemon. Hold its queued Connect before ManagedTun::request.
                h.continuation.connect();
                let command = h.advance().await.unwrap().unwrap();
                h.observe(TunnelPhase::Disconnecting);
                old.control.detach();
                drop(old);
                old_request.transport_joined();
                if command == "Disconnect" {
                    h.observe(TunnelPhase::Disconnected);
                    assert_eq!(h.admit().await, Some("Connect"));
                }
                h.observe(TunnelPhase::Connecting);
                let mut intermediate = assigned_config();
                intermediate.mtu = 1380;
                intermediate.addresses.retain(std::net::IpAddr::is_ipv4);
                intermediate.ipv6_gateway = None;
                intermediate.routes.retain(ipnetwork::IpNetwork::is_ipv4);
                // Linux's admission entry does not apply Android's projection.
                // Supply that same pure projection for this never-acquired target.
                let intermediate = talpid_tunnel::tun_provider::transport::router_config(
                    &intermediate,
                    broker.local_routes(),
                );
                let (completion, delayed) = oneshot::channel();
                *h.platform.delayed_completion.lock().unwrap() = Some(completion);
                let mut admitted = admit_before_second
                    .then(|| ManagedTun::request(broker.clone(), intermediate.clone()).unwrap());
                h.continuation.connect();
                let second = h.advance().await.unwrap();
                if admitted.is_none() {
                    admitted = Some(
                        ManagedTun::request(broker.clone(), intermediate)
                            .expect("second settings reconnect closed queued target admission"),
                    );
                }
                assert_eq!(
                    second,
                    Some("Connect"),
                    "normal reconnect became Disconnect"
                );
                let mut admitted = admitted.unwrap();
                let cancelled = broker.pending_request().unwrap();
                h.runtime
                    .internal_update(&h.policy, h.target, h.phase)
                    .await;
                let (generation, observation) = bounded(delayed).await.unwrap();
                assert!(
                    h.platform
                        .opened
                        .lock()
                        .unwrap()
                        .last()
                        .unwrap()
                        .same_android_config(cancelled.config())
                );
                let intermediate_cleanup = broker.transport_cleanup();
                // The TSM cancels this exact superseded request, not global
                // admission. No frontend acknowledgement may make it ready/Up.
                intermediate_cleanup.cancel();
                admitted.request.transport_joined();
                assert!(admitted.request.configured().await.is_err());
                assert!(!old_attempt.current());
                assert!(broker.pending_request().is_none());
                // Complete the exact matching frontend observation only after
                // cancellation. Local may adopt the sink, never this old target.
                assert!(h.platform.feed.publish(
                    h.platform.feed.registration(),
                    generation,
                    observation.clone()
                ));
                h.settle_capture().await;
                assert_eq!(
                    broker.snapshot().capture_generation,
                    Some(generation as u64)
                );
                assert!(broker.snapshot().capture_ready);
                assert!(!broker.snapshot().ordinary_ready);
                assert!(admitted.request.configured().await.is_err());
                let mut final_config = assigned_config();
                final_config.mtu = 1280;
                h.connect_endpoint_with(final_config).await;
                let latest = h
                    .request
                    .as_mut()
                    .unwrap()
                    .configured()
                    .await
                    .unwrap()
                    .generation();
                // Delayed predecessor cleanup must not choose the new request.
                cleanup.cancel();
                drop(old_request);
                intermediate_cleanup.cancel();
                assert!(!h.platform.feed.publish(
                    h.platform.feed.registration(),
                    generation,
                    observation
                ));
                assert!(
                    admitted.request.configured().await.is_err(),
                    "late matching completion certified cancelled target after successor settled"
                );
                drop(admitted);
                assert_eq!(
                    h.request
                        .as_mut()
                        .unwrap()
                        .configured()
                        .await
                        .unwrap()
                        .generation(),
                    latest
                );
                assert!(h.transport.as_ref().unwrap().control.current());
                assert!(matches!(
                    old_packet.write(|_| panic!("old packet reached final write")),
                    talpid_types::relay_flow::RelayWriteOutcome::Stale
                ));
                let applied = h.platform.opened.lock().unwrap().last().unwrap().clone();
                assert_eq!(applied.mtu, 1280);
                assert!(applied.addresses.iter().any(std::net::IpAddr::is_ipv4));
                assert!(applied.addresses.iter().any(std::net::IpAddr::is_ipv6));
            } else if index == 2 {
                h.user_disconnect();
                assert!(!h.transport.as_ref().unwrap().control.current());
                assert!(ManagedTun::request(broker.clone(), assigned_config()).is_err());
                h.observe(TunnelPhase::Disconnecting);
                h.acknowledge_transport_close();
                h.advance().await.unwrap();
                bounded(async {
                    while !h.runtime.capture_configuration_ready() {
                        h.runtime.notifications().1.await;
                        h.advance().await.unwrap();
                    }
                })
                .await;
            } else if index == 3 {
                // A subsequent explicit secured Connect releases the intentional
                // unsecured stop without a blocking preflight capture.
                h.target = TargetState::Secured;
                h.continuation.connect();
                assert_eq!(h.admit().await, Some("Connect"));
                h.connect_endpoint().await;
            }
            assert_eq!(broker.snapshot().session_generation, session);
            assert!(authority.current(&grant));
            let capture = peer(&h);
            let nonce = format!("{index:08}");
            capture
                .send(&tcp_packet(local, sequence, ack, 0x18, nonce.as_bytes()))
                .await
                .unwrap();
            let mut received = Vec::new();
            while received.len() < 8 {
                let bytes = capture_reply(&capture).await;
                let payload = packet::parse(&bytes).unwrap().payload;
                received.extend_from_slice(payload);
                ack = ack.wrapping_add(payload.len() as u32);
            }
            assert_eq!(received, nonce.as_bytes());
            sequence += 8;
            capture
                .send(&tcp_packet(local, sequence, ack, 0x10, &[]))
                .await
                .unwrap();
            capture
                .send(&udp_packet(udp_flow, nonce.as_bytes()))
                .await
                .unwrap();
            loop {
                let bytes = capture_reply(&capture).await;
                let packet = packet::parse(&bytes).unwrap();
                if packet.flow.transport == Transport::Udp {
                    assert_eq!(packet.payload, nonce.as_bytes());
                    break;
                }
            }
        }
        bounded(tcp_task).await.unwrap();
        bounded(udp_task).await.unwrap();
        h.runtime.begin_shutdown();
        assert!(!h.transport.as_ref().unwrap().control.current());
        assert!(ManagedTun::request(broker, assigned_config()).is_err());
        h.close().await;
    }
}

#[tokio::test]
async fn connect_dispatch_does_not_wait_for_capture_or_parameters() {
    let mut h = Handover::new(policy());
    h.continuation.connect();
    assert_eq!(
        h.advance().await.unwrap(),
        Some("Connect"),
        "Connect was withheld before parameters/capture acknowledgement"
    );
    assert!(
        h.runtime.has_owner(),
        "independent Local Partial reader absent"
    );
    bounded(h.runtime.notifications().1).await;
    assert_eq!(h.advance().await.unwrap(), None);
    assert!(
        h.platform.opened.lock().unwrap().is_empty(),
        "blocking preflight was established"
    );
    assert_eq!(
        h.runtime.status().forwarding,
        ForwardingAvailability::Active
    );
    let session = h.runtime.broker().snapshot().session_generation;
    for phase in [
        TunnelPhase::Connecting,
        TunnelPhase::Error,
        TunnelPhase::Disconnecting,
    ] {
        h.observe(phase);
        h.runtime.update(&h.policy, h.target, phase).await;
        assert_eq!(
            h.runtime.status().forwarding,
            ForwardingAvailability::Active
        );
        assert_eq!(h.runtime.broker().snapshot().session_generation, session);
        assert!(!h.runtime.broker().snapshot().ordinary_ready);
    }
    h.close().await;
}

#[tokio::test]
async fn reconnect_from_unsecured_error_and_failed_close_is_not_latched() {
    for local in [false, true] {
        let mut configured = policy();
        configured.enabled = local;
        let mut h = Handover::new(configured);
        h.target = TargetState::Unsecured;
        h.observe(TunnelPhase::Error);
        h.continuation.connect();
        assert_eq!(h.advance().await.unwrap(), Some("Connect"));
        assert_eq!(h.target, TargetState::Unsecured);
        let pending = h.connect_endpoint_with(assigned_config()).await;
        let broker = h.runtime.broker();
        let old = h.transport.take().unwrap();
        let mut request = h.request.take().unwrap();
        let receipt = bounded(request.configured()).await.unwrap();
        let attempt = old.control.capability();
        let cleanup = broker.transport_cleanup();
        h.continuation.connect();
        assert_eq!(h.advance().await.unwrap(), Some("Connect"));
        h.observe(TunnelPhase::Disconnecting);
        old.control.detach();
        drop(old);
        request.transport_joined();
        assert!(!pending.release_ready(), "TSM close has not joined yet");
        // The real TSM's joined close can publish Error, not Disconnected.
        h.observe(TunnelPhase::Error);
        assert!(!attempt.current());
        assert!(
            pending.release_ready(),
            "Error must acknowledge the joined close"
        );
        assert!(
            receipt.current(),
            "Local may retain the same observed capture"
        );
        assert!(!h.continuation.joined(), "Error is not public Disconnected");
        h.continuation.connect();
        assert_eq!(h.advance().await.unwrap(), Some("Connect"));
        h.connect_endpoint().await;
        cleanup.cancel();
        drop(request);
        assert!(h.transport.as_ref().unwrap().control.current());
        assert_eq!(h.commands, vec!["Connect", "Connect", "Connect"]);
        h.close().await;
    }
}

#[tokio::test]
async fn exclusion_change_establishes_one_effective_capture() {
    for settings_first in [false, true] {
        let mut h = Handover::new(policy());
        h.runtime.set_excluded_packages(vec![]);
        h.continuation.connect();
        assert_eq!(h.admit().await, Some("Connect"));
        h.connect_endpoint().await;
        let broker = h.runtime.broker();
        let session = broker.snapshot().session_generation;
        let authority = h.platform.authority.lock().unwrap().clone().unwrap();
        let grant = authority.authorize(flow(Transport::Udp, 45996)).unwrap();
        let old = h.transport.take().unwrap();
        let old_request = h.request.take().unwrap();
        let attempt = old.control.capability();
        let mut stale = attempt
            .packet(
                talpid_types::relay_flow::RelayBuffer::copy_from(
                    b"stale-exclusion",
                    broker.application_buffers().as_ref(),
                )
                .unwrap(),
            )
            .unwrap();
        let before = h.platform.starts.load(SeqCst);
        let packages = vec![
            "missing.package".to_owned(),
            "later.installed.package".to_owned(),
        ];
        if settings_first {
            h.runtime.set_excluded_packages(packages.clone());
            h.runtime.update(&h.policy, h.target, h.phase).await;
        }
        h.observe(TunnelPhase::Disconnecting);
        old.control.detach();
        drop(old);
        old_request.transport_joined();
        h.observe(TunnelPhase::Connecting);
        h.runtime.update(&h.policy, h.target, h.phase).await;
        let mut config = assigned_config();
        config.excluded_packages = packages.clone();
        h.connect_endpoint_with(config.clone()).await;
        // The TSM can configure its new request before the asynchronous settings
        // acknowledgement reaches the daemon. Old persisted app coverage must
        // not independently hand that new capture back to the old projection.
        if !settings_first {
            h.runtime.set_excluded_packages(packages.clone());
            h.runtime.update(&h.policy, h.target, h.phase).await;
            h.settle_capture().await;
        }
        assert_eq!(
            h.platform.starts.load(SeqCst),
            before + 1,
            "one effective coverage change"
        );
        assert_eq!(
            h.platform
                .opened
                .lock()
                .unwrap()
                .last()
                .unwrap()
                .excluded_packages,
            packages
        );
        assert_eq!(broker.snapshot().session_generation, session);
        assert!(matches!(
            stale.write(|_| panic!("stale writer")),
            talpid_types::relay_flow::RelayWriteOutcome::Stale
        ));
        drop(old_request);
        let generation = broker.snapshot().capture_generation;
        config.excluded_packages.reverse();
        config.excluded_packages.push("missing.package".to_owned());
        h.runtime
            .set_excluded_packages(config.excluded_packages.clone());
        let request = h.request.take().unwrap();
        h.transport.take();
        request.transport_joined();
        h.observe(TunnelPhase::Disconnecting);
        h.observe(TunnelPhase::Connecting);
        h.connect_endpoint_with(config).await;
        assert_eq!(
            h.platform.starts.load(SeqCst),
            before + 1,
            "equivalent coverage must reuse capture"
        );
        assert_eq!(broker.snapshot().capture_generation, generation);
        assert_eq!(broker.snapshot().session_generation, session);
        drop(request);
        assert!(authority.current(&grant));
        h.user_disconnect();
        h.observe(TunnelPhase::Disconnecting);
        h.acknowledge_transport_close();
        h.advance().await.unwrap();
        h.settle_capture().await;
        assert_eq!(
            h.platform
                .application_coverage
                .lock()
                .unwrap()
                .last()
                .unwrap(),
            &vec![
                "later.installed.package".to_owned(),
                "missing.package".to_owned(),
                "missing.package".to_owned()
            ],
            "Partial uses the stored current exclusions, including missing names"
        );
        assert_eq!(broker.snapshot().session_generation, session);
        h.close().await;
    }
    let mut h = Handover::new(policy());
    let packages = vec![
        "missing.package".to_owned(),
        "later.installed.package".to_owned(),
    ];
    h.runtime.set_excluded_packages(packages.clone());
    h.enter_blocking_error_with(packages.clone()).await;
    h.runtime.update(&h.policy, h.target, h.phase).await;
    h.settle_capture().await;
    assert_eq!(
        h.platform.application_coverage.lock().unwrap().last(),
        Some(&packages),
        "Error before any target uses current exclusions"
    );
    h.close().await;
}

#[tokio::test]
async fn continuation_leaves_off_status_for_the_daemon_notification_boundary() {
    for off in [
        LocalNetworkAccess::default(),
        LocalNetworkAccess {
            enabled: true,
            rules: vec![],
        },
        LocalNetworkAccess {
            enabled: true,
            rules: policy()
                .rules
                .into_iter()
                .map(|mut rule| {
                    rule.enabled = false;
                    rule
                })
                .collect(),
        },
    ] {
        let mut h = Handover::new(policy());
        h.continuation.connect();
        assert_eq!(h.admit().await, Some("Connect"));
        h.connect_endpoint().await;
        h.user_disconnect();
        h.observe(TunnelPhase::Disconnecting);
        h.acknowledge_transport_close();
        h.advance().await.unwrap();
        bounded(async {
            while !h.runtime.capture_configuration_ready() {
                h.runtime.notifications().1.await;
                h.advance().await.unwrap();
            }
        })
        .await;
        assert_eq!(
            h.runtime.status().forwarding,
            ForwardingAvailability::Active
        );
        let revision = h.runtime.status().revision;
        h.policy = off;
        // Reproduce refresh_local_network_status: continuation first, then the
        // publication call whose returned sample actually reaches the notifier.
        assert!(h.runtime.continue_connect(&mut h.continuation).is_none());
        let published = h
            .runtime
            .update(&h.policy, h.target, h.phase)
            .await
            .expect("continuation consumed Off before the daemon could notify it");
        assert_eq!(published.forwarding, ForwardingAvailability::Off);
        assert_eq!(published.revision, revision + 1);
        assert!(
            !h.runtime.has_owner(),
            "Off must follow joined capture release"
        );
        assert!(
            h.runtime
                .internal_update(&h.policy, h.target, h.phase)
                .await
                .is_none()
        );
        h.close().await;
    }
}

#[tokio::test]
async fn runtime_router_keeps_one_local_tcp_udp_consumer_through_held_boundaries() {
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let physical = (tcp.local_addr().unwrap(), udp.local_addr().unwrap());
    let tcp_task = tokio::spawn(async move {
        let (mut stream, tuple) = tcp.accept().await.unwrap();
        for index in 0..12 {
            let mut bytes = [0; 8];
            stream.read_exact(&mut bytes).await.unwrap();
            assert_eq!(bytes.as_slice(), format!("{index:08}").as_bytes());
            assert_eq!(stream.peer_addr().unwrap(), tuple);
            stream.write_all(&bytes).await.unwrap();
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(30), tcp.accept())
                .await
                .is_err()
        );
    });
    let udp_task = tokio::spawn(async move {
        let mut tuple = None;
        for index in 0..12 {
            let mut bytes = [0; 128];
            let (count, source) = udp.recv_from(&mut bytes).await.unwrap();
            assert_eq!(&bytes[..count], format!("{index:08}").as_bytes());
            assert_eq!(*tuple.get_or_insert(source), source);
            udp.send_to(&bytes[..count], source).await.unwrap();
        }
    });
    let mut h = Handover::unstarted_with_physical(policy(), physical);
    h.target = TargetState::Unsecured;
    h.observe(TunnelPhase::Disconnected);
    assert_eq!(h.advance().await.unwrap(), None);
    bounded(h.runtime.notifications().1).await;
    h.runtime.owner_changed(&h.policy, h.target, h.phase);
    let broker = h.runtime.broker();
    let session = broker.snapshot().session_generation;
    let authority = h.platform.authority.lock().unwrap().clone().unwrap();
    let local = flow(Transport::Tcp, 45990);
    let udp_flow = flow(Transport::Udp, 45991);
    let grant = authority.authorize(local).unwrap();
    let peer = || {
        UnixDatagram::from_std(
            h.platform
                .peer
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .try_clone()
                .unwrap(),
        )
        .unwrap()
    };
    peer()
        .send(&tcp_packet(local, 100, 0, 2, &[]))
        .await
        .unwrap();
    let syn = capture_reply(&peer()).await;
    let mut ack = u32::from_be_bytes(syn[24..28].try_into().unwrap()).wrapping_add(1);
    let mut sequence = 101;
    for index in 0..12 {
        match index {
            1 => {
                h.target = TargetState::Secured;
                h.continuation.connect();
                assert_eq!(h.admit().await, Some("Connect"));
            }
            2 | 7 => {
                h.observe(TunnelPhase::Connecting);
            }
            3 => {
                h.enter_blocking_error().await;
            }
            4 | 8 => {
                h.connect_endpoint().await;
            }
            5 => {
                h.continuation.connect();
                assert_eq!(h.advance().await.unwrap(), Some("Connect"));
                h.observe(TunnelPhase::Disconnecting);
            }
            6 => {
                h.transport.take();
                h.request.take();
                h.observe(TunnelPhase::Connecting);
                assert_eq!(h.advance().await.unwrap(), None);
            }
            9 => {
                h.runtime.suspend();
                h.transport.take();
                h.request.take();
                h.observe(TunnelPhase::Disconnecting);
                h.enter_blocking_error().await;
            }
            10 => {
                h.user_disconnect();
                h.observe(TunnelPhase::Disconnecting);
            }
            11 => {
                h.acknowledge_transport_close();
                assert_eq!(h.advance().await.unwrap(), None);
                bounded(async {
                    while !h.runtime.capture_configuration_ready() {
                        h.runtime.notifications().1.await;
                        assert_eq!(h.advance().await.unwrap(), None);
                    }
                })
                .await;
            }
            _ => {}
        }
        h.runtime.update(&h.policy, h.target, h.phase).await;
        h.settle_capture().await;
        assert_eq!(
            h.runtime.status().forwarding,
            ForwardingAvailability::Active,
            "stage {index}"
        );
        assert_eq!(
            broker.snapshot().session_generation,
            session,
            "stage {index}"
        );
        assert!(
            authority.current(&grant),
            "stage {index} revoked the Local grant"
        );
        let capture = UnixDatagram::from_std(
            h.platform
                .peer
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .try_clone()
                .unwrap(),
        )
        .unwrap();
        let nonce = format!("{index:08}");
        capture
            .send(&tcp_packet(local, sequence, ack, 0x18, nonce.as_bytes()))
            .await
            .unwrap();
        let mut received = Vec::new();
        while received.len() < 8 {
            let bytes = capture_reply(&capture).await;
            let payload = packet::parse(&bytes).unwrap().payload;
            received.extend_from_slice(payload);
            ack = ack.wrapping_add(payload.len() as u32);
        }
        assert_eq!(received, nonce.as_bytes());
        sequence += 8;
        capture
            .send(&tcp_packet(local, sequence, ack, 0x10, &[]))
            .await
            .unwrap();
        capture
            .send(&udp_packet(udp_flow, nonce.as_bytes()))
            .await
            .unwrap();
        loop {
            let bytes = capture_reply(&capture).await;
            let packet = packet::parse(&bytes).unwrap();
            if packet.flow.transport == Transport::Udp {
                assert_eq!(packet.payload, nonce.as_bytes());
                break;
            }
        }
        // A live public packet enters the real reader at every held boundary.
        // It must never appear as physical traffic or an app-facing reply.
        if !broker.snapshot().ordinary_ready {
            let mut public = udp_flow;
            public.destination = "1.1.1.1:443".parse().unwrap();
            capture
                .send(&udp_packet(public, b"public-must-drop"))
                .await
                .unwrap();
            let deadline = tokio::time::Instant::now() + Duration::from_millis(30);
            let mut output = [0; 128];
            while let Ok(result) =
                tokio::time::timeout_at(deadline, capture.recv(&mut output)).await
            {
                let count = result.unwrap();
                let packet = packet::parse(&output[..count]).unwrap();
                // The Local peer may close after its last exact read. Permit
                // only that connection's empty TCP ACK/FIN, never a public
                // response, reset, duplicate payload or unrelated packet.
                assert_eq!(
                    packet.flow.transport,
                    Transport::Tcp,
                    "stage {index}: unexpected injection"
                );
                assert_eq!(packet.flow.source, local.destination);
                assert_eq!(packet.flow.destination, local.source);
                assert!(packet.payload.is_empty());
                assert_eq!(output[33] & 4, 0, "Local stream reset at stage {index}");
            }
            if let Some(pair) = &mut h.transport {
                assert!(bounded(pair.receive.recv()).await.is_err());
            }
        }
    }
    bounded(tcp_task).await.unwrap();
    bounded(udp_task).await.unwrap();
    assert_eq!(
        h.platform.starts.load(SeqCst),
        5,
        "Partial -> actual safe Error -> target -> actual safe Error -> Partial; no pre-Connect blocking capture"
    );
    h.close().await;
}

#[tokio::test]
async fn disconnect_cancels_pre_parameter_admission_without_a_late_connect() {
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut h = Handover::unstarted_with_physical(
        policy(),
        ("127.0.0.1:9".parse().unwrap(), udp.local_addr().unwrap()),
    );
    h.observe(TunnelPhase::Disconnected);
    h.continuation.connect();
    assert_eq!(
        h.advance().await.unwrap(),
        Some("Connect"),
        "direct Connect was withheld before parameters"
    );
    assert!(h.platform.opened.lock().unwrap().is_empty());
    h.user_disconnect();
    assert_eq!(h.advance().await.unwrap(), None);
    bounded(async {
        while !h.runtime.capture_configuration_ready() {
            h.runtime.notifications().1.await;
            assert_eq!(h.advance().await.unwrap(), None);
        }
    })
    .await;
    assert_eq!(h.commands, ["Connect", "Disconnect"]);
    assert_eq!(
        h.runtime.status().forwarding,
        ForwardingAvailability::Active
    );
    let peer = UnixDatagram::from_std(
        h.platform
            .peer
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .try_clone()
            .unwrap(),
    )
    .unwrap();
    let nonce = b"cancelled-connect-still-local";
    peer.send(&udp_packet(flow(Transport::Udp, 45992), nonce))
        .await
        .unwrap();
    let mut bytes = [0; 128];
    let (count, source) = bounded(udp.recv_from(&mut bytes)).await.unwrap();
    assert_eq!(&bytes[..count], nonce);
    udp.send_to(&bytes[..count], source).await.unwrap();
    assert_eq!(
        packet::parse(&capture_reply(&peer).await).unwrap().payload,
        nonce
    );
    assert_eq!(h.advance().await.unwrap(), None);
    assert_eq!(
        h.commands,
        ["Connect", "Disconnect"],
        "late native ack resumed cancelled Secured intent"
    );
    assert!(!h.runtime.broker().snapshot().ordinary_ready);
    h.close().await;
}

#[tokio::test]
async fn actual_capture_loss_retries_with_a_fresh_router_not_a_cancelled_target_request() {
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut h = Handover::unstarted_with_physical(
        policy(),
        ("127.0.0.1:9".parse().unwrap(), udp.local_addr().unwrap()),
    );
    h.observe(TunnelPhase::Disconnected);
    h.continuation.connect();
    assert_eq!(h.admit().await, Some("Connect"));
    h.connect_endpoint().await;
    let broker = h.runtime.broker();
    let old_session = broker.snapshot().session_generation;
    let generation = h.platform.generation.load(SeqCst);
    h.platform.feed.invalidate(generation);
    bounded(async {
        while !h.runtime.failed() {
            h.runtime.notifications().1.await;
            h.runtime.owner_changed(&h.policy, h.target, h.phase);
        }
    })
    .await;
    assert!(!broker.snapshot().ordinary_ready);
    assert!(!broker.snapshot().capture_ready);
    h.observe(TunnelPhase::Disconnecting);
    h.acknowledge_transport_close();
    h.observe(TunnelPhase::Error);
    h.continuation.connect();
    assert_eq!(
        h.admit().await,
        Some("Connect"),
        "explicit retry stalled on the cancelled target's old request"
    );
    h.connect_endpoint().await;
    assert_ne!(broker.snapshot().session_generation, old_session);
    let peer = UnixDatagram::from_std(
        h.platform
            .peer
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .try_clone()
            .unwrap(),
    )
    .unwrap();
    let nonce = b"fresh-session-after-real-loss";
    peer.send(&udp_packet(flow(Transport::Udp, 45993), nonce))
        .await
        .unwrap();
    let mut bytes = [0; 128];
    let (count, source) = bounded(udp.recv_from(&mut bytes)).await.unwrap();
    assert_eq!(&bytes[..count], nonce);
    udp.send_to(&bytes[..count], source).await.unwrap();
    assert_eq!(
        packet::parse(&capture_reply(&peer).await).unwrap().payload,
        nonce
    );
    h.close().await;
}

impl Handover {
    async fn enter_blocking_error(&mut self) {
        self.enter_blocking_error_with(vec![]).await;
    }

    async fn enter_blocking_error_with(&mut self, excluded_packages: Vec<String>) {
        use talpid_tunnel::tun_provider::{ConfigurationPurpose, transport::TransportMode};
        let broker = self.runtime.broker();
        let mut safe = talpid_tunnel::tun_provider::blocking_config();
        safe.dns_servers = Some(vec!["192.0.2.1".parse().unwrap()]);
        safe.excluded_packages = excluded_packages;
        let mut operation = TransportMode::selected(Some(&broker))
            .reconfigure::<talpid_tunnel::packet_attachment::AttachmentError>(
                safe,
                ConfigurationPurpose::Blocking,
                false,
                |_| panic!("managed Error selected Native"),
            )
            .unwrap()
            .unwrap();
        self.runtime
            .internal_update(&self.policy, self.target, self.phase)
            .await;
        let receipt = self.wait_for_capture_configuration(&mut operation).await;
        assert!(receipt.current());
        assert!(broker.acquire(&receipt).is_err());
        let actual = operation.configured_result().await.unwrap().applied;
        assert_eq!(actual.mtu, 1380);
        assert_eq!(actual.dns_servers, Some(vec!["192.0.2.1".parse().unwrap()]));
        self.request = Some(operation);
        self.observe(TunnelPhase::Error);
    }

    fn new(policy: LocalNetworkAccess) -> Self {
        let mut harness = Self::unstarted(policy);
        harness.observe(TunnelPhase::Disconnected);
        harness
    }

    fn unstarted(policy: LocalNetworkAccess) -> Self {
        Self::unstarted_with_physical(
            policy,
            (
                "127.0.0.1:9".parse().unwrap(),
                "127.0.0.1:9".parse().unwrap(),
            ),
        )
    }

    fn unstarted_with_physical(
        policy: LocalNetworkAccess,
        physical: (SocketAddr, SocketAddr),
    ) -> Self {
        let platform = Arc::new(PacketPlatform {
            feed: CaptureNetworkFeed::new(43),
            expected: Mutex::new(None),
            opened: Mutex::new(Vec::new()),
            application_coverage: Mutex::new(Vec::new()),
            peer: Mutex::new(None),
            descriptors: Mutex::new(Vec::new()),
            starts: AtomicUsize::new(0),
            releases: AtomicUsize::new(0),
            completed_releases: Mutex::new(Vec::new()),
            released: tokio::sync::Notify::new(),
            fail_release: AtomicBool::new(false),
            retain_handover: AtomicBool::new(false),
            delayed_completion: Mutex::new(None),
            authority: Mutex::new(None),
            generation: 0.into(),
            physical,
        });
        let feed = LocalNetworkFeed::new(33);
        assert!(feed.publish(33, physical_snapshot()));
        let runtime = LocalNetworkRuntime::with_factory(
            &policy,
            Some(feed.clone()),
            PacketFactory(platform.clone()),
            Arc::new(|_, _| Ok(())),
        );
        Self {
            runtime,
            physical_feed: feed,
            platform,
            continuation: ConnectContinuation::default(),
            policy,
            target: TargetState::Secured,
            phase: TunnelPhase::Disconnected,
            transport: None,
            request: None,
            commands: Vec::new(),
        }
    }

    fn observe(&mut self, phase: TunnelPhase) {
        self.phase = phase;
        self.runtime
            .observe_transport(&mut self.continuation, phase);
    }

    async fn advance(&mut self) -> io::Result<Option<&'static str>> {
        use talpid_core::tunnel_state_machine::TunnelCommand;
        let command = self.runtime.continue_connect(&mut self.continuation);
        let command = command.map(|command| match command {
            TunnelCommand::Connect => "Connect",
            TunnelCommand::Disconnect => "Disconnect",
            _ => panic!("unexpected continuation command"),
        });
        if let Some(command) = command {
            self.commands.push(command);
        }
        self.runtime
            .update(&self.policy, self.target, self.phase)
            .await;
        Ok(command)
    }

    async fn admit(&mut self) -> Option<&'static str> {
        bounded(async {
            loop {
                if let Some(command) = self.advance().await.unwrap() {
                    break Some(command);
                }
                self.runtime.notifications().1.await;
            }
        })
        .await
    }

    async fn connect_endpoint(&mut self) {
        self.connect_endpoint_with(assigned_config()).await;
    }

    async fn connect_endpoint_with(
        &mut self,
        config: talpid_tunnel::tun_provider::TunConfig,
    ) -> talpid_tunnel::packet_attachment::PendingCaptureRequest {
        self.observe(TunnelPhase::Connecting);
        let broker = self.runtime.broker();
        let mut configured_request = None;
        if broker.snapshot().mode == AttachmentMode::ManagedRequired {
            let projected = talpid_tunnel::tun_provider::transport::router_config(
                &config,
                broker.local_routes(),
            );
            let mut request = broker.request_target_capture(config, projected).unwrap();
            configured_request = broker.pending_request();
            self.runtime
                .update(&self.policy, self.target, self.phase)
                .await;
            // Service native acknowledgements and queued latest-intent work as
            // the daemon does; never hold the actor awaiting a target request.
            let receipt = self.wait_for_capture_configuration(&mut request).await;
            let mut pair = broker.acquire(&receipt).unwrap();
            pair.control.activate().unwrap();
            let mut public = flow(Transport::Udp, 45100);
            public.source.set_ip(fixed_config().addresses[0]);
            public.destination = "1.1.1.1:443".parse().unwrap();
            let bytes = udp_packet(public, b"ready-handover-consumer");
            self.platform
                .peer
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .send(&bytes)
                .unwrap();
            bounded(pair.receive.recv())
                .await
                .unwrap()
                .handoff(|actual| assert_eq!(actual, bytes))
                .unwrap();
            self.request = Some(request);
            self.transport = Some(pair);
        }
        self.observe(TunnelPhase::Connected);
        self.runtime
            .update(&self.policy, self.target, self.phase)
            .await;
        self.settle_capture().await;
        assert_eq!(
            self.runtime.status().forwarding,
            if self.policy.announced_routes().is_empty() {
                ForwardingAvailability::Off
            } else {
                ForwardingAvailability::Active
            }
        );
        configured_request.expect("Handover fixture uses managed requests")
    }

    async fn settle_capture(&mut self) {
        bounded(async {
            loop {
                self.runtime
                    .owner_changed(&self.policy, self.target, self.phase);
                self.runtime
                    .internal_update(&self.policy, self.target, self.phase)
                    .await;
                if self.runtime.capture_configuration_ready() {
                    break;
                }
                let (_, owner, broker) = self.runtime.notifications();
                tokio::select! {
                    _ = owner => {},
                    _ = broker => {},
                }
            }
        })
        .await;
    }

    fn user_disconnect(&mut self) {
        use talpid_core::tunnel_state_machine::TunnelCommand;
        self.target = TargetState::Unsecured;
        assert!(matches!(
            self.runtime.request_disconnect(&mut self.continuation),
            TunnelCommand::Disconnect
        ));
        self.commands.push("Disconnect");
    }

    fn acknowledge_transport_close(&mut self) {
        // The stand-in transport keeps its exact broker halves/request until the
        // delayed close acknowledgement. This is the TSM's joined boundary.
        self.transport.take();
        self.request.take();
        self.commands.push("Joined");
        self.observe(TunnelPhase::Disconnected);
    }

    async fn wait_for_capture_configuration(
        &mut self,
        request: &mut talpid_tunnel::packet_attachment::ConfigurationRequest,
    ) -> talpid_tunnel::packet_attachment::CaptureReceipt {
        bounded(async {
            loop {
                let completed = {
                    let (_, owner, broker) = self.runtime.notifications();
                    tokio::select! {
                        biased;
                        result = request.configured() => Some(result),
                        _ = owner => None,
                        _ = broker => None,
                    }
                };
                if let Some(receipt) = completed {
                    break receipt;
                }
                self.runtime
                    .owner_changed(&self.policy, self.target, self.phase);
                self.runtime
                    .internal_update(&self.policy, self.target, self.phase)
                    .await;
            }
        })
        .await
        .unwrap()
    }

    async fn wait_for_capture_release(&self, generation: i64) {
        // Readiness and target traffic can precede the asynchronous predecessor
        // release. Join the exact epoch, not a notification or aggregate count.
        bounded(async {
            loop {
                self.platform.released.notified().await;
                if self
                    .platform
                    .completed_releases
                    .lock()
                    .unwrap()
                    .contains(&generation)
                {
                    break;
                }
            }
        })
        .await;
    }

    async fn close(mut self) {
        self.runtime.begin_shutdown();
        self.acknowledge_transport_close();
        self.runtime.shutdown().await.unwrap();
    }
}

// B7a: reproduce configuration restoration using the real daemon/front-end owner.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connected_policy_toggle_and_app_restore_deliver_fresh_local_tcp_udp() {
    for mtu in [1280, 1380] {
        for settings_first in [false, true] {
            policy_toggle_and_app_restore_case(mtu, settings_first).await;
        }
    }
}

async fn policy_toggle_and_app_restore_case(mtu: u16, settings_first: bool) {
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let physical = (tcp.local_addr().unwrap(), udp.local_addr().unwrap());
    let tcp_hits = Arc::new(AtomicUsize::new(0));
    let udp_hits = Arc::new(AtomicUsize::new(0));
    let hits = tcp_hits.clone();
    let tcp_task = tokio::spawn(async move {
        for index in 0..8 {
            let (mut stream, _) = tcp.accept().await.unwrap();
            let mut bytes = [0; 8];
            stream.read_exact(&mut bytes).await.unwrap();
            assert_eq!(bytes.as_slice(), format!("{index:08}").as_bytes());
            hits.fetch_add(1, SeqCst);
            stream.write_all(&bytes).await.unwrap();
        }
    });
    let hits = udp_hits.clone();
    let udp_task = tokio::spawn(async move {
        for index in 0..8 {
            let mut bytes = [0; 128];
            let (count, source) = udp.recv_from(&mut bytes).await.unwrap();
            assert_eq!(&bytes[..count], format!("{index:08}").as_bytes());
            hits.fetch_add(1, SeqCst);
            udp.send_to(&bytes[..count], source).await.unwrap();
        }
    });
    let mut h = Handover::unstarted_with_physical(policy(), physical);
    h.observe(TunnelPhase::Disconnected);
    h.advance().await.unwrap();
    h.settle_capture().await;
    let mut target = assigned_config();
    target.mtu = mtu;
    h.connect_endpoint_with(target.clone()).await;
    let broker = h.runtime.broker();
    let session = broker.snapshot().session_generation;
    let first_capture = broker.snapshot().capture_generation;
    let authority = h.platform.authority.lock().unwrap().clone().unwrap();
    for index in 0..8u16 {
        // The device toggles legacy LAN, runs a Local off/on ordinary control,
        // restores legacy LAN, changes app coverage, repeats the off/on control,
        // then restores coverage. Every positive probe is a fresh socket/tuple.
        if [1, 3, 4, 7].contains(&index) {
            h.observe(TunnelPhase::Disconnecting);
            let old = h.transport.take();
            let old_request = h.request.take();
            match index {
                1 => target.allow_lan = true,
                3 => target.allow_lan = false,
                4 => target.excluded_packages = vec!["com.android.deskclock".into()],
                7 => target.excluded_packages.clear(),
                _ => unreachable!(),
            }
            if settings_first {
                h.runtime
                    .set_excluded_packages(target.excluded_packages.clone());
                h.runtime.update(&h.policy, h.target, h.phase).await;
                // A second settings acknowledgement can arrive before the
                // predecessor transport has joined, as in the device restore.
                if index == 7 {
                    h.runtime.update(&h.policy, h.target, h.phase).await;
                }
            }
            drop(old);
            if let Some(request) = old_request {
                request.transport_joined();
            }
            if index == 7 {
                // Make the new fd exist while the native observation remains
                // pending; coalesce policy demand before admitting its epoch.
                let (opened, opening) = oneshot::channel();
                *h.platform.delayed_completion.lock().unwrap() = Some(opened);
                h.observe(TunnelPhase::Connecting);
                let projected = talpid_tunnel::tun_provider::transport::router_config(
                    &target,
                    broker.local_routes(),
                );
                let mut request = broker
                    .request_target_capture(target.clone(), projected)
                    .unwrap();
                h.runtime.update(&h.policy, h.target, h.phase).await;
                let (generation, observation) = bounded(opening).await.unwrap();
                assert!(!broker.snapshot().capture_ready);
                h.policy.enabled = false;
                h.runtime.update(&h.policy, h.target, h.phase).await;
                h.policy.enabled = true;
                h.runtime.update(&h.policy, h.target, h.phase).await;
                assert!(h.platform.feed.publish(43, generation, observation));
                let receipt = h.wait_for_capture_configuration(&mut request).await;
                let pair = broker.acquire(&receipt).unwrap();
                pair.control.activate().unwrap();
                h.request = Some(request);
                h.transport = Some(pair);
                h.observe(TunnelPhase::Connected);
                h.runtime.update(&h.policy, h.target, h.phase).await;
            } else {
                h.connect_endpoint_with(target.clone()).await;
            }
            if !settings_first {
                h.runtime
                    .set_excluded_packages(target.excluded_packages.clone());
                h.runtime.update(&h.policy, h.target, h.phase).await;
            }
        }
        if [2, 5, 6].contains(&index) {
            h.policy.enabled = false;
            let mut stopped = physical_snapshot();
            stopped.sequence = 20 + i64::from(index) * 2;
            stopped.observer_running = false;
            assert!(h.physical_feed.publish(33, stopped));
            h.runtime.update(&h.policy, h.target, h.phase).await;
            h.settle_capture().await;
            assert_eq!(h.runtime.status().forwarding, ForwardingAvailability::Off);
            assert!(
                authority
                    .authorize(flow(Transport::Tcp, 47000 + index))
                    .is_err()
            );
            // Ordinary readiness must remain independent of Local demand.
            assert!(broker.snapshot().ordinary_ready);
            let ordinary = UnixDatagram::from_std(
                h.platform
                    .peer
                    .lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .try_clone()
                    .unwrap(),
            )
            .unwrap();
            for bytes in [
                tcp_packet(flow(Transport::Tcp, 49000 + index), 100, 0, 2, &[]),
                udp_packet(flow(Transport::Udp, 49000 + index), b"Local-off-control"),
            ] {
                ordinary.send(&bytes).await.unwrap();
                bounded(h.transport.as_mut().unwrap().receive.recv())
                    .await
                    .unwrap()
                    .handoff(|actual| assert_eq!(actual, bytes))
                    .unwrap();
            }
            assert_eq!(tcp_hits.load(SeqCst), usize::from(index));
            assert_eq!(udp_hits.load(SeqCst), usize::from(index));
            h.policy.enabled = true;
            let mut resumed = physical_snapshot();
            resumed.sequence = 21 + i64::from(index) * 2;
            assert!(h.physical_feed.publish(33, resumed));
            h.runtime.update(&h.policy, h.target, h.phase).await;
        }
        h.settle_capture().await;
        assert!(broker.snapshot().capture_ready);
        assert!(broker.snapshot().ordinary_ready);
        assert_eq!(broker.snapshot().session_generation, session);
        assert_eq!(
            h.runtime.status().forwarding,
            ForwardingAvailability::Active
        );
        let generation = broker.snapshot().capture_generation;
        if index == 7 {
            assert_ne!(
                generation, first_capture,
                "restored app coverage uses the new capture"
            );
            assert_eq!(h.platform.starts.load(SeqCst), 8);
        }
        let local = flow(Transport::Tcp, 47000 + index);
        assert_eq!(
            authority.disposition(local.destination.ip()),
            Disposition::Local
        );
        let grant = authority.authorize(local).unwrap();
        assert!(authority.current(&grant));
        let capture = UnixDatagram::from_std(
            h.platform
                .peer
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .try_clone()
                .unwrap(),
        )
        .unwrap();
        capture
            .send(&tcp_packet(local, 100, 0, 2, &[]))
            .await
            .unwrap();
        let syn = capture_reply(&capture).await;
        assert_eq!(syn[33] & 0x12, 0x12, "stage {index}: SYN-ACK");
        let mut ack = u32::from_be_bytes(syn[24..28].try_into().unwrap()).wrapping_add(1);
        let nonce = format!("{index:08}");
        capture
            .send(&tcp_packet(local, 101, ack, 0x18, nonce.as_bytes()))
            .await
            .unwrap();
        let mut received = Vec::new();
        while received.len() < 8 {
            let bytes = capture_reply(&capture).await;
            let packet = packet::parse(&bytes).unwrap();
            assert_eq!(packet.flow.destination, local.source);
            received.extend_from_slice(packet.payload);
            ack = ack.wrapping_add(packet.payload.len() as u32);
        }
        assert_eq!(received, nonce.as_bytes(), "stage {index}: TCP consumer");
        capture
            .send(&tcp_packet(local, 109, ack, 0x14, &[]))
            .await
            .unwrap();
        let udp_flow = flow(Transport::Udp, 48000 + index);
        capture
            .send(&udp_packet(udp_flow, nonce.as_bytes()))
            .await
            .unwrap();
        loop {
            let bytes = capture_reply(&capture).await;
            let packet = packet::parse(&bytes).unwrap();
            if packet.flow.transport == Transport::Udp {
                assert_eq!(packet.flow.destination, udp_flow.source);
                assert_eq!(
                    packet.payload,
                    nonce.as_bytes(),
                    "stage {index}: UDP consumer"
                );
                break;
            }
            assert!(packet.payload.is_empty());
        }
        assert_eq!(tcp_hits.load(SeqCst), usize::from(index + 1));
        assert_eq!(udp_hits.load(SeqCst), usize::from(index + 1));
        assert_eq!(broker.snapshot().capture_generation, generation);
        eprintln!(
            "B7a mtu={mtu} settings_first={settings_first} stage={index} generation={generation:?} TCP/UDP peer+consumer delivered"
        );
    }
    bounded(tcp_task).await.unwrap();
    bounded(udp_task).await.unwrap();
    h.close().await;
}

#[tokio::test]
async fn startup_snapshot_connects_or_serves_partial_without_an_initial_transition() {
    for target in [TargetState::Secured, TargetState::Unsecured] {
        for enabled in [false, true] {
            let mut configured = policy();
            configured.enabled = enabled;
            let mut h = Handover::unstarted(configured);
            h.target = target;
            // spawn() has initialized the producer's current state, but emits
            // no initial transition. Use the same snapshot seam as Daemon::run.
            h.continuation = h.runtime.initialize_transport(h.phase);
            assert_eq!(
                h.runtime.broker().snapshot().mode,
                AttachmentMode::ManagedRequired
            );
            assert_eq!(
                h.runtime.broker().local_routes(),
                h.policy
                    .announced_routes()
                    .iter()
                    .map(|cidr| cidr.network())
                    .collect::<Vec<_>>()
            );
            assert!(
                !h.runtime.has_owner(),
                "startup selection established a capture"
            );
            if target == TargetState::Secured {
                h.continuation.connect();
            }
            if target == TargetState::Secured {
                assert_eq!(
                    h.admit().await,
                    Some("Connect"),
                    "startup snapshot {target:?}, rules {enabled}"
                );
            } else {
                assert_eq!(h.advance().await.unwrap(), None);
            }
            if target == TargetState::Secured {
                assert_eq!(
                    h.advance().await.unwrap(),
                    None,
                    "queued reconciliation duplicated startup Connect"
                );
                h.connect_endpoint().await;
            } else if enabled {
                bounded(h.runtime.notifications().1).await;
                h.runtime.owner_changed(&h.policy, h.target, h.phase);
            }
            assert_eq!(
                h.runtime.status().forwarding,
                if enabled {
                    ForwardingAvailability::Active
                } else {
                    ForwardingAvailability::Off
                }
            );
            h.close().await;
        }
    }
}

#[tokio::test]
async fn coalesced_handover_keeps_reconnect_until_join_unless_user_disconnects() {
    for direction in 0..3 {
        for user_disconnect in [false, true] {
            let mut original = policy();
            if direction == 1 {
                original.enabled = false;
            }
            let mut h = Handover::new(original.clone());
            h.continuation.connect();
            assert_eq!(h.admit().await, Some("Connect"));
            h.connect_endpoint().await;
            assert_eq!(
                h.platform.starts.load(SeqCst),
                if original.enabled { 2 } else { 1 },
                "only Local Partial then actual target; rules off opens the target once"
            );
            h.commands.clear();
            h.policy = original.clone();
            if direction == 2 {
                h.policy.rules[0].cidrs = vec!["172.16.0.0/16".parse().unwrap()];
            } else {
                h.policy.enabled = !h.policy.enabled;
            }
            assert_eq!(
                h.advance().await.unwrap(),
                None,
                "Local settings must not disconnect ordinary VPN"
            );
            assert!(h.transport.as_ref().unwrap().control.current());
            h.continuation.connect();
            assert_eq!(h.advance().await.unwrap(), Some("Connect"));
            h.observe(TunnelPhase::Disconnecting);
            // An ordinary settings event returns to A before the transport joins.
            h.policy = original;
            assert_eq!(h.advance().await.unwrap(), None);
            if user_disconnect {
                h.user_disconnect();
                assert_eq!(h.advance().await.unwrap(), None);
            }
            if user_disconnect {
                h.acknowledge_transport_close();
            } else {
                h.transport.take();
                h.request.take();
                h.commands.push("Joined");
                h.observe(TunnelPhase::Connecting);
            }
            if user_disconnect {
                assert_eq!(h.advance().await.unwrap(), None);
            } else {
                assert_eq!(
                    h.advance().await.unwrap(),
                    None,
                    "coalesced direction {direction}"
                );
            }
            if user_disconnect {
                assert_eq!(h.commands, ["Connect", "Disconnect", "Joined"]);
                if !h.policy.announced_routes().is_empty() {
                    bounded(h.runtime.notifications().1).await;
                    h.runtime.owner_changed(&h.policy, h.target, h.phase);
                    assert_eq!(
                        h.runtime.status().forwarding,
                        ForwardingAvailability::Active
                    );
                } else {
                    assert_eq!(h.runtime.status().forwarding, ForwardingAvailability::Off);
                }
            } else {
                assert_eq!(h.commands, ["Connect", "Joined"]);
                h.connect_endpoint().await;
            }
            h.close().await;
        }
    }
}

#[tokio::test]
async fn managed_teardown_revokes_now_but_releases_only_after_transport_join() {
    // The fixture must reject a platform callback while its actual descriptor
    // remains owned, not infer closure from a Unix peer's eventual send error.
    {
        let (_delivery, platform, _broker) = release_fixture();
        let capture = platform
            .open(
                1,
                &CaptureConfig::Partial(vec!["10.0.2.2/32".into()].into()),
            )
            .unwrap();
        let peer = platform.peer.lock().unwrap().take().unwrap();
        assert!(!platform.peer_closed(&peer));
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| platform.closed(1))).is_err()
        );
        assert_eq!(platform.releases.load(SeqCst), 0);
        drop(capture);
        platform.closed(1).unwrap();
        assert!(platform.peer_closed(&peer));
    }
    for (trigger, allow_lan) in [
        ("disconnect", false),
        ("rules-off", false),
        ("routes", false),
        ("rules-off", true),
        ("routes", true),
        ("shutdown", false),
    ] {
        for fail_release in [false, true] {
            let mut h = Handover::new(policy());
            h.continuation.connect();
            assert_eq!(h.admit().await, Some("Connect"));
            h.settle_capture().await;
            let initial_generation = h.platform.generation.load(SeqCst);
            let mut target = assigned_config();
            target.allow_lan = allow_lan;
            h.connect_endpoint_with(target).await;
            h.wait_for_capture_release(initial_generation).await;
            if trigger != "shutdown" {
                verify_live_router_change(h, trigger, fail_release, allow_lan).await;
                continue;
            }
            h.commands.clear();
            let authority = h.platform.authority.lock().unwrap().clone().unwrap();
            let mut local = flow(Transport::Udp, 45020);
            local.source.set_ip(fixed_config().addresses[0]);
            let grant = authority.authorize(local).unwrap();
            let ordinary = h.transport.as_ref().unwrap().control.capability();
            let peer = h
                .platform
                .peer
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .try_clone()
                .unwrap();

            // The actual fake transport task retains the same attempt/request
            // until an explicit close acknowledgement; no actor sleep/restart
            // or extra Connect is allowed to manufacture that acknowledgement.
            let transport = h.transport.take().unwrap();
            let request = h.request.take().unwrap();
            let (acknowledge, closed) = oneshot::channel();
            let joining = tokio::spawn(async move {
                closed.await.unwrap();
                drop(transport);
                request.transport_joined();
                drop(request);
            });
            h.platform.fail_release.store(fail_release, SeqCst);
            h.runtime.begin_shutdown();
            assert!(matches!(
                h.runtime.request_disconnect(&mut h.continuation),
                talpid_core::tunnel_state_machine::TunnelCommand::Disconnect
            ));
            h.commands.push("Disconnect");
            assert!(
                !authority.current(&grant),
                "{trigger}: Local revocation was late"
            );
            assert!(
                !ordinary.current(),
                "{trigger}: ordinary revocation was late"
            );
            h.observe(TunnelPhase::Disconnecting);
            assert_eq!(
                bounded(h.advance()).await.unwrap(),
                None,
                "actor blocked on transport close"
            );
            // Process a further ordinary settings event while the close is held.
            h.policy.rules[0].name = "latest settings while closing".into();
            assert_eq!(bounded(h.advance()).await.unwrap(), None);
            bounded(h.runtime.notifications().2).await;
            h.runtime.owner_changed(&h.policy, h.target, h.phase);
            assert!(h.runtime.has_owner());
            assert_eq!(
                h.runtime.broker().snapshot().mode,
                AttachmentMode::ManagedRequired
            );
            assert_eq!(h.commands, ["Disconnect"]);
            assert!(
                tokio::time::timeout(Duration::from_millis(80), h.platform.released.notified())
                    .await
                    .is_err(),
                "{trigger}: platform release preceded joined transport teardown"
            );
            assert_eq!(
                peer.send(b"held-capture")
                    .expect("owned descriptor closed before join"),
                12
            );
            assert!(
                h.runtime.stop().await.is_err(),
                "explicit stop bypassed joined release"
            );
            assert_eq!(h.platform.releases.load(SeqCst), 1);

            acknowledge.send(()).unwrap();
            bounded(joining).await.unwrap();
            // Physical/device/control completion alone cannot bypass the normal
            // handover's separate TSM acknowledgement.
            assert!(
                tokio::time::timeout(Duration::from_millis(30), h.platform.released.notified())
                    .await
                    .is_err()
            );
            h.acknowledge_transport_close();
            let first = h.runtime.shutdown().await;
            if fail_release {
                assert!(first.is_err());
                assert!(h.runtime.has_owner());
                assert_eq!(
                    h.runtime.broker().snapshot().mode,
                    AttachmentMode::ManagedRequired
                );
                let attempts = h.platform.releases.load(SeqCst);
                assert_eq!(attempts, 2, "new release failure retried in the same event");
                h.runtime
                    .internal_update(&h.policy, h.target, h.phase)
                    .await;
                assert_eq!(h.platform.releases.load(SeqCst), attempts);
                h.platform.fail_release.store(false, SeqCst);
                h.runtime.shutdown().await.unwrap();
                assert_eq!(h.platform.releases.load(SeqCst), 3);
            } else {
                first.unwrap();
            }
            assert!(
                h.platform.peer_closed(&peer),
                "descriptor survived acknowledged release"
            );
            assert!(!h.runtime.has_owner());
            h.close().await;
        }
    }
    // A later shutdown can inherit an already-joined, failed capture release.
    // It must not demand a second TSM transition to release that retained owner.
    let mut h = Handover::new(policy());
    h.continuation.connect();
    h.admit().await;
    h.settle_capture().await;
    let initial_generation = h.platform.generation.load(SeqCst);
    h.connect_endpoint().await;
    h.wait_for_capture_release(initial_generation).await;
    h.commands.clear();
    h.platform.fail_release.store(true, SeqCst);
    h.user_disconnect();
    h.acknowledge_transport_close();
    h.advance().await.unwrap();
    bounded(h.runtime.notifications().1).await;
    bounded(async {
        while !h.runtime.failed() {
            h.runtime.notifications().1.await;
        }
    })
    .await;
    assert!(h.runtime.has_owner());
    h.runtime.begin_shutdown();
    h.platform.fail_release.store(false, SeqCst);
    // The owned completion may already be ready. It acknowledges the retained
    // request without needing another public transition or physical event.
    bounded(h.runtime.shutdown_with_transport(async { Ok(()) }))
        .await
        .unwrap();
    assert!(!h.runtime.has_owner());
    assert_eq!(h.commands, ["Disconnect", "Joined"]);
    assert_eq!(h.platform.releases.load(SeqCst), 4);
}

async fn verify_live_router_change(
    mut h: Handover,
    trigger: &str,
    fail_release: bool,
    allow_lan: bool,
) {
    h.commands.clear();
    let old_generation = h.platform.generation.load(SeqCst);
    let broker = h.runtime.broker();
    let session = broker.snapshot().session_generation;
    let authority = h.platform.authority.lock().unwrap().clone().unwrap();
    let grant = authority.authorize(flow(Transport::Udp, 45912)).unwrap();
    let old_peer = h
        .platform
        .peer
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .try_clone()
        .unwrap();
    let before = h.platform.releases.load(SeqCst);
    let opens = h.platform.starts.load(SeqCst);
    h.platform.fail_release.store(fail_release, SeqCst);
    if trigger == "disconnect" {
        h.user_disconnect();
        h.observe(TunnelPhase::Disconnecting);
        assert_eq!(bounded(h.advance()).await.unwrap(), None);
        assert!(
            authority.current(&grant),
            "Disconnect revoked Local before Partial handover"
        );
        assert!(!h.transport.as_ref().unwrap().control.current());
        assert_eq!(old_peer.send(b"held-capture").unwrap(), 12);
        assert!(
            tokio::time::timeout(Duration::from_millis(30), async {
                while h.platform.releases.load(SeqCst) == before {
                    h.platform.released.notified().await;
                }
            })
            .await
            .is_err(),
            "platform released before target joined"
        );
        // A further settings event must be serviced while the target is held.
        h.policy.rules[0].name = "latest while joining".into();
        assert_eq!(bounded(h.advance()).await.unwrap(), None);
        h.acknowledge_transport_close();
    } else {
        if trigger == "rules-off" {
            h.policy.enabled = false;
        } else {
            h.policy.rules[0].cidrs = vec!["172.16.0.0/16".parse().unwrap()];
        }
    }
    assert_eq!(bounded(h.advance()).await.unwrap(), None);
    if trigger != "disconnect" {
        assert!(!authority.current(&grant), "policy revoke was late");
        assert!(
            h.transport.as_ref().unwrap().control.current(),
            "Local policy retired ordinary VPN"
        );
        assert!(h.commands.is_empty());
    }
    if trigger != "disconnect" && !allow_lan {
        assert_eq!(
            h.platform.starts.load(SeqCst),
            opens,
            "default-covered route change reopened the sink"
        );
        assert_eq!(h.platform.releases.load(SeqCst), before);
        assert_eq!(h.platform.generation.load(SeqCst), old_generation);
        assert_eq!(broker.snapshot().session_generation, session);
        assert!(h.runtime.capture_configuration_ready());
        assert!(!h.platform.peer_closed(&old_peer));
        let mut public = flow(Transport::Udp, 45913);
        public.destination = "1.1.1.1:443".parse().unwrap();
        let bytes = udp_packet(public, b"ordinary-vpn-survives-covered-local-change");
        old_peer.send(&bytes).unwrap();
        bounded(h.transport.as_mut().unwrap().receive.recv())
            .await
            .unwrap()
            .handoff(|actual| assert_eq!(actual, bytes))
            .unwrap();
        assert_eq!(h.platform.starts.load(SeqCst), opens);
        assert_eq!(h.platform.releases.load(SeqCst), before);
        h.platform.fail_release.store(false, SeqCst);
        h.close().await;
        return;
    }
    bounded(h.runtime.notifications().1).await;
    bounded(async {
        while h.platform.releases.load(SeqCst) == before {
            h.runtime.notifications().1.await;
        }
    })
    .await;
    if fail_release {
        bounded(async {
            while !h.runtime.failed() {
                h.runtime.notifications().1.await;
            }
        })
        .await;
        let failed_count = h.platform.releases.load(SeqCst);
        h.runtime
            .internal_update(&h.policy, h.target, h.phase)
            .await;
        assert_eq!(
            h.platform.releases.load(SeqCst),
            failed_count,
            "internal event retried failed release"
        );
        h.platform.fail_release.store(false, SeqCst);
        assert_eq!(h.advance().await.unwrap(), None);
        bounded(h.runtime.notifications().1).await;
        assert_eq!(h.platform.releases.load(SeqCst), failed_count + 1);
    }
    // A configuration ack and an unrelated platform release are not closure of
    // this exact predecessor. Drive both stages inside the same existing bound.
    let settled = tokio::time::timeout(Duration::from_secs(5), async {
        while !h.runtime.capture_configuration_ready()
            || !h
                .platform
                .completed_releases
                .lock()
                .unwrap()
                .contains(&old_generation)
        {
            h.runtime.notifications().1.await;
            h.runtime
                .internal_update(&h.policy, h.target, h.phase)
                .await;
        }
    })
    .await;
    assert!(
        settled.is_ok(),
        "{trigger}, failure={fail_release}, starts={}, releases={}, broker={:?}, failed={}, applied platforms={:?}",
        h.platform.starts.load(SeqCst),
        h.platform.releases.load(SeqCst),
        broker.snapshot(),
        h.runtime.failed(),
        h.platform.opened.lock().unwrap()
    );
    h.runtime.owner_changed(&h.policy, h.target, h.phase);
    assert_eq!(broker.snapshot().session_generation, session);
    assert!(
        h.platform.peer_closed(&old_peer),
        "{trigger}, failure={fail_release}: predecessor survived exact configuration/release acknowledgements"
    );
    if trigger == "disconnect" {
        assert!(authority.current(&grant));
        assert_eq!(h.commands, ["Disconnect", "Joined"]);
        assert_eq!(
            h.runtime.status().forwarding,
            ForwardingAvailability::Active
        );
    } else {
        let mut public = flow(Transport::Udp, 45913);
        public.destination = "1.1.1.1:443".parse().unwrap();
        let bytes = udp_packet(public, b"ordinary-vpn-survives-local-off");
        h.platform
            .peer
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .send(&bytes)
            .unwrap();
        bounded(h.transport.as_mut().unwrap().receive.recv())
            .await
            .unwrap()
            .handoff(|actual| assert_eq!(actual, bytes))
            .unwrap();
    }
    h.close().await;
}

#[tokio::test]
async fn joined_internal_transport_retry_replaces_capture_without_a_tsm_handover() {
    let mut h = Handover::new(policy());
    h.continuation.connect();
    assert_eq!(h.admit().await, Some("Connect"));
    h.settle_capture().await;
    let initial_generation = h.platform.generation.load(SeqCst);
    h.connect_endpoint().await;
    h.wait_for_capture_release(initial_generation).await;
    let broker = h.runtime.broker();
    let first_generation = broker.snapshot().capture_generation.unwrap();
    let first_session = broker.snapshot().session_generation;
    let old_peer = h
        .platform
        .peer
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .try_clone()
        .unwrap();
    let config = h.platform.opened.lock().unwrap().last().unwrap().clone();
    let old_request = h.request.take().unwrap();
    let transport = h.transport.take().unwrap();
    transport.control.detach();
    bounded(h.runtime.notifications().2).await;
    h.runtime.owner_changed(&h.policy, h.target, h.phase);
    let mut next_request = broker
        .request_target_capture(assigned_config(), config)
        .unwrap();
    // A successor request is not proof that old device/control cleanup joined.
    h.observe(TunnelPhase::Connecting);
    h.runtime
        .internal_update(&h.policy, h.target, h.phase)
        .await;
    assert_eq!(h.platform.starts.load(SeqCst), 2);
    assert_eq!(h.platform.releases.load(SeqCst), 1);
    // The successor can become ready without destroying Local or acknowledging
    // predecessor cleanup. The old descriptor remains owned until the exact join.
    let receipt = h.wait_for_capture_configuration(&mut next_request).await;
    assert_eq!(
        receipt.generation(),
        first_generation,
        "equal projection unnecessarily reopened the capture"
    );
    assert_eq!(broker.snapshot().session_generation, first_session);
    assert_eq!(old_peer.send(b"predecessor-retained").unwrap(), 20);
    assert_eq!(h.platform.releases.load(SeqCst), 1);
    drop(transport);
    old_request.transport_joined();
    // This is the same production broker notification selected by the daemon.
    bounded(h.runtime.notifications().2).await;
    h.runtime
        .internal_update(&h.policy, h.target, h.phase)
        .await;
    assert_eq!(old_peer.send(b"same-current-sink").unwrap(), 17);
    let pair = broker.acquire(&receipt).unwrap();
    pair.control.activate().unwrap();
    h.request = Some(next_request);
    h.transport = Some(pair);
    drop(old_request);
    h.observe(TunnelPhase::Connected);
    h.runtime
        .internal_update(&h.policy, h.target, h.phase)
        .await;
    assert_eq!(
        h.runtime.status().forwarding,
        ForwardingAvailability::Active
    );
    assert_eq!(
        h.commands,
        ["Connect"],
        "internal device retry invented a TSM handover"
    );
    assert_eq!(h.platform.releases.load(SeqCst), 1);
    h.close().await;
}

#[tokio::test]
async fn forced_fifth_attempt_replaces_sink_without_replacing_local_session() {
    use talpid_tunnel::tun_provider::{ConfigurationPurpose, transport::TransportMode};
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let physical = (tcp.local_addr().unwrap(), udp.local_addr().unwrap());
    let tcp_task = tokio::spawn(async move {
        let (mut stream, tuple) = tcp.accept().await.unwrap();
        for n in 0..=5 {
            let mut bytes = [0; 8];
            stream.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, format!("{n:08}").as_bytes());
            assert_eq!(stream.peer_addr().unwrap(), tuple);
            stream.write_all(&bytes).await.unwrap();
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(30), tcp.accept())
                .await
                .is_err()
        );
    });
    let udp_task = tokio::spawn(async move {
        let mut tuple = None;
        for n in 0..=5 {
            let mut bytes = [0; 8];
            let (len, source) = udp.recv_from(&mut bytes).await.unwrap();
            assert_eq!(len, 8);
            assert_eq!(&bytes, format!("{n:08}").as_bytes());
            assert_eq!(*tuple.get_or_insert(source), source, "UDP socket replaced");
            udp.send_to(&bytes, source).await.unwrap();
        }
    });
    let mut h = Handover::unstarted_with_physical(policy(), physical);
    h.observe(TunnelPhase::Disconnected);
    h.connect_endpoint().await;
    let broker = h.runtime.broker();
    let session = broker.snapshot().session_generation;
    let first_epoch = broker.snapshot().capture_generation;
    let authority = h.platform.authority.lock().unwrap().clone().unwrap();
    let tcp_flow = flow(Transport::Tcp, 45996);
    let udp_flow = flow(Transport::Udp, 45997);
    let grant = authority.authorize(tcp_flow).unwrap();
    let peer = |h: &Handover| {
        UnixDatagram::from_std(
            h.platform
                .peer
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .try_clone()
                .unwrap(),
        )
        .unwrap()
    };
    peer(&h)
        .send(&tcp_packet(tcp_flow, 100, 0, 2, &[]))
        .await
        .unwrap();
    let syn = capture_reply(&peer(&h)).await;
    let mut ack = u32::from_be_bytes(syn[24..28].try_into().unwrap()).wrapping_add(1);
    let mut sequence = 101;
    for attempt in 0..=5 {
        if attempt > 0 {
            let old = h.transport.take().unwrap();
            let old_request = h.request.take().unwrap();
            let mut stale = old
                .control
                .capability()
                .packet(
                    talpid_types::relay_flow::RelayBuffer::copy_from(
                        b"stale-fifth-writer",
                        broker.application_buffers().as_ref(),
                    )
                    .unwrap(),
                )
                .unwrap();
            old.control.detach();
            drop(old);
            old_request.transport_joined();
            if attempt == 5 {
                let old_epoch = broker.snapshot().capture_generation.unwrap();
                // The unchanged TSM fifth-attempt branch supplies forced=true;
                // this invokes its actual provider/broker/actor operation.
                let mut forced = TransportMode::selected(Some(&broker))
                    .reconfigure::<talpid_tunnel::packet_attachment::AttachmentError>(
                        assigned_config(),
                        ConfigurationPurpose::ForcedRefresh,
                        true,
                        |_| panic!("Native refresh"),
                    )
                    .unwrap()
                    .unwrap();
                h.runtime
                    .internal_update(&h.policy, h.target, h.phase)
                    .await;
                let refreshed = h.wait_for_capture_configuration(&mut forced).await;
                assert_ne!(
                    refreshed.generation(),
                    old_epoch,
                    "fifth retry reused equal-config fd"
                );
                assert!(
                    broker.acquire(&refreshed).is_err(),
                    "refresh is not a target"
                );
                h.wait_for_capture_release(old_epoch as i64).await;
                drop(forced);
            }
            drop(old_request);
            h.connect_endpoint().await;
            assert!(matches!(
                stale.write(|_| panic!("stale writer reached sink")),
                talpid_types::relay_flow::RelayWriteOutcome::Stale
            ));
            if attempt < 5 {
                assert_eq!(broker.snapshot().capture_generation, first_epoch);
                assert_eq!(
                    h.platform.starts.load(SeqCst),
                    1,
                    "nonforced equal retry rebuilt fd"
                );
            } else {
                assert_eq!(h.platform.starts.load(SeqCst), 2);
            }
        }
        assert_eq!(broker.snapshot().session_generation, session);
        assert!(authority.current(&grant));
        let capture = peer(&h);
        let nonce = format!("{attempt:08}");
        capture
            .send(&tcp_packet(tcp_flow, sequence, ack, 0x18, nonce.as_bytes()))
            .await
            .unwrap();
        let mut received = Vec::new();
        while received.len() < 8 {
            let bytes = capture_reply(&capture).await;
            let payload = packet::parse(&bytes).unwrap().payload;
            received.extend_from_slice(payload);
            ack = ack.wrapping_add(payload.len() as u32);
        }
        assert_eq!(received, nonce.as_bytes());
        sequence += 8;
        capture
            .send(&tcp_packet(tcp_flow, sequence, ack, 0x10, &[]))
            .await
            .unwrap();
        capture
            .send(&udp_packet(udp_flow, nonce.as_bytes()))
            .await
            .unwrap();
        loop {
            let bytes = capture_reply(&capture).await;
            let parsed = packet::parse(&bytes).unwrap();
            if parsed.flow.transport == Transport::Udp {
                assert_eq!(parsed.payload, nonce.as_bytes());
                break;
            }
        }
    }
    bounded(tcp_task).await.unwrap();
    bounded(udp_task).await.unwrap();
    h.close().await;
}

#[tokio::test]
async fn mullvad_retry_does_not_require_local_feed_event() {
    use talpid_tunnel::tun_provider::{ConfigurationPurpose, transport::TransportMode};
    for lose_fd in [false, true] {
        let mut h = Handover::new(policy());
        h.connect_endpoint().await;
        let broker = h.runtime.broker();
        let old_epoch = h.platform.generation.load(SeqCst);
        let old = h.transport.take().unwrap();
        old.control.detach();
        drop(old);
        let old_request = h.request.take().unwrap();
        old_request.transport_joined();
        // Retain the daemon's deferred release while the next TSM state has
        // not yet published. Reconfigure must acknowledge this exact identity,
        // including after synchronous fd/network loss removed broker.capture.
        h.observe(TunnelPhase::Disconnecting);
        if lose_fd {
            let expected = h.platform.expected.lock().unwrap().clone().unwrap();
            assert!(h.platform.feed.publish(
                h.platform.feed.registration(),
                old_epoch,
                CaptureNetworkObservation {
                    network_handle: old_epoch << 32,
                    network: format!("net-{old_epoch}"),
                    interface_name: expected.interface_name,
                    owner_uid: expected.owner_uid,
                    routes: expected.routes,
                    addresses: expected.addresses,
                    dns_servers: expected.dns_servers,
                    mtu: expected.mtu,
                    fresh: false,
                    lost: true,
                    api_level: 33,
                }
            ));
            assert!(!broker.snapshot().capture_ready);
            bounded(h.runtime.notifications().1).await;
            h.runtime.owner_changed(&h.policy, h.target, h.phase);
        } else {
            h.platform.retain_handover.store(true, SeqCst);
        }
        let mut failed_config = assigned_config();
        failed_config.mtu = 1380;
        failed_config.dns_servers = Some(vec!["192.0.2.1".parse().unwrap()]);
        let mut first = TransportMode::selected(Some(&broker))
            .reconfigure::<talpid_tunnel::packet_attachment::AttachmentError>(
                failed_config,
                ConfigurationPurpose::Blocking,
                false,
                |_| panic!("Native blocking"),
            )
            .unwrap()
            .unwrap();
        h.runtime
            .internal_update(&h.policy, h.target, h.phase)
            .await;
        if !lose_fd {
            bounded(h.runtime.notifications().1).await;
            assert!(
                bounded(first.configured()).await.is_err(),
                "rolled-back operation stayed pending"
            );
            let starts = h.platform.starts.load(SeqCst);
            for _ in 0..3 {
                h.runtime
                    .internal_update(&h.policy, h.target, h.phase)
                    .await;
            }
            assert_eq!(
                h.platform.starts.load(SeqCst),
                starts,
                "same failed operation repeated"
            );
            h.observe(TunnelPhase::Error);
            for _ in 0..3 {
                h.runtime.update(&h.policy, h.target, h.phase).await;
                h.runtime
                    .internal_update(&h.policy, h.target, h.phase)
                    .await;
                assert!(
                    h.runtime.failed(),
                    "an input cleared the failed operation latch"
                );
            }
            assert_eq!(
                h.platform.starts.load(SeqCst),
                starts,
                "Error retried a failed blocking operation"
            );
            h.platform.retain_handover.store(false, SeqCst);
        } else {
            h.wait_for_capture_configuration(&mut first).await;
            assert!(
                h.platform.descriptor_closed(old_epoch),
                "weak cleanup identity failed to join predecessor"
            );
        }
        first.cancel();
        first.transport_joined();
        // A new exact request wakes the daemon through broker notification only.
        // No Local feed publish, settings update, or public TSM transition.
        let projected = talpid_tunnel::tun_provider::transport::router_config(
            &assigned_config(),
            broker.local_routes(),
        );
        let mut next = broker
            .request_target_capture(assigned_config(), projected)
            .unwrap();
        h.runtime
            .internal_update(&h.policy, h.target, h.phase)
            .await;
        let receipt = h.wait_for_capture_configuration(&mut next).await;
        let mut pair = broker.acquire(&receipt).unwrap();
        pair.control.activate().unwrap();
        let mut public = flow(Transport::Udp, 45998);
        public.destination = "1.1.1.1:443".parse().unwrap();
        let bytes = udp_packet(public, b"retry-without-local-event");
        h.platform
            .peer
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .send(&bytes)
            .unwrap();
        bounded(pair.receive.recv())
            .await
            .unwrap()
            .handoff(|actual| assert_eq!(actual, bytes))
            .unwrap();
        drop(old_request);
        drop(first);
        h.request = Some(next);
        h.transport = Some(pair);
        h.close().await;
    }
    error_local_routes_follow_current_safe_base().await;
}

async fn error_local_routes_follow_current_safe_base() {
    use talpid_tunnel::tun_provider::{ConfigurationPurpose, transport::TransportMode};
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let physical = (tcp.local_addr().unwrap(), udp.local_addr().unwrap());
    let tcp_task = tokio::spawn(async move {
        let (mut stream, tuple) = tcp.accept().await.unwrap();
        for stage in 0..4 {
            let mut bytes = [0; 8];
            stream.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, format!("{stage:08}").as_bytes());
            assert_eq!(stream.peer_addr().unwrap(), tuple);
            stream.write_all(&bytes).await.unwrap();
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(30), tcp.accept())
                .await
                .is_err(),
            "Error route edit reopened TCP"
        );
    });
    let udp_task = tokio::spawn(async move {
        let mut tuple = None;
        for expected in ["udp00000", "udp00001", "udp00002", "newroute", "udp00003"] {
            let mut bytes = [0; 8];
            let (len, source) = udp.recv_from(&mut bytes).await.unwrap();
            assert_eq!(len, 8);
            assert_eq!(&bytes, expected.as_bytes());
            if expected != "newroute" {
                assert_eq!(
                    *tuple.get_or_insert(source),
                    source,
                    "Error route edit replaced eligible UDP socket"
                );
            }
            udp.send_to(&bytes, source).await.unwrap();
        }
    });
    let mut h = Handover::unstarted_with_physical(policy(), physical);
    h.observe(TunnelPhase::Disconnected);
    let mut target = assigned_config();
    target.mtu = 1420;
    target.dns_servers = Some(vec!["1.1.1.1".parse().unwrap()]);
    h.connect_endpoint_with(target).await;
    let broker = h.runtime.broker();
    let session = broker.snapshot().session_generation;
    let authority = h.platform.authority.lock().unwrap().clone().unwrap();
    let tcp_flow = flow(Transport::Tcp, 45986);
    let udp_flow = flow(Transport::Udp, 45987);
    let grant = authority.authorize(tcp_flow).unwrap();
    let peer = |h: &Handover| {
        UnixDatagram::from_std(
            h.platform
                .peer
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .try_clone()
                .unwrap(),
        )
        .unwrap()
    };
    peer(&h)
        .send(&tcp_packet(tcp_flow, 100, 0, 2, &[]))
        .await
        .unwrap();
    let syn = capture_reply(&peer(&h)).await;
    let mut ack = u32::from_be_bytes(syn[24..28].try_into().unwrap()).wrapping_add(1);
    let mut sequence = 101;
    for stage in 0..4 {
        if stage == 1 {
            let old = h.transport.take().unwrap();
            old.control.detach();
            drop(old);
            let old = h.request.take().unwrap();
            old.transport_joined();
            h.observe(TunnelPhase::Disconnecting);
            let mut safe = talpid_tunnel::tun_provider::blocking_config();
            safe.allow_lan = true;
            safe.excluded_packages = vec!["current.safe.exclusion".into()];
            safe.dns_servers = Some(vec!["192.0.2.1".parse().unwrap()]);
            let mut operation = TransportMode::selected(Some(&broker))
                .reconfigure::<talpid_tunnel::packet_attachment::AttachmentError>(
                    safe,
                    ConfigurationPurpose::Blocking,
                    false,
                    |_| panic!("Native Error configuration"),
                )
                .unwrap()
                .unwrap();
            h.runtime
                .internal_update(&h.policy, h.target, h.phase)
                .await;
            h.wait_for_capture_configuration(&mut operation).await;
            h.request = Some(operation);
            drop(old);
            h.observe(TunnelPhase::Error);
        } else if stage == 2 {
            h.policy.rules[0].cidrs.push("10.0.2.3/32".parse().unwrap());
        } else if stage == 3 {
            h.policy.rules[0]
                .cidrs
                .retain(|prefix| prefix.to_string() != "10.0.2.3/32");
        }
        h.runtime.update(&h.policy, h.target, h.phase).await;
        h.settle_capture().await;
        assert_eq!(broker.snapshot().session_generation, session);
        assert!(authority.current(&grant));
        let actual = h.platform.opened.lock().unwrap().last().unwrap().clone();
        if stage > 0 {
            assert_eq!(h.phase, TunnelPhase::Error, "Local edit left Error");
            assert_eq!(actual.mtu, 1380);
            assert_eq!(actual.dns_servers, Some(vec!["192.0.2.1".parse().unwrap()]));
            assert_eq!(actual.excluded_packages, vec!["current.safe.exclusion"]);
            assert!(
                !actual
                    .routes
                    .iter()
                    .any(|r| r.contains("10.0.2.4".parse().unwrap())),
                "Error reused cached target Allow LAN"
            );
            assert_eq!(
                actual
                    .routes
                    .iter()
                    .any(|r| r.contains("10.0.2.3".parse().unwrap())),
                stage == 2,
                "Error Local route addition/removal did not reach actual platform config"
            );
            assert!(
                broker.pending_request().is_none(),
                "Local edit manufactured a blocking receipt"
            );
            assert!(!broker.snapshot().ordinary_ready);
        }
        assert!(
            actual
                .routes
                .iter()
                .any(|r| r.contains("10.0.2.2".parse().unwrap()))
        );
        let capture = peer(&h);
        let nonce = format!("{stage:08}");
        capture
            .send(&tcp_packet(tcp_flow, sequence, ack, 0x18, nonce.as_bytes()))
            .await
            .unwrap();
        let mut received = Vec::new();
        while received.len() < 8 {
            let bytes = capture_reply(&capture).await;
            let payload = packet::parse(&bytes).unwrap().payload;
            received.extend_from_slice(payload);
            ack = ack.wrapping_add(payload.len() as u32);
        }
        assert_eq!(received, nonce.as_bytes());
        sequence += 8;
        capture
            .send(&tcp_packet(tcp_flow, sequence, ack, 0x10, &[]))
            .await
            .unwrap();
        let udp_nonce = format!("udp{stage:05}");
        capture
            .send(&udp_packet(udp_flow, udp_nonce.as_bytes()))
            .await
            .unwrap();
        loop {
            let bytes = capture_reply(&capture).await;
            let parsed = packet::parse(&bytes).unwrap();
            if parsed.flow.transport == Transport::Udp {
                assert_eq!(parsed.payload, udp_nonce.as_bytes());
                break;
            }
        }
        if stage == 2 {
            let mut added = flow(Transport::Udp, 45988);
            added.destination = "10.0.2.3:18080".parse().unwrap();
            capture.send(&udp_packet(added, b"newroute")).await.unwrap();
            assert_eq!(
                packet::parse(&capture_reply(&capture).await)
                    .unwrap()
                    .payload,
                b"newroute",
                "new Error route did not deliver end-consumer nonce"
            );
        }
        assert_eq!(h.platform.starts.load(SeqCst), stage + 1);
    }
    bounded(tcp_task).await.unwrap();
    bounded(udp_task).await.unwrap();
    h.close().await;
}
