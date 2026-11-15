//! Independent loopback GotaTun peers, adapted from the archived crypto fixture.
//! The capture and remote consumers compare full raw bytes, never tunnel status.
use super::super::*;
use super::*;
use crate::connectivity::{CancelToken, Check};
use gotatun::{
    packet::{Ip, Packet, PacketBufPool},
    tun::{IpRecv, IpSend, MtuWatcher},
    x25519::StaticSecret,
};
use std::{io, time::Duration};
use talpid_net::bypass::NoopBypass;
use talpid_netstack::buffer_budget::BufferBudget;
use talpid_tunnel::packet_attachment::{AttachmentBroker, AttachmentMode, CaptureLease};
use talpid_types::{
    net::wireguard::{PrivateKey, TunnelConfig},
    relay_flow::{RelaySources, RelayWriteOutcome},
};
use tokio::sync::mpsc;

#[path = "translated_fixture.rs"]
mod translated_fixture;

fn config() -> Config {
    let private_key = PrivateKey::new_from_random();
    Config {
        entry_peer: PeerConfig {
            public_key: private_key.public_key(),
            allowed_ips: vec!["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()],
            endpoint: "127.0.0.1:9".parse().unwrap(),
            psk: None,
            constant_packet_size: false,
        },
        tunnel: TunnelConfig {
            private_key,
            addresses: vec![
                "10.12.34.56".parse().unwrap(),
                "fd00:1234::56".parse().unwrap(),
            ],
        },
        exit_peer: None,
        ipv4_gateway: "10.12.34.1".parse().unwrap(),
        ipv6_gateway: Some("fd00:1234::1".parse().unwrap()),
        mtu: 1420,
        #[cfg(target_os = "linux")]
        fwmark: None,
        #[cfg(target_os = "linux")]
        enable_ipv6: true,
        obfuscator_config: None,
        obfuscation_mtu: 1500,
        quantum_resistant: false,
        daita: false,
        routes: vec!["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()],
    }
}

fn tun_config(config: &Config) -> tun_provider::TunConfig {
    let mut tun = tun_provider::blocking_config();
    tun.addresses = config.tunnel.addresses.clone();
    tun.mtu = config.mtu;
    tun.ipv4_gateway = config.ipv4_gateway;
    tun.ipv6_gateway = config.ipv6_gateway;
    tun.routes = config.routes.clone();
    tun.dns_servers = Some(vec![config.ipv4_gateway.into()]);
    tun
}

#[tokio::test(start_paused = true)]
async fn managed_route_timeout_preserves_upstream_recoverable_start_cause() {
    use std::os::fd::{BorrowedFd, OwnedFd};
    use std::sync::atomic::{AtomicI64, Ordering::SeqCst};
    use talpid_lan_forwarder::{Disposition, Flow, Forwarder, LocalAuthority, Refused};
    use talpid_tunnel::{
        android_frontend::{
            CaptureConfig, CaptureFormat, CaptureHandover, FrontendOwner, FrontendPlatform,
        },
        tun_provider::ConfigurationError,
    };
    use talpid_types::capture_network::{
        CaptureExpectation, CaptureNetworkFeed, CaptureNetworkObservation, CapturePrefix,
    };
    struct NoLocal;
    impl LocalAuthority for NoLocal {
        type Grant = ();
        fn disposition(&self, _: std::net::IpAddr) -> Disposition {
            Disposition::Drop
        }
        fn authorize(&self, _: Flow) -> Result<(), Refused> {
            Err(Refused::Denied)
        }
        fn prepare(&self, _: &socket2::Socket, _: &()) -> Result<(), Refused> {
            panic!("Local not requested")
        }
        fn current(&self, _: &()) -> bool {
            false
        }
        fn physical_destination(&self, _: &(), _: Flow) -> std::net::SocketAddr {
            panic!("Local not requested")
        }
    }
    struct Routes {
        feed: Arc<CaptureNetworkFeed>,
        expected: Mutex<Option<CaptureExpectation>>,
        generation: AtomicI64,
        bound: tokio::sync::Notify,
        waiting: tokio::sync::Notify,
        post_bind: Mutex<Option<Arc<(Mutex<bool>, std::sync::Condvar)>>>,
        peers: Mutex<Vec<std::os::unix::net::UnixDatagram>>,
    }
    impl Routes {
        fn publish(&self, ready: bool) {
            self.report(ready, false);
        }
        fn report(&self, ready: bool, lost: bool) {
            let e = self.expected.lock().unwrap().clone().unwrap();
            let generation = self.generation.load(SeqCst);
            let changed = self.feed.publish(
                71,
                generation,
                CaptureNetworkObservation {
                    network_handle: 99,
                    network: "99".into(),
                    interface_name: e.interface_name,
                    owner_uid: e.owner_uid,
                    routes: if ready { e.routes } else { vec![] },
                    addresses: e.addresses,
                    dns_servers: e.dns_servers,
                    mtu: e.mtu,
                    fresh: !lost,
                    lost,
                    api_level: 33,
                },
            );
            assert_eq!(
                changed, ready,
                "an unchanged Pending report is accepted without publishing a change"
            );
        }
    }
    impl FrontendPlatform for Routes {
        fn open(&self, _: i64, _: &CaptureConfig) -> io::Result<tun_provider::AppliedTun> {
            let (fd, peer) = std::os::unix::net::UnixDatagram::pair()?;
            fd.set_nonblocking(true)?;
            self.peers.lock().unwrap().push(peer);
            Ok(OwnedFd::from(fd).into())
        }
        fn handover(&self, _: i64, _: i64, _: &CaptureConfig) -> CaptureHandover {
            panic!("new owner after timeout")
        }
        fn capture_format(&self, _: BorrowedFd<'_>) -> io::Result<CaptureFormat> {
            CaptureFormat::from_flags(0x1001)
        }
        fn interface_name(&self, _: BorrowedFd<'_>) -> io::Result<String> {
            Ok("tun-routes".into())
        }
        fn capture_feed(&self) -> Arc<CaptureNetworkFeed> {
            self.feed.clone()
        }
        fn expectation(
            &self,
            config: &CaptureConfig,
            name: String,
        ) -> io::Result<CaptureExpectation> {
            let c = config.secured_config().unwrap();
            let e = CaptureExpectation::requested(
                name,
                1000,
                33,
                &c.addresses,
                &c.routes
                    .iter()
                    .map(|r| CapturePrefix {
                        address: r.network(),
                        prefix_length: r.prefix().into(),
                    })
                    .collect::<Vec<_>>(),
                c.dns_servers.as_deref().unwrap(),
                c.mtu,
            )
            .unwrap();
            *self.expected.lock().unwrap() = Some(e.clone());
            Ok(e)
        }
        fn bind(&self, generation: i64, _: &str) -> io::Result<bool> {
            self.generation.store(generation, SeqCst);
            self.publish(false);
            let hold = self.post_bind.lock().unwrap().take();
            self.bound.notify_one();
            if let Some(hold) = hold {
                let mut released = hold.0.lock().unwrap();
                while !*released {
                    released = hold.1.wait(released).unwrap();
                }
            }
            Ok(true)
        }
        fn readiness_pending(&self, generation: i64) {
            assert_eq!(self.generation.load(SeqCst), generation);
            self.waiting.notify_one();
        }
        fn closed(&self, _: i64) -> io::Result<()> {
            Ok(())
        }
    }
    let platform = Arc::new(Routes {
        feed: CaptureNetworkFeed::new(71),
        expected: Mutex::new(None),
        generation: 0.into(),
        bound: tokio::sync::Notify::new(),
        waiting: tokio::sync::Notify::new(),
        post_bind: Mutex::new(None),
        peers: Mutex::new(vec![]),
    });
    let (broker, root, control) = broker();
    let config = config();
    for case in [
        "timeout",
        "recover",
        "lost-before-receipt",
        "lost-after-receipt",
    ] {
        let hold = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
        let release = ReleaseSetup(hold.clone());
        *platform.post_bind.lock().unwrap() = Some(hold);
        let target = tun_config(&config);
        let capture_config = tun_provider::transport::router_config(&target, vec![]);
        let request = broker
            .request_target_capture(target.clone(), capture_config.clone())
            .unwrap();
        let mut pending = PendingManaged::new(tun_provider::transport::ManagedTun {
            broker: broker.clone(),
            config: target,
            capture_config,
            request,
        });
        let capture = CaptureConfig::Secured {
            broker: broker.clone(),
            request: broker.pending_request().unwrap(),
            disposition: Arc::new(|_| {
                talpid_tunnel::android_frontend::CaptureDisposition::Drop(
                    talpid_tunnel::android_frontend::CaptureDropReason::NoTarget,
                )
            }),
        };
        let (_updates, updates) = tokio::sync::watch::channel(0);
        let mut owner = FrontendOwner::start(
            platform.clone(),
            capture,
            Forwarder::with_mtu(
                Arc::new(NoLocal),
                Arc::new(BufferBudget::new(30 * 1024 * 1024)),
                config.mtu.into(),
            )
            .unwrap(),
            updates,
            broker.clone(),
        )
        .unwrap();
        tokio::select! {
            biased;
            _ = platform.bound.notified() => {},
            result = owner.ready() => panic!("frontend terminated before bind: {result:?}"),
        }
        // Acquisition is deliberately still held after bind. This scheduling
        // delay must not consume any part of the actual route-readiness window.
        let (resume, held) = tokio::sync::oneshot::channel();
        if case == "lost-after-receipt" {
            pending.after_receipt = Some(held);
        } else {
            drop(held);
        }
        let mut create = Box::pin(pending.create(&config));
        assert!(futures::FutureExt::now_or_never(create.as_mut()).is_none());
        tokio::time::advance(Duration::from_secs(5)).await;
        assert!(futures::FutureExt::now_or_never(create.as_mut()).is_none());
        assert!(futures::FutureExt::now_or_never(owner.ready()).is_none());
        assert!(
            futures::FutureExt::now_or_never(platform.waiting.notified()).is_none(),
            "readiness timeout reported before acquisition joined"
        );
        drop(release);
        tokio::select! {
            biased;
            _ = platform.waiting.notified() => {},
            result = owner.ready() => panic!("frontend terminated before pending readiness poll: {result:?}"),
        }
        // The signal comes only after the actual timeout's first pending poll.
        let began = tokio::time::Instant::now();
        tokio::time::advance(Duration::from_millis(1999)).await;
        assert!(futures::FutureExt::now_or_never(create.as_mut()).is_none());
        assert!(futures::FutureExt::now_or_never(owner.ready()).is_none());
        if case != "timeout" {
            platform.publish(true);
            owner.ready().await.unwrap();
            if case.starts_with("lost-") {
                let revoke = || {
                    platform.report(true, true);
                    assert!(
                        !broker.snapshot().capture_ready,
                        "loss did not revoke synchronously"
                    );
                };
                let result = if case == "lost-after-receipt" {
                    // Owner.ready already published the exact current receipt.
                    // This poll consumes it and parks at the existing seam,
                    // before broker.acquire and all control/device allocation.
                    assert!(futures::FutureExt::now_or_never(create.as_mut()).is_none());
                    assert!(broker.snapshot().capture_ready);
                    assert!(broker.snapshot().attachment.is_none());
                    assert_eq!(control.used(), 0);
                    revoke();
                    resume.send(()).unwrap();
                    create.await
                } else {
                    revoke();
                    create.await
                };
                let error = match result {
                    Err(error) => error,
                    Ok(_) => panic!("lost fd acquired a transport"),
                };
                let TunnelError::RecoverableStartWireguardError(cause) =
                    managed_configuration_error(error)
                else {
                    panic!("capture loss lost recoverable start classification")
                };
                assert!(matches!(
                    cause.downcast_ref::<ConfigurationError>(),
                    Some(ConfigurationError::Attachment(
                        AttachmentError::CaptureUnready
                    ))
                ));
                assert!(broker.snapshot().attachment.is_none());
                assert!(!broker.snapshot().ordinary_ready);
                assert_eq!(control.used(), 0);
            } else {
                let pair = create.await.unwrap();
                pair.owner.stop().await;
                drop(pair);
            }
        } else {
            tokio::time::advance(Duration::from_millis(1)).await;
            let error = match create.await {
                Err(error) => error,
                Ok(_) => panic!("missing routes acquired a device"),
            };
            assert!(matches!(
                error
                    .get_ref()
                    .and_then(|e| e.downcast_ref::<ConfigurationError>()),
                Some(ConfigurationError::RoutesTimedOut)
            ));
            let TunnelError::RecoverableStartWireguardError(cause) =
                managed_configuration_error(error)
            else {
                panic!("route timeout lost recoverable classification")
            };
            assert!(matches!(
                cause.downcast_ref::<ConfigurationError>(),
                Some(ConfigurationError::RoutesTimedOut)
            ));
            assert!(owner.ready().await.is_err());
            assert_eq!(began.elapsed(), Duration::from_secs(2));
        }
        owner.stop().await.unwrap();
        drop(pending);
        assert_eq!(control.used(), 0);
    }
    let dns = vec!["1.1.1.1".parse().unwrap()];
    for cause in [
        ConfigurationError::InvalidDnsServers(dns.clone()),
        ConfigurationError::NotPrepared,
        ConfigurationError::OtherLegacyAlwaysOnVpn,
        ConfigurationError::OtherAlwaysOnApp {
            app_name: "other.vpn".into(),
        },
    ] {
        let expected = cause.to_string();
        let TunnelError::ManagedConfiguration(actual) =
            managed_configuration_error(io::Error::other(cause))
        else {
            panic!("known cause erased")
        };
        assert_eq!(actual.to_string(), expected);
    }
    let TunnelError::ManagedConfiguration(ConfigurationError::InvalidDnsServers(actual)) =
        managed_configuration_error(io::Error::other(ConfigurationError::InvalidDnsServers(
            dns.clone(),
        )))
    else {
        panic!("TSM lost actionable DNS cause")
    };
    assert_eq!(actual, dns);
    for attachment in [
        AttachmentError::Disabled,
        AttachmentError::CaptureUnready,
        AttachmentError::OrdinaryUnready,
        AttachmentError::Stale,
        AttachmentError::Full,
        AttachmentError::Closed,
        AttachmentError::Busy,
        AttachmentError::Invalid,
    ] {
        assert!(
            matches!(ConfigurationError::from(io::Error::other(attachment)), ConfigurationError::Attachment(actual) if actual == attachment)
        );
        assert!(
            matches!(ConfigurationError::from(io::Error::other(ConfigurationError::from(attachment))), ConfigurationError::Attachment(actual) if actual == attachment)
        );
    }
    drop((broker, control));
    assert_eq!(
        root.used(),
        0,
        "configuration/acquisition failure retained a region owner"
    );
}

fn fixed_config(config: &Config) -> tun_provider::TunConfig {
    let mut tun = tun_config(config);
    tun.addresses = vec![
        "172.27.1.1".parse().unwrap(),
        "fdf0:ce4a:801d::172:27:1:1".parse().unwrap(),
    ];
    tun.mtu = 1280;
    tun
}

#[tokio::test]
async fn assigned_target_configuration_is_not_the_capture_projection() {
    let (broker, _root, control) = broker();
    let config = config();
    let capture_config = fixed_config(&config);
    let request = broker
        .request_target_capture(tun_config(&config), capture_config.clone())
        .unwrap();
    let mut pending = PendingManaged::new(talpid_tunnel::tun_provider::transport::ManagedTun {
        broker: broker.clone(),
        config: tun_config(&config),
        capture_config: capture_config.clone(),
        request,
    });
    let request = broker.pending_request().unwrap();
    assert_eq!(request.target_config(), &tun_config(&config));
    assert_eq!(request.config(), &capture_config);
    let capture = broker.open_capture(Some(&request)).unwrap();
    let receipt = capture
        .bind_observed_identity(
            "tun17",
            99,
            RelaySources {
                ipv4: Some("172.27.1.1".parse().unwrap()),
                ipv6: Some("fdf0:ce4a:801d::172:27:1:1".parse().unwrap()),
            },
            1280,
        )
        .unwrap();
    broker.acknowledge(&request, &receipt).unwrap();
    let pair = pending
        .create(&config)
        .await
        .expect("assigned target rejected fixed capture");
    assert_eq!(
        pair.owner.control.capability().sources().ipv4,
        config.tunnel_ipv4()
    );
    assert_eq!(pair.owner.control.capability().mtu(), config.mtu);
    assert_eq!(
        pair.owner
            .control
            .capability()
            .sink()
            .unwrap()
            .identity()
            .mtu,
        1280
    );
    pair.owner.stop().await;
    drop(pair);
    assert_eq!(control.used(), 0);
}

fn broker() -> (AttachmentBroker, BufferBudget, BufferBudget) {
    let root = BufferBudget::new(64 * 1024 * 1024);
    let application = root.reserve(22 * 1024 * 1024).unwrap().region().unwrap();
    let control = root.reserve(8 * 1024 * 1024).unwrap().region().unwrap();
    let capture = root.reserve(2 * 1024 * 1024).unwrap().region().unwrap();
    let broker = AttachmentBroker::new(
        Arc::new(application),
        Arc::new(capture),
        Arc::new(control.clone()),
    )
    .unwrap();
    broker.set_mode(AttachmentMode::ManagedRequired).unwrap();
    (broker, root, control)
}

fn acknowledge(broker: &AttachmentBroker, config: &Config) -> CaptureLease {
    let request = broker.pending_request().unwrap();
    let capture = broker.open_capture(Some(&request)).unwrap();
    let receipt = capture
        .bind_observed_identity(
            "tun17",
            0xf123_4567_0000_0063,
            RelaySources {
                ipv4: config.tunnel_ipv4(),
                ipv6: config.tunnel_ipv6(),
            },
            config.mtu,
        )
        .unwrap();
    broker.acknowledge(&request, &receipt).unwrap();
    capture
}

fn echo_reply(request: &[u8]) -> Vec<u8> {
    let mut reply = request.to_vec();
    reply[12..16].copy_from_slice(&request[16..20]);
    reply[16..20].copy_from_slice(&request[12..16]);
    reply[20] = 0;
    reply[22..24].fill(0);
    let checksum = internet_checksum::checksum(&reply[20..]);
    reply[22..24].copy_from_slice(&checksum);
    reply[10..12].fill(0);
    let checksum = internet_checksum::checksum(&reply[..20]);
    reply[10..12].copy_from_slice(&checksum);
    reply
}

struct RemoteSend {
    output: mpsc::Sender<Packet<Ip>>,
    observed: mpsc::Sender<Vec<u8>>,
    gateway: Ipv4Addr,
    reply_errors: bool,
}
struct RemoteReceive(mpsc::Receiver<Packet<Ip>>);
impl IpSend for RemoteSend {
    async fn send(&mut self, packet: Packet<Ip>) -> io::Result<()> {
        let bytes = packet.into_bytes();
        let private = bytes.len() == 70
            && bytes[0] == 0x45
            && bytes[9] == 1
            && bytes[16..20] == self.gateway.octets()
            && bytes[20] == 8;
        let returned = if private {
            echo_reply(&bytes)
        } else {
            self.observed
                .try_send(bytes.to_vec())
                .map_err(|_| io::ErrorKind::WouldBlock)?;
            if (bytes[0] >> 4 == 4 && u16::from_be_bytes([bytes[6], bytes[7]]) & 0x3fff != 0)
                || (bytes[0] >> 4 == 6 && bytes[6] == 44)
            {
                return Ok(()); // The independent fragment consumer owns reassembly.
            }
            if !self.reply_errors
                && ((bytes[0] >> 4 == 4 && bytes[9] == 1 && bytes[20] == 3)
                    || (bytes[0] >> 4 == 6 && bytes[6] == 58 && bytes[40] < 128))
            {
                return Ok(());
            }
            application_reply(&bytes)
        };
        self.output
            .try_send(Packet::<[u8]>::copy_from(&returned).try_into_ip().unwrap())
            .map_err(|_| io::ErrorKind::WouldBlock.into())
    }
}
impl IpRecv for RemoteReceive {
    async fn recv<'a>(
        &'a mut self,
        _: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + Send + 'a> {
        Ok(std::iter::once(
            self.0.recv().await.ok_or(io::ErrorKind::BrokenPipe)?,
        ))
    }
    fn mtu(&self) -> MtuWatcher {
        MtuWatcher::new(1420)
    }
}

enum Remote {
    Single(
        Device<(
            gotatun::udp::socket::UdpSocketFactory,
            RemoteSend,
            RemoteReceive,
        )>,
    ),
    Multi {
        exit: Device<(UdpChannelFactory, RemoteSend, RemoteReceive)>,
        entry: Device<(
            gotatun::udp::socket::UdpSocketFactory,
            TunChannelTx,
            TunChannelRx,
        )>,
    },
}
impl Remote {
    async fn stop(self) {
        match self {
            Self::Single(device) => device.stop().await,
            Self::Multi { exit, entry } => {
                exit.stop().await;
                entry.stop().await;
            }
        }
    }
}

async fn remote(config: &mut Config, multihop: bool) -> (Remote, mpsc::Receiver<Vec<u8>>) {
    let (remote, observations, _) = remote_impl(config, multihop, true).await;
    (remote, observations)
}

async fn remote_controlled(
    config: &mut Config,
    multihop: bool,
) -> (Remote, mpsc::Receiver<Vec<u8>>, mpsc::Sender<Packet<Ip>>) {
    remote_impl(config, multihop, false).await
}
async fn remote_impl(
    config: &mut Config,
    multihop: bool,
    reply_errors: bool,
) -> (Remote, mpsc::Receiver<Vec<u8>>, mpsc::Sender<Packet<Ip>>) {
    let key = PrivateKey::new_from_random();
    config.entry_peer.public_key = key.public_key();
    let reservation = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = reservation.local_addr().unwrap().port();
    drop(reservation);
    config.entry_peer.endpoint = (Ipv4Addr::LOCALHOST, port).into();
    let (output, input) = mpsc::channel(512);
    let (observed, observations) = mpsc::channel(512);
    let send = RemoteSend {
        output: output.clone(),
        observed,
        gateway: config.ipv4_gateway,
        reply_errors,
    };
    let receive = RemoteReceive(input);
    let peer = PeerConfig {
        public_key: config.tunnel.private_key.public_key(),
        allowed_ips: vec!["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()],
        endpoint: "127.0.0.1:9".parse().unwrap(),
        psk: None,
        constant_packet_size: false,
    };
    let remote = if multihop {
        let exit_key = PrivateKey::new_from_random();
        let exit_address: Ipv4Addr = "10.12.34.2".parse().unwrap();
        config.entry_peer.allowed_ips = vec!["10.12.34.2/32".parse().unwrap()];
        config.exit_peer = Some(PeerConfig {
            public_key: exit_key.public_key(),
            allowed_ips: vec!["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()],
            endpoint: (exit_address, 51820).into(),
            psk: None,
            constant_packet_size: false,
        });
        let (entry_send, entry_receive, exit_transport) = new_udp_tun_channel(
            32,
            exit_address,
            Ipv6Addr::UNSPECIFIED,
            MtuWatcher::new(1500),
        );
        let exit = DeviceBuilder::new()
            .with_udp(exit_transport)
            .with_listen_port(51820)
            .with_private_key(StaticSecret::from(exit_key.to_bytes()))
            .with_peer(to_gotatun_peer(&peer, None))
            .with_ip_pair(send, receive)
            .build()
            .await
            .unwrap();
        let entry = DeviceBuilder::new()
            .with_default_udp()
            .with_listen_port(port)
            .with_private_key(StaticSecret::from(key.to_bytes()))
            .with_peer(to_gotatun_peer(&peer, None))
            .with_ip_pair(entry_send, entry_receive)
            .build()
            .await
            .unwrap();
        Remote::Multi { exit, entry }
    } else {
        Remote::Single(
            DeviceBuilder::new()
                .with_default_udp()
                .with_listen_port(port)
                .with_private_key(StaticSecret::from(key.to_bytes()))
                .with_peer(to_gotatun_peer(&peer, None))
                .with_ip_pair(send, receive)
                .build()
                .await
                .unwrap(),
        )
    };
    (remote, observations, output)
}

fn ipv4(protocol: u8, nonce: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; 40 + nonce.len()];
    bytes[0] = 0x45;
    let length = bytes.len() as u16;
    bytes[2..4].copy_from_slice(&length.to_be_bytes());
    bytes[8] = 64;
    bytes[9] = protocol;
    bytes[12..16].copy_from_slice(&[10, 12, 34, 56]);
    bytes[16..20].copy_from_slice(&[203, 0, 113, 20]);
    bytes[20..22].copy_from_slice(&43000u16.to_be_bytes());
    bytes[22..24].copy_from_slice(&53u16.to_be_bytes());
    bytes[32] = 0x50;
    bytes[40..].copy_from_slice(nonce);
    if protocol == 17 {
        let length = (bytes.len() - 20) as u16;
        bytes[24..26].copy_from_slice(&length.to_be_bytes());
    } else if protocol == 1 {
        bytes[20] = 8;
        bytes[21] = 0;
    }
    fix_wire(&mut bytes, 20, protocol);
    bytes
}

// Independent full-wire oracle, separate from production RFC1624 adjustments.
fn wire_sum(bytes: &[u8], offset: usize, protocol: u8) -> [u8; 2] {
    let mut input = Vec::new();
    if bytes[0] >> 4 == 4 {
        if protocol != 1 {
            input.extend_from_slice(&bytes[12..20]);
            input.extend_from_slice(&[0, protocol]);
            input.extend_from_slice(&((bytes.len() - offset) as u16).to_be_bytes());
        }
    } else {
        input.extend_from_slice(&bytes[8..40]);
        input.extend_from_slice(&((bytes.len() - offset) as u32).to_be_bytes());
        input.extend_from_slice(&[0, 0, 0, protocol]);
    }
    input.extend_from_slice(&bytes[offset..]);
    internet_checksum::checksum(&input)
}

fn fix_wire(bytes: &mut [u8], offset: usize, protocol: u8) {
    if let Some(field) = match protocol {
        6 => Some(16),
        17 => Some(6),
        1 | 58 => Some(2),
        _ => None,
    } {
        bytes[offset + field..offset + field + 2].fill(0);
        let sum = wire_sum(bytes, offset, protocol);
        bytes[offset + field..offset + field + 2].copy_from_slice(&if protocol == 17
            && sum == [0, 0]
        {
            [255, 255]
        } else {
            sum
        });
    }
    if bytes[0] >> 4 == 4 {
        bytes[10..12].fill(0);
        let sum = internet_checksum::checksum(&bytes[..usize::from(bytes[0] & 15) * 4]);
        bytes[10..12].copy_from_slice(&sum);
    }
}

fn application_reply(bytes: &[u8]) -> Vec<u8> {
    let mut reply = bytes.to_vec();
    let v4 = bytes[0] >> 4 == 4;
    let (start, width) = if v4 { (12, 4) } else { (8, 16) };
    reply[start..start + width].copy_from_slice(&bytes[start + width..start + 2 * width]);
    reply[start + width..start + 2 * width].copy_from_slice(&bytes[start..start + width]);
    let offset = if v4 {
        usize::from(bytes[0] & 15) * 4
    } else if bytes[6] == 0 {
        48
    } else {
        40
    };
    let protocol = if v4 {
        bytes[9]
    } else if bytes[6] == 0 {
        bytes[40]
    } else {
        bytes[6]
    };
    if protocol == 6 || protocol == 17 {
        reply[offset..offset + 2].copy_from_slice(&bytes[offset + 2..offset + 4]);
        reply[offset + 2..offset + 4].copy_from_slice(&bytes[offset..offset + 2]);
    } else if protocol == 1 && bytes[offset] == 8 {
        reply[offset] = 0;
    } else if protocol == 58 && bytes[offset] == 128 {
        reply[offset] = 129;
    } else if protocol == 1 && bytes[offset] == 3 {
        // A peer error quotes the opposite direction. Swapping both endpoints
        // preserves the quoted IP/pseudoheader checksum even when truncated.
        let quote = offset + 8;
        reply[quote + 12..quote + 16].copy_from_slice(&bytes[quote + 16..quote + 20]);
        reply[quote + 16..quote + 20].copy_from_slice(&bytes[quote + 12..quote + 16]);
    }
    fix_wire(&mut reply, offset, protocol);
    reply
}

async fn establish_and_observe(
    check: &mut Check,
    client: &GotaTun,
    owner: &ManagedControl,
    final_setup: impl std::future::Future<Output = Result<(), crate::CloseMsg>>,
) -> Result<(), crate::CloseMsg> {
    use futures::StreamExt;
    let (send, mut events) = futures::channel::mpsc::unbounded();
    let hook = talpid_tunnel::EventHook::new(send);
    let event = talpid_tunnel::TunnelEvent::Up {
        metadata: crate::tunnel_metadata(client.get_interface_name(), &config()),
        selected_obfuscation: None,
    };
    let result = crate::establish_and_activate(check, client, Some(owner), final_setup, |()| {
        hook.enqueue(event.clone())
    })
    .await;
    match result {
        Ok(Some(acknowledged)) => {
            let (received, acknowledgement) = events.next().await.unwrap();
            assert_eq!(received, event);
            // Reading current authority here also proves publication released
            // its guards before the asynchronous consumer acknowledgement.
            assert!(owner.control.current());
            acknowledgement.send(()).unwrap();
            acknowledged.await.unwrap();
            Ok(())
        }
        Ok(None) => panic!("live event consumer was not queued"),
        Err(error) => {
            assert!(events.try_recv().is_err(), "failed setup queued Up");
            Err(error)
        }
    }
}

#[tokio::test]
async fn singlehop_raw_ip_reaches_independent_crypto_and_capture_consumers() {
    crypto(false).await;
}
#[tokio::test]
async fn multihop_exit_raw_ip_reaches_independent_crypto_and_capture_consumers() {
    crypto(true).await;
}

async fn crypto(multihop: bool) {
    let (broker, _root, control) = broker();
    let mut config = config();
    let (remote, mut observed) = remote(&mut config, multihop).await;
    let source = PendingManaged::request(broker.clone(), tun_config(&config)).unwrap();
    let capture = acknowledge(&broker, &config);
    let mut client = GotaTun::new(
        PlaintextSource::Managed(source),
        Arc::new(NoopBypass),
        None,
        &config,
        None,
        String::new(),
    )
    .await
    .unwrap();
    assert_eq!(client.get_interface_name(), "tun17");
    let owner = client.managed().unwrap();
    let (cancel, receiver) = CancelToken::new();
    let mut check = Check::new_with_smoltcp(owner.pinger().unwrap(), 0, receiver);
    assert!(!broker.snapshot().ordinary_ready);
    assert!(capture.try_send(&ipv4(17, b"early-must-drop")).is_err());
    tokio::time::timeout(
        Duration::from_secs(5),
        establish_and_observe(&mut check, &client, &owner, async { Ok(()) }),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(broker.snapshot().ordinary_ready);
    assert!(
        tokio::time::timeout(Duration::from_millis(20), capture.reply())
            .await
            .is_err(),
        "private reply leaked"
    );
    let mut vectors = vec![
        ipv4(6, b"tcp-nonce"),
        ipv4(17, b"dns-udp-nonce"),
        ipv4(1, b"public-icmp-nonce"),
        ipv4(47, b"address-independent-gre"),
    ];
    let mut configured_dns = ipv4(17, b"actual-configured-dns-tuple");
    configured_dns[16..20].copy_from_slice(&config.ipv4_gateway.octets());
    let udp_length = (configured_dns.len() - 20) as u16;
    configured_dns[24..26].copy_from_slice(&udp_length.to_be_bytes());
    configured_dns[10..12].fill(0);
    fix_wire(&mut configured_dns, 20, 17);
    assert_eq!(
        tun_config(&config).dns_servers,
        Some(vec![config.ipv4_gateway.into()])
    );
    vectors.push(configured_dns);
    let quoted = application_reply(&ipv4(17, b"truncated-quotation-nonce"));
    let mut quotation = ipv4(1, b"");
    quotation.truncate(28);
    quotation[20] = 3;
    quotation.extend_from_slice(&quoted[..28]);
    let size = quotation.len() as u16;
    quotation[2..4].copy_from_slice(&size.to_be_bytes());
    fix_wire(&mut quotation, 20, 1);
    vectors.push(quotation);
    let mut v6 = vec![0; 64];
    v6[0] = 0x60;
    v6[4..6].copy_from_slice(&24u16.to_be_bytes());
    v6[6] = 0; // native-accepted hop-by-hop extension
    v6[7] = 64;
    v6[8..24].copy_from_slice(&config.tunnel_ipv6().unwrap().octets());
    v6[24..40].copy_from_slice(&"2001:db8:240::20".parse::<Ipv6Addr>().unwrap().octets());
    v6[40] = 47;
    v6[48..64].copy_from_slice(b"ipv6-extension!!");
    vectors.push(v6);
    vectors.push(ipv4(17, &vec![0x95; 1350]));
    for bytes in vectors {
        capture.try_send(&bytes).unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), observed.recv())
                .await
                .unwrap()
                .unwrap(),
            bytes
        );
        let mut reply = tokio::time::timeout(Duration::from_secs(2), capture.reply())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            reply.write(|received| {
                assert_eq!(received, application_reply(&bytes));
                Ok(received.len())
            }),
            RelayWriteOutcome::Written
        ));
    }
    // Fill ordinary return storage while its capture consumer is blocked. The
    // private pinger still reaches its authenticated return consumer under load.
    for sequence in 0..talpid_tunnel::packet_attachment::PACKET_CAPACITY {
        capture
            .try_send(&ipv4(17, &sequence.to_be_bytes()))
            .unwrap();
    }
    for _ in 0..talpid_tunnel::packet_attachment::PACKET_CAPACITY {
        tokio::time::timeout(Duration::from_secs(2), observed.recv())
            .await
            .unwrap()
            .unwrap();
    }
    let prior = owner.ledger.lock().unwrap().highest;
    assert!(check.establish_connectivity(&client).await.unwrap());
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            {
                let ledger = owner.ledger.lock().unwrap();
                if ledger.highest > prior && ledger.live.is_empty() {
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .expect("ordinary backpressure starved private authenticated replies");
    // The same real readiness function refuses a cancelled already-successful
    // Check, and receipt loss revokes ordinary traffic synchronously.
    cancel.close();
    assert!(
        establish_and_observe(&mut check, &client, &owner, async { Ok(()) })
            .await
            .is_err()
    );
    capture.retire();
    assert!(!broker.snapshot().ordinary_ready);
    assert!(capture.try_send(&ipv4(17, b"retired")).is_err());
    tokio::time::timeout(Duration::from_secs(2), client.shutdown())
        .await
        .unwrap();
    drop((check, owner, client));
    assert_eq!(control.used(), 0);
    tokio::time::timeout(Duration::from_secs(2), remote.stop())
        .await
        .unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn installed_managed_target_crosses_fd_epochs_without_reusing_the_old_receipt() {
    for retire_session in [false, true] {
        let (broker, _root, control) = broker();
        let mut config = config();
        let (remote, mut observed) = remote(&mut config, false).await;
        let source = PendingManaged::request(broker.clone(), tun_config(&config)).unwrap();
        let capture = acknowledge(&broker, &config);
        let mut client = GotaTun::new(
            PlaintextSource::Managed(source),
            Arc::new(NoopBypass),
            None,
            &config,
            None,
            String::new(),
        )
        .await
        .unwrap();
        let owner = client.managed().unwrap();
        let (_cancel, receiver) = CancelToken::new();
        let mut check = Check::new_with_smoltcp(owner.pinger().unwrap(), 0, receiver);
        tokio::time::timeout(
            Duration::from_secs(5),
            establish_and_observe(&mut check, &client, &owner, async { Ok(()) }),
        )
        .await
        .unwrap()
        .unwrap();
        let receipt = owner.receipt.clone();
        let predecessor_lost = capture.revoker();
        let target = broker.snapshot().attachment;
        let session = broker.snapshot().session_generation;
        let old_sink = owner.control.capability().sink().unwrap();
        let mut successor = None;
        let mut change = None;
        for stage in 0..2 {
            if stage == 1 {
                let mut config = tun_config(&config);
                config.dns_servers = Some(vec!["10.12.34.2".parse().unwrap()]);
                config
                    .excluded_packages
                    .push("unrelated.excluded.app".into());
                successor = Some(broker.request_capture(config).unwrap());
                let pending = broker.pending_request().unwrap();
                let capability = owner.control.capability();
                let sink = capability.sink().unwrap();
                let handover = capture
                    .begin_handover(Some(&pending), sink.identity().sources, sink.identity().mtu)
                    .unwrap();
                assert!(!receipt.current());
                let next = handover
                    .bind_identity(
                        "tun18",
                        Some(0xf123_4567_0000_0064),
                        sink.identity().sources,
                        sink.identity().mtu,
                    )
                    .unwrap();
                broker.acknowledge(&pending, &next).unwrap();
                successor.as_mut().unwrap().configured().await.unwrap();
                assert!(
                    !receipt.current(),
                    "handover resurrected the predecessor receipt"
                );
                predecessor_lost();
                assert_eq!(broker.snapshot().attachment, target);
                assert_eq!(broker.snapshot().session_generation, session);
                assert_eq!(owner.interface(), "tun18");
                change = Some(handover);
            }
            let bytes = ipv4(
                17,
                if stage == 0 {
                    b"before-epoch"
                } else {
                    b"after-epoch"
                },
            );
            capture.try_send(&bytes).unwrap();
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(2), observed.recv())
                    .await
                    .expect("installed Managed receive lost its target at fd handover")
                    .unwrap(),
                bytes
            );
            let mut reply = tokio::time::timeout(Duration::from_secs(2), capture.reply())
                .await
                .expect("installed Managed send lost its target at fd handover")
                .unwrap();
            if stage == 1 {
                assert!(matches!(
                    reply.write_to(&old_sink, |_| panic!("reply entered predecessor fd")),
                    RelayWriteOutcome::Retry
                ));
            }
            let sink = owner.control.capability().sink().unwrap();
            let (fd, consumer) = std::os::unix::net::UnixDatagram::pair().unwrap();
            consumer
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            assert!(matches!(
                reply.write_to(&sink, |packet| fd.send(packet)),
                RelayWriteOutcome::Written
            ));
            let mut received = vec![0; bytes.len()];
            assert_eq!(consumer.recv(&mut received).unwrap(), bytes.len());
            assert_eq!(received, application_reply(&bytes));
            let prior = owner.ledger.lock().unwrap().highest;
            assert!(check.establish_connectivity(&client).await.unwrap());
            tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    {
                        let ledger = owner.ledger.lock().unwrap();
                        if ledger.highest > prior && ledger.live.is_empty() {
                            break;
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
            })
            .await
            .expect("private authenticated control did not cross the same target");
            owner.activate().unwrap();
        }
        if retire_session {
            change.as_ref().unwrap().revoker()();
        } else {
            owner.revoke();
        }
        assert!(!owner.live());
        assert!(owner.activate().is_err());
        assert!(
            owner
                .publish(|| panic!("retired target published Up"))
                .is_err()
        );
        tokio::time::timeout(Duration::from_secs(1), owner.cancelled())
            .await
            .unwrap();
        assert!(capture.try_send(&ipv4(17, b"retired-target")).is_err());
        assert!(
            tokio::time::timeout(Duration::from_millis(30), observed.recv())
                .await
                .is_err()
        );
        assert!(
            establish_and_observe(&mut check, &client, &owner, async { Ok(()) })
                .await
                .is_err()
        );
        client.shutdown().await;
        let finished = change.as_mut().unwrap().finish();
        if retire_session {
            assert_eq!(
                finished,
                Err(talpid_tunnel::packet_attachment::AttachmentError::Stale)
            );
        } else {
            finished.unwrap();
        }
        if let Some(successor) = &successor {
            successor.transport_joined();
        }
        capture.retire();
        drop((check, owner, client, successor, change, old_sink));
        assert_eq!(control.used(), 0);
        remote.stop().await;
    }
}

#[tokio::test]
async fn initial_activation_keeps_exact_epoch_and_retired_adapter_halves_refuse_consumers() {
    for retire_session in [false, true] {
        let (broker, _root, control) = broker();
        let config = config();
        let mut pending = PendingManaged::request(broker.clone(), tun_config(&config)).unwrap();
        let capture = acknowledge(&broker, &config);
        let mut pair = pending.create(&config).await.unwrap();
        pair.owner.installed();
        let successor = broker.request_capture(tun_config(&config)).unwrap();
        let request = broker.pending_request().unwrap();
        let mut change = capture
            .begin_handover(
                Some(&request),
                pair.owner.control.capability().identity().sources,
                config.mtu,
            )
            .unwrap();
        assert!(
            pair.owner.activate().is_err(),
            "unbound successor activated an initial target"
        );
        let receipt = change
            .bind_identity(
                "tun18",
                Some(0xf123_4567_0000_0064),
                pair.owner.control.capability().identity().sources,
                config.mtu,
            )
            .unwrap();
        broker.acknowledge(&request, &receipt).unwrap();
        assert!(!pair.owner.receipt.current());
        assert!(
            pair.owner.activate().is_err(),
            "stale initial receipt activated through a different fd epoch"
        );
        assert!(!broker.snapshot().ordinary_ready);
        if retire_session {
            capture.retire();
        } else {
            pair.owner.revoke();
        }
        let mut pool = PacketBufPool::new(1);
        assert!(pair.receive.recv(&mut pool).await.is_err());
        assert!(
            pair.send
                .send(
                    Packet::<[u8]>::copy_from(&ipv4(17, b"retired-return"))
                        .try_into_ip()
                        .unwrap()
                )
                .await
                .is_err()
        );
        pair.owner.stop().await;
        let finished = change.finish();
        if retire_session {
            assert_eq!(
                finished,
                Err(talpid_tunnel::packet_attachment::AttachmentError::Stale)
            );
        } else {
            finished.unwrap();
        }
        successor.transport_joined();
        capture.retire();
        drop((pair, pending, successor, change));
        assert_eq!(control.used(), 0);
    }
}

#[tokio::test]
async fn real_request_without_matching_receipt_never_creates_application_source() {
    let (broker, _root, control) = broker();
    let config = config();
    let mut pending = PendingManaged::request(broker.clone(), tun_config(&config)).unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(30), pending.create(&config))
            .await
            .is_err()
    );
    assert!(!broker.snapshot().ordinary_ready);
    assert_eq!(control.used(), 0);
    let capture = acknowledge(&broker, &config);
    capture.retire();
    assert!(pending.create(&config).await.is_err());
    assert_eq!(control.used(), 0);
}

#[tokio::test]
async fn private_matching_rejects_replay_and_does_not_claim_application_icmp() {
    let (broker, _root, control) = broker();
    let config = config();
    let mut pending = PendingManaged::request(broker.clone(), tun_config(&config)).unwrap();
    let _capture = acknowledge(&broker, &config);
    let mut pair = pending.create(&config).await.unwrap();
    let mut pinger = pair.owner.pinger().unwrap();
    use crate::connectivity::Pinger;
    pinger.send_icmp().await.unwrap();
    let mut pool = PacketBufPool::new(1);
    let request = pair
        .receive
        .recv(&mut pool)
        .await
        .unwrap()
        .next()
        .unwrap()
        .into_bytes();
    let good = echo_reply(&request);
    let mut bad = good.clone();
    bad[69] ^= 1;
    // A malformed checksum cannot satisfy the private consumer.
    pair.send
        .send(Packet::<[u8]>::copy_from(&bad).try_into_ip().unwrap())
        .await
        .unwrap();
    assert_eq!(pair.owner.ledger.lock().unwrap().live.len(), 1);
    pair.send
        .send(Packet::<[u8]>::copy_from(&good).try_into_ip().unwrap())
        .await
        .unwrap();
    assert_eq!(pair.owner.ledger.lock().unwrap().live.len(), 0);
    assert!(matches!(pair.owner.reply(&good), Reply::Discard));
    // A guessed tuple with a different, valid-checksummed payload is raw IP.
    let mut application = good.clone();
    application[28] ^= 1;
    application[22..24].fill(0);
    let checksum = internet_checksum::checksum(&application[20..]);
    application[22..24].copy_from_slice(&checksum);
    assert!(matches!(pair.owner.reply(&application), Reply::Application));
    pinger.send_icmp().await.unwrap();
    let request = pair
        .receive
        .recv(&mut pool)
        .await
        .unwrap()
        .next()
        .unwrap()
        .into_bytes();
    pair.owner.ledger.lock().unwrap().live[0].1 = Instant::now() - REQUEST_LIFETIME;
    assert!(matches!(
        pair.owner.reply(&echo_reply(&request)),
        Reply::Discard
    ));
    pair.send
        .send(Packet::<[u8]>::copy_from(&good).try_into_ip().unwrap())
        .await
        .unwrap();
    assert_eq!(pair.owner.ledger.lock().unwrap().live.len(), 0);
    assert!(!broker.snapshot().ordinary_ready);
    // Before device installation, even valid peer statistics cannot activate.
    assert!(pair.owner.activate().is_err());
    pair.owner.stop().await;
    assert!(pair.receive.recv(&mut pool).await.is_err());
    drop((pair, pinger, pending));
    assert_eq!(control.used(), 0);
}

#[tokio::test]
async fn readiness_refuses_unauthenticated_peer_even_with_installed_source_and_receipt() {
    let (broker, _root, control) = broker();
    let config = config(); // port 9 has no fixture peer/key
    let source = PendingManaged::request(broker.clone(), tun_config(&config)).unwrap();
    let capture = acknowledge(&broker, &config);
    let mut client = GotaTun::new(
        PlaintextSource::Managed(source),
        Arc::new(NoopBypass),
        None,
        &config,
        None,
        String::new(),
    )
    .await
    .unwrap();
    let owner = client.managed().unwrap();
    let (_cancel, receiver) = CancelToken::new();
    let mut check = Check::new_with_smoltcp(owner.pinger().unwrap(), 0, receiver);
    let outcome = tokio::time::timeout(
        Duration::from_secs(6),
        establish_and_observe(&mut check, &client, &owner, async { Ok(()) }),
    )
    .await
    .unwrap();
    assert!(outcome.is_err());
    assert!(!broker.snapshot().ordinary_ready);
    assert!(capture.try_send(&ipv4(17, b"no-auth-no-output")).is_err());
    client.shutdown().await;
    drop((check, owner, client));
    assert_eq!(control.used(), 0);
}

#[tokio::test]
async fn receipt_loss_and_cancel_after_authenticated_check_refuse_activation() {
    for lose_receipt in [false, true] {
        let (broker, _root, control) = broker();
        let mut config = config();
        let (remote, _observed) = remote(&mut config, false).await;
        let source = PendingManaged::request(broker.clone(), tun_config(&config)).unwrap();
        let capture = acknowledge(&broker, &config);
        let mut client = GotaTun::new(
            PlaintextSource::Managed(source),
            Arc::new(NoopBypass),
            None,
            &config,
            None,
            String::new(),
        )
        .await
        .unwrap();
        let owner = client.managed().unwrap();
        let (cancel, receiver) = CancelToken::new();
        let mut check = Check::new_with_smoltcp(owner.pinger().unwrap(), 0, receiver);
        let (passed, reached) = tokio::sync::oneshot::channel();
        {
            let setup = establish_and_observe(&mut check, &client, &owner, async {
                passed.send(()).unwrap();
                std::future::pending::<Result<(), crate::CloseMsg>>().await
            });
            tokio::pin!(setup);
            tokio::select! {
                _ = reached => {},
                result = &mut setup => panic!("setup ended before final barrier: {result:?}"),
                _ = tokio::time::sleep(Duration::from_secs(5)) => panic!("real authenticated Check did not complete"),
            }
            assert!(!broker.snapshot().ordinary_ready);
            if lose_receipt {
                capture.retire();
            } else {
                cancel.close();
            }
            assert!(
                tokio::time::timeout(Duration::from_secs(1), setup)
                    .await
                    .unwrap()
                    .is_err()
            );
        }
        assert!(!broker.snapshot().ordinary_ready);
        assert!(capture.try_send(&ipv4(17, b"lost-factor")).is_err());
        client.shutdown().await;
        drop((check, owner, client));
        assert_eq!(control.used(), 0);
        remote.stop().await;
    }
}

#[tokio::test]
async fn up_enqueue_is_checked_against_retirement_after_activation() {
    let (broker, _root, control) = broker();
    let mut config = config();
    let (remote, _observed) = remote(&mut config, false).await;
    let source = PendingManaged::request(broker.clone(), tun_config(&config)).unwrap();
    let capture = acknowledge(&broker, &config);
    let mut client = GotaTun::new(
        PlaintextSource::Managed(source),
        Arc::new(NoopBypass),
        None,
        &config,
        None,
        String::new(),
    )
    .await
    .unwrap();
    let owner = client.managed().unwrap();
    let (_cancel, receiver) = CancelToken::new();
    let mut check = Check::new_with_smoltcp(owner.pinger().unwrap(), 0, receiver);
    establish_and_observe(&mut check, &client, &owner, async { Ok(()) })
        .await
        .unwrap();
    let (send, mut events) = futures::channel::mpsc::unbounded();
    let hook = talpid_tunnel::EventHook::new(send);
    let event = talpid_tunnel::TunnelEvent::Up {
        metadata: crate::tunnel_metadata(client.get_interface_name(), &config),
        selected_obfuscation: None,
    };
    // A real authenticated Check and a configured pair do not substitute for
    // installation of that pair in a GotaTun device. Observe the actual Up queue.
    let (uninstalled_broker, _uninstalled_root, uninstalled_credit) = self::broker();
    let mut pending =
        PendingManaged::request(uninstalled_broker.clone(), tun_config(&config)).unwrap();
    let uninstalled_capture = acknowledge(&uninstalled_broker, &config);
    let uninstalled = pending.create(&config).await.unwrap();
    assert!(
        establish_and_observe(&mut check, &client, &uninstalled.owner, async { Ok(()) })
            .await
            .is_err()
    );
    assert!(
        uninstalled_capture
            .try_send(&ipv4(17, b"not-installed"))
            .is_err()
    );
    uninstalled.owner.stop().await;
    drop(uninstalled);
    assert_eq!(uninstalled_credit.used(), 0);
    // Deterministic activation -> loss -> actual enqueue ordering. Replacing
    // the checked publication with a direct callback makes this assertion fail.
    capture.retire();
    assert!(owner.publish(|| hook.enqueue(event)).is_err());
    assert!(events.try_recv().is_err());
    assert!(!broker.snapshot().ordinary_ready);
    client.shutdown().await;
    drop((check, owner, client));
    assert_eq!(control.used(), 0);
    remote.stop().await;
}

#[cfg(unix)]
struct FirstBindEnobufs {
    broker: AttachmentBroker,
    attempts: Mutex<Vec<(u64, u64)>>,
    always: bool,
}
#[cfg(unix)]
impl SocketBypass for FirstBindEnobufs {
    fn bypass_socket(
        &self,
        _: socket2::SockRef<'_>,
        _: &talpid_net::bypass::BypassToken,
    ) -> io::Result<()> {
        let snapshot = self.broker.snapshot();
        let mut attempts = self.attempts.lock().unwrap();
        attempts.push((
            snapshot.capture_generation.unwrap(),
            snapshot.attachment.unwrap(),
        ));
        if self.always || attempts.len() == 1 {
            Err(io::Error::from_raw_os_error(
                nix::errno::Errno::ENOBUFS as i32,
            ))
        } else {
            Ok(())
        }
    }
    fn revoke_bypass(
        &self,
        _: socket2::SockRef<'_>,
        _: &talpid_net::bypass::BypassToken,
    ) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(unix)]
#[tokio::test]
async fn actual_enobufs_bind_retries_with_fresh_request_capture_attempt_and_control() {
    let (broker, _root, control) = broker();
    let mut config = config();
    let (remote, mut observed) = remote(&mut config, false).await;
    let source = PendingManaged::request(broker.clone(), tun_config(&config)).unwrap();
    let first_request = broker.pending_request().unwrap().id();
    let first_capture = acknowledge(&broker, &config);
    let actor_broker = broker.clone();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let actor = tokio::spawn(async move {
        let capture = first_capture;
        let mut requests = vec![first_request];
        let mut changes = actor_broker.changes();
        tokio::pin!(stopped);
        loop {
            let state = *changes.borrow_and_update();
            if let Some(request) = actor_broker.pending_request() {
                assert!(
                    request.id() > *requests.last().unwrap(),
                    "retry reused request"
                );
                requests.push(request.id());
                assert!(state.capture_ready, "ENOBUFS retired capture");
                capture.acknowledge_request(&request).unwrap();
            }
            tokio::select! { _ = &mut stopped => return (capture, requests), result = changes.changed() => result.unwrap() }
        }
    });
    let bypass = Arc::new(FirstBindEnobufs {
        broker: broker.clone(),
        attempts: Mutex::new(Vec::new()),
        always: false,
    });
    let mut client = tokio::time::timeout(
        Duration::from_secs(5),
        GotaTun::new(
            PlaintextSource::Managed(source),
            bypass.clone(),
            None,
            &config,
            None,
            String::new(),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    let attempts = bypass.attempts.lock().unwrap().clone();
    assert!(attempts.len() >= 2);
    assert_eq!(attempts[0].0, attempts[1].0, "ENOBUFS replaced capture");
    assert_ne!(
        attempts[0].1, attempts[1].1,
        "consumed attempt/queues reused"
    );
    assert_eq!(control.used(), CONTROL_STORAGE);
    let owner = client.managed().unwrap();
    let (_cancel, receiver) = CancelToken::new();
    let mut check = Check::new_with_smoltcp(owner.pinger().unwrap(), 0, receiver);
    establish_and_observe(&mut check, &client, &owner, async { Ok(()) })
        .await
        .unwrap();
    stop.send(()).unwrap();
    let (capture, requests) = actor.await.unwrap();
    assert!(
        requests.len() == 2,
        "retry did not request fresh target configuration"
    );
    let bytes = ipv4(17, b"fresh-enobufs-attempt-nonce");
    capture.try_send(&bytes).unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), observed.recv())
            .await
            .unwrap()
            .unwrap(),
        bytes
    );
    let mut reply = tokio::time::timeout(Duration::from_secs(2), capture.reply())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        reply.write(|received| {
            assert_eq!(received, application_reply(&bytes));
            Ok(received.len())
        }),
        RelayWriteOutcome::Written
    ));
    client.shutdown().await;
    drop((check, owner, client));
    assert_eq!(control.used(), 0);
    remote.stop().await;
}

#[tokio::test]
async fn cancelled_setup_owner_and_cancelled_shutdown_keep_joined_cleanup() {
    let (broker, _root, control) = broker();
    let config = config();
    let mut source = PendingManaged::request(broker.clone(), tun_config(&config)).unwrap();
    let (resume, held) = tokio::sync::oneshot::channel();
    let (finished, completion) = tokio::sync::oneshot::channel();
    source.after_receipt = Some(held);
    source.cleanup_complete = Some(finished);
    // The external caller is cancelled while its worker awaits the real receipt.
    assert!(
        tokio::time::timeout(
            Duration::from_millis(20),
            GotaTun::new(
                PlaintextSource::Managed(source),
                Arc::new(NoopBypass),
                None,
                &config,
                None,
                String::new()
            )
        )
        .await
        .is_err()
    );
    // Caller-drop now cancels the pending operation; no late platform receipt
    // or held-stage completion is needed to finish this exact setup owner.
    assert!(broker.pending_request().is_none());
    assert!(broker.snapshot().attachment.is_none());
    assert!(!broker.snapshot().ordinary_ready);
    assert_eq!(control.used(), 0);
    let joined_cleanup = async {
        completion
            .await
            .expect("setup dropped its completion without cleanup");
        assert!(broker.snapshot().attachment.is_none());
        assert!(!broker.snapshot().ordinary_ready);
        assert_eq!(control.used(), 0);
    };
    tokio::pin!(joined_cleanup);
    tokio::time::timeout(Duration::from_secs(2), &mut joined_cleanup)
        .await
        .unwrap();
    assert!(!broker.snapshot().ordinary_ready);
    assert!(
        resume.send(()).is_err(),
        "cancelled setup retained a network wait"
    );
    let source = PendingManaged::request(broker.clone(), tun_config(&config)).unwrap();
    let _capture = acknowledge(&broker, &config);
    let mut client = GotaTun::new(
        PlaintextSource::Managed(source),
        Arc::new(NoopBypass),
        None,
        &config,
        None,
        String::new(),
    )
    .await
    .unwrap();
    {
        use std::{
            future::{Future, poll_fn},
            task::Poll,
        };
        let stop = client.shutdown();
        tokio::pin!(stop);
        poll_fn(|cx| {
            assert!(stop.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
    }
    assert!(client.cleanup.is_some());
    assert_eq!(control.used(), CONTROL_STORAGE);
    client.shutdown().await;
    assert_eq!(control.used(), 0);
}

#[tokio::test]
async fn native_monitor_disconnect_aborts_pending_ephemeral_negotiation_promptly() {
    let mut config = config();
    config.quantum_resistant = true;
    let (ready, pending) = tokio::sync::oneshot::channel();
    let (completed, completion) = tokio::sync::oneshot::channel();
    let monitor = tokio::spawn(async move {
        let bypass: Arc<dyn SocketBypass> = Arc::new(NoopBypass);
        let negotiation = crate::ephemeral::negotiate_ephemeral_peers(&config, 3, None, &bypass);
        tokio::pin!(negotiation);
        std::future::poll_fn(|cx| {
            assert!(std::future::Future::poll(negotiation.as_mut(), cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        ready.send(()).unwrap();
        let _ = negotiation.await;
        let _ = completed.send(());
    });
    tokio::time::timeout(Duration::from_secs(2), pending)
        .await
        .unwrap()
        .unwrap();
    let (close, close_rx) = futures::channel::oneshot::channel();
    let (events, event_rx) = std::sync::mpsc::channel();
    let (cancellation, _receiver) = CancelToken::new();
    let observed_cancellation = cancellation.clone();
    close.send(()).unwrap();
    tokio::time::timeout(
        Duration::from_millis(250),
        crate::close_android_monitor(false, close_rx, cancellation, monitor, events),
    )
    .await
    .expect("Native disconnect waited for negotiation");
    assert!(!observed_cancellation.is_closed());
    assert!(matches!(event_rx.try_recv(), Ok(crate::CloseMsg::Stop)));
    assert!(
        tokio::time::timeout(Duration::from_millis(250), completion)
            .await
            .unwrap()
            .is_err(),
        "negotiation finished instead of being aborted"
    );
}

#[tokio::test]
async fn managed_monitor_disconnect_waits_for_cancelled_owner_and_actual_joined_cleanup() {
    let (broker, _root, control) = broker();
    let config = config();
    let source = PendingManaged::request(broker.clone(), tun_config(&config)).unwrap();
    let _capture = acknowledge(&broker, &config);
    let mut client = GotaTun::new(
        PlaintextSource::Managed(source),
        Arc::new(NoopBypass),
        None,
        &config,
        None,
        String::new(),
    )
    .await
    .unwrap();
    let (cancellation, mut receiver) = CancelToken::new();
    let (noticed, cancelled) = tokio::sync::oneshot::channel();
    let (release, cleanup) = tokio::sync::oneshot::channel();
    let monitor = tokio::spawn(async move {
        receiver.cancelled().await;
        noticed.send(()).unwrap();
        cleanup.await.unwrap();
        client.shutdown().await;
    });
    let (close, close_rx) = futures::channel::oneshot::channel();
    let (events, event_rx) = std::sync::mpsc::channel();
    let shutdown = tokio::spawn(crate::close_android_monitor(
        true,
        close_rx,
        cancellation,
        monitor,
        events,
    ));
    close.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(2), cancelled)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        control.used(),
        CONTROL_STORAGE,
        "cancel refunded a live producer"
    );
    assert!(matches!(
        event_rx.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty)
    ));
    release.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(2), shutdown)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(event_rx.try_recv(), Ok(crate::CloseMsg::Stop)));
    assert_eq!(
        control.used(),
        0,
        "Stop preceded actual control/device joins"
    );
    assert!(!broker.snapshot().ordinary_ready);
}

#[derive(Default)]
struct SetupBypass {
    hits: std::sync::atomic::AtomicUsize,
    entered: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    hold: Option<Arc<(Mutex<bool>, std::sync::Condvar)>>,
}
impl SocketBypass for SetupBypass {
    fn bypass_socket(
        &self,
        _: socket2::SockRef<'_>,
        _: &talpid_net::bypass::BypassToken,
    ) -> io::Result<()> {
        self.hits.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if let Some(entered) = self.entered.lock().unwrap().take() {
            let _ = entered.send(());
        }
        if let Some(hold) = &self.hold {
            let mut released = hold.0.lock().unwrap();
            while !*released {
                released = hold.1.wait(released).unwrap();
            }
        }
        Ok(())
    }
    fn revoke_bypass(
        &self,
        _: socket2::SockRef<'_>,
        _: &talpid_net::bypass::BypassToken,
    ) -> io::Result<()> {
        Ok(())
    }
}
struct ReleaseSetup(Arc<(Mutex<bool>, std::sync::Condvar)>);
impl Drop for ReleaseSetup {
    fn drop(&mut self) {
        *self.0.0.lock().unwrap() = true;
        self.0.1.notify_all();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn managed_setup_cancellation_joins_each_owned_stage() {
    use futures::FutureExt;
    // A completed Device::stop may leave its final Drop task owning plaintext
    // halves. Their own destruction, not task scheduling, gates acknowledgement.
    {
        let (broker, _root, control) = broker();
        let config = config();
        let mut source = PendingManaged::request(broker.clone(), tun_config(&config)).unwrap();
        let request = broker.pending_request().unwrap();
        let _capture = acknowledge(&broker, &config);
        let ManagedPair {
            send,
            receive,
            owner,
        } = source.create(&config).await.unwrap();
        owner.guard.lock().await.as_mut().unwrap().stop().await;
        let mut stopped = Box::pin(owner.stop_after_device());
        assert!(stopped.as_mut().now_or_never().is_none());
        assert!(!request.release_ready());
        assert_eq!(control.used(), CONTROL_STORAGE);
        drop(send);
        assert!(stopped.as_mut().now_or_never().is_none());
        assert!(!request.release_ready());
        drop(receive);
        stopped.await;
        assert!(request.release_ready());
        drop(owner);
        assert_eq!(control.used(), 0);
    }
    // A current-thread worker cannot run between caller-drop and the next
    // pending-request inspection. Hold the fallback receipt at that boundary.
    tokio::task::spawn_blocking(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let (broker, _root, control) = broker();
                let config = config();
                let mut source =
                    PendingManaged::request(broker.clone(), tun_config(&config)).unwrap();
                let exact_cleanup = source.cleanup();
                let first = broker.pending_request().unwrap().id();
                let (finished, completion) = tokio::sync::oneshot::channel();
                source.cleanup_complete = Some(finished);
                let capture = acknowledge(&broker, &config);
                let bypass = Arc::new(FirstBindEnobufs {
                    broker: broker.clone(),
                    attempts: Mutex::new(Vec::new()),
                    always: false,
                });
                let mut caller = Box::pin(GotaTun::new(
                    PlaintextSource::Managed(source),
                    bypass.clone(),
                    None,
                    &config,
                    None,
                    String::new(),
                ));
                assert!(caller.as_mut().now_or_never().is_none());
                let mut changes = broker.changes();
                let second = tokio::time::timeout(Duration::from_secs(2), async {
                    loop {
                        let _ = changes.borrow_and_update();
                        if let Some(request) = broker.pending_request() {
                            assert!(request.id() > first);
                            break request;
                        }
                        changes.changed().await.unwrap();
                    }
                })
                .await
                .unwrap();
                assert_eq!(
                    control.used(),
                    0,
                    "fallback published before old cleanup/refund"
                );
                assert_eq!(bypass.attempts.lock().unwrap().len(), 1);
                drop(caller);
                assert!(
                    broker.pending_request().is_none(),
                    "caller-drop left the second receipt admissible before worker scheduling"
                );
                // This is the next platform-admission pass. A stale pending request
                // would authorize configuration; none may escape caller-drop.
                let mut platform_admissions = 0;
                if let Some(request) = broker.pending_request() {
                    platform_admissions += 1;
                    capture.acknowledge_request(&request).unwrap();
                }
                assert_eq!(platform_admissions, 0);
                let successor = broker
                    .request_target_capture(tun_config(&config), tun_config(&config))
                    .unwrap();
                let successor_id = broker.pending_request().unwrap().id();
                exact_cleanup.cancel();
                assert_eq!(
                    broker.pending_request().unwrap().id(),
                    successor_id,
                    "old setup cancelled unrelated successor"
                );
                tokio::time::timeout(Duration::from_secs(2), completion)
                    .await
                    .unwrap()
                    .unwrap();
                assert!(second.release_ready());
                assert_eq!(
                    bypass.attempts.lock().unwrap().len(),
                    1,
                    "cancel admitted another device"
                );
                assert_eq!(control.used(), 0);
                assert_eq!(broker.pending_request().unwrap().id(), successor_id);
                assert!(capture.capability().unwrap().current());
                drop(successor);
            });
    })
    .await
    .unwrap();
    // Pending receipt, consumed receipt and an already-running private stack.
    for stage in ["receipt", "acquisition", "control", "device"] {
        let (broker, _root, control) = broker();
        let config = config();
        let mut source = PendingManaged::request(broker.clone(), tun_config(&config)).unwrap();
        let request = broker.pending_request().unwrap();
        let (finished, completion) = tokio::sync::oneshot::channel();
        source.cleanup_complete = Some(finished);
        let (entered, reached) = tokio::sync::oneshot::channel();
        let (resume, held) = tokio::sync::oneshot::channel();
        let hold = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
        let release = ReleaseSetup(hold.clone());
        let bypass = Arc::new(SetupBypass {
            entered: Mutex::new(if stage == "device" {
                Some(entered)
            } else {
                None
            }),
            hold: (stage == "device").then_some(hold),
            ..Default::default()
        });
        // Entered is used by exactly one real boundary, never by a timer.
        let (stage_entered, stage_reached) = tokio::sync::oneshot::channel();
        if stage == "acquisition" {
            source.after_receipt = Some(held);
            source.after_receipt_entered = Some(stage_entered);
        } else if stage == "control" {
            source.after_stack = Some((stage_entered, held));
        } else {
            drop((stage_entered, held));
        }
        let capture = (stage != "receipt").then(|| acknowledge(&broker, &config));
        let mut setup = Box::pin(GotaTun::new(
            PlaintextSource::Managed(source),
            bypass.clone(),
            None,
            &config,
            None,
            String::new(),
        ));
        assert!(setup.as_mut().now_or_never().is_none());
        match stage {
            "acquisition" | "control" => {
                tokio::time::timeout(Duration::from_secs(2), stage_reached)
                    .await
                    .unwrap()
                    .unwrap()
            }
            "device" => tokio::time::timeout(Duration::from_secs(2), reached)
                .await
                .unwrap()
                .unwrap(),
            _ => {}
        }
        drop(setup);
        assert!(broker.pending_request().is_none());
        assert!(
            broker.snapshot().attachment.is_none(),
            "{stage}: cancellation did not revoke immediately"
        );
        assert!(!broker.snapshot().ordinary_ready);
        let mut completion = Box::pin(completion);
        if stage == "device" {
            assert_eq!(
                control.used(),
                CONTROL_STORAGE,
                "refunded started device work"
            );
            assert!(
                completion.as_mut().now_or_never().is_none(),
                "Stop preceded device join"
            );
        }
        drop(release);
        tokio::time::timeout(Duration::from_secs(2), completion)
            .await
            .unwrap()
            .unwrap();
        assert!(request.release_ready());
        assert_eq!(control.used(), 0, "{stage}: control leaked after join");
        if stage != "device" {
            assert_eq!(
                bypass.hits.load(std::sync::atomic::Ordering::SeqCst),
                0,
                "cancel started a device"
            );
        }
        if let Some(capture) = capture {
            assert!(capture.capability().unwrap().current());
        }
        assert!(resume.send(()).is_err());
    }
    // Observe a real temporary device's handshake before cancelling PQ/DAITA.
    for (pq, daita) in [(true, false), (false, true), (true, true)] {
        let relay = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut config = config();
        config.quantum_resistant = pq;
        config.daita = daita;
        config.entry_peer.endpoint = relay.local_addr().unwrap();
        let bypass: Arc<dyn SocketBypass> = Arc::new(NoopBypass);
        let (cancel, receiver) = CancelToken::new();
        let negotiation = crate::ephemeral::negotiate_ephemeral_peers_cancellable(
            &config, 3, None, &bypass, receiver,
        );
        tokio::pin!(negotiation);
        let mut bytes = [0u8; 2048];
        tokio::select! {
            result = &mut negotiation => panic!("negotiation ended before handshake: {}", result.is_ok()),
            result = tokio::time::timeout(Duration::from_secs(2), relay.recv_from(&mut bytes)) => { assert!(result.unwrap().unwrap().0 > 0); },
        }
        cancel.close();
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(2), negotiation)
                .await
                .unwrap(),
            Err(crate::CloseMsg::Stop)
        ));
    }
    // Both real bind attempts fail: the fallback is exactly once, with a fresh
    // request/attempt after the old private guard has joined and refunded.
    #[cfg(unix)]
    {
        let (broker, _root, control) = broker();
        let config = config();
        let source = PendingManaged::request(broker.clone(), tun_config(&config)).unwrap();
        let first = broker.pending_request().unwrap().id();
        let capture = acknowledge(&broker, &config);
        let actor_broker = broker.clone();
        let actor_control = control.clone();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let actor = tokio::spawn(async move {
            let mut requests = vec![first];
            let mut changes = actor_broker.changes();
            tokio::pin!(stopped);
            loop {
                let _ = changes.borrow_and_update();
                if let Some(request) = actor_broker.pending_request() {
                    assert_eq!(actor_control.used(), 0, "retry retained old control stack");
                    assert!(request.id() > *requests.last().unwrap());
                    requests.push(request.id());
                    capture.acknowledge_request(&request).unwrap();
                }
                tokio::select! {
                    _ = &mut stopped => return requests,
                    result = changes.changed() => result.unwrap(),
                }
            }
        });
        let bypass = Arc::new(FirstBindEnobufs {
            broker: broker.clone(),
            attempts: Mutex::new(Vec::new()),
            always: true,
        });
        let result = tokio::time::timeout(
            Duration::from_secs(3),
            GotaTun::new(
                PlaintextSource::Managed(source),
                bypass.clone(),
                None,
                &config,
                None,
                String::new(),
            ),
        )
        .await
        .unwrap();
        assert!(result.is_err());
        stop.send(()).unwrap();
        let requests = actor.await.unwrap();
        assert_eq!(requests.len(), 2, "more than one ENOBUFS retry");
        let attempts = bypass.attempts.lock().unwrap();
        assert_eq!(attempts.len(), 2);
        assert_ne!(attempts[0].1, attempts[1].1);
        assert_eq!(control.used(), 0);
    }
    // Obfuscator commitment is cancellable after the real peer-stat check.
    let (broker, _root, control) = broker();
    let mut config = config();
    let (remote, _observed) = remote(&mut config, false).await;
    let source = PendingManaged::request(broker.clone(), tun_config(&config)).unwrap();
    let _capture = acknowledge(&broker, &config);
    let mut client = GotaTun::new(
        PlaintextSource::Managed(source),
        Arc::new(NoopBypass),
        None,
        &config,
        None,
        String::new(),
    )
    .await
    .unwrap();
    let owner = client.managed().unwrap();
    let (cancel, receiver) = CancelToken::new();
    let mut check = Check::new_with_smoltcp(owner.pinger().unwrap(), 0, receiver);
    let (entered, reached) = tokio::sync::oneshot::channel();
    {
        let setup = establish_and_observe(&mut check, &client, &owner, async {
            entered.send(()).unwrap();
            std::future::pending().await
        });
        tokio::pin!(setup);
        tokio::select! {
            result = &mut setup => panic!("commitment not held: {result:?}"),
            _ = reached => {},
        }
        cancel.close();
        assert!(
            tokio::time::timeout(Duration::from_secs(2), setup)
                .await
                .unwrap()
                .is_err()
        );
    }
    assert!(!broker.snapshot().ordinary_ready);
    client.shutdown().await;
    drop((client, owner, check));
    assert_eq!(control.used(), 0);
    remote.stop().await;
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn native_setup_and_private_pinger_preserve_upstream_configuration_domain() {
    use crate::connectivity::Pinger;
    use futures::FutureExt;
    use std::os::fd::{AsRawFd, IntoRawFd};
    // A real Native constructor runs before its caller's first suspension, not
    // in an unowned worker. A borrowed Unix fd stands in for the native IP fd.
    let name = std::fs::read_dir("/sys/class/net")
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .find(|name| {
            std::fs::read_to_string(format!("/sys/class/net/{name}/mtu"))
                .ok()
                .and_then(|s| s.trim().parse::<u16>().ok())
                .is_some()
        })
        .unwrap();
    let (fd, peer) = std::os::unix::net::UnixDatagram::pair().unwrap();
    let path = format!("/proc/self/fd/{}", fd.as_raw_fd());
    let inode = std::fs::read_link(&path).unwrap();
    let mut tun = tun::Configuration::default();
    tun.raw_fd(fd.into_raw_fd()).tun_name(name);
    let device = GotaTunDevice::from_tun_device(
        tun::AsyncDevice::new(tun::Device::new(&tun).unwrap()).unwrap(),
    )
    .unwrap();
    let (retired, destroyed) = tokio::sync::oneshot::channel::<()>();
    let device = NativeDevice {
        device,
        _retired: Some(Arc::new(retired)),
    };
    let bypass = Arc::new(SetupBypass::default());
    let config = config();
    let mut setup = Box::pin(GotaTun::new(
        PlaintextSource::Native(device),
        bypass.clone(),
        None,
        &config,
        None,
        String::new(),
    ));
    let result = setup.as_mut().now_or_never();
    assert!(
        bypass.hits.load(std::sync::atomic::Ordering::SeqCst) > 0,
        "Native constructor detached from caller"
    );
    let mut destroyed = Box::pin(destroyed);
    assert!(
        destroyed.as_mut().now_or_never().is_none(),
        "live Native half signalled retirement"
    );
    drop((result, setup));
    assert!(
        tokio::time::timeout(Duration::from_secs(2), destroyed)
            .await
            .unwrap()
            .is_err()
    );
    assert_ne!(std::fs::read_link(&path).ok(), Some(inode));
    drop(peer);
    for (v4, v6, mtu) in [(true, false, 1220), (true, true, 1280), (false, true, 1280)] {
        let (broker, _root, control) = broker();
        let mut config = self::config();
        config
            .tunnel
            .addresses
            .retain(|ip| if ip.is_ipv4() { v4 } else { v6 });
        config.mtu = mtu;
        let (remote, mut observed) = remote(&mut config, false).await;
        let source = PendingManaged::request(broker.clone(), tun_config(&config)).unwrap();
        let capture = acknowledge(&broker, &config);
        let mut client = GotaTun::new(
            PlaintextSource::Managed(source),
            Arc::new(NoopBypass),
            None,
            &config,
            None,
            String::new(),
        )
        .await
        .expect("upstream-valid family/MTU rejected by private pinger");
        let owner = client.managed().unwrap();
        let mut pinger = owner.pinger().unwrap();
        if v4 {
            pinger.send_icmp().await.unwrap();
        } else {
            let error = pinger.send_icmp().await.unwrap_err();
            use std::error::Error as _;
            assert_eq!(
                error
                    .source()
                    .unwrap()
                    .downcast_ref::<io::Error>()
                    .unwrap()
                    .kind(),
                io::ErrorKind::AddrNotAvailable
            );
            assert_eq!(
                control.used(),
                0,
                "unavailable private source allocated a fake IPv4 stack"
            );
        }
        // Constructor-domain proof: open this installed carrier explicitly to
        // drive ordinary bytes; B4 separately owns pre-Up admission timing.
        owner.activate().unwrap();
        let mut bytes = if v6 {
            let mut bytes = vec![0; 48 + 8];
            bytes[0] = 0x60;
            bytes[4..6].copy_from_slice(&16u16.to_be_bytes());
            bytes[6] = 17;
            bytes[7] = 64;
            bytes[8..24].copy_from_slice(&config.tunnel_ipv6().unwrap().octets());
            bytes[24..40].copy_from_slice(&"2001:db8::42".parse::<Ipv6Addr>().unwrap().octets());
            bytes[40..42].copy_from_slice(&43000u16.to_be_bytes());
            bytes[42..44].copy_from_slice(&53u16.to_be_bytes());
            bytes[44..46].copy_from_slice(&16u16.to_be_bytes());
            bytes[48..].copy_from_slice(b"v6-nonce");
            fix_wire(&mut bytes, 40, 17);
            bytes
        } else {
            ipv4(17, b"v4-nonce")
        };
        capture.try_send(&bytes).unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), observed.recv())
                .await
                .unwrap()
                .unwrap(),
            bytes
        );
        let mut reply = tokio::time::timeout(Duration::from_secs(2), capture.reply())
            .await
            .unwrap()
            .unwrap();
        bytes = application_reply(&bytes);
        assert!(matches!(
            reply.write(|actual| {
                assert_eq!(actual, bytes);
                Ok(actual.len())
            }),
            RelayWriteOutcome::Written
        ));
        let (_cancel, receiver) = CancelToken::new();
        let mut check = Check::new_with_smoltcp(pinger, 0, receiver);
        assert!(
            check.establish_connectivity(&client).await.unwrap(),
            "ordinary authenticated stats must suffice without a private reply"
        );
        assert!(
            client
                .get_tunnel_stats()
                .await
                .unwrap()
                .values()
                .any(|s| s.rx_bytes > 0 && s.tx_bytes > 0)
        );
        client.shutdown().await;
        drop((client, owner, check, reply));
        assert_eq!(control.used(), 0);
        remote.stop().await;
    }
}

// Independent endpoint/device from the archived TCP fixture. This is ordinary
// application TCP, not a control stream and not a production adapter hook.
#[derive(Default)]
struct TcpPackets {
    input: VecDeque<Vec<u8>>,
    output: VecDeque<Vec<u8>>,
}
struct TcpRx(Vec<u8>);
struct TcpTx<'a>(&'a mut VecDeque<Vec<u8>>);
impl smoltcp::phy::RxToken for TcpRx {
    fn consume<R, F>(self, operation: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        operation(&self.0)
    }
}
impl smoltcp::phy::TxToken for TcpTx<'_> {
    fn consume<R, F>(self, length: usize, operation: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut bytes = vec![0; length];
        let value = operation(&mut bytes);
        self.0.push_back(bytes);
        value
    }
}
impl smoltcp::phy::Device for TcpPackets {
    type RxToken<'a> = TcpRx;
    type TxToken<'a> = TcpTx<'a>;
    fn receive(
        &mut self,
        _: smoltcp::time::Instant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        Some((TcpRx(self.input.pop_front()?), TcpTx(&mut self.output)))
    }
    fn transmit(&mut self, _: smoltcp::time::Instant) -> Option<Self::TxToken<'_>> {
        Some(TcpTx(&mut self.output))
    }
    fn capabilities(&self) -> smoltcp::phy::DeviceCapabilities {
        let mut caps = smoltcp::phy::DeviceCapabilities::default();
        caps.medium = smoltcp::phy::Medium::Ip;
        caps.max_transmission_unit = 1420;
        caps
    }
}
struct TcpEndpoint {
    device: TcpPackets,
    interface: smoltcp::iface::Interface,
    sockets: smoltcp::iface::SocketSet<'static>,
    socket: smoltcp::iface::SocketHandle,
    started: Instant,
    output: mpsc::Sender<Packet<Ip>>,
    received: Vec<u8>,
    response: Vec<u8>,
    sent: usize,
}
impl TcpEndpoint {
    fn new(output: mpsc::Sender<Packet<Ip>>, response: Vec<u8>) -> Self {
        use smoltcp::{
            iface::{Config, Interface, SocketSet},
            socket::tcp,
            wire::{HardwareAddress, IpCidr},
        };
        let address: Ipv4Addr = "203.0.113.20".parse().unwrap();
        let mut device = TcpPackets::default();
        let mut interface = Interface::new(
            Config::new(HardwareAddress::Ip),
            &mut device,
            smoltcp::time::Instant::from_millis(0),
        );
        interface
            .update_ip_addrs(|addresses| addresses.push(IpCidr::new(address.into(), 32)).unwrap());
        interface
            .routes_mut()
            .add_default_ipv4_route(address)
            .unwrap();
        let mut sockets = SocketSet::new(Vec::new());
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; 32768]),
            tcp::SocketBuffer::new(vec![0; 32768]),
        );
        socket.set_ack_delay(None);
        socket.listen(443).unwrap();
        let socket = sockets.add(socket);
        Self {
            device,
            interface,
            sockets,
            socket,
            started: Instant::now(),
            output,
            received: Vec::new(),
            response,
            sent: 0,
        }
    }
    fn pump(&mut self) -> io::Result<()> {
        use smoltcp::socket::tcp;
        let now = smoltcp::time::Instant::from_millis(self.started.elapsed().as_millis() as i64);
        self.interface
            .poll(now, &mut self.device, &mut self.sockets);
        let socket = self.sockets.get_mut::<tcp::Socket<'_>>(self.socket);
        let mut buffer = [0; 4096];
        if socket.can_recv() {
            let count = socket.recv_slice(&mut buffer).unwrap();
            self.received.extend_from_slice(&buffer[..count]);
        }
        if !self.received.is_empty() && socket.can_send() && self.sent < self.response.len() {
            self.sent += socket.send_slice(&self.response[self.sent..]).unwrap();
        }
        if self.sent == self.response.len() && socket.state() == tcp::State::CloseWait {
            socket.close();
        }
        self.interface
            .poll(now, &mut self.device, &mut self.sockets);
        while let Some(bytes) = self.device.output.pop_front() {
            self.output
                .try_send(Packet::<[u8]>::copy_from(&bytes).try_into_ip().unwrap())
                .map_err(|_| io::ErrorKind::WouldBlock)?;
        }
        Ok(())
    }
}
struct TcpRemoteSend(Arc<Mutex<TcpEndpoint>>);
struct TcpRemoteReceive {
    endpoint: Arc<Mutex<TcpEndpoint>>,
    input: mpsc::Receiver<Packet<Ip>>,
}
impl IpSend for TcpRemoteSend {
    async fn send(&mut self, packet: Packet<Ip>) -> io::Result<()> {
        let bytes = packet.into_bytes();
        let mut endpoint = self.0.lock().unwrap();
        if bytes[9] == 1 {
            let reply = echo_reply(&bytes);
            return endpoint
                .output
                .try_send(Packet::<[u8]>::copy_from(&reply).try_into_ip().unwrap())
                .map_err(|_| io::ErrorKind::WouldBlock.into());
        }
        assert_eq!(bytes[9], 6);
        assert_eq!(&bytes[12..16], &[10, 12, 34, 56]);
        assert_eq!(&bytes[16..20], &[203, 0, 113, 20]);
        endpoint.device.input.push_back(bytes.to_vec());
        endpoint.pump()
    }
}
impl IpRecv for TcpRemoteReceive {
    async fn recv<'a>(
        &'a mut self,
        _: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + Send + 'a> {
        loop {
            tokio::select! {
                packet = self.input.recv() => return Ok(std::iter::once(packet.ok_or(io::ErrorKind::BrokenPipe)?)),
                _ = tokio::time::sleep(Duration::from_millis(2)) => self.endpoint.lock().unwrap().pump()?,
            }
        }
    }
    fn mtu(&self) -> MtuWatcher {
        MtuWatcher::new(1420)
    }
}

#[tokio::test]
async fn ordinary_tcp_stream_consumers_receive_full_nonces_through_real_crypto() {
    use talpid_netstack::smoltcp_network::{SmoltcpNetworkConfig, smoltcp_network};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    for translated in [false, true] {
        let (broker, _root, control) = broker();
        let mut config = config();
        config.tunnel.addresses.retain(|address| address.is_ipv4());
        config.ipv6_gateway = None;
        let key = PrivateKey::new_from_random();
        config.entry_peer.public_key = key.public_key();
        let reservation = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = reservation.local_addr().unwrap().port();
        drop(reservation);
        config.entry_peer.endpoint = (Ipv4Addr::LOCALHOST, port).into();
        let (output, input) = mpsc::channel(64);
        let request: Vec<_> = b"ordinary-application-request-nonce"
            .iter()
            .copied()
            .cycle()
            .take(12305)
            .collect();
        let response: Vec<_> = b"independent-peer-response-nonce"
            .iter()
            .copied()
            .cycle()
            .take(16371)
            .collect();
        let endpoint = Arc::new(Mutex::new(TcpEndpoint::new(output, response.clone())));
        let peer = PeerConfig {
            public_key: config.tunnel.private_key.public_key(),
            allowed_ips: vec!["10.12.34.56/32".parse().unwrap()],
            endpoint: "127.0.0.1:9".parse().unwrap(),
            psk: None,
            constant_packet_size: false,
        };
        let remote = DeviceBuilder::new()
            .with_default_udp()
            .with_listen_port(port)
            .with_private_key(StaticSecret::from(key.to_bytes()))
            .with_peer(to_gotatun_peer(&peer, None))
            .with_ip_pair(
                TcpRemoteSend(endpoint.clone()),
                TcpRemoteReceive {
                    endpoint: endpoint.clone(),
                    input,
                },
            )
            .build()
            .await
            .unwrap();
        let source = if translated {
            translated_fixture::projected(&broker, &config)
        } else {
            PendingManaged::request(broker.clone(), tun_config(&config)).unwrap()
        };
        let capture = if translated {
            translated_fixture::bind(&broker)
        } else {
            acknowledge(&broker, &config)
        };
        let mut client = GotaTun::new(
            PlaintextSource::Managed(source),
            Arc::new(NoopBypass),
            None,
            &config,
            None,
            String::new(),
        )
        .await
        .unwrap();
        let owner = client.managed().unwrap();
        let (_cancel, receiver) = CancelToken::new();
        let mut check = Check::new_with_smoltcp(owner.pinger().unwrap(), 0, receiver);
        establish_and_observe(&mut check, &client, &owner, async { Ok(()) })
            .await
            .unwrap();
        let (application, mut app_output, mut app_input, mut app_guard) =
            smoltcp_network(SmoltcpNetworkConfig {
                ipv4_addr: if translated {
                    "172.27.1.1".parse().unwrap()
                } else {
                    config.tunnel_ipv4().unwrap()
                },
                ipv6_addr: None,
                mtu: if translated { 1280 } else { config.mtu },
            });
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let bridge = tokio::spawn(async move {
            let mut pool = PacketBufPool::new(4);
            tokio::pin!(stopped);
            loop {
                tokio::select! {
                    _ = &mut stopped => return capture,
                    packets = app_output.recv(&mut pool) => {
                        for packet in packets.unwrap() {
                            capture.try_send(&packet.into_bytes()).unwrap();
                        }
                    }
                    reply = capture.reply() => {
                        let mut reply = reply.unwrap();
                        let mut bytes = None;
                        assert!(matches!(reply.write(|packet| { bytes = Some(packet.to_vec()); Ok(packet.len()) }), RelayWriteOutcome::Written));
                        app_input.send(Packet::<[u8]>::copy_from(&bytes.unwrap()).try_into_ip().unwrap()).await.unwrap();
                    }
                }
            }
        });
        let mut stream = application
            .clone()
            .tcp_connect("203.0.113.20:443".parse().unwrap())
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), stream.write_all(&request))
            .await
            .unwrap()
            .unwrap();
        let mut received = vec![0; response.len()];
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut received))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received, response);
        tokio::time::timeout(Duration::from_secs(2), async {
            while endpoint.lock().unwrap().received.len() < request.len() {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(endpoint.lock().unwrap().received, request);
        stop.send(()).unwrap();
        let capture = bridge.await.unwrap();
        drop((stream, application));
        app_guard.stop().await;
        client.shutdown().await;
        drop((owner, check, client, capture));
        assert_eq!(control.used(), 0);
        remote.stop().await;
    }
}
