use super::*;
use crate::local_delivery::DeliveryBuffers;
use futures::{
    FutureExt,
    io::{AsyncReadExt, AsyncWriteExt},
};
use std::sync::{
    Mutex,
    atomic::{AtomicUsize, Ordering},
};
use talpid_tunnel::packet_attachment::AttachmentBroker;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::TcpListener,
};

const LOCAL: SocketAddr = SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 0);
const DEFAULT: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1));
const PHYSICAL: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 2));
const MARKER: u32 = 0x68;

#[derive(Clone)]
struct Platform(
    Arc<Mutex<State>>,
    Option<i64>,
    Arc<Mutex<()>>,
    AttachmentBroker,
);

struct State {
    epoch: i64,
    token: Option<i64>,
    deny_prepare: bool,
    prepared: usize,
}

impl Platform {
    fn new(epoch: i64, token: Option<i64>) -> Self {
        let buffers = DeliveryBuffers::new();
        let broker =
            AttachmentBroker::new(buffers._application, buffers._capture, buffers._control)
                .unwrap();
        Self(
            Arc::new(Mutex::new(State {
                epoch,
                token,
                deny_prepare: false,
                prepared: 0,
            })),
            token.map(|_| 11),
            Arc::new(Mutex::new(())),
            broker,
        )
    }
}

impl DnsPlatform for Platform {
    fn capture_broker(&self) -> &AttachmentBroker {
        &self.3
    }

    fn with_service_capture<T>(&self, action: impl FnOnce(i64) -> io::Result<T>) -> io::Result<T> {
        let _capture = self.2.lock().unwrap();
        let epoch = self.0.lock().unwrap().epoch;
        action(epoch)
    }

    fn physical_dns(&self) -> io::Result<Option<PhysicalDns>> {
        // The capture monitor is held here, like Kotlin's reentrant service monitor.
        assert!(self.2.try_lock().is_err());
        Ok(self.1.map(|token| PhysicalDns {
            token,
            interface: 12,
            servers: vec![PHYSICAL],
        }))
    }

    fn own_socket(&self, epoch: i64, token: i64, fd: Option<BorrowedFd<'_>>) -> io::Result<bool> {
        let mut state = self.0.lock().unwrap();
        if state.epoch != epoch || state.token != Some(token) {
            return Ok(false);
        }
        if let Some(fd) = fd {
            state.prepared += 1;
            if state.deny_prepare {
                return Ok(false);
            }
            let socket = socket2::SockRef::from(&fd);
            assert_eq!(socket.local_addr()?.as_socket().unwrap().port(), 0);
            // Mark the actual live socket without needing Android or root in the builder.
            socket.set_tos_v4(MARKER)?;
        }
        Ok(true)
    }
}

fn select(platform: &Platform, target: &DnsTarget, expected: IpAddr) -> DnsRuntime<Platform> {
    let defaults = AtomicUsize::new(0);
    let (adapter, servers) = DnsRuntime::select(platform.clone(), target.clone(), || {
        defaults.fetch_add(1, Ordering::Relaxed);
        Ok(vec![DEFAULT])
    })
    .unwrap();
    assert_eq!(servers, [expected]);
    assert_eq!(defaults.into_inner(), usize::from(expected == DEFAULT));
    adapter
}

async fn round_trip(adapter: &DnsRuntime<Platform>, marker: u32) {
    tokio::time::timeout(Duration::from_secs(5), async {
        let udp = UdpSocket::bind(LOCAL).await.unwrap();
        let server = udp.local_addr().unwrap();
        let socket = adapter.bind_udp(LOCAL, server).await.unwrap();
        let (tos, local_addr) = {
            let inner = socket.socket.lock().unwrap();
            let inner = inner.as_ref().unwrap();
            (
                socket2::SockRef::from(inner).tos_v4().unwrap(),
                inner.local_addr().unwrap(),
            )
        };
        assert_eq!(tos, marker);
        assert_eq!(
            poll_fn(|cx| socket.poll_send_to(cx, b"udp", server))
                .await
                .unwrap(),
            3
        );
        let mut buffer = [0; 3];
        let (len, source) = udp.recv_from(&mut buffer).await.unwrap();
        assert_eq!((len, &buffer), (3, b"udp"));
        assert_eq!(source, local_addr);
        udp.send_to(b"UDP", source).await.unwrap();
        assert_eq!(
            poll_fn(|cx| socket.poll_recv_from(cx, &mut buffer))
                .await
                .unwrap(),
            (3, server)
        );
        assert_eq!(&buffer, b"UDP");

        let tcp = TcpListener::bind(LOCAL).await.unwrap();
        let mut socket = adapter
            .connect_tcp(tcp.local_addr().unwrap(), Some(LOCAL), None)
            .await
            .unwrap();
        let inner = &socket.socket.as_ref().unwrap().0;
        assert_eq!(socket2::SockRef::from(inner).tos_v4().unwrap(), marker);
        let (mut peer, source) = tcp.accept().await.unwrap();
        assert_eq!(source, inner.local_addr().unwrap());
        socket.write_all(b"tcp").await.unwrap();
        peer.read_exact(&mut buffer).await.unwrap();
        assert_eq!(&buffer, b"tcp");
        peer.write_all(b"TCP").await.unwrap();
        socket.read_exact(&mut buffer).await.unwrap();
        assert_eq!(&buffer, b"TCP");
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn off_without_capture_uses_stock_sockets() {
    let platform = Platform::new(1, None);
    let adapter = select(&platform, &DnsTarget::new(TargetState::Unsecured), DEFAULT);
    round_trip(&adapter, 0).await;
    assert_eq!(platform.0.lock().unwrap().prepared, 0);
}

#[tokio::test]
async fn native_reservation_fences_stock_dns_before_service_open() {
    let platform = Platform::new(1, Some(11));
    let target = DnsTarget::new(TargetState::Unsecured);
    let idle = select(&platform, &target, DEFAULT);
    let peer = UdpSocket::bind(LOCAL).await.unwrap();
    let server = peer.local_addr().unwrap();
    let socket = idle.bind_udp(LOCAL, server).await.unwrap();

    let reservation = platform.3.open_capture(None).unwrap();
    assert_eq!(
        platform.3.snapshot().capture_generation,
        Some(reservation.generation())
    );
    assert!(!platform.3.snapshot().capture_ready);
    assert!(
        matches!(DnsRuntime::select(platform.clone(), target.clone(), || panic!("stock DNS during reservation")),
            Err(error) if error.kind() == io::ErrorKind::NotConnected)
    );
    assert_eq!(
        poll_fn(|cx| socket.poll_send_to(cx, b"old", server))
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::NotConnected
    );
    assert!(peer.recv_from(&mut [0; 3]).now_or_never().is_none());

    platform.0.lock().unwrap().epoch = -2;
    round_trip(&select(&platform, &target, PHYSICAL), MARKER).await;
    drop(reservation);
    // Native packet retirement is not Android's acknowledgement of fd closure.
    round_trip(&select(&platform, &target, PHYSICAL), MARKER).await;
    platform.0.lock().unwrap().epoch = 3;
    round_trip(&select(&platform, &target, DEFAULT), 0).await;
}

#[tokio::test]
async fn off_with_capture_uses_only_prepared_sockets() {
    for epoch in [-1, -2] {
        let platform = Platform::new(epoch, Some(11));
        let adapter = select(&platform, &DnsTarget::new(TargetState::Unsecured), PHYSICAL);
        round_trip(&adapter, MARKER).await;
        assert_eq!(platform.0.lock().unwrap().prepared, 2);
    }
}

#[tokio::test]
async fn off_unavailable_stale_or_denied_never_falls_back() {
    let target = DnsTarget::new(TargetState::Unsecured);
    let tcp = TcpListener::bind(LOCAL).await.unwrap();
    let server = tcp.local_addr().unwrap();
    let unknown = Platform::new(0, None);
    assert!(
        matches!(DnsRuntime::select(unknown, target.clone(), || panic!("default fallback")), Err(e) if e.kind() == io::ErrorKind::NotConnected)
    );
    let missing = Platform::new(-1, None);
    assert!(
        matches!(DnsRuntime::select(missing, target.clone(), || panic!("default fallback")), Err(e) if e.kind() == io::ErrorKind::NotConnected)
    );
    for (token, deny, preparations) in [(None, false, 0), (Some(12), false, 0), (Some(11), true, 2)]
    {
        let platform = Platform::new(-1, Some(11));
        let adapter = select(&platform, &target, PHYSICAL);
        {
            let mut state = platform.0.lock().unwrap();
            state.token = token;
            state.deny_prepare = deny;
        }
        assert!(
            matches!(adapter.bind_udp(LOCAL, server).await, Err(e) if e.kind() == io::ErrorKind::NotConnected)
        );
        assert!(
            matches!(adapter.connect_tcp(server, None, None).await, Err(e) if e.kind() == io::ErrorKind::NotConnected)
        );
        assert_eq!(platform.0.lock().unwrap().prepared, preparations);
        assert!(tcp.accept().now_or_never().is_none());
    }
}

#[tokio::test]
async fn mullvad_on_keeps_upstream_servers_and_sockets() {
    let target = DnsTarget::new(TargetState::Secured);
    let platform = Platform::new(-1, Some(11));
    let mut physical = platform.0.lock().unwrap();
    physical.deny_prepare = true;
    // A secured lookup must not consult the capture monitor or physical authority.
    let adapter = select(&platform, &target, DEFAULT);
    drop(physical);
    round_trip(&adapter, 0).await;
    target.publish(TargetState::Unsecured);
    target.publish(TargetState::Secured);
    assert!(
        matches!(adapter.run::<()>(|| panic!("retired upstream grant")), Err(e) if e.kind() == io::ErrorKind::NotConnected)
    );
    assert_eq!(platform.0.lock().unwrap().prepared, 0);
}

#[tokio::test]
async fn capture_establishment_changes_next_tcp_attempt() {
    let target = DnsTarget::new(TargetState::Unsecured);
    let platform = Platform::new(1, Some(11));
    let idle = select(&platform, &target, DEFAULT);
    let tcp = TcpListener::bind(LOCAL).await.unwrap();
    let server = tcp.local_addr().unwrap();
    let mut socket = idle.connect_tcp(server, None, None).await.unwrap();
    platform.0.lock().unwrap().epoch = -2;
    // No new application I/O via the retired idle grant. Already-submitted kernel
    // work belongs to Android, as with stock sockets during VPN establishment.
    assert_eq!(
        socket.write(b"old").await.unwrap_err().kind(),
        io::ErrorKind::NotConnected
    );
    assert!(
        matches!(idle.connect_tcp(server, None, None).await, Err(e) if e.kind() == io::ErrorKind::NotConnected)
    );
    round_trip(&select(&platform, &target, PHYSICAL), MARKER).await;
}

#[tokio::test]
async fn prepared_sockets_survive_handover_on_the_same_network() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let platform = Platform::new(-1, Some(11));
        let adapter = select(&platform, &DnsTarget::new(TargetState::Unsecured), PHYSICAL);
        let udp = UdpSocket::bind(LOCAL).await.unwrap();
        let server = udp.local_addr().unwrap();
        let socket = adapter.bind_udp(LOCAL, server).await.unwrap();
        let tcp = TcpListener::bind(LOCAL).await.unwrap();
        let mut stream = adapter
            .connect_tcp(tcp.local_addr().unwrap(), None, None)
            .await
            .unwrap();
        let (mut peer, _) = tcp.accept().await.unwrap();

        platform.0.lock().unwrap().epoch = -2;
        poll_fn(|cx| socket.poll_send_to(cx, b"udp", server))
            .await
            .unwrap();
        let mut buffer = [0; 3];
        let (len, source) = udp.recv_from(&mut buffer).await.unwrap();
        assert_eq!((len, &buffer), (3, b"udp"));
        udp.send_to(b"UDP", source).await.unwrap();
        poll_fn(|cx| socket.poll_recv_from(cx, &mut buffer))
            .await
            .unwrap();
        assert_eq!(&buffer, b"UDP");
        stream.write_all(b"tcp").await.unwrap();
        peer.read_exact(&mut buffer).await.unwrap();
        assert_eq!(&buffer, b"tcp");
        peer.write_all(b"TCP").await.unwrap();
        stream.read_exact(&mut buffer).await.unwrap();
        assert_eq!(&buffer, b"TCP");
        assert_eq!(platform.0.lock().unwrap().prepared, 2);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn rejected_prepared_io_closes_both_transports() {
    tokio::time::timeout(Duration::from_secs(5), async {
        for (epoch, token) in [(-2, Some(12)), (2, Some(11)), (0, Some(11))] {
            let platform = Platform::new(-1, Some(11));
            let adapter = select(&platform, &DnsTarget::new(TargetState::Unsecured), PHYSICAL);
            let udp = UdpSocket::bind(LOCAL).await.unwrap();
            let server = udp.local_addr().unwrap();
            let socket = adapter.bind_udp(LOCAL, server).await.unwrap();
            let tcp = TcpListener::bind(LOCAL).await.unwrap();
            let mut stream = adapter
                .connect_tcp(tcp.local_addr().unwrap(), None, None)
                .await
                .unwrap();
            let (mut peer, _) = tcp.accept().await.unwrap();
            poll_fn(|cx| socket.poll_send_to(cx, b"before", server))
                .await
                .unwrap();
            let mut buffer = [0; 8];
            let (_, source) = udp.recv_from(&mut buffer).await.unwrap();
            udp.send_to(b"reply", source).await.unwrap();
            {
                let mut state = platform.0.lock().unwrap();
                state.epoch = epoch;
                state.token = token;
            }

            assert_eq!(
                poll_fn(|cx| socket.poll_recv_from(cx, &mut buffer))
                    .await
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::NotConnected
            );
            assert_eq!(
                stream.write(b"rejected").await.unwrap_err().kind(),
                io::ErrorKind::NotConnected
            );
            let _rebound = UdpSocket::bind(source)
                .await
                .expect("retired UDP fd closed");
            assert_eq!(
                peer.read(&mut buffer).await.unwrap(),
                0,
                "retired TCP fd closed"
            );
            assert!(udp.recv_from(&mut buffer).now_or_never().is_none());
        }
    })
    .await
    .unwrap();
}

#[test]
fn prepared_action_runs_under_capture_monitor() {
    let platform = Platform::new(-1, Some(11));
    let adapter = select(&platform, &DnsTarget::new(TargetState::Unsecured), PHYSICAL);
    adapter
        .run(|| {
            assert!(platform.2.try_lock().is_err());
            Ok(())
        })
        .unwrap();
}
