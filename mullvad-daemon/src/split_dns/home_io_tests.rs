use super::*;
use crate::split_dns::transport::{Protocol, exchange};
use futures::{StreamExt, io::AsyncWriteExt};
use hickory_net::{
    runtime::iocompat::AsyncIoTokioAsStd, tcp::TcpStream as DnsTcp, xfer::DnsStreamHandle,
};
use hickory_proto::{
    op::{Message, Query},
    rr::{Name, RData, Record, RecordType, rdata::A},
};
use std::{
    sync::Condvar,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst},
};
use talpid_netstack::buffer_budget::BufferBudget;
use tokio::net::TcpListener;

struct FixtureCapability {
    target: SocketAddr,
    live: AtomicBool,
    prepared: AtomicUsize,
    barrier: Option<Arc<(Mutex<bool>, Condvar)>>,
    started: tokio::sync::Notify,
}

struct ReleaseBarrier(Arc<(Mutex<bool>, Condvar)>);

impl Drop for ReleaseBarrier {
    fn drop(&mut self) {
        *self.0.0.lock().unwrap() = true;
        self.0.1.notify_all();
    }
}

impl FixtureCapability {
    fn new(target: SocketAddr) -> Self {
        Self {
            target,
            live: AtomicBool::new(true),
            prepared: AtomicUsize::new(0),
            barrier: None,
            started: tokio::sync::Notify::new(),
        }
    }
}

impl Capability for FixtureCapability {
    fn destination(&self) -> SocketAddr {
        self.target
    }
    fn permits(&self, _: bool) -> bool {
        true
    }
    fn current(&self) -> bool {
        self.live.load(SeqCst)
    }
    fn prepare(&self, _: &socket2::Socket) -> io::Result<()> {
        self.prepared.fetch_add(1, SeqCst);
        self.started.notify_one();
        if let Some(barrier) = &self.barrier {
            let (released, wake) = &**barrier;
            let mut guard = released.lock().unwrap();
            while !*guard {
                guard = wake.wait(guard).unwrap();
            }
        }
        Ok(())
    }
}

struct PanickingCapability(FixtureCapability);

impl Capability for PanickingCapability {
    fn destination(&self) -> SocketAddr {
        self.0.target
    }
    fn permits(&self, _: bool) -> bool {
        true
    }
    fn current(&self) -> bool {
        true
    }
    fn prepare(&self, _: &socket2::Socket) -> io::Result<()> {
        panic!("test platform preparation panic")
    }
}

fn question() -> Message {
    let mut message = Message::query();
    message.add_query(Query::query(
        Name::from_ascii("nonce.home.").unwrap(),
        RecordType::A,
    ));
    message
}

fn answer(request: Message) -> Message {
    let name = request.queries[0].name().clone();
    let mut response = request.into_response();
    response.add_answer(Record::from_rdata(
        name,
        741,
        RData::A(A::new(10, 77, 10, 1)),
    ));
    response
}

#[tokio::test]
async fn split_dns_home_io_udp_tcp_both_families_reach_exact_prepared_peer() {
    for host in ["127.0.0.1:0", "[::1]:0"] {
        for protocol in [Protocol::Udp, Protocol::Tcp] {
            let (peer, server) = match protocol {
                Protocol::Udp => {
                    let socket = UdpSocket::bind(host).await.unwrap();
                    let peer = socket.local_addr().unwrap();
                    (
                        peer,
                        tokio::spawn(async move {
                            let mut bytes = vec![0; 65535];
                            let (length, from) = socket.recv_from(&mut bytes).await.unwrap();
                            let bytes = answer(Message::from_vec(&bytes[..length]).unwrap())
                                .to_vec()
                                .unwrap();
                            socket.send_to(&bytes, from).await.unwrap();
                        }),
                    )
                }
                Protocol::Tcp => {
                    let listener = TcpListener::bind(host).await.unwrap();
                    let peer = listener.local_addr().unwrap();
                    (
                        peer,
                        tokio::spawn(async move {
                            let (socket, from) = listener.accept().await.unwrap();
                            let (mut stream, mut sender) =
                                DnsTcp::from_stream(AsyncIoTokioAsStd(socket), from);
                            let request =
                                stream.next().await.unwrap().unwrap().to_message().unwrap();
                            sender
                                .send(hickory_proto::op::SerialMessage::new(
                                    answer(request).to_vec().unwrap(),
                                    from,
                                ))
                                .unwrap();
                            while let Some(message) = stream.next().await {
                                message.unwrap();
                            }
                        }),
                    )
                }
            };
            let budget = Arc::new(BufferBudget::new(65536));
            let owner = HomeIoOwner::new(budget.clone());
            let capability = Arc::new(FixtureCapability::new(peer));
            let runtime = owner.with_capability(capability.clone()).unwrap();
            let request = question();
            let response = exchange(
                runtime.clone(),
                peer,
                protocol,
                Duration::from_secs(2),
                request.clone(),
            )
            .await
            .unwrap();
            assert_eq!(response.into_message(), answer(request));
            assert_eq!(capability.prepared.load(SeqCst), 1);
            tokio::time::timeout(Duration::from_secs(2), server)
                .await
                .unwrap()
                .unwrap();
            drop(runtime);
            owner.close().await.unwrap();
            assert_eq!(budget.used(), 0);
        }
    }
}

#[tokio::test]
async fn split_dns_home_io_wrong_peer_source_bind_and_unfunded_work_never_prepare() {
    let budget = Arc::new(BufferBudget::new(CAPABILITY_BYTES));
    let owner = HomeIoOwner::new(budget.clone());
    let target = "127.0.0.1:53".parse().unwrap();
    let capability = Arc::new(FixtureCapability::new(target));
    let runtime = owner.with_capability(capability.clone()).unwrap();
    assert!(
        runtime
            .bind_udp(
                "0.0.0.0:0".parse().unwrap(),
                "127.0.0.2:53".parse().unwrap()
            )
            .await
            .is_err()
    );
    assert!(
        runtime
            .bind_udp("127.0.0.1:0".parse().unwrap(), target)
            .await
            .is_err()
    );
    assert!(
        runtime
            .connect_tcp(target, Some("0.0.0.0:0".parse().unwrap()), None)
            .await
            .is_err()
    );
    assert!(
        runtime
            .bind_udp("0.0.0.0:0".parse().unwrap(), target)
            .await
            .is_err()
    );
    assert!(runtime.connect_tcp(target, None, None).await.is_err());
    assert_eq!(capability.prepared.load(SeqCst), 0);
    drop(runtime);
    owner.close().await.unwrap();
    assert_eq!(budget.used(), 0);
}

#[tokio::test]
async fn split_dns_home_io_revoked_udp_and_tcp_cannot_send_or_return_bytes() {
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target = udp.local_addr().unwrap();
    let budget = Arc::new(BufferBudget::new(65536));
    let owner = HomeIoOwner::new(budget.clone());
    let capability = Arc::new(FixtureCapability::new(target));
    let runtime = owner.with_capability(capability.clone()).unwrap();
    let socket = runtime
        .bind_udp("0.0.0.0:0".parse().unwrap(), target)
        .await
        .unwrap();
    capability.live.store(false, SeqCst);
    assert_eq!(
        socket.send_to(b"denied", target).await.unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );
    let mut bytes = [0; 16];
    assert_eq!(
        socket.recv_from(&mut bytes).await.unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );
    assert!(udp.try_recv_from(&mut bytes).is_err());
    drop(socket);
    drop(runtime);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = listener.local_addr().unwrap();
    let capability = Arc::new(FixtureCapability::new(target));
    let runtime = owner.with_capability(capability.clone()).unwrap();
    let mut socket = runtime
        .connect_tcp(target, None, Some(Duration::from_secs(2)))
        .await
        .unwrap();
    let (_peer, _) = listener.accept().await.unwrap();
    capability.live.store(false, SeqCst);
    assert_eq!(
        socket.write_all(b"denied").await.unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );
    assert_eq!(
        futures::io::AsyncReadExt::read(&mut socket, &mut bytes)
            .await
            .unwrap_err()
            .kind(),
        io::ErrorKind::PermissionDenied
    );
    drop(socket);
    drop(runtime);
    owner.close().await.unwrap();
    assert_eq!(budget.used(), 0);
}

#[tokio::test]
async fn split_dns_home_io_cancelled_waiter_still_joins_preparation_and_refunds_credit() {
    let budget = Arc::new(BufferBudget::new(65536));
    let owner = HomeIoOwner::new(budget.clone());
    let target = "127.0.0.1:53".parse().unwrap();
    let barrier = Arc::new((Mutex::new(false), Condvar::new()));
    let release = ReleaseBarrier(barrier.clone());
    let capability = Arc::new(FixtureCapability {
        barrier: Some(barrier.clone()),
        ..FixtureCapability::new(target)
    });
    let runtime = owner.with_capability(capability.clone()).unwrap();
    let waiter =
        tokio::spawn(async move { runtime.bind_udp("0.0.0.0:0".parse().unwrap(), target).await });
    capability.started.notified().await;
    waiter.abort();
    assert!(matches!(waiter.await, Err(error) if error.is_cancelled()));
    assert!(budget.used() >= PREPARATION_BYTES + CAPABILITY_BYTES);
    assert!(
        tokio::time::timeout(Duration::from_millis(20), owner.close())
            .await
            .is_err(),
        "close returned before blocking preparation joined"
    );
    assert!(owner.with_capability(capability.clone()).is_err());
    drop(release);
    tokio::time::timeout(Duration::from_secs(2), owner.close())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(budget.used(), 0);
}

#[tokio::test]
async fn split_dns_home_io_slow_preparation_does_not_serialize_an_independent_exchange() {
    let budget = Arc::new(BufferBudget::new(
        2 * (CAPABILITY_BYTES + PREPARATION_BYTES),
    ));
    let owner = HomeIoOwner::new(budget.clone());
    let barrier = Arc::new((Mutex::new(false), Condvar::new()));
    let release = ReleaseBarrier(barrier.clone());
    let slow = Arc::new(FixtureCapability {
        barrier: Some(barrier.clone()),
        ..FixtureCapability::new("127.0.0.1:53".parse().unwrap())
    });
    let runtime = owner.with_capability(slow.clone()).unwrap();
    let waiter = tokio::spawn(async move {
        runtime
            .bind_udp(
                "0.0.0.0:0".parse().unwrap(),
                "127.0.0.1:53".parse().unwrap(),
            )
            .await
    });
    slow.started.notified().await;
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target = socket.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut bytes = [0; 1024];
        let (length, from) = socket.recv_from(&mut bytes).await.unwrap();
        socket
            .send_to(
                &answer(Message::from_vec(&bytes[..length]).unwrap())
                    .to_vec()
                    .unwrap(),
                from,
            )
            .await
            .unwrap();
    });
    let fast = owner
        .with_capability(Arc::new(FixtureCapability::new(target)))
        .unwrap();
    let request = question();
    let result = exchange(
        fast,
        target,
        Protocol::Udp,
        Duration::from_secs(2),
        request.clone(),
    )
    .await
    .unwrap();
    assert_eq!(result.into_message(), answer(request));
    server.await.unwrap();
    slow.live.store(false, SeqCst);
    drop(release);
    assert!(
        matches!(waiter.await.unwrap(), Err(error) if error.kind() == io::ErrorKind::PermissionDenied)
    );
    owner.close().await.unwrap();
    assert_eq!(budget.used(), 0);
}

#[tokio::test]
async fn split_dns_home_io_panicked_preparation_remains_failed_after_join_and_refunds_credit() {
    let budget = Arc::new(BufferBudget::new(65536));
    let owner = HomeIoOwner::new(budget.clone());
    let target = "127.0.0.1:53".parse().unwrap();
    let runtime = owner
        .with_capability(Arc::new(PanickingCapability(FixtureCapability::new(
            target,
        ))))
        .unwrap();
    assert!(
        runtime
            .bind_udp("0.0.0.0:0".parse().unwrap(), target)
            .await
            .is_err()
    );
    drop(runtime);
    assert!(owner.close().await.is_err());
    assert!(owner.close().await.is_err(), "joined panic was forgotten");
    assert!(
        owner
            .with_capability(Arc::new(FixtureCapability::new(target)))
            .is_err()
    );
    assert_eq!(budget.used(), 0);
}
