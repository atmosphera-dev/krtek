//! Exact Home-grant socket I/O. This is not an Ordinary carrier adapter.
//!
//! The owner retains blocking platform preparations until they join, including
//! when the waiting query is cancelled. Each I/O checks the same irreversible
//! capability. Nothing here selects another resolver or obtains a new grant.

use std::{
    future::{Future, poll_fn},
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Duration,
};

use futures::io::{AsyncRead, AsyncWrite};
use hickory_net::runtime::{
    DnsTcpStream, DnsUdpSocket, RuntimeProvider, TokioHandle, TokioTime,
    iocompat::AsyncIoTokioAsStd,
};
use talpid_types::relay_flow::{RelayBufferAllocator, RelayBufferReservation};
use tokio::{
    net::{TcpSocket, TcpStream, UdpSocket},
    sync::oneshot,
    task::JoinSet,
};

const PREPARATION_BYTES: usize = 16 * 1024;
const CAPABILITY_BYTES: usize = 4096;

/// Private injection seam: production construction below accepts only the
/// existing Home query grant, not an arbitrary physical resolver address.
trait Capability: Send + Sync {
    fn destination(&self) -> SocketAddr;
    fn permits(&self, tcp: bool) -> bool;
    fn current(&self) -> bool;
    fn prepare(&self, socket: &socket2::Socket) -> io::Result<()>;
}

struct HomeCapability {
    authority: Arc<crate::local_delivery::DeliveryAuthority>,
    grant: crate::local_delivery::home_dns::HomeDnsGrant,
}

impl Capability for HomeCapability {
    fn destination(&self) -> SocketAddr {
        self.grant.destination()
    }

    fn current(&self) -> bool {
        self.authority.home_dns_current(&self.grant)
    }

    fn permits(&self, tcp: bool) -> bool {
        (self.grant.transport() == talpid_lan_forwarder::Transport::Tcp) == tcp
    }

    fn prepare(&self, socket: &socket2::Socket) -> io::Result<()> {
        self.authority
            .home_dns_prepare(socket, &self.grant)
            .map_err(|_| revoked())
    }
}

fn revoked() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "Home DNS authority retired",
    )
}

#[derive(Default)]
struct Preparations {
    closed: bool,
    failed: bool,
    tasks: JoinSet<()>,
}

/// This is owned alongside the capture service, never by an individual waiter.
/// Closing is cancellation-safe: handles stay here until poll_join_next removes
/// their terminal result, not in a detached future's local JoinSet.
#[derive(Clone)]
pub(crate) struct HomeIoOwner {
    preparations: Arc<Mutex<Preparations>>,
    buffers: Arc<dyn RelayBufferAllocator>,
    closed: tokio::sync::watch::Sender<bool>,
}

impl HomeIoOwner {
    pub(crate) fn new(buffers: Arc<dyn RelayBufferAllocator>) -> Self {
        Self {
            preparations: Arc::default(),
            buffers,
            closed: tokio::sync::watch::channel(false).0,
        }
    }

    pub(crate) fn runtime(
        &self,
        authority: Arc<crate::local_delivery::DeliveryAuthority>,
        grant: crate::local_delivery::home_dns::HomeDnsGrant,
    ) -> io::Result<HomeRuntime> {
        self.with_capability(Arc::new(HomeCapability { authority, grant }))
    }

    /// Cancellation drops only nonblocking I/O. Blocking platform work remains
    /// in this owner and must be joined by close before capture-owner release.
    pub(crate) async fn exchange(
        &self,
        authority: Arc<crate::local_delivery::DeliveryAuthority>,
        grant: &crate::local_delivery::home_dns::HomeDnsGrant,
        timeout: Duration,
        message: hickory_proto::op::Message,
    ) -> Result<hickory_proto::op::DnsResponse, super::transport::ExchangeError> {
        let runtime = self.runtime(authority.clone(), grant.clone())?;
        let protocol = match grant.transport() {
            talpid_lan_forwarder::Transport::Udp => super::transport::Protocol::Udp,
            talpid_lan_forwarder::Transport::Tcp => super::transport::Protocol::Tcp,
        };
        let result = tokio::select! {
            biased;
            _ = authority.home_dns_retired(grant) => Err(revoked().into()),
            result = super::transport::exchange(runtime, grant.destination(), protocol, timeout, message) => result,
        };
        if authority.home_dns_current(grant) {
            result
        } else {
            Err(revoked().into())
        }
    }

    fn with_capability(&self, capability: Arc<dyn Capability>) -> io::Result<HomeRuntime> {
        if !capability.current() || self.preparations.lock().unwrap().closed {
            return Err(revoked());
        }
        let storage = self
            .buffers
            .try_reserve(CAPABILITY_BYTES)
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        Ok(HomeRuntime {
            capability,
            owner: self.clone(),
            _storage: storage,
        })
    }

    pub(crate) async fn close(&self) -> io::Result<()> {
        self.preparations.lock().unwrap().closed = true;
        self.closed.send_replace(true);
        while let Some(result) =
            poll_fn(|cx| self.preparations.lock().unwrap().tasks.poll_join_next(cx)).await
        {
            self.preparations.lock().unwrap().failed |= result.is_err();
        }
        if self.preparations.lock().unwrap().failed {
            Err(io::Error::other("Home DNS preparation panicked"))
        } else {
            Ok(())
        }
    }

    pub(crate) async fn closed(&self) {
        let mut closed = self.closed.subscribe();
        while !*closed.borrow_and_update() {
            if closed.changed().await.is_err() {
                break;
            }
        }
    }

    async fn prepare(&self, runtime: HomeRuntime, tcp: bool) -> io::Result<socket2::Socket> {
        runtime.check(runtime.capability.destination())?;
        if !runtime.capability.permits(tcp) {
            return Err(revoked());
        }
        let charge = self
            .buffers
            .try_reserve(PREPARATION_BYTES)
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        let (sender, receiver) = oneshot::channel();
        {
            let mut owned = self.preparations.lock().unwrap();
            if owned.closed {
                return Err(revoked());
            }
            // Reap completed work without losing a failed preparation's outcome.
            while let Some(result) = owned.tasks.try_join_next() {
                owned.failed |= result.is_err();
            }
            if owned.failed {
                return Err(io::Error::other("Home DNS preparation panicked"));
            }
            owned.tasks.spawn_blocking(move || {
                // Credit and grant outlive a dropped/cancelled query receiver.
                let _charge = charge;
                let result = (|| {
                    let target = runtime.capability.destination();
                    runtime.check(target)?;
                    let socket = socket2::Socket::new(
                        socket2::Domain::for_address(target),
                        if tcp {
                            socket2::Type::STREAM
                        } else {
                            socket2::Type::DGRAM
                        },
                        Some(if tcp {
                            socket2::Protocol::TCP
                        } else {
                            socket2::Protocol::UDP
                        }),
                    )?;
                    runtime.capability.prepare(&socket)?;
                    runtime.check(target)?;
                    socket.set_nonblocking(true)?;
                    Ok(socket)
                })();
                let _ = sender.send(result);
            });
        }
        receiver.await.map_err(io::Error::other)?
    }
}

#[derive(Clone)]
pub(crate) struct HomeRuntime {
    capability: Arc<dyn Capability>,
    owner: HomeIoOwner,
    // All clones and sockets retain one capability allocation, not N copies.
    _storage: Arc<dyn RelayBufferReservation>,
}

impl HomeRuntime {
    pub(crate) fn current(&self) -> bool {
        self.check(self.capability.destination()).is_ok()
    }

    fn check(&self, server: SocketAddr) -> io::Result<()> {
        if self.capability.current()
            && !self.owner.preparations.lock().unwrap().closed
            && server == self.capability.destination()
        {
            Ok(())
        } else {
            Err(revoked())
        }
    }
}

impl RuntimeProvider for HomeRuntime {
    // The low-level exchange uses neither create_handle nor spawn_bg. Hickory's
    // stream is polled in the query task itself, not a resolver background task.
    type Handle = TokioHandle;
    type Timer = TokioTime;
    type Udp = HomeUdp;
    type Tcp = HomeTcp;

    fn create_handle(&self) -> Self::Handle {
        TokioHandle::default()
    }

    fn connect_tcp(
        &self,
        server: SocketAddr,
        bind: Option<SocketAddr>,
        timeout: Option<Duration>,
    ) -> Pin<Box<dyn Future<Output = io::Result<HomeTcp>> + Send>> {
        let runtime = self.clone();
        Box::pin(async move {
            runtime.check(server)?;
            if bind.is_some() {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            let socket = runtime.owner.prepare(runtime.clone(), true).await?;
            runtime.check(server)?;
            socket.set_tcp_nodelay(true)?;
            let socket = TcpSocket::from_std_stream(socket.into());
            let connect = socket.connect(server);
            let socket = match timeout {
                Some(limit) => tokio::time::timeout(limit, connect)
                    .await
                    .map_err(|_| io::ErrorKind::TimedOut)??,
                None => connect.await?,
            };
            runtime.check(server)?;
            Ok(HomeTcp {
                socket: AsyncIoTokioAsStd(socket),
                runtime,
            })
        })
    }

    fn bind_udp(
        &self,
        local: SocketAddr,
        server: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = io::Result<HomeUdp>> + Send>> {
        let runtime = self.clone();
        Box::pin(async move {
            runtime.check(server)?;
            if !local.ip().is_unspecified()
                || local.port() != 0
                || local.is_ipv6() != server.is_ipv6()
            {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            let socket = runtime.owner.prepare(runtime.clone(), false).await?;
            runtime.check(server)?;
            // Only an ephemeral source bind. The platform has already protected
            // and bound this socket to the exact grant's physical network.
            socket.bind(&local.into())?;
            let socket = UdpSocket::from_std(socket.into())?;
            Ok(HomeUdp { socket, runtime })
        })
    }
}

pub(crate) struct HomeUdp {
    socket: UdpSocket,
    runtime: HomeRuntime,
}

impl DnsUdpSocket for HomeUdp {
    type Time = TokioTime;

    fn poll_send_to(
        &self,
        cx: &mut Context<'_>,
        bytes: &[u8],
        target: SocketAddr,
    ) -> Poll<io::Result<usize>> {
        self.runtime.check(target)?;
        let result = self.socket.poll_send_to(cx, bytes, target);
        self.runtime.check(target)?;
        result
    }

    fn poll_recv_from(
        &self,
        cx: &mut Context<'_>,
        bytes: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>> {
        let server = self.runtime.capability.destination();
        self.runtime.check(server)?;
        let mut buffer = tokio::io::ReadBuf::new(bytes);
        let result = self.socket.poll_recv_from(cx, &mut buffer);
        self.runtime.check(server)?;
        result.map_ok(|peer| (buffer.filled().len(), peer))
    }
}

pub(crate) struct HomeTcp {
    socket: AsyncIoTokioAsStd<TcpStream>,
    runtime: HomeRuntime,
}

impl DnsTcpStream for HomeTcp {
    type Time = TokioTime;
}

impl AsyncRead for HomeTcp {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let server = self.runtime.capability.destination();
        self.runtime.check(server)?;
        let result = Pin::new(&mut self.socket).poll_read(cx, bytes);
        self.runtime.check(server)?;
        result
    }
}

impl AsyncWrite for HomeTcp {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let server = self.runtime.capability.destination();
        self.runtime.check(server)?;
        let result = Pin::new(&mut self.socket).poll_write(cx, bytes);
        self.runtime.check(server)?;
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.runtime.check(self.runtime.capability.destination())?;
        Pin::new(&mut self.socket).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Shutdown releases an existing descriptor; it never authorizes data.
        Pin::new(&mut self.socket).poll_close(cx)
    }
}

#[cfg(test)]
#[path = "home_io_tests.rs"]
mod tests;
