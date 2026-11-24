//! Keep both Hickory transports under the same route grant.
use futures::io::{AsyncRead, AsyncWrite};
use hickory_net::runtime::{
    DnsTcpStream, DnsUdpSocket, RuntimeProvider, TokioHandle, TokioRuntimeProvider, TokioTime,
    iocompat::AsyncIoTokioAsStd,
};
use mullvad_types::states::TargetState;
use std::{
    future::{Future, poll_fn},
    io,
    net::{IpAddr, SocketAddr},
    os::fd::{AsFd, BorrowedFd},
    pin::Pin,
    sync::{Arc, Mutex, RwLock},
    task::{Context, Poll},
    time::Duration,
};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};

fn unavailable() -> io::Error {
    io::Error::new(io::ErrorKind::NotConnected, "Android DNS route unavailable")
}

#[derive(Clone, Copy)]
enum Route {
    Upstream,
    Idle(i64),
    Physical {
        epoch: i64,
        token: i64,
        interface: u32,
    },
}

/// Read-only projection of the daemon's existing target-state owner.
#[derive(Clone)]
pub(crate) struct DnsTarget(Arc<RwLock<(TargetState, u64)>>);

impl DnsTarget {
    pub(crate) fn new(target: TargetState) -> Self {
        Self(Arc::new(RwLock::new((target, 0))))
    }

    pub(crate) fn publish(&self, target: TargetState) {
        let mut state = self.0.write().unwrap();
        if state.0 != target {
            *state = (target, state.1 + 1);
        }
    }
}

pub(super) struct PhysicalDns {
    pub token: i64,
    pub interface: u32,
    pub servers: Vec<IpAddr>,
}

pub(super) trait DnsPlatform: Clone + Send + Sync + Unpin + 'static {
    fn with_capture<T>(&self, action: impl FnOnce(i64) -> io::Result<T>) -> io::Result<T>;
    fn physical_dns(&self) -> io::Result<Option<PhysicalDns>>;
    fn own_socket(&self, epoch: i64, token: i64, fd: Option<BorrowedFd<'_>>) -> io::Result<bool>;
}

#[derive(Clone)]
pub(super) struct DnsRuntime<P> {
    upstream: TokioRuntimeProvider,
    platform: P,
    target: DnsTarget,
    target_epoch: u64,
    route: Route,
}

impl<P: DnsPlatform> DnsRuntime<P> {
    pub fn select(
        platform: P,
        target: DnsTarget,
        default_servers: impl FnOnce() -> io::Result<Vec<IpAddr>>,
    ) -> io::Result<(Self, Vec<IpAddr>)> {
        let (state, target_epoch) = *target.0.read().unwrap();
        let (route, servers) = if state == TargetState::Secured {
            (Route::Upstream, default_servers()?)
        } else {
            platform.with_capture(|epoch| match epoch {
                1.. => Ok((Route::Idle(epoch), default_servers()?)),
                ..0 => {
                    let physical = platform
                        .physical_dns()?
                        .filter(|snapshot| !snapshot.servers.is_empty())
                        .ok_or_else(unavailable)?;
                    Ok((
                        Route::Physical {
                            epoch,
                            token: physical.token,
                            interface: physical.interface,
                        },
                        physical.servers,
                    ))
                }
                0 => Err(unavailable()),
            })?
        };
        Ok((
            Self {
                upstream: TokioRuntimeProvider::default(),
                platform,
                target,
                target_epoch,
                route,
            },
            servers,
        ))
    }

    pub fn run<T>(&self, action: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
        let target = self.target.0.read().unwrap();
        if target.1 != self.target_epoch {
            return Err(unavailable());
        }
        match self.route {
            Route::Upstream => action(),
            Route::Idle(expected) => self.platform.with_capture(|epoch| {
                if epoch == expected {
                    action()
                } else {
                    Err(unavailable())
                }
            }),
            Route::Physical { token, .. } => self.platform.with_capture(|current| {
                // A capture handover does not change the binding of a prepared socket.
                // The current owner must still allow physical DNS, and the original
                // network token must still be live. Check both before polling I/O.
                if current >= 0 {
                    return Err(unavailable());
                }
                self.check_socket(current, token, None)?;
                action()
            }),
        }
    }

    fn poll_socket<S, T>(
        &self,
        socket: &mut Option<S>,
        action: impl FnOnce(&mut S) -> Poll<io::Result<T>>,
    ) -> Poll<io::Result<T>> {
        let live = socket.as_mut().ok_or_else(unavailable)?;
        match self.run(|| Ok(action(live))) {
            Ok(poll) => poll,
            Err(err) => {
                if matches!(self.route, Route::Physical { .. }) {
                    // No later poll can revive a socket after authority rejected it.
                    *socket = None;
                }
                Poll::Ready(Err(err))
            }
        }
    }

    fn check_socket(&self, epoch: i64, token: i64, fd: Option<BorrowedFd<'_>>) -> io::Result<()> {
        if self.platform.own_socket(epoch, token, fd)? {
            Ok(())
        } else {
            Err(unavailable())
        }
    }

    fn scoped(&self, mut address: SocketAddr) -> SocketAddr {
        if let (Route::Physical { interface, .. }, SocketAddr::V6(v6)) = (self.route, &mut address)
            && v6.ip().is_unicast_link_local()
        {
            v6.set_scope_id(interface);
        }
        address
    }

    async fn guarded<F, T>(&self, future: F) -> io::Result<T>
    where
        F: Future<Output = io::Result<T>>,
    {
        let mut future = std::pin::pin!(future);
        poll_fn(|cx| self.run(|| Ok(future.as_mut().poll(cx)))?).await
    }
}

impl<P: DnsPlatform> RuntimeProvider for DnsRuntime<P> {
    type Handle = TokioHandle;
    type Timer = TokioTime;
    type Udp = DnsUdp<P>;
    type Tcp = DnsTcp<P>;

    fn create_handle(&self) -> TokioHandle {
        self.upstream.create_handle()
    }

    fn connect_tcp(
        &self,
        server: SocketAddr,
        bind: Option<SocketAddr>,
        timeout: Option<Duration>,
    ) -> Pin<Box<dyn Future<Output = io::Result<DnsTcp<P>>> + Send>> {
        let runtime = self.clone();
        Box::pin(async move {
            let socket = if let Route::Physical { epoch, token, .. } = runtime.route {
                let socket = runtime.run(|| {
                    let socket = if server.is_ipv4() {
                        TcpSocket::new_v4()
                    } else {
                        TcpSocket::new_v6()
                    }?;
                    runtime.check_socket(epoch, token, Some(socket.as_fd()))?;
                    if let Some(bind) = bind {
                        socket.bind(bind)?;
                    }
                    socket.set_nodelay(true)?;
                    Ok(socket)
                })?;
                let connect = runtime.guarded(socket.connect(runtime.scoped(server)));
                let stream =
                    tokio::time::timeout(timeout.unwrap_or(Duration::from_secs(5)), connect)
                        .await
                        .map_err(|_| io::ErrorKind::TimedOut)??;
                AsyncIoTokioAsStd(stream)
            } else {
                runtime
                    .guarded(runtime.upstream.connect_tcp(server, bind, timeout))
                    .await?
            };
            Ok(DnsTcp {
                socket: Some(socket),
                runtime,
            })
        })
    }

    fn bind_udp(
        &self,
        local: SocketAddr,
        server: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = io::Result<DnsUdp<P>>> + Send>> {
        let runtime = self.clone();
        Box::pin(async move {
            let socket = if let Route::Physical { epoch, token, .. } = runtime.route {
                runtime.run(|| {
                    let socket = socket2::Socket::new(
                        socket2::Domain::for_address(local),
                        socket2::Type::DGRAM,
                        Some(socket2::Protocol::UDP),
                    )?;
                    socket.set_nonblocking(true)?;
                    runtime.check_socket(epoch, token, Some(socket.as_fd()))?;
                    socket.bind(&local.into())?;
                    UdpSocket::from_std(socket.into())
                })?
            } else {
                runtime
                    .guarded(runtime.upstream.bind_udp(local, server))
                    .await?
            };
            Ok(DnsUdp {
                socket: Mutex::new(Some(socket)),
                runtime,
            })
        })
    }
}

pub(super) struct DnsUdp<P> {
    // Hickory polls UDP via &self. Serialize the nonblocking poll and any fd drop.
    socket: Mutex<Option<UdpSocket>>,
    runtime: DnsRuntime<P>,
}

impl<P: DnsPlatform> DnsUdpSocket for DnsUdp<P> {
    type Time = TokioTime;

    fn poll_send_to(
        &self,
        cx: &mut Context<'_>,
        bytes: &[u8],
        server: SocketAddr,
    ) -> Poll<io::Result<usize>> {
        self.runtime
            .poll_socket(&mut self.socket.lock().unwrap(), |socket| {
                socket.poll_send_to(cx, bytes, self.runtime.scoped(server))
            })
    }

    fn poll_recv_from(
        &self,
        cx: &mut Context<'_>,
        bytes: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>> {
        self.runtime
            .poll_socket(&mut self.socket.lock().unwrap(), |socket| {
                DnsUdpSocket::poll_recv_from(socket, cx, bytes)
            })
    }
}

pub(super) struct DnsTcp<P> {
    socket: Option<AsyncIoTokioAsStd<TcpStream>>,
    runtime: DnsRuntime<P>,
}

impl<P: DnsPlatform> DnsTcpStream for DnsTcp<P> {
    type Time = TokioTime;
}

impl<P: DnsPlatform> AsyncRead for DnsTcp<P> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.runtime.poll_socket(&mut this.socket, |socket| {
            Pin::new(socket).poll_read(cx, bytes)
        })
    }
}

impl<P: DnsPlatform> AsyncWrite for DnsTcp<P> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.runtime.poll_socket(&mut this.socket, |socket| {
            Pin::new(socket).poll_write(cx, bytes)
        })
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.runtime
            .poll_socket(&mut this.socket, |socket| Pin::new(socket).poll_flush(cx))
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.socket.as_mut() {
            Some(socket) => Pin::new(socket).poll_close(cx),
            None => Poll::Ready(Ok(())),
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
#[path = "android_dns_io_tests.rs"]
mod tests;
