//! Actual unprotected kernel TCP sockets, registered before SYN emission. Only
//! DNS interception is skipped; the existing IP policy still routes each packet.
use std::{
    collections::LinkedList,
    io,
    net::SocketAddr,
    sync::{Arc, Mutex, Weak},
    task::{Context, Poll},
};
use talpid_lan_forwarder::{Flow, ReceiveScope, tcp_service::TcpChannel};
use talpid_types::relay_flow::{
    RelayBufferAllocator, RelayBufferReservation, RelayCapture, RelaySocketContext, RelayTargetId,
};
use tokio::net::TcpStream;

#[derive(Default)]
pub(super) struct Registry(Mutex<LinkedList<Registration>>);
struct Registration {
    socket: Weak<OwnedTcp>,
    _charge: Arc<dyn RelayBufferReservation>,
}

pub(super) struct OwnedTcp {
    pub(super) flow: Flow,
    socket: TcpStream,
    scope: ReceiveScope,
    context: RelaySocketContext,
    _charge: Arc<dyn RelayBufferReservation>,
}

impl Registry {
    pub(super) fn prune(&self) {
        let mut sockets = self.0.lock().unwrap();
        for _ in 0..sockets.len() {
            let socket = sockets.pop_front().unwrap();
            if let Some(owned) = socket.socket.upgrade() {
                if !owned.current() {
                    let _ =
                        socket2::SockRef::from(&owned.socket).shutdown(std::net::Shutdown::Both);
                }
                sockets.push_back(socket);
            }
        }
    }
    /// Some(false) is a retired, still-owned socket, not a client query and
    /// not permission to route into a successor target. Closing bytes stay out
    /// of the DNS parser even when split DNS has just been disabled.
    pub(super) fn route(&self, flow: Flow) -> Option<bool> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .filter_map(|entry| entry.socket.upgrade())
            .find(|socket| socket.flow == flow)
            .map(|socket| {
                let current = socket.current();
                if !current {
                    let _ =
                        socket2::SockRef::from(&socket.socket).shutdown(std::net::Shutdown::Both);
                }
                current
            })
    }
    pub(super) fn owns(&self, flow: Flow) -> bool {
        self.route(flow) == Some(true)
    }
    pub(super) async fn connect(
        &self,
        source: SocketAddr,
        resolver: SocketAddr,
        scope: ReceiveScope,
        capture: RelayCapture,
        buffers: &dyn RelayBufferAllocator,
    ) -> io::Result<Arc<OwnedTcp>> {
        let context = capture
            .socket_context(RelayTargetId::MULLVAD)
            .ok_or(io::ErrorKind::PermissionDenied)?;
        let charge = buffers
            .try_reserve(16 * 1024)
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        let registration = buffers
            .try_reserve(size_of::<Registration>() + 512)
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        let socket = socket2::Socket::new(
            socket2::Domain::for_address(resolver),
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )?;
        // This is a source-address bind, never a protect() or underlying Network
        // bind. The socket itself owns the port; no reservation descriptor exists.
        if resolver.is_ipv6() {
            socket.set_only_v6(true)?;
        }
        socket.bind(&SocketAddr::new(source.ip(), 0).into())?;
        socket.set_nonblocking(true)?;
        socket.set_linger(Some(std::time::Duration::ZERO))?;
        let local = socket
            .local_addr()?
            .as_socket()
            .ok_or(io::ErrorKind::AddrNotAvailable)?;
        let owned = Arc::new(OwnedTcp {
            flow: Flow {
                source: local,
                destination: resolver,
                transport: talpid_lan_forwarder::Transport::Tcp,
            },
            socket: TcpStream::from_std(socket.into())?,
            scope,
            context,
            _charge: charge,
        });
        self.prune();
        {
            let mut sockets = self.0.lock().unwrap();
            sockets.push_back(Registration {
                socket: Arc::downgrade(&owned),
                _charge: registration,
            });
        }
        // Registry publication precedes connect: the SYN can reach TUN before
        // writable/connect completion. Never obtain a new target on a retry.
        let result = owned
            .with_current(|| socket2::SockRef::from(&owned.socket).connect(&resolver.into()))?;
        match result {
            Ok(()) => {}
            Err(error) if error.raw_os_error() == Some(libc::EINPROGRESS) => {
                owned.socket.writable().await?;
                if let Some(error) = owned.socket.take_error()? {
                    return Err(error);
                }
            }
            Err(error) => return Err(error),
        }
        owned.with_current(|| ())?;
        Ok(owned)
    }
}
impl OwnedTcp {
    pub(super) fn current(&self) -> bool {
        self.scope.current() && self.context.current()
    }
    fn with_current<T>(&self, operation: impl FnOnce() -> T) -> io::Result<T> {
        if !self.current() {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        self.context
            .with_current(|| {
                if !self.scope.current() {
                    return Err(io::ErrorKind::PermissionDenied.into());
                }
                Ok(operation())
            })
            .map_err(|_| io::Error::from(io::ErrorKind::PermissionDenied))?
    }
}
impl Drop for OwnedTcp {
    fn drop(&mut self) {
        let _ = socket2::SockRef::from(&self.socket).shutdown(std::net::Shutdown::Both);
    }
}

pub(super) struct Upstream(pub Arc<OwnedTcp>);
impl TcpChannel for Upstream {
    fn current(&self) -> bool {
        self.0.current()
    }
    fn try_read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.0.with_current(|| self.0.socket.try_read(bytes))?
    }
    fn try_write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.with_current(|| self.0.socket.try_write(bytes))?
    }
    fn shutdown(&mut self) -> io::Result<()> {
        socket2::SockRef::from(&self.0.socket).shutdown(std::net::Shutdown::Write)
    }
    fn abort(&mut self) {
        let _ = socket2::SockRef::from(&self.0.socket).shutdown(std::net::Shutdown::Both);
    }
    fn poll_read_ready(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.current() {
            return Poll::Ready(Err(io::ErrorKind::PermissionDenied.into()));
        }
        self.0.socket.poll_read_ready(cx)
    }
    fn poll_write_ready(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.current() {
            return Poll::Ready(Err(io::ErrorKind::PermissionDenied.into()));
        }
        self.0.socket.poll_write_ready(cx)
    }
}
