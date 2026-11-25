//! Partial Ordinary authority, separate from both Home grants and tunnel
//! admission. Every query and I/O reads Android's current lockdown state.
use super::{
    home_io::{Capability, HomeIoOwner, HomeRuntime},
    response::failure,
    transport::{self, ExchangeError, Protocol},
};
use std::{
    io,
    net::SocketAddr,
    os::fd::AsRawFd,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use talpid_lan_forwarder::ReceiveScope;
use talpid_tunnel::android_frontend::FrontendPlatform;
use talpid_types::relay_flow::{RelayCapture, RelaySink};

pub(super) struct SystemIo {
    platform: Arc<dyn FrontendPlatform>,
    pub(super) partial: Arc<AtomicBool>,
    pub(super) io: HomeIoOwner,
}
impl SystemIo {
    pub(super) fn new(
        platform: Arc<dyn FrontendPlatform>,
        buffers: Arc<dyn talpid_types::relay_flow::RelayBufferAllocator>,
    ) -> Self {
        Self {
            platform,
            partial: Arc::new(AtomicBool::new(false)),
            io: HomeIoOwner::new(buffers),
        }
    }
    pub(super) fn is_partial(&self) -> bool {
        self.partial.load(Ordering::Acquire)
    }
    pub(super) fn authorize(
        &self,
        resolver: SocketAddr,
        tcp: bool,
        scope: ReceiveScope,
        capture: RelayCapture,
    ) -> Result<Arc<SystemQuery>, ExchangeError> {
        SystemQuery::authorize(
            self.platform.clone(),
            resolver,
            tcp,
            scope,
            capture,
            self.partial.clone(),
        )
    }
}

pub(super) struct SystemQuery {
    platform: Arc<dyn FrontendPlatform>,
    authority: Authority,
    destination: SocketAddr,
    tcp: bool,
    scope: ReceiveScope,
    capture: RelayCapture,
    sink: RelaySink,
    partial: Arc<AtomicBool>,
    live: AtomicBool,
}

enum Authority {
    Network(i64),
    Ambiguous(i64),
}
impl Capability for SystemQuery {
    fn destination(&self) -> SocketAddr {
        self.destination
    }
    fn permits(&self, tcp: bool) -> bool {
        matches!(self.authority, Authority::Network(_)) && tcp == self.tcp
    }
    fn current(&self) -> bool {
        self.current()
    }
    fn prepare(&self, socket: &socket2::Socket) -> io::Result<()> {
        let Authority::Network(token) = self.authority else {
            return Err(io::ErrorKind::PermissionDenied.into());
        };
        if !self.current() {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        self.platform
            .prepare_system_dns(socket.as_raw_fd(), token)?;
        if self.current() {
            Ok(())
        } else {
            Err(io::ErrorKind::PermissionDenied.into())
        }
    }
}
impl SystemQuery {
    pub(super) fn authorize(
        platform: Arc<dyn FrontendPlatform>,
        resolver: SocketAddr,
        tcp: bool,
        scope: ReceiveScope,
        capture: RelayCapture,
        partial: Arc<AtomicBool>,
    ) -> Result<Arc<Self>, ExchangeError> {
        if resolver.port() != 53 {
            return Err(ExchangeError::Closed);
        }
        let mut destination = resolver;
        let authority = if let Some(snapshot) = platform.system_dns() {
            if !snapshot.dns_servers.contains(&resolver.ip()) {
                return Err(ExchangeError::Closed);
            }
            if let SocketAddr::V6(address) = &mut destination
                && address.ip().is_unicast_link_local()
            {
                let index = u32::try_from(snapshot.interface_index)
                    .ok()
                    .filter(|index| *index != 0)
                    .ok_or(ExchangeError::Closed)?;
                address.set_scope_id(index);
            }
            Authority::Network(snapshot.token)
        } else {
            let token = platform.system_dns_failure_token();
            if token <= 0 {
                return Err(ExchangeError::Closed);
            }
            Authority::Ambiguous(token)
        };
        let sink = capture.sink().ok_or(ExchangeError::Closed)?;
        if scope.destination() != resolver.ip() || !sink.identity().sources.contains(scope.source())
        {
            return Err(ExchangeError::Closed);
        }
        let query = Arc::new(Self {
            platform,
            authority,
            destination,
            tcp,
            scope,
            capture,
            sink,
            partial,
            live: AtomicBool::new(true),
        });
        if query.current() {
            Ok(query)
        } else {
            Err(ExchangeError::Closed)
        }
    }
    pub(super) fn current(&self) -> bool {
        let current = self.live.load(Ordering::Acquire)
            && self.partial.load(Ordering::Acquire)
            && self.scope.current()
            && self.capture.current()
            && self
                .capture
                .sink()
                .is_some_and(|sink| sink.same_sink(&self.sink))
            && match self.authority {
                Authority::Network(token) => self.platform.system_dns_current(token),
                Authority::Ambiguous(token) => self.platform.system_dns_failure_token() == token,
            };
        if !current {
            self.live.store(false, Ordering::Release);
        }
        current
    }
    pub(super) async fn exchange(
        self: &Arc<Self>,
        owner: &HomeIoOwner,
        bytes: Vec<u8>,
    ) -> Result<Vec<u8>, ExchangeError> {
        if !self.current() {
            return Err(ExchangeError::Closed);
        }
        if matches!(self.authority, Authority::Ambiguous(_)) {
            use hickory_proto::op::{MessageType, ResponseCode};
            let request = transport::decode_message(&bytes)?;
            if request.metadata.message_type != MessageType::Query {
                return Err(ExchangeError::Malformed);
            }
            let bytes = failure(&request, ResponseCode::ServFail)?;
            return if self.current() {
                Ok(bytes)
            } else {
                Err(ExchangeError::Closed)
            };
        }
        let runtime: HomeRuntime = owner.with_capability(self.clone())?;
        let reply = transport::exchange_bytes(
            runtime,
            self.destination,
            if self.tcp {
                Protocol::Tcp
            } else {
                Protocol::Udp
            },
            Duration::from_secs(5),
            bytes,
        )
        .await?;
        if !self.current() {
            return Err(ExchangeError::Closed);
        }
        Ok(reply.as_buffer().to_vec())
    }
}

#[cfg(test)]
#[path = "system_tests.rs"]
pub(crate) mod tests;
