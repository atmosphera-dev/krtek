//! The result of one actual managed Android configuration operation.
#[cfg(unix)]
use super::AndroidTunConfig;
use crate::packet_attachment::AttachmentError;
#[cfg(unix)]
use std::os::fd::OwnedFd;
use std::{io, net::IpAddr, sync::Arc};

#[derive(Clone, Debug, thiserror::Error)]
pub enum ConfigurationError {
    #[error("Invalid DNS servers: {0:?}")]
    InvalidDnsServers(Vec<IpAddr>),
    #[error("Invalid IPv6 configuration")]
    InvalidIpv6Config {
        addresses: Vec<IpAddr>,
        routes: Vec<ipnetwork::IpNetwork>,
        dns_servers: Vec<IpAddr>,
    },
    #[error("VPN profile not prepared")]
    NotPrepared,
    #[error("Another legacy VPN is always on")]
    OtherLegacyAlwaysOnVpn,
    #[error("Another VPN app is always on: {app_name}")]
    OtherAlwaysOnApp { app_name: String },
    #[error("Failed to establish the tunnel device")]
    Establish,
    #[error("Routes timed out")]
    RoutesTimedOut,
    #[error("Owned VPN network observation unavailable")]
    ObservationUnavailable,
    #[error("Owned VPN network observation failed")]
    Observation(#[source] Arc<io::Error>),
    #[error(transparent)]
    Attachment(#[from] AttachmentError),
    #[error("Platform configuration failed")]
    Platform(#[source] Arc<io::Error>),
}

impl From<io::Error> for ConfigurationError {
    fn from(error: io::Error) -> Self {
        error
            .get_ref()
            .and_then(|e| e.downcast_ref::<Self>())
            .cloned()
            .or_else(|| {
                error
                    .get_ref()
                    .and_then(|e| e.downcast_ref::<AttachmentError>())
                    .copied()
                    .map(Self::Attachment)
            })
            .unwrap_or_else(|| Self::Platform(Arc::new(error)))
    }
}

/// The platform transfers the descriptor only after every fallible result getter.
/// A rejected configuration can still have established a safe capture. Its typed
/// cause and applied fields must travel with that same descriptor, never a cache.
#[cfg(unix)]
pub struct AppliedTun {
    pub fd: OwnedFd,
    pub profile: Option<AndroidTunConfig>,
    pub cause: Option<ConfigurationError>,
}

#[cfg(unix)]
impl From<OwnedFd> for AppliedTun {
    fn from(fd: OwnedFd) -> Self {
        Self {
            fd,
            profile: None,
            cause: None,
        }
    }
}

#[cfg(unix)]
impl std::os::fd::AsFd for AppliedTun {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigurationPurpose {
    Target,
    Blocking,
    ForcedRefresh,
}
