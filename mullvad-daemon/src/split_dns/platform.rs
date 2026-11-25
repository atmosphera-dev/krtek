//! DNS dispatch owned by the managed capture frontend.
use super::{home_io, transport};

#[path = "capture.rs"]
pub(crate) mod capture;
#[path = "home_path.rs"]
pub(crate) mod home_path;
#[path = "local_path.rs"]
mod local_path;
#[path = "response.rs"]
mod response;
#[path = "system.rs"]
mod system;
#[path = "tcp.rs"]
mod tcp;
#[path = "tcp_egress.rs"]
mod tcp_egress;
#[path = "tcp_io.rs"]
mod tcp_io;
#[path = "udp.rs"]
mod udp;
#[path = "udp_work.rs"]
mod udp_work;

#[cfg(test)]
use super::fixture;
#[cfg(test)]
#[path = "../../../test/scripts/split_dns_server.rs"]
mod fixture_server;

/// Production selection for run 11. Message consumers receive only the path
/// interface; a later Home WireGuard path does not change their routing logic.
pub(crate) fn local_home_path(
    authority: std::sync::Arc<crate::local_delivery::DeliveryAuthority>,
    buffers: std::sync::Arc<dyn talpid_types::relay_flow::RelayBufferAllocator>,
) -> std::sync::Arc<dyn home_path::HomeDnsPath> {
    std::sync::Arc::new(local_path::LocalHomeDnsPath::new(authority, buffers))
}
