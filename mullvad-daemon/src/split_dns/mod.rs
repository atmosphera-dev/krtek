//! Selective full-capture UDP DNS with Home-only transports. Partial forwarding
//! and the per-message TCP frontend are separate integration milestones.

mod transport;
mod udp;
mod udp_work;

pub(crate) mod home_path;
mod local_path;

pub(crate) mod home_io;

pub(crate) mod capture;
/// Production selection for run 11. Message consumers receive only the path
/// interface; a later Home WireGuard path does not change their routing logic.
pub(crate) fn local_home_path(
    authority: std::sync::Arc<crate::local_delivery::DeliveryAuthority>,
    buffers: std::sync::Arc<dyn talpid_types::relay_flow::RelayBufferAllocator>,
) -> std::sync::Arc<dyn home_path::HomeDnsPath> {
    std::sync::Arc::new(local_path::LocalHomeDnsPath::new(authority, buffers))
}
#[cfg(test)]
pub(crate) use transport::{ExchangeError, Protocol, decode_message};

#[cfg(test)]
#[path = "../../../test/scripts/split_dns_fixture.rs"]
mod fixture;

#[cfg(test)]
#[path = "../../../test/scripts/split_dns_server.rs"]
mod fixture_server;
