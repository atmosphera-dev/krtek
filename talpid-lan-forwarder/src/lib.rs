//! Local TCP and UDP delivery from raw application IP packets.
//!
//! Policy and physical-network selection belong to the consumer's injected
//! authority. This library must never select a network or fall back to an
//! unprepared socket. It has no Android or daemon dependencies.
//!
//! Pinned stock lwIP completes canonical IPv4/IPv6 Local TCP and UDP input.
//! Incomplete IP state never authorizes a flow. Rust validates complete transport
//! checksums before admission; smoltcp retains TCP and native UDP builds replies.
//! Extension-prefixed transport, atomic IPv6 Fragment input and ICMP are unsupported.
//!
//! The authority triages `Local` or `Drop`, authorizes the original tuple and
//! prepares every physical socket off the owner task. Preparation failure never
//! connects an unbound socket. Grants accompany queued data through the final
//! synchronous `Forwarder::write_output` sink write, including WouldBlock
//! retries. `Forwarder::wait` observes internal progress only; select sink
//! writability separately while `Forwarder::has_output` is true.
//! Update authority inputs before signalling revalidation; join
//! `Forwarder::close_all` before acknowledging shutdown to the consumer.
//! Construction requires the runtime's shared storage allocator. Admission
//! reserves fixed per-flow ingress/ring/task credit; output and capture working
//! space are precharged separately so earlier flows can progress under pressure.

pub mod authority;
#[cfg(feature = "r06-diagnostics")]
pub mod diagnostics;
#[cfg(test)]
mod dns_candidate_tests;
mod forwarder;
mod ip_endpoint;
pub mod packet;
pub mod packet_receiver;
pub mod tcp_service;

pub use authority::{Disposition, LocalAuthority, ReceiveScope, Refused};
pub use forwarder::{Forwarder, MAX_SUPPORTED_MTU, MIN_SUPPORTED_MTU, Stats, validate_mtu};
pub use packet::{Flow, Transport};
