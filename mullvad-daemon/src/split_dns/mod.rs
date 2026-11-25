//! Selective UDP and per-message TCP DNS. Full capture keeps Android's resolver
//! list; Partial uses the original non-VPN resolvers with a separate OS gate.

pub(crate) mod home_io;
pub(crate) mod transport;

// Only Android and the Linux test harness supply a managed capture frontend.
// The portable DNS exchange and its tests do not depend on that frontend.
#[cfg(any(target_os = "android", all(test, target_os = "linux")))]
pub(crate) mod platform;

#[cfg(test)]
#[path = "../../../test/scripts/split_dns_fixture.rs"]
mod fixture;
