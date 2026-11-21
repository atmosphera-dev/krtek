//! Inactive split-DNS transport contracts. Live capture does not select these
//! transports until the complete authority/configuration integration is ready.

mod transport;

#[cfg(test)]
pub(crate) mod home_io;

#[cfg(test)]
#[path = "../../../test/scripts/split_dns_fixture.rs"]
mod fixture;

#[cfg(test)]
#[path = "../../../test/scripts/split_dns_server.rs"]
mod fixture_server;
