//! Inactive split-DNS transport contracts. Live capture does not select these
//! transports until the complete authority/configuration integration is ready.

mod transport;

#[cfg(test)]
#[path = "../../../test/scripts/split_dns_fixture.rs"]
mod fixture;
