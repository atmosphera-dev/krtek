//! A selected Home path, independent of how that path reaches the user's DNS.
//!
//! Message routing has no Local grant, physical network or socket-preparation
//! capability. A path issues one irreversible query lease for one transport;
//! the consumer retains it through final emission and checks `current` there.
//! No available path is an error, never permission to use ordinary DNS.

use std::{future::Future, io, net::SocketAddr, pin::Pin, time::Duration};

use hickory_proto::op::{DnsResponse, Message};

use super::transport::{ExchangeError, Protocol};

pub(super) type PathFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub(super) trait HomeDnsPath: Send + Sync {
    /// `client` is the original captured source, not an upstream bind request.
    /// The path selects its configured Home resolver and authorizes the request.
    fn authorize(
        &self,
        client: SocketAddr,
        protocol: Protocol,
    ) -> Result<Box<dyn HomeDnsQuery>, ExchangeError>;

    /// Join path-owned preparation work before releasing the capture owner.
    /// Cancelling this future must not lose that ownership.
    fn close(&self) -> PathFuture<'_, io::Result<()>>;
}

pub(super) trait HomeDnsQuery: Send + Sync {
    fn current(&self) -> bool;
    fn retired(&self) -> PathFuture<'_, ()>;
    fn exchange(
        &self,
        timeout: Duration,
        message: Message,
    ) -> PathFuture<'_, Result<DnsResponse, ExchangeError>>;
}
