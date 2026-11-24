//! Run 11's Home path: existing eligible Local delivery, never an Ordinary exit.

use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use hickory_proto::op::{DnsResponse, Message};
use talpid_lan_forwarder::Transport;
use talpid_types::relay_flow::RelayBufferAllocator;

use crate::local_delivery::{
    DeliveryAuthority,
    home_dns::{DnsInput, HomeDnsGrant},
};

use super::{
    home_io::HomeIoOwner,
    home_path::{HomeDnsPath, HomeDnsQuery, PathFuture},
    transport::{ExchangeError, Protocol},
};

pub(super) struct LocalHomeDnsPath {
    authority: Arc<DeliveryAuthority>,
    buffers: Arc<dyn RelayBufferAllocator>,
    io: HomeIoOwner,
}

impl LocalHomeDnsPath {
    pub(super) fn new(
        authority: Arc<DeliveryAuthority>,
        buffers: Arc<dyn RelayBufferAllocator>,
    ) -> Self {
        Self {
            authority,
            io: HomeIoOwner::new(buffers.clone()),
            buffers,
        }
    }
}

impl HomeDnsPath for LocalHomeDnsPath {
    fn authorize(
        &self,
        input: &DnsInput,
        client: SocketAddr,
        protocol: Protocol,
    ) -> Result<Box<dyn HomeDnsQuery>, ExchangeError> {
        let transport = match protocol {
            Protocol::Udp => Transport::Udp,
            Protocol::Tcp => Transport::Tcp,
        };
        let grant = self
            .authority
            .home_dns_authorize_configured(input, client, transport, &*self.buffers)
            .map_err(|error| io::Error::other(format!("Home path refused: {error:?}")))?;
        // Owner closure and resource admission are checked before issuing a lease,
        // not delayed until the consumer first polls its exchange future.
        let runtime = self.io.runtime(self.authority.clone(), grant.clone())?;
        Ok(Box::new(LocalQuery {
            authority: self.authority.clone(),
            grant,
            io: self.io.clone(),
            runtime,
        }))
    }

    fn close(&self) -> PathFuture<'_, io::Result<()>> {
        Box::pin(self.io.close())
    }
}

struct LocalQuery {
    authority: Arc<DeliveryAuthority>,
    grant: HomeDnsGrant,
    io: HomeIoOwner,
    // Retain capability admission credit for the entire issued query lifetime.
    runtime: super::home_io::HomeRuntime,
}

impl HomeDnsQuery for LocalQuery {
    fn current(&self) -> bool {
        self.runtime.current() && self.authority.home_dns_current(&self.grant)
    }

    fn retired(&self) -> PathFuture<'_, ()> {
        Box::pin(async move {
            tokio::select! {
                _ = self.io.closed() => {},
                _ = self.authority.home_dns_retired(&self.grant) => {},
            }
        })
    }

    fn exchange(
        &self,
        timeout: Duration,
        message: Message,
    ) -> PathFuture<'_, Result<DnsResponse, ExchangeError>> {
        Box::pin(async move {
            tokio::select! {
                biased;
                _ = self.retired() => Err(io::Error::new(io::ErrorKind::PermissionDenied, "Home path retired").into()),
                result = self.io.exchange(self.authority.clone(), &self.grant, timeout, message) => result,
            }
        })
    }
}

impl Drop for LocalQuery {
    fn drop(&mut self) {
        self.grant.retire();
    }
}

#[cfg(test)]
#[path = "local_path_tests.rs"]
mod tests;
