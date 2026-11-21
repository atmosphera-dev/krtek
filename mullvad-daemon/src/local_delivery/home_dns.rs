//! Home query capabilities reuse the Local capture/grant/preparation owner.
//! No resolver selection, fallback or ordinary physical bypass lives here.

use super::*;

#[derive(Clone)]
pub(crate) struct HomeDnsGrant(Arc<HomeQuery>);

struct HomeQuery {
    flow: Flow,
    grant: DeliveryGrant,
    scope: ReceiveScope,
    live: watch::Sender<bool>,
    _storage: Arc<dyn RelayBufferReservation>,
}

impl HomeDnsGrant {
    pub(crate) fn destination(&self) -> SocketAddr {
        let mut destination = self.0.flow.destination;
        if let SocketAddr::V6(address) = &mut destination {
            address.set_scope_id(self.0.grant.physical.scope_id);
        }
        destination
    }

    pub(crate) fn retire(&self) {
        self.0.live.send_replace(false);
    }

    pub(crate) async fn retired(&self) {
        let mut changes = self.0.live.subscribe();
        while *changes.borrow_and_update() {
            if changes.changed().await.is_err() {
                break;
            }
        }
    }
}

impl DeliveryAuthority {
    pub(crate) fn home_dns_authorize(
        &self,
        flow: Flow,
        buffers: &dyn RelayBufferAllocator,
    ) -> Result<HomeDnsGrant, Refused> {
        if flow.destination.port() != 53 {
            return Err(Refused::Denied);
        }
        // Same fixed grant/task metadata allowance as Local; cloned providers
        // share this backing rather than cloning per-query grant allocations.
        let storage = buffers
            .try_reserve(size_of::<HomeQuery>() + 4096)
            .map_err(|_| Refused::Full)?;
        let scope = self.receive_for(
            flow.source.ip(),
            flow.destination.ip(),
            ReceivePurpose::HomeDns,
            buffers,
        )?;
        let grant = self.authorize_received_for(flow, &scope, ReceivePurpose::HomeDns)?;
        Ok(HomeDnsGrant(Arc::new(HomeQuery {
            flow,
            grant,
            scope,
            live: watch::channel(true).0,
            _storage: storage,
        })))
    }

    pub(crate) fn home_dns_current(&self, query: &HomeDnsGrant) -> bool {
        *query.0.live.borrow() && query.0.scope.current() && self.current(&query.0.grant)
    }

    pub(crate) fn home_dns_prepare(
        &self,
        socket: &socket2::Socket,
        query: &HomeDnsGrant,
    ) -> Result<(), Refused> {
        if !self.home_dns_current(query) {
            return Err(Refused::Stale);
        }
        self.prepare(socket, &query.0.grant)?;
        if self.home_dns_current(query) {
            Ok(())
        } else {
            Err(Refused::Stale)
        }
    }
}

#[cfg(test)]
#[path = "home_dns_tests.rs"]
mod tests;
