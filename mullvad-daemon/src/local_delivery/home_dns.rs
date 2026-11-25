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
    pub(crate) fn transport(&self) -> talpid_lan_forwarder::Transport {
        self.0.flow.transport
    }

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
    /// Non-authorizing input scope, also available for unavailable-Home SERVFAIL.
    /// The committed-policy publication revokes it before notification coalescing.
    pub(crate) fn dns_input(
        &self,
        source: IpAddr,
        resolver: IpAddr,
        buffers: &dyn RelayBufferAllocator,
    ) -> Result<(Arc<SuffixMatcher>, ReceiveScope), Refused> {
        let mut inputs = self.inputs.write().unwrap();
        inputs.revalidate_receive();
        let dns = &inputs.policy.split_dns;
        if !dns.enabled {
            return Err(Refused::Denied);
        }
        let matcher = inputs.dns_matcher.clone().ok_or(Refused::Denied)?;
        let capture = inputs.capture.as_ref().ok_or(Refused::Denied)?;
        if !inputs.endpoint || !capture.sources.contains(&source) {
            return Err(Refused::Denied);
        }
        let identity = capture.identity;
        let generation = capture.generation()?;
        let key = (source, resolver);
        if let Some(scope) = inputs.dns_inputs.get(&key).and_then(|r| r.scope.upgrade()) {
            return Ok((matcher, scope));
        }
        let scope = ReceiveScope::new(source, resolver, buffers)?;
        let revision = inputs.dns_revision;
        inputs.dns_inputs.insert(
            key,
            DnsInputScope {
                scope: scope.downgrade(),
                revision,
                capture: identity,
                generation,
                _charge: scope.registration_credit(),
            },
        );
        Ok((matcher, scope))
    }

    pub(crate) fn dns_enabled(&self) -> bool {
        self.inputs.read().unwrap().policy.split_dns.enabled
    }

    /// Resolver selection belongs to the Local Home path, never to the DNS
    /// message consumer. The normal authorization below rechecks the selected
    /// address and policy, so a concurrent policy replacement cannot grant the
    /// old address under the new policy.
    pub(crate) fn home_dns_authorize_configured(
        &self,
        source: SocketAddr,
        transport: talpid_lan_forwarder::Transport,
        buffers: &dyn RelayBufferAllocator,
    ) -> Result<HomeDnsGrant, Refused> {
        let destination = self
            .inputs
            .read()
            .unwrap()
            .policy
            .split_dns
            .home_resolver
            .ok_or(Refused::Denied)?;
        self.home_dns_authorize(
            Flow {
                transport,
                source,
                destination: SocketAddr::new(destination, 53),
            },
            buffers,
        )
    }

    /// Observe authority changes as well as explicit per-query retirement. A
    /// blocked socket does not have to become readable to notice revocation.
    pub(crate) async fn home_dns_retired(&self, query: &HomeDnsGrant) {
        let mut authority = self.subscribe();
        loop {
            if !self.home_dns_current(query) {
                return;
            }
            tokio::select! {
                _ = query.retired() => return,
                result = authority.changed() => if result.is_err() { return; },
            }
        }
    }

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
