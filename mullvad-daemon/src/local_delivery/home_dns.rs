//! Home query capabilities reuse the Local capture/grant/preparation owner.
//! No resolver selection, fallback or ordinary physical bypass lives here.

use super::*;

/// The classifier and its revocable capture registration are acquired together.
#[derive(Clone)]
pub(crate) struct DnsInput {
    matcher: Arc<SuffixMatcher>,
    scope: ReceiveScope,
}

impl DnsInput {
    pub(crate) fn matcher(&self) -> &SuffixMatcher {
        &self.matcher
    }

    pub(crate) fn scope(&self) -> &ReceiveScope {
        &self.scope
    }

    #[cfg(test)]
    pub(crate) fn for_test(matcher: SuffixMatcher, scope: ReceiveScope) -> Self {
        Self {
            matcher: Arc::new(matcher),
            scope,
        }
    }
}

#[derive(Clone)]
pub(crate) struct HomeDnsGrant(Arc<HomeQuery>);

struct HomeQuery {
    flow: Flow,
    grant: DeliveryGrant,
    scope: ReceiveScope,
    classification: ReceiveScope,
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
    ) -> Result<DnsInput, Refused> {
        let mut inputs = self.inputs.write().unwrap();
        inputs.reclaim_dns_inputs();
        // The broker advances independently of the authority lock. Reuse and
        // replacement must both use the same generation read for admission.
        let identity = inputs.dns_capture().and_then(|(capture, identity)| {
            capture
                .sources
                .contains(&source)
                .then_some(identity)
                .ok_or(Refused::Denied)
        });
        let key = (source, resolver);
        let current = inputs
            .dns_inputs
            .get(&key)
            .and_then(|record| record.revalidate(identity.ok()));
        if current.is_none() {
            inputs.dns_inputs.remove(&key);
        }
        let identity = identity?;
        let matcher = inputs.dns_matcher.clone().ok_or(Refused::Denied)?;
        if let Some(scope) = current {
            return Ok(DnsInput { matcher, scope });
        }

        let retired = Arc::downgrade(&inputs.retired_dns_inputs);
        let notify = Box::new(move |id, charge| {
            if let Some(retired) = retired.upgrade() {
                retired.lock().unwrap().push((key, id, charge));
            }
        });
        let scope = ReceiveScope::new_notifying(source, resolver, buffers, Some(notify))?;
        inputs.dns_inputs.insert(
            key,
            DnsInputScope {
                id: scope.id(),
                scope: scope.downgrade(),
                identity,
                _charge: scope.registration_credit(),
            },
        );
        Ok(DnsInput { matcher, scope })
    }

    pub(crate) fn dns_enabled(&self) -> bool {
        self.inputs.read().unwrap().policy.split_dns.enabled
    }

    /// Select and commit the grant under the same authority lock. Even an
    /// unchanged Home address cannot authorize classification by a retired policy.
    pub(crate) fn home_dns_authorize_configured(
        &self,
        input: &DnsInput,
        source: SocketAddr,
        transport: talpid_lan_forwarder::Transport,
        buffers: &dyn RelayBufferAllocator,
    ) -> Result<HomeDnsGrant, Refused> {
        let mut inputs = self.inputs.write().unwrap();
        let classification = input.scope();
        if !classification.current() || classification.source() != source.ip() {
            return Err(Refused::Stale);
        }
        let record = inputs
            .dns_inputs
            .get(&(classification.source(), classification.destination()))
            .ok_or(Refused::Stale)?;
        if record.identity.revision != inputs.dns_revision || record.id != classification.id() {
            return Err(Refused::Stale);
        }
        let expected = record.identity;
        let destination = inputs
            .policy
            .split_dns
            .home_resolver
            .ok_or(Refused::Denied)?;
        let flow = Flow {
            transport,
            source,
            destination: SocketAddr::new(destination, 53),
        };
        let scope = self.receive_for(
            &mut inputs,
            source.ip(),
            destination,
            ReceivePurpose::HomeDns,
            buffers,
        )?;
        let grant = Self::authorize_received_for(&inputs, flow, &scope, ReceivePurpose::HomeDns)?;
        if expected
            != (DnsInputIdentity {
                capture: grant.capture,
                generation: grant.generation,
                revision: grant.dns_revision,
            })
            || !classification.current()
        {
            return Err(Refused::Stale);
        }
        Self::home_dns_query(flow, grant, scope, classification.clone(), buffers)
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

    #[cfg(test)]
    pub(crate) fn home_dns_authorize(
        &self,
        flow: Flow,
        buffers: &dyn RelayBufferAllocator,
    ) -> Result<HomeDnsGrant, Refused> {
        if flow.destination.port() != 53 {
            return Err(Refused::Denied);
        }
        let mut inputs = self.inputs.write().unwrap();
        let scope = self.receive_for(
            &mut inputs,
            flow.source.ip(),
            flow.destination.ip(),
            ReceivePurpose::HomeDns,
            buffers,
        )?;
        let grant = Self::authorize_received_for(&inputs, flow, &scope, ReceivePurpose::HomeDns)?;
        Self::home_dns_query(flow, grant, scope.clone(), scope, buffers)
    }

    fn home_dns_query(
        flow: Flow,
        grant: DeliveryGrant,
        scope: ReceiveScope,
        classification: ReceiveScope,
        buffers: &dyn RelayBufferAllocator,
    ) -> Result<HomeDnsGrant, Refused> {
        // Same fixed grant/task metadata allowance as Local; cloned providers
        // share this backing rather than cloning per-query grant allocations.
        let storage = buffers
            .try_reserve(size_of::<HomeQuery>() + 4096)
            .map_err(|_| Refused::Full)?;
        Ok(HomeDnsGrant(Arc::new(HomeQuery {
            flow,
            grant,
            scope,
            classification,
            live: watch::channel(true).0,
            _storage: storage,
        })))
    }

    pub(crate) fn home_dns_current(&self, query: &HomeDnsGrant) -> bool {
        *query.0.live.borrow()
            && query.0.classification.current()
            && query.0.scope.current()
            && self.current(&query.0.grant)
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
