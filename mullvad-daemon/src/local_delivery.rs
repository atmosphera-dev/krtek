//! Daemon-owned delivery decisions and joined frontend reconciliation.
use mullvad_types::settings::local_network_access::{
    LocalNetworkAccess,
    eligibility::{NetworkLease, NetworkObservation, evaluate, evaluate_associated},
    split_dns::SuffixMatcher,
    status::ForwardingAvailability,
};
#[cfg(test)]
use mullvad_types::states::TargetState;
use std::{
    collections::BTreeMap,
    future::Future,
    io,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicU64, Ordering},
    },
};
use talpid_lan_forwarder::{
    Disposition, Flow, LocalAuthority, ReceiveScope, Refused,
    authority::{MAX_RECEIVE_SCOPES, WeakReceiveScope},
};
use talpid_netstack::buffer_budget::BufferBudget;
#[cfg(test)]
use talpid_tunnel::packet_attachment::AttachmentMode;
use talpid_tunnel::packet_attachment::{AttachmentBroker, PendingCaptureRequest};
use talpid_tunnel::tun_provider::transport::{ROUTER_IPV4, ROUTER_IPV6};
use talpid_types::relay_flow::{RelayBufferAllocator, RelayBufferReservation};
use tokio::sync::watch;

/// One root per runtime, retained across frontend replacements. Other regions
/// remain protected until managed relay/control/capture consumers are installed.
pub struct DeliveryBuffers {
    pub local: Arc<dyn RelayBufferAllocator>,
    pub _application: Arc<dyn RelayBufferAllocator>,
    pub _control: Arc<dyn RelayBufferAllocator>,
    pub _capture: Arc<dyn RelayBufferAllocator>,
    _root: BufferBudget,
    _metadata: Arc<dyn RelayBufferReservation>,
}
impl DeliveryBuffers {
    pub fn new() -> Self {
        let root = BufferBudget::new(64 * 1024 * 1024);
        let region = |mib: usize| {
            root.reserve(mib * 1024 * 1024)
                .expect("fixed root partition")
                .region()
                .expect("region metadata")
        };
        Self {
            local: Arc::new(region(30)),
            _application: Arc::new(region(22)),
            _control: Arc::new(region(8)),
            _capture: Arc::new(region(2)),
            _metadata: root.try_reserve(512).expect("root metadata"),
            _root: root,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnerState {
    Running,
    #[cfg(any(target_os = "android", test))]
    Stopped,
    Failed,
}

#[cfg(test)]
pub fn frontend_wanted(
    rules_on: bool,
    has_routes: bool,
    target: TargetState,
    tunnel_disconnected: bool,
) -> bool {
    rules_on && has_routes && target == TargetState::Unsecured && tunnel_disconnected
}

pub fn availability(
    platform_supported: bool,
    rules_on: bool,
    has_routes: bool,
    endpoint: bool,
    owner: Option<OwnerState>,
    last_start_failed: bool,
) -> ForwardingAvailability {
    use ForwardingAvailability::*;
    if !platform_supported {
        NotAvailable
    } else if !rules_on || !has_routes {
        Off
    } else if last_start_failed || owner == Some(OwnerState::Failed) {
        Failed
    } else if endpoint && owner == Some(OwnerState::Running) {
        Active
    } else {
        PausedWhileConnected
    }
}

pub type SocketPreparer =
    dyn Fn(&socket2::Socket, &NetworkLease) -> Result<(), Refused> + Send + Sync;

struct Inputs {
    policy: LocalNetworkAccess,
    observation: Option<NetworkObservation>,
    observation_confirmed: bool,
    capture: Option<CaptureAuthority>,
    endpoint: bool,
    receive: BTreeMap<ReceiveKey, ReceiveRecord>,
    dns_revision: u64,
    dns_matcher: Option<Arc<SuffixMatcher>>,
    dns_inputs: BTreeMap<(IpAddr, IpAddr), DnsInputScope>,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum ReceivePurpose {
    Local,
    HomeDns,
}

impl ReceivePurpose {
    fn is_home(self) -> bool {
        self == Self::HomeDns
    }
}

type ReceiveKey = (IpAddr, IpAddr, ReceivePurpose);

// Home query capabilities and non-authorizing capture input scopes share the
// existing authority owner, including pre-coalescing policy revocation.
#[cfg(any(target_os = "android", test))]
pub(crate) mod home_dns;

struct DnsInputScope {
    scope: WeakReceiveScope,
    revision: u64,
    capture: u64,
    generation: Option<u64>,
    _charge: Arc<dyn RelayBufferReservation>,
}

/// Fixed non-transport facts, deliberately without NetworkLease's rule-ID Vec.
/// Re-evaluation permits unrelated rule edits but cannot migrate a datagram to a
/// replacement network, logical session or app source.
struct ReceiveIdentity {
    capture: u64,
    generation: Option<u64>,
    source: IpAddr,
    destination: IpAddr,
    network_handle: i64,
    interface_index: i32,
    scope_id: u32,
    purpose: ReceivePurpose,
    dns_revision: u64,
}

impl ReceiveIdentity {
    fn from_grant(grant: &DeliveryGrant) -> Self {
        Self {
            capture: grant.capture,
            generation: grant.generation,
            source: grant.source,
            destination: grant.physical.destination,
            network_handle: grant.physical.network_handle,
            interface_index: grant.physical.interface_index,
            scope_id: grant.physical.scope_id,
            purpose: grant.purpose,
            dns_revision: grant.dns_revision,
        }
    }

    fn matches(&self, grant: &DeliveryGrant) -> bool {
        self.capture == grant.capture
            && self.generation == grant.generation
            && self.source == grant.source
            && self.destination == grant.physical.destination
            && self.network_handle == grant.physical.network_handle
            && self.interface_index == grant.physical.interface_index
            && self.scope_id == grant.physical.scope_id
            && self.purpose == grant.purpose
            && self.dns_revision == grant.dns_revision
    }
}

struct ReceiveRecord {
    id: u64,
    scope: WeakReceiveScope,
    identity: ReceiveIdentity,
    _charge: Arc<dyn RelayBufferReservation>,
}

type RetiredReceive = (ReceiveKey, u64, Arc<dyn RelayBufferReservation>);

impl Inputs {
    fn compile_dns(policy: &LocalNetworkAccess) -> Option<Arc<SuffixMatcher>> {
        if !policy.split_dns.enabled {
            return None;
        }
        SuffixMatcher::compile(policy.split_dns.suffixes.iter().map(String::as_str))
            .ok()
            .map(Arc::new)
    }

    fn grant(&self, source: IpAddr, destination: IpAddr) -> Result<DeliveryGrant, Refused> {
        self.grant_for(source, destination, ReceivePurpose::Local)
    }

    fn grant_for(
        &self,
        source: IpAddr,
        destination: IpAddr,
        purpose: ReceivePurpose,
    ) -> Result<DeliveryGrant, Refused> {
        let capture = self.capture.as_ref().ok_or(Refused::Denied)?;
        if !self.endpoint
            || !capture.sources.contains(&source)
            || capture
                .reserved
                .iter()
                .any(|prefix| prefix.contains(destination))
        {
            return Err(Refused::Denied);
        }
        let generation = capture.generation()?;
        let observation = self.observation.as_ref().ok_or(Refused::Denied)?;
        let physical = if purpose.is_home() {
            let dns = &self.policy.split_dns;
            if !dns.enabled
                || dns.home_resolver != Some(destination)
                || dns.validate(&self.policy.rules).is_err()
            {
                return Err(Refused::Denied);
            }
            evaluate_associated(
                &self.policy,
                observation,
                destination,
                dns.local_rule_id.ok_or(Refused::Denied)?,
            )
        } else {
            evaluate(&self.policy, observation, destination)
        }
        .map_err(|_| Refused::Denied)?;
        Ok(DeliveryGrant {
            physical,
            capture: capture.identity,
            generation,
            source,
            purpose,
            dns_revision: if purpose.is_home() {
                self.dns_revision
            } else {
                0
            },
            scope: None,
        })
    }

    fn revalidate_receive(&mut self) {
        self.dns_inputs.retain(|(source, _), record| {
            let Some(scope) = record.scope.upgrade() else {
                return false;
            };
            let current = self.endpoint
                && self.dns_revision == record.revision
                && self.capture.as_ref().is_some_and(|capture| {
                    capture.identity == record.capture
                        && capture.sources.contains(source)
                        && capture.generation().is_ok_and(|g| g == record.generation)
                });
            if !current {
                scope.revoke();
            }
            scope.current()
        });
        let mut records = std::mem::take(&mut self.receive);
        records.retain(|_, record| {
            let Some(scope) = record.scope.upgrade() else {
                return false;
            };
            if !self
                .grant_for(scope.source(), scope.destination(), record.identity.purpose)
                .is_ok_and(|grant| record.identity.matches(&grant))
            {
                scope.revoke();
            }
            scope.current()
        });
        self.receive = records;
    }
}

/// Logical capture ownership, independent of descriptor/observation epochs.
/// Physical network identity alone cannot authorize a reply into a new session.
#[derive(Clone)]
struct CaptureAuthority {
    identity: u64,
    sources: Vec<IpAddr>,
    broker: Option<AttachmentBroker>,
    reserved: Vec<ipnetwork::IpNetwork>,
}

impl CaptureAuthority {
    fn new(
        mut sources: Vec<IpAddr>,
        broker: Option<AttachmentBroker>,
        reserved: Vec<ipnetwork::IpNetwork>,
    ) -> Self {
        sources.sort();
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let identity = NEXT
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .expect("capture authority identity exhausted");
        Self {
            identity,
            sources,
            broker,
            reserved,
        }
    }

    fn partial() -> Self {
        Self::new(vec![ROUTER_IPV4.into(), ROUTER_IPV6.into()], None, vec![])
    }

    fn generation(&self) -> Result<Option<u64>, Refused> {
        match &self.broker {
            None => Ok(None),
            Some(broker) => {
                let state = broker.snapshot();
                state.session_generation.map(Some).ok_or(Refused::Stale)
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveryGrant {
    pub physical: NetworkLease,
    capture: u64,
    generation: Option<u64>,
    source: IpAddr,
    purpose: ReceivePurpose,
    dns_revision: u64,
    scope: Option<GrantScope>,
}

/// Every issued transport grant retains its original irreversible scope. This
/// reaches per-I/O current checks even before the async flow owner revalidates.
#[derive(Clone)]
struct GrantScope(ReceiveScope);
impl std::fmt::Debug for GrantScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GrantScope(redacted)")
    }
}
impl PartialEq for GrantScope {
    fn eq(&self, other: &Self) -> bool {
        self.0.id() == other.0.id()
    }
}
impl Eq for GrantScope {}

pub struct DeliveryAuthority {
    inputs: RwLock<Inputs>,
    preparer: Arc<SocketPreparer>,
    revalidate: watch::Sender<u64>,
    retired_receive: Arc<Mutex<Vec<RetiredReceive>>>,
}

impl DeliveryAuthority {
    pub fn new(policy: &LocalNetworkAccess, preparer: Arc<SocketPreparer>) -> Self {
        Self {
            inputs: RwLock::new(Inputs {
                policy: policy.clone(),
                observation: None,
                observation_confirmed: false,
                capture: Some(CaptureAuthority::partial()),
                endpoint: true,
                receive: BTreeMap::new(),
                dns_revision: 1,
                dns_matcher: Inputs::compile_dns(policy),
                dns_inputs: BTreeMap::new(),
            }),
            preparer,
            revalidate: watch::channel(0).0,
            retired_receive: Arc::default(),
        }
    }

    /// Publish the new authority before waking any owner. A missing record is not
    /// an empty/default observation and can never retain an old lease.
    #[cfg(test)]
    pub fn update(&self, policy: &LocalNetworkAccess, observation: Option<NetworkObservation>) {
        let mut inputs = self.inputs.write().unwrap();
        if inputs.policy != *policy {
            inputs.dns_matcher = Inputs::compile_dns(policy);
            inputs.dns_revision = inputs
                .dns_revision
                .checked_add(1)
                .expect("DNS policy revision exhausted");
        }
        inputs.policy = policy.clone();
        inputs.observation = observation;
        inputs.observation_confirmed = true;
        inputs.revalidate_receive();
        self.reclaim_receive(&mut inputs);
        drop(inputs);
        self.wake();
    }

    /// The committed settings listener publishes every accepted policy before
    /// generic settings notifications can be handled against a later value.
    pub fn update_policy(&self, policy: &LocalNetworkAccess) {
        let mut inputs = self.inputs.write().unwrap();
        if inputs.policy != *policy {
            inputs.dns_matcher = Inputs::compile_dns(policy);
            inputs.dns_revision = inputs
                .dns_revision
                .checked_add(1)
                .expect("DNS policy revision exhausted");
            inputs.policy = policy.clone();
            inputs.revalidate_receive();
            self.reclaim_receive(&mut inputs);
            drop(inputs);
            self.wake();
        }
    }

    /// Runs synchronously at the producer boundary. No platform call, new grant
    /// or feed reentry is permitted here: the Kotlin event lock may be held.
    pub fn observe(&self, event: talpid_types::local_network::AuthorityObservation) {
        use talpid_types::local_network::AuthorityObservation;
        let (snapshot, confirmed) = match event {
            AuthorityObservation::Published(snapshot) => (snapshot, true),
            AuthorityObservation::Revalidate(snapshot) => (Some(snapshot), false),
        };
        let observation = snapshot
            .as_deref()
            .filter(|s| s.observer_running)
            .map(NetworkObservation::from);
        let mut inputs = self.inputs.write().unwrap();
        inputs.observation = observation;
        inputs.observation_confirmed = confirmed;
        inputs.revalidate_receive();
        self.reclaim_receive(&mut inputs);
        drop(inputs);
        self.wake();
    }

    fn wake(&self) {
        self.revalidate.send_modify(|revision| {
            *revision = revision
                .checked_add(1)
                .expect("delivery revision exhausted");
        });
    }

    fn reclaim_receive(&self, inputs: &mut Inputs) {
        // Take the queue before dropping records/credits. A temporary guard can
        // retire during revalidation, without lock recursion or a full-map scan.
        let retired = std::mem::take(&mut *self.retired_receive.lock().unwrap());
        for (key, id, _charge) in retired {
            if inputs
                .receive
                .get(&key)
                .is_some_and(|record| record.id == id)
            {
                inputs.receive.remove(&key);
            }
        }
    }

    fn install(&self, capture: CaptureAuthority) {
        let mut inputs = self.inputs.write().unwrap();
        inputs.capture = Some(capture);
        inputs.revalidate_receive();
        self.reclaim_receive(&mut inputs);
        drop(inputs);
        self.wake();
    }

    /// Only the retained owner can reconcile an epoch without minting a new
    /// permission identity. During establish, protect both reserved sets.
    fn reconcile_capture(&self, capture: CaptureAuthority, establishing: bool) {
        let mut inputs = self.inputs.write().unwrap();
        if let Some(current) = inputs.capture.as_mut() {
            assert_eq!(current.sources, capture.sources);
            assert!(
                current
                    .broker
                    .as_ref()
                    .zip(capture.broker.as_ref())
                    .is_some_and(|(a, b)| a.same_broker(b))
            );
            if establishing {
                for prefix in capture.reserved {
                    if !current.reserved.contains(&prefix) {
                        current.reserved.push(prefix);
                    }
                }
            } else {
                current.reserved = capture.reserved;
            }
        }
        inputs.revalidate_receive();
        self.reclaim_receive(&mut inputs);
        drop(inputs);
        self.wake();
    }

    pub fn revoke(&self) {
        let mut inputs = self.inputs.write().unwrap();
        inputs.capture = None;
        inputs.revalidate_receive();
        self.reclaim_receive(&mut inputs);
        drop(inputs);
        self.wake();
    }

    pub fn endpoint(&self, ready: bool) {
        let mut inputs = self.inputs.write().unwrap();
        if inputs.endpoint != ready {
            inputs.endpoint = ready;
            inputs.revalidate_receive();
            self.reclaim_receive(&mut inputs);
            drop(inputs);
            self.wake();
        }
    }

    #[cfg(any(target_os = "android", test))]
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.revalidate.subscribe()
    }

    fn receive_for(
        &self,
        source: IpAddr,
        destination: IpAddr,
        purpose: ReceivePurpose,
        buffers: &dyn RelayBufferAllocator,
    ) -> Result<ReceiveScope, Refused> {
        let mut inputs = self.inputs.write().unwrap();
        self.reclaim_receive(&mut inputs);
        let key = (source, destination, purpose);
        let grant = match inputs.grant_for(source, destination, purpose) {
            Ok(grant) => grant,
            Err(error) => {
                #[cfg(feature = "r06-diagnostics")]
                talpid_lan_forwarder::diagnostics::observe(
                    "receive-grant-refused",
                    format_args!("source={source} destination={destination} reason={error:?}"),
                );
                if let Some(record) = inputs.receive.remove(&key)
                    && let Some(scope) = record.scope.upgrade()
                {
                    scope.revoke();
                }
                return Err(error);
            }
        };
        if let Some(record) = inputs.receive.get(&key)
            && let Some(scope) = record.scope.upgrade()
        {
            if scope.current() && record.identity.matches(&grant) {
                #[cfg(feature = "r06-diagnostics")]
                talpid_lan_forwarder::diagnostics::observe(
                    "receive-scope-reused",
                    format_args!(
                        "source={source} destination={destination} scope={} generation={:?} network={} observation={}",
                        scope.id(),
                        grant.generation,
                        grant.physical.network_handle,
                        grant.physical.sequence
                    ),
                );
                return Ok(scope);
            }
            scope.revoke();
        }
        inputs.receive.remove(&key);
        // A benign witness retains existing receive/fragment/flow continuity,
        // but cannot mint a new scope or transport before complete confirmation.
        if !inputs.observation_confirmed {
            return Err(Refused::Stale);
        }
        if !purpose.is_home() && inputs.receive.len() >= MAX_RECEIVE_SCOPES {
            inputs
                .receive
                .retain(|_, record| record.scope.upgrade().is_some_and(|scope| scope.current()));
            // The two fixed app source families can each have one Home scope.
            // They never consume the native Local receiver's 4098 scope slots.
            if inputs.receive.keys().filter(|key| !key.2.is_home()).count() == MAX_RECEIVE_SCOPES {
                return Err(Refused::Full);
            }
        }
        let retired = self.retired_receive.clone();
        let retired: talpid_lan_forwarder::authority::ReceiveRetirement =
            Box::new(move |id, charge| {
                retired.lock().unwrap().push((key, id, charge));
            });
        let scope = if purpose.is_home() {
            // Application and Home upstream are separate IP legs. Their
            // non-authorizing context must not require equal address families.
            ReceiveScope::new_context_notifying(source, destination, buffers, Some(retired))?
        } else {
            ReceiveScope::new_notifying(source, destination, buffers, Some(retired))?
        };
        inputs.receive.insert(
            key,
            ReceiveRecord {
                id: scope.id(),
                scope: scope.downgrade(),
                identity: ReceiveIdentity::from_grant(&grant),
                _charge: scope.registration_credit(),
            },
        );
        #[cfg(feature = "r06-diagnostics")]
        talpid_lan_forwarder::diagnostics::observe(
            "receive-scope-created",
            format_args!(
                "source={source} destination={destination} scope={} generation={:?} network={} observation={}",
                scope.id(),
                grant.generation,
                grant.physical.network_handle,
                grant.physical.sequence
            ),
        );
        Ok(scope)
    }

    fn authorize_received_for(
        &self,
        flow: Flow,
        scope: &ReceiveScope,
        purpose: ReceivePurpose,
    ) -> Result<DeliveryGrant, Refused> {
        let inputs = self.inputs.read().unwrap();
        if !inputs.observation_confirmed {
            return Err(Refused::Stale);
        }
        if !scope.current()
            || scope.source() != flow.source.ip()
            || scope.destination() != flow.destination.ip()
        {
            return Err(Refused::Stale);
        }
        let record = inputs
            .receive
            .get(&(scope.source(), scope.destination(), purpose))
            .ok_or(Refused::Stale)?;
        if !record
            .scope
            .upgrade()
            .is_some_and(|registered| registered.id() == scope.id())
        {
            return Err(Refused::Stale);
        }
        let mut grant = inputs.grant_for(flow.source.ip(), flow.destination.ip(), purpose)?;
        if !record.identity.matches(&grant) {
            scope.revoke();
            return Err(Refused::Stale);
        }
        grant.scope = Some(GrantScope(scope.clone()));
        #[cfg(feature = "r06-diagnostics")]
        talpid_lan_forwarder::diagnostics::observe(
            "complete-flow-authorized",
            format_args!(
                "flow={flow:?} scope={} generation={:?} network={} observation={}",
                scope.id(),
                grant.generation,
                grant.physical.network_handle,
                grant.physical.sequence
            ),
        );
        Ok(grant)
    }
}

impl LocalAuthority for DeliveryAuthority {
    type Grant = DeliveryGrant;

    fn disposition(&self, destination: IpAddr) -> Disposition {
        let inputs = self.inputs.read().unwrap();
        if inputs.policy.enabled
            && inputs.policy.validate_local_rules().is_ok()
            && !inputs.capture.as_ref().is_some_and(|capture| {
                capture
                    .reserved
                    .iter()
                    .any(|prefix| prefix.contains(destination))
            })
            && !destination.is_unspecified()
            && !destination.is_loopback()
            && !destination.is_multicast()
            && !matches!(destination, IpAddr::V4(ip) if ip.is_broadcast())
            && inputs.policy.matching_rules(destination).next().is_some()
        {
            Disposition::Local
        } else {
            Disposition::Drop
        }
    }

    fn authorize(&self, flow: Flow) -> Result<DeliveryGrant, Refused> {
        let inputs = self.inputs.read().unwrap();
        if !inputs.observation_confirmed {
            return Err(Refused::Denied);
        }
        inputs.grant(flow.source.ip(), flow.destination.ip())
    }

    fn receive(
        &self,
        source: IpAddr,
        destination: IpAddr,
        buffers: &dyn RelayBufferAllocator,
    ) -> Result<ReceiveScope, Refused> {
        self.receive_for(source, destination, ReceivePurpose::Local, buffers)
    }

    fn authorize_received(
        &self,
        flow: Flow,
        scope: &ReceiveScope,
    ) -> Result<DeliveryGrant, Refused> {
        self.authorize_received_for(flow, scope, ReceivePurpose::Local)
    }

    fn prepare(&self, socket: &socket2::Socket, grant: &DeliveryGrant) -> Result<(), Refused> {
        if !self.current(grant) {
            return Err(Refused::Stale);
        }
        let prepared = (self.preparer)(socket, &grant.physical);
        #[cfg(feature = "r06-diagnostics")]
        talpid_lan_forwarder::diagnostics::observe(
            "protect-bind-result",
            format_args!(
                "generation={:?} network={} observation={} result={prepared:?}",
                grant.generation, grant.physical.network_handle, grant.physical.sequence
            ),
        );
        prepared?;
        if self.current(grant) {
            Ok(())
        } else {
            Err(Refused::Stale)
        }
    }

    fn current(&self, grant: &DeliveryGrant) -> bool {
        let inputs = self.inputs.read().unwrap();
        inputs.endpoint
            && grant.scope.as_ref().is_none_or(|scope| scope.0.current())
            && inputs.capture.as_ref().is_some_and(|capture| {
                capture.identity == grant.capture
                    && capture.sources.contains(&grant.source)
                    && capture.generation() == Ok(grant.generation)
                    && !capture
                        .reserved
                        .iter()
                        .any(|prefix| prefix.contains(grant.physical.destination))
            })
            && inputs.observation.as_ref().is_some_and(|observation| {
                if grant.purpose.is_home() {
                    inputs.dns_revision == grant.dns_revision
                        && inputs.policy.split_dns.enabled
                        && inputs.policy.split_dns.home_resolver == Some(grant.physical.destination)
                        && inputs.policy.split_dns.local_rule_id.is_some_and(|id| {
                            grant
                                .physical
                                .is_current_associated(&inputs.policy, observation, id)
                        })
                } else {
                    grant.physical.is_current(&inputs.policy, observation)
                }
            })
    }

    fn physical_destination(&self, grant: &DeliveryGrant, flow: Flow) -> SocketAddr {
        let mut destination = flow.destination;
        if let SocketAddr::V6(address) = &mut destination {
            address.set_scope_id(grant.physical.scope_id);
        }
        destination
    }
}

// The lifecycle is host-compiled over the same ownership protocol as the native
// owner. Fakes implement this boundary only in tests; there is no runtime hook.
pub trait DeliveryOwner {
    fn ready(&mut self) -> impl Future<Output = io::Result<()>> + Send;
    fn handover(&mut self, config: DeliveryConfig) -> io::Result<()>;
    fn retry_handover_release(&mut self) -> io::Result<()>;
    fn stop(&mut self) -> impl Future<Output = io::Result<()>> + Send;
    fn retry_release(&mut self) -> io::Result<()>;
    fn state(&self) -> OwnerState;
    fn release_failed(&self) -> bool;
    fn changed(&mut self) -> impl Future<Output = ()> + Send;
}

pub trait FrontendFactory: Send + Sync {
    type Owner: DeliveryOwner + Send;
    fn supported(&self) -> bool;
    fn start(
        &self,
        config: DeliveryConfig,
        authority: Arc<DeliveryAuthority>,
        buffers: Arc<dyn RelayBufferAllocator>,
        broker: AttachmentBroker,
    ) -> io::Result<Self::Owner>;
}

#[derive(Clone)]
pub enum DeliveryConfig {
    Partial(talpid_tunnel::tun_provider::PartialConfig),
    Router(talpid_tunnel::tun_provider::TunConfig),
    Secured {
        broker: AttachmentBroker,
        request: PendingCaptureRequest,
    },
}

impl DeliveryConfig {
    fn same_capture(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Partial(a), Self::Partial(b)) => a.same_android_config(b),
            (Self::Router(a), Self::Router(b)) => a.same_android_config(b),
            (Self::Secured { request: a, .. }, Self::Secured { request: b, .. }) => {
                a.id() == b.id()
            }
            _ => false,
        }
    }

    fn authority(&self, broker: &AttachmentBroker) -> CaptureAuthority {
        match self {
            Self::Partial(_) => {
                let mut authority = CaptureAuthority::partial();
                authority.broker = Some(broker.clone());
                authority
            }
            Self::Secured { .. } | Self::Router(_) => {
                let config = self.router_config().expect("router projection");
                let reserved = config
                    .gateways()
                    .into_iter()
                    .map(ipnetwork::IpNetwork::from)
                    .chain([talpid_tunnel::tun_provider::SOCKS_PROXIES])
                    .collect();
                CaptureAuthority::new(
                    vec![ROUTER_IPV4.into(), ROUTER_IPV6.into()],
                    Some(broker.clone()),
                    reserved,
                )
            }
        }
    }

    fn compatible(&self, other: &Self, broker: &AttachmentBroker) -> bool {
        let sources = |config: &Self| {
            let mut sources = config.authority(broker).sources;
            sources.sort();
            sources
        };
        let own_broker = |config: &Self| match config {
            Self::Partial(_) | Self::Router(_) => true,
            Self::Secured {
                broker: selected, ..
            } => broker.same_broker(selected),
        };
        own_broker(self) && own_broker(other) && sources(self) == sources(other)
    }

    #[cfg(test)]
    fn mtu(&self) -> u16 {
        self.router_config().map_or(
            talpid_tunnel::tun_provider::transport::LOCAL_ONLY_MTU,
            |config| config.mtu,
        )
    }

    pub fn router_config(&self) -> Option<&talpid_tunnel::tun_provider::TunConfig> {
        match self {
            Self::Partial(_) => None,
            Self::Router(config) => Some(config),
            Self::Secured { request, .. } => Some(request.config()),
        }
    }

    #[cfg(any(target_os = "android", all(test, target_os = "linux")))]
    fn into_frontend(
        self,
        classifier: Arc<DeliveryAuthority>,
    ) -> talpid_tunnel::android_frontend::CaptureConfig {
        use talpid_tunnel::android_frontend::{CaptureConfig, CaptureDisposition};
        let disposition = Arc::new(move |destination| {
            if classifier.disposition(destination) == Disposition::Local {
                CaptureDisposition::Local
            } else {
                CaptureDisposition::Tunnel(talpid_types::relay_flow::RelayTargetId::MULLVAD)
            }
        });
        match self {
            Self::Partial(routes) => CaptureConfig::Partial(routes),
            Self::Router(config) => CaptureConfig::Router {
                config,
                disposition,
            },
            Self::Secured { broker, request } => CaptureConfig::Secured {
                broker,
                request,
                disposition,
            },
        }
    }
}

pub struct Delivery<F: FrontendFactory> {
    factory: F,
    pub authority: Arc<DeliveryAuthority>,
    owner: Option<F::Owner>,
    applied: Option<DeliveryConfig>,
    last_start_failed: bool,
    release_outstanding: bool,
    owner_ready: bool,
    pending: Option<Readiness>,
    desired: Option<DeliveryConfig>,
    handover_failed: bool,
    // A failed establishment belongs to its exact configuration/request, not
    // whichever broker notification happens to reconcile it next.
    failed_establishment: Option<DeliveryConfig>,
    // A coalesced external retry belongs to the pending operation, not to an
    // internal readiness/state notification. Consume it only after that join.
    retry_requested: bool,
    // TSM release authority is not configuration/readiness authority. Keep both
    // exact requests through pending readiness and predecessor cleanup.
    releases: [Option<PendingCaptureRequest>; 2],
    buffers: Arc<dyn RelayBufferAllocator>,
    broker: AttachmentBroker,
}

enum Readiness {
    Initial,
    Handover {
        config: DeliveryConfig,
        predecessor: Option<u64>,
    },
    Release,
}

impl<F: FrontendFactory> Delivery<F> {
    pub fn supported(&self) -> bool {
        self.factory.supported()
    }

    pub fn applied_config(&self) -> Option<DeliveryConfig> {
        self.applied.clone()
    }
    pub fn pending_or_applied_config(&self) -> Option<DeliveryConfig> {
        // An old target request may describe a live retained epoch, but cannot
        // authorize opening a replacement after actual capture/session loss.
        if !self
            .owner
            .as_ref()
            .is_some_and(|owner| owner.state() == OwnerState::Running)
            || self.broker.snapshot().session_generation.is_none()
        {
            return None;
        }
        match &self.pending {
            Some(Readiness::Handover { config, .. }) => Some(config.clone()),
            _ => self.applied_config(),
        }
    }
    pub fn release_ready(&self) -> bool {
        self.releases
            .iter()
            .flatten()
            .all(PendingCaptureRequest::release_ready)
    }
    pub fn defer_release(&self) {
        for request in self.releases.iter().flatten() {
            request.defer_release();
        }
    }
    pub fn transport_joined(&self) {
        for request in self.releases.iter().flatten() {
            request.handover_joined();
        }
    }

    fn retain_release(&mut self, config: &DeliveryConfig) -> io::Result<()> {
        let applied = match &self.applied {
            Some(DeliveryConfig::Secured { request, .. }) => Some(request.id()),
            _ => None,
        };
        // A joined predecessor no longer needs a future TSM acknowledgement.
        // Keep the applied request even when no target has acquired it yet.
        for slot in &mut self.releases {
            if slot
                .as_ref()
                .is_some_and(|request| Some(request.id()) != applied && request.release_ready())
            {
                *slot = None;
            }
        }
        if let DeliveryConfig::Secured { request, .. } = config {
            if self
                .releases
                .iter()
                .flatten()
                .any(|held| held.id() == request.id())
            {
                return Ok(());
            }
            let slot = self
                .releases
                .iter_mut()
                .find(|slot| slot.is_none())
                .ok_or_else(|| io::Error::from(io::ErrorKind::WouldBlock))?;
            *slot = Some(request.clone());
        }
        Ok(())
    }
    pub fn new(
        factory: F,
        authority: Arc<DeliveryAuthority>,
        buffers: Arc<dyn RelayBufferAllocator>,
        broker: AttachmentBroker,
    ) -> Self {
        Self {
            factory,
            authority,
            owner: None,
            applied: None,
            last_start_failed: false,
            release_outstanding: false,
            owner_ready: false,
            pending: None,
            desired: None,
            handover_failed: false,
            failed_establishment: None,
            retry_requested: false,
            releases: [None, None],
            buffers,
            broker,
        }
    }

    pub fn has_owner(&self) -> bool {
        // Terminal and unreleased owners still exclude every replacement/Connect.
        self.owner.is_some()
    }

    #[cfg(test)]
    pub fn availability(
        &self,
        policy: &LocalNetworkAccess,
        target: TargetState,
        disconnected: bool,
    ) -> ForwardingAvailability {
        availability(
            self.factory.supported(),
            policy.enabled,
            !policy.announced_routes().is_empty(),
            self.ready()
                && frontend_wanted(
                    policy.enabled,
                    !policy.announced_routes().is_empty(),
                    target,
                    disconnected,
                ),
            self.owner.as_ref().map(DeliveryOwner::state),
            self.failed(),
        )
    }

    pub async fn changed(&mut self) {
        let reconcile = match self.owner.as_mut() {
            Some(owner) if self.pending.is_some() => {
                let result = owner.ready().await;
                let success = result.is_ok();
                self.received_ready(result);
                success
            }
            Some(owner) => {
                owner.changed().await;
                true
            }
            None => std::future::pending().await,
        };
        // A settings event may supersede the in-flight request. Reconcile the
        // latest intent after its exact acknowledgement, without another event
        // or a closed-channel readiness loop. Failures wait for an external retry.
        if self.retry_requested || reconcile && !self.failed() {
            self.reconcile_config(self.desired.clone()).await;
        }
    }

    fn received_ready(&mut self, result: io::Result<()>) {
        match self.pending.take().expect("retained readiness owner") {
            Readiness::Initial => {
                self.owner_ready = result.is_ok();
                if result.is_err() {
                    self.failed_establishment = self.applied.clone();
                    self.last_start_failed = true;
                    self.authority.revoke();
                }
            }
            Readiness::Handover {
                config,
                predecessor,
            } => {
                if result.is_ok() {
                    self.authority
                        .reconcile_capture(config.authority(&self.broker), false);
                    self.applied = Some(config);
                } else {
                    self.handover_failed = !result
                        .as_ref()
                        .is_err_and(|error| error.kind() == io::ErrorKind::WouldBlock);
                    if self.handover_failed {
                        self.failed_establishment = Some(config);
                    }
                    let snapshot = self.broker.snapshot();
                    if snapshot.capture_ready && snapshot.capture_generation == predecessor {
                        self.authority.reconcile_capture(
                            self.applied.as_ref().unwrap().authority(&self.broker),
                            false,
                        );
                    } else {
                        self.last_start_failed = true;
                        self.authority.revoke();
                    }
                }
            }
            Readiness::Release => {
                self.handover_failed = result.is_err();
            }
        }
    }

    pub fn owner_changed(&mut self) {
        if self
            .owner
            .as_ref()
            .is_some_and(|owner| owner.state() == OwnerState::Failed)
        {
            self.last_start_failed = true;
            self.authority.revoke();
        }
        // No maintain/retry here: only an external event can grant another attempt.
    }

    #[cfg(test)]
    pub async fn maintain(
        &mut self,
        policy: &LocalNetworkAccess,
        target: TargetState,
        disconnected: bool,
    ) {
        let routes: Vec<_> = policy
            .announced_routes()
            .iter()
            .map(ToString::to_string)
            .collect();
        let wanted = self.factory.supported()
            && frontend_wanted(policy.enabled, !routes.is_empty(), target, disconnected);
        self.maintain_config(wanted.then_some(DeliveryConfig::Partial(routes.into())))
            .await;
    }

    pub async fn maintain_config(&mut self, wanted: Option<DeliveryConfig>) {
        self.maintain_config_inner(wanted, true).await;
    }

    pub async fn reconcile_config(&mut self, wanted: Option<DeliveryConfig>) {
        self.maintain_config_inner(wanted, false).await;
    }

    async fn maintain_config_inner(&mut self, wanted: Option<DeliveryConfig>, external: bool) {
        use futures::FutureExt;
        if wanted.as_ref().is_some_and(|config| {
            matches!(config,
            DeliveryConfig::Secured { broker, .. } if !self.broker.same_broker(broker))
        }) {
            self.handover_failed = true;
            return;
        }
        self.desired = wanted.clone();
        if self.pending.is_some() {
            self.retry_requested |= external;
            return;
        }
        let new_operation = matches!(wanted.as_ref(), Some(DeliveryConfig::Secured { request, .. })
            if self.failed_establishment.as_ref().is_none_or(|failed| !matches!(failed, DeliveryConfig::Secured { request: old, .. } if old.id() == request.id())));
        let external_retry = std::mem::take(&mut self.retry_requested) || external || new_operation;
        if !self.retry_permitted(wanted.as_ref(), external_retry) {
            return;
        }
        self.failed_establishment = None;
        self.handover_failed = false;
        let retry_allowed = external_retry && self.can_retry_release();
        let healthy = self
            .owner
            .as_ref()
            .is_some_and(|owner| owner.state() == OwnerState::Running);
        let same = wanted
            .as_ref()
            .zip(self.applied.as_ref())
            .is_some_and(|(a, b)| a.same_capture(b));
        if healthy && self.owner_ready {
            let compatible = wanted
                .as_ref()
                .zip(self.applied.as_ref())
                .is_some_and(|(a, b)| a.compatible(b, &self.broker));
            if compatible {
                if self.retain_release(wanted.as_ref().unwrap()).is_err() {
                    return;
                }
                if self.owner.as_ref().unwrap().release_failed() {
                    // Recheck at dispatch: the native owner may publish a
                    // failure after the earlier reconciliation admission.
                    if self.retry_permitted(wanted.as_ref(), external_retry)
                        && self
                            .owner
                            .as_mut()
                            .unwrap()
                            .retry_handover_release()
                            .is_ok()
                    {
                        self.pending = Some(Readiness::Release);
                    }
                } else if !same {
                    let config = wanted.as_ref().unwrap();
                    let predecessor = self.broker.snapshot().capture_generation;
                    // The owner can run on another runtime thread immediately
                    // after dispatch. Publish restrictive policy first, without
                    // retaining the authority lock over the command boundary.
                    self.authority
                        .reconcile_capture(config.authority(&self.broker), true);
                    if let Err(error) = self.owner.as_mut().unwrap().handover(config.clone()) {
                        if error.kind() != io::ErrorKind::WouldBlock {
                            if let DeliveryConfig::Secured { request, .. } = config {
                                request.fail(
                                    &self.broker,
                                    talpid_tunnel::tun_provider::ConfigurationError::from(error),
                                );
                            }
                            self.failed_establishment = Some(config.clone());
                            self.handover_failed = true;
                        }
                        self.authority.reconcile_capture(
                            self.applied.as_ref().unwrap().authority(&self.broker),
                            false,
                        );
                    } else {
                        self.pending = Some(Readiness::Handover {
                            config: config.clone(),
                            predecessor,
                        });
                    }
                } else {
                    // Equal Builder fields can still carry new relay metadata.
                    // Refresh reservations without establishing another sink.
                    self.authority
                        .reconcile_capture(wanted.as_ref().unwrap().authority(&self.broker), false);
                    self.applied = wanted.clone();
                }
                if self.pending.is_some()
                    && let Some(result) = self.owner.as_mut().unwrap().ready().now_or_never()
                {
                    self.received_ready(result);
                }
                return;
            }
        }
        if self.has_owner() && (!same || !healthy || retry_allowed) && !self.release_ready() {
            self.authority.revoke();
            return;
        }
        self.last_start_failed = false;
        if self.has_owner()
            && (!same || !healthy || retry_allowed)
            && self.stop_owner(retry_allowed).await.is_err()
        {
            self.last_start_failed = true;
            return;
        }
        if let Some(config) = wanted.filter(|_| self.factory.supported() && !self.has_owner()) {
            // Retain before dispatch: the native actor can establish/acknowledge
            // on another runtime thread before Delivery receives readiness.
            self.retain_release(&config)
                .expect("no owner retains a release");
            self.authority.install(config.authority(&self.broker));
            match self.factory.start(
                config.clone(),
                self.authority.clone(),
                self.buffers.clone(),
                self.broker.clone(),
            ) {
                Ok(owner) => {
                    // Acquire the recovery handle before the first suspension.
                    self.owner = Some(owner);
                    self.owner_ready = false;
                    self.pending = Some(Readiness::Initial);
                    self.applied = Some(config);
                    // Never hold the daemon actor waiting for an Android callback
                    // or transport request. Retain pending readiness for select.
                    if let Some(result) = self.owner.as_mut().unwrap().ready().now_or_never() {
                        let failed = result.is_err();
                        self.received_ready(result);
                        if failed && self.release_ready() {
                            let _ = self.stop_owner(false).await;
                        }
                    }
                }
                Err(error) => {
                    if let DeliveryConfig::Secured { request, .. } = &config {
                        request.fail(
                            &self.broker,
                            talpid_tunnel::tun_provider::ConfigurationError::from(error),
                        );
                    }
                    self.failed_establishment = Some(config);
                    self.releases = [None, None];
                    self.last_start_failed = true;
                    self.authority.revoke();
                }
            }
        }
    }

    async fn stop_owner(&mut self, retry_allowed: bool) -> io::Result<()> {
        self.authority.revoke();
        if !self.release_ready() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "Transport teardown is not joined",
            ));
        }
        let Some(owner) = self.owner.as_mut() else {
            return Ok(());
        };
        if let Err(error) = owner.stop().await {
            self.release_outstanding = true;
            if !retry_allowed {
                return Err(error);
            }
            owner.retry_release()?;
            owner.stop().await?;
        }
        self.owner = None;
        self.owner_ready = false;
        self.pending = None;
        self.applied = None;
        self.releases = [None, None];
        self.release_outstanding = false;
        Ok(())
    }

    pub async fn stop(&mut self) -> io::Result<()> {
        self.desired = None;
        self.retry_requested = false;
        let result = self.stop_owner(self.can_retry_release()).await;
        if result.is_ok() {
            self.failed_establishment = None;
            self.handover_failed = false;
        }
        if !result
            .as_ref()
            .is_err_and(|error| error.kind() == io::ErrorKind::WouldBlock)
        {
            self.last_start_failed = result.is_err();
        }
        result
    }

    pub fn fail(&mut self) {
        self.last_start_failed = true;
        self.authority.revoke();
    }

    /// Internal reconciliation may advance a different establishment, never
    /// repeat a failed operation. A release still belongs to the retained owner
    /// even if the desired configuration changes; only external intent retries it.
    fn retry_permitted(&self, wanted: Option<&DeliveryConfig>, external: bool) -> bool {
        if matches!((self.failed_establishment.as_ref(), wanted),
            (Some(DeliveryConfig::Secured { request: failed, .. }), Some(DeliveryConfig::Secured { request: wanted, .. }))
                if failed.id() == wanted.id()
                    && self.broker.pending_request().is_none_or(|pending| pending.id() != wanted.id()))
        {
            // A completed request cannot be replayed. Pre-work owner failures
            // with a still-pending broker result retain explicit retry intent.
            return false;
        }
        external
            || (!self.can_retry_release()
                && !self
                    .failed_establishment
                    .as_ref()
                    .zip(wanted)
                    .is_some_and(|(failed, wanted)| failed.same_capture(wanted)))
    }

    fn can_retry_release(&self) -> bool {
        self.release_outstanding
            || self
                .owner
                .as_ref()
                .is_some_and(DeliveryOwner::release_failed)
    }

    pub fn failed(&self) -> bool {
        self.last_start_failed
            || self.handover_failed
            || self.release_failed()
            || self.release_outstanding
            || self
                .owner
                .as_ref()
                .is_some_and(|owner| owner.state() == OwnerState::Failed)
    }

    pub fn release_failed(&self) -> bool {
        self.release_outstanding
            || self
                .owner
                .as_ref()
                .is_some_and(DeliveryOwner::release_failed)
    }

    pub fn ready(&self) -> bool {
        self.owner_ready
            && !self.last_start_failed
            && !self.release_outstanding
            && self
                .owner
                .as_ref()
                .is_some_and(|owner| owner.state() == OwnerState::Running)
    }

    #[cfg(test)]
    pub fn configuration_ready(&self) -> bool {
        self.ready()
            && self.pending.is_none()
            && !self.failed()
            && self
                .applied
                .as_ref()
                .zip(self.desired.as_ref())
                .is_some_and(|(applied, desired)| applied.same_capture(desired))
    }

    pub fn owner_state(&self) -> Option<OwnerState> {
        self.owner.as_ref().map(DeliveryOwner::state)
    }
}

#[cfg(any(target_os = "android", all(test, target_os = "linux")))]
mod managed_platform;

#[cfg(target_os = "android")]
mod platform {
    pub use super::managed_platform::PlatformFactory;
    use super::*;
    use std::os::fd::AsRawFd;
    use talpid_tunnel::tun_provider::local_network::{LocalNetworkPlatform, PrepareError};

    pub fn preparer(platform: Arc<LocalNetworkPlatform>) -> Arc<SocketPreparer> {
        Arc::new(move |socket, lease| {
            let result = platform.prepare(
                socket.as_raw_fd(),
                lease.network_handle,
                lease.sequence,
                lease.needs_wifi_name,
            );
            #[cfg(feature = "r06-diagnostics")]
            talpid_lan_forwarder::diagnostics::observe(
                "platform-protect-bind-result",
                format_args!(
                    "fd={} network={} observation={} result={result:?}",
                    socket.as_raw_fd(),
                    lease.network_handle,
                    lease.sequence
                ),
            );
            result.map_err(|error| match error {
                PrepareError::Stale => Refused::Stale,
                _ => Refused::PreparationFailed,
            })
        })
    }
}

#[cfg(not(target_os = "android"))]
mod platform {
    use super::*;
    pub struct PlatformFactory;
    pub enum PlatformOwner {}
    pub fn preparer() -> Arc<SocketPreparer> {
        Arc::new(|_, _| Err(Refused::PreparationFailed))
    }
    impl FrontendFactory for PlatformFactory {
        type Owner = PlatformOwner;
        fn supported(&self) -> bool {
            false
        }
        fn start(
            &self,
            _: DeliveryConfig,
            _: Arc<DeliveryAuthority>,
            _: Arc<dyn RelayBufferAllocator>,
            _: AttachmentBroker,
        ) -> io::Result<PlatformOwner> {
            Err(io::ErrorKind::Unsupported.into())
        }
    }
    impl DeliveryOwner for PlatformOwner {
        fn handover(&mut self, _: DeliveryConfig) -> io::Result<()> {
            match *self {}
        }
        fn retry_handover_release(&mut self) -> io::Result<()> {
            match *self {}
        }
        async fn ready(&mut self) -> io::Result<()> {
            match *self {}
        }
        async fn stop(&mut self) -> io::Result<()> {
            match *self {}
        }
        fn retry_release(&mut self) -> io::Result<()> {
            match *self {}
        }
        fn state(&self) -> OwnerState {
            match *self {}
        }
        fn release_failed(&self) -> bool {
            match *self {}
        }
        async fn changed(&mut self) {
            match *self {}
        }
    }
}
pub use platform::{PlatformFactory, preparer};

#[cfg(test)]
pub(crate) mod tests;
