//! Capture-owned VPN observations, separate from physical-network eligibility.
//! A generation is retired synchronously on identity loss, before notifying its
//! async owner. No platform/JNI work is performed while holding the feed lock.
#[cfg(target_os = "android")]
use jnix::FromJava;
use std::{
    net::IpAddr,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{Arc, Mutex},
};
use tokio::sync::watch;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[cfg_attr(target_os = "android", derive(FromJava))]
#[cfg_attr(
    target_os = "android",
    jnix(class_name = "net.mullvad.talpid.model.InetNetwork")
)]
pub struct CapturePrefix {
    pub address: IpAddr,
    pub prefix_length: i16,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[cfg_attr(target_os = "android", derive(FromJava))]
#[cfg_attr(target_os = "android", jnix(package = "net.mullvad.talpid.model"))]
pub struct CaptureRoute {
    pub destination: CapturePrefix,
    pub gateway: Option<IpAddr>,
    pub interface_name: String,
    pub route_type: Option<i32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(target_os = "android", derive(FromJava))]
#[cfg_attr(target_os = "android", jnix(package = "net.mullvad.talpid.model"))]
pub struct CaptureNetworkObservation {
    pub network_handle: i64,
    pub network: String,
    pub interface_name: String,
    pub owner_uid: Option<i32>,
    pub routes: Vec<CaptureRoute>,
    pub addresses: Vec<CapturePrefix>,
    pub dns_servers: Vec<IpAddr>,
    pub mtu: Option<i32>,
    pub fresh: bool,
    pub lost: bool,
    pub api_level: i32,
}

#[derive(Clone, Debug)]
pub struct CaptureExpectation {
    pub interface_name: String,
    pub owner_uid: Option<i32>,
    pub api_level: i32,
    pub routes: Vec<CaptureRoute>,
    pub addresses: Vec<CapturePrefix>,
    pub dns_servers: Vec<IpAddr>,
    pub mtu: Option<i32>,
}

impl CaptureExpectation {
    /// Expected routes use upstream Android Route's destination-prefix semantics.
    /// Platform-added connected/unreachable routes and optional report fields are
    /// diagnostics, not additional configuration requirements.
    pub fn requested(
        interface_name: String,
        owner_uid: i32,
        api_level: i32,
        addresses: &[IpAddr],
        routes: &[CapturePrefix],
        dns_servers: &[IpAddr],
        mtu: u16,
    ) -> Option<Self> {
        if interface_name.is_empty()
            || owner_uid < 0
            || api_level < 28
            || addresses.is_empty()
            || mtu == 0
            || (mtu < 1280
                && (addresses.iter().any(IpAddr::is_ipv6)
                    || routes.iter().any(|route| route.address.is_ipv6())
                    || dns_servers.iter().any(IpAddr::is_ipv6)))
        {
            return None;
        }
        let addresses: Vec<_> = addresses
            .iter()
            .map(|ip| CapturePrefix {
                address: *ip,
                prefix_length: if ip.is_ipv4() { 32 } else { 128 },
            })
            .collect();
        let mut projected = Vec::new();
        for prefix in routes {
            let bits = u8::try_from(prefix.prefix_length).ok()?;
            let network = ipnetwork::IpNetwork::new(prefix.address, bits).ok()?;
            if network.network() != prefix.address {
                return None;
            }
            projected.push(CaptureRoute {
                destination: prefix.clone(),
                gateway: None,
                interface_name: interface_name.clone(),
                route_type: (api_level >= 33).then_some(1),
            });
        }
        projected.sort();
        projected.dedup();
        Some(Self {
            interface_name,
            owner_uid: (api_level >= 30).then_some(owner_uid),
            api_level,
            routes: projected,
            addresses,
            dns_servers: dns_servers.to_vec(),
            mtu: (api_level >= 29).then_some(i32::from(mtu)),
        })
    }

    fn matches(&self, observation: &CaptureNetworkObservation) -> bool {
        self.owns(observation)
            && self.routes.iter().all(|expected| {
                observation
                    .routes
                    .iter()
                    .any(|actual| actual.destination == expected.destination)
            })
    }

    fn owns(&self, observation: &CaptureNetworkObservation) -> bool {
        observation.fresh
            && !observation.lost
            && observation.api_level == self.api_level
            && observation.owner_uid == self.owner_uid
            && observation.interface_name == self.interface_name
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CaptureNetworkState {
    Pending,
    Ready(Arc<CaptureNetworkObservation>),
    Lost,
}

struct Generation {
    id: i64,
    expected: Option<CaptureExpectation>,
    handle: Option<i64>,
    revoke: Option<Arc<dyn Fn() + Send + Sync>>,
    state: watch::Sender<CaptureNetworkState>,
}

struct State {
    closed: bool,
    last_generation: i64,
    generation: Option<Generation>,
    predecessor: Option<Predecessor>,
}

struct Predecessor {
    generation: Generation,
    revoke: Option<Arc<dyn Fn() + Send + Sync>>,
}

pub struct CaptureNetworkFeed {
    registration: i64,
    state: Mutex<State>,
    lockdown: watch::Sender<bool>,
}

impl CaptureNetworkFeed {
    pub fn new(registration: i64) -> Arc<Self> {
        Arc::new(Self {
            registration,
            lockdown: watch::channel(true).0,
            state: Mutex::new(State {
                closed: registration <= 0,
                last_generation: 0,
                generation: None,
                predecessor: None,
            }),
        })
    }

    pub fn registration(&self) -> i64 {
        self.registration
    }

    /// Platform configuration input, never destination or socket authority.
    pub fn lockdown(&self) -> bool {
        *self.lockdown.borrow()
    }

    pub fn lockdown_changes(&self) -> watch::Receiver<bool> {
        self.lockdown.subscribe()
    }

    pub fn publish_lockdown(&self, registration: i64, enabled: bool) {
        let state = self.state.lock().expect("capture feed");
        if registration != self.registration || state.closed {
            return;
        }
        self.lockdown.send_if_modified(|current| {
            let changed = *current != enabled;
            *current = enabled;
            changed
        });
    }

    pub fn register<E>(&self, attach: impl FnOnce(i64) -> Result<bool, E>) -> bool {
        let open = !self.state.lock().expect("capture feed").closed;
        let attached = open
            && matches!(
                catch_unwind(AssertUnwindSafe(|| attach(self.registration))),
                Ok(Ok(true))
            );
        if !attached {
            self.close();
        }
        attached
    }

    /// Called before platform opening. A replacement cannot supersede an owner
    /// that still owes cleanup; invalidate must precede platform release.
    pub fn begin(&self, id: i64) -> Option<watch::Receiver<CaptureNetworkState>> {
        let mut state = self.state.lock().expect("capture feed");
        if state.closed
            || id <= state.last_generation
            || state.generation.is_some()
            || state.predecessor.is_some()
        {
            return None;
        }
        state.last_generation = id;
        let (sender, receiver) = watch::channel(CaptureNetworkState::Pending);
        state.generation = Some(Generation {
            id,
            expected: None,
            handle: None,
            revoke: None,
            state: sender,
        });
        Some(receiver)
    }

    /// Freeze the predecessor's write authority before entering establish, while
    /// retaining its observation and cleanup record. Expected old-interface loss
    /// updates that record but cannot retire the logical session. No third epoch
    /// is admitted until exact old cleanup or a proven pre-establish rollback.
    /// A Partial successor deliberately has no managed feed generation.
    pub fn begin_handover(
        &self,
        predecessor: i64,
        successor: Option<i64>,
    ) -> Option<Option<watch::Receiver<CaptureNetworkState>>> {
        let mut state = self.state.lock().expect("capture feed");
        if state.closed
            || state.predecessor.is_some()
            || successor.is_some_and(|id| id <= state.last_generation)
            || !state.generation.as_ref().is_some_and(|g| {
                g.id == predecessor && matches!(*g.state.borrow(), CaptureNetworkState::Ready(_))
            })
        {
            return None;
        }
        let mut generation = state.generation.take().expect("checked predecessor");
        let revoke = generation.revoke.take();
        state.predecessor = Some(Predecessor { generation, revoke });
        let receiver = successor.map(|id| {
            state.last_generation = id;
            let (sender, receiver) = watch::channel(CaptureNetworkState::Pending);
            state.generation = Some(Generation {
                id,
                expected: None,
                handle: None,
                revoke: None,
                state: sender,
            });
            receiver
        });
        Some(receiver)
    }

    /// The caller must also possess positive platform evidence that establish
    /// was never entered. An observed lost predecessor is never restored here.
    pub fn rollback_handover(&self, predecessor: i64) -> bool {
        let mut state = self.state.lock().expect("capture feed");
        if state.closed
            || state
                .generation
                .as_ref()
                .is_some_and(|g| g.revoke.is_some())
            || !state.predecessor.as_ref().is_some_and(|old| {
                old.generation.id == predecessor
                    && matches!(
                        *old.generation.state.borrow(),
                        CaptureNetworkState::Ready(_)
                    )
            })
        {
            return false;
        }
        if let Some(generation) = state.generation.take() {
            Self::set_state(&generation, CaptureNetworkState::Lost);
        }
        let mut old = state.predecessor.take().expect("checked predecessor");
        old.generation.revoke = old.revoke.take();
        state.generation = Some(old.generation);
        true
    }

    /// After descriptor adoption and the borrowed TUNGETIFF query. Observations
    /// received before binding cannot acknowledge readiness or pin a handle.
    pub fn bind(&self, id: i64, expected: CaptureExpectation) -> bool {
        let mut state = self.state.lock().expect("capture feed");
        let Some(generation) = state.generation.as_mut().filter(|g| g.id == id) else {
            return false;
        };
        if generation.expected.is_some() || expected.interface_name.is_empty() {
            return false;
        }
        generation.expected = Some(expected);
        true
    }

    /// Issue the receipt and install its synchronous revoker in one feed turn.
    /// The operation may only bind/acknowledge native capabilities, never JNI,
    /// await, or reenter this feed. Publication cannot slip between them.
    pub fn acknowledge<T>(
        &self,
        id: i64,
        revoke: Arc<dyn Fn() + Send + Sync>,
        operation: impl FnOnce(&CaptureNetworkObservation) -> T,
    ) -> Option<T> {
        let mut state = self.state.lock().expect("capture feed");
        let generation = state.generation.as_mut().filter(|g| g.id == id)?;
        if generation.revoke.is_some() {
            return None;
        }
        let observation = match &*generation.state.borrow() {
            CaptureNetworkState::Ready(observation) => observation.clone(),
            _ => return None,
        };
        let result = operation(&observation);
        generation.revoke = Some(revoke);
        Some(result)
    }

    pub fn publish(
        &self,
        registration: i64,
        id: i64,
        mut observation: CaptureNetworkObservation,
    ) -> bool {
        if registration != self.registration {
            return false;
        }
        observation.routes.sort();
        observation.routes.dedup();
        observation.addresses.sort();
        observation.addresses.dedup();
        observation.dns_servers.sort();
        observation.dns_servers.dedup();
        let mut state = self.state.lock().expect("capture feed");
        let generation = if state.generation.as_ref().is_some_and(|g| g.id == id) {
            state.generation.as_mut()
        } else {
            state
                .predecessor
                .as_mut()
                .map(|old| &mut old.generation)
                .filter(|g| g.id == id)
        };
        let Some(generation) = generation else {
            return false;
        };
        // Registration/publication failures have no usable network identity.
        // They still retire their exact generation, including before fd binding.
        if observation.lost && observation.network_handle == 0 {
            Self::revoke(generation);
            return Self::set_state(generation, CaptureNetworkState::Lost);
        }
        let Some(expected) = &generation.expected else {
            return false;
        };
        if matches!(*generation.state.borrow(), CaptureNetworkState::Lost) {
            return false;
        }
        if let Some(handle) = generation.handle {
            if handle != observation.network_handle {
                return false;
            }
        } else {
            if observation.interface_name != expected.interface_name
                || observation.api_level != expected.api_level
                || observation.owner_uid != expected.owner_uid
                || !observation.fresh
                || observation.lost
                || observation.network_handle == 0
            {
                return false;
            }
            generation.handle = Some(observation.network_handle);
        }
        let next = if !expected.owns(&observation) {
            Self::revoke(generation);
            CaptureNetworkState::Lost
        } else if generation.revoke.is_some() || expected.matches(&observation) {
            CaptureNetworkState::Ready(Arc::new(observation))
        } else {
            CaptureNetworkState::Pending
        };
        Self::set_state(generation, next)
    }

    fn set_state(generation: &Generation, next: CaptureNetworkState) -> bool {
        generation.state.send_if_modified(|previous| {
            if *previous == next {
                false
            } else {
                *previous = next;
                true
            }
        })
    }

    fn revoke(generation: &mut Generation) {
        if let Some(revoke) = generation.revoke.take() {
            revoke();
        }
    }

    /// Serialize the final nonblocking Local sink operation with observation
    /// revocation. No JNI, await or feed reentry is permitted in the callback.
    pub fn with_ready<T>(&self, id: i64, operation: impl FnOnce() -> T) -> Option<T> {
        let state = self.state.lock().expect("capture feed");
        let generation = state.generation.as_ref().filter(|g| g.id == id)?;
        if !matches!(*generation.state.borrow(), CaptureNetworkState::Ready(_)) {
            return None;
        }
        Some(operation())
    }

    pub fn invalidate(&self, id: i64) {
        let mut state = self.state.lock().expect("capture feed");
        if state.generation.as_ref().is_some_and(|g| g.id == id) {
            let mut generation = state.generation.take().expect("matched generation");
            Self::revoke(&mut generation);
            Self::set_state(&generation, CaptureNetworkState::Lost);
        }
        if state
            .predecessor
            .as_ref()
            .is_some_and(|old| old.generation.id == id)
        {
            let old = state.predecessor.take().expect("matched predecessor");
            // Its revoker was disarmed by the same owner's handover transaction.
            // Exact epoch cleanup must not revoke the successor/session.
            Self::set_state(&old.generation, CaptureNetworkState::Lost);
        }
    }

    pub fn close(&self) {
        let mut state = self.state.lock().expect("capture feed");
        state.closed = true;
        self.lockdown.send_replace(true);
        if let Some(mut generation) = state.generation.take() {
            Self::revoke(&mut generation);
            Self::set_state(&generation, CaptureNetworkState::Lost);
        }
        if let Some(mut old) = state.predecessor.take() {
            if let Some(revoke) = old.revoke.take() {
                revoke();
            }
            Self::set_state(&old.generation, CaptureNetworkState::Lost);
        }
    }
}

#[cfg(test)]
mod tests;
