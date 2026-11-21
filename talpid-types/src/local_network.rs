//! Runtime-only Android observations and a latest-value feed. Never persist these records.
#[cfg(target_os = "android")]
use jnix::FromJava;
use std::{
    fmt,
    net::IpAddr,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{Arc, Mutex},
};
use tokio::sync::watch;

#[derive(Clone, Default, Eq, PartialEq)]
#[cfg_attr(target_os = "android", derive(FromJava))]
#[cfg_attr(target_os = "android", jnix(package = "net.mullvad.talpid.model"))]
pub struct LocalNetworkSnapshot {
    pub sequence: i64,
    /// Watcher event fence, independent of the coalesced status sequence. Zero
    /// is used by producers that publish complete observations synchronously.
    pub authority_revision: i64,
    pub observer_running: bool,
    pub local_ready: bool,
    pub fine_ready: bool,
    pub background_ready: bool,
    pub location_enabled: bool,
    pub location_allowed: bool,
    pub networks: Vec<LocalPhysicalNetwork>,
}

#[derive(Clone, Eq, PartialEq)]
#[cfg_attr(target_os = "android", derive(FromJava))]
#[cfg_attr(target_os = "android", jnix(package = "net.mullvad.talpid.model"))]
pub struct LocalPhysicalNetwork {
    pub network_handle: i64,
    pub transport: i32,
    pub capabilities_fresh: bool,
    pub links_fresh: bool,
    pub blocked: bool,
    pub interface_index: i32,
    pub addresses: Vec<LocalPhysicalAddress>,
    pub routes: Vec<LocalPhysicalRoute>,
    pub ssid_hex: Option<String>,
}

#[derive(Clone, Eq, PartialEq)]
#[cfg_attr(target_os = "android", derive(FromJava))]
#[cfg_attr(target_os = "android", jnix(package = "net.mullvad.talpid.model"))]
pub struct LocalPhysicalAddress {
    pub prefix: LocalPhysicalPrefix,
    pub usable: bool,
}

#[derive(Clone, Eq, PartialEq)]
#[cfg_attr(target_os = "android", derive(FromJava))]
#[cfg_attr(target_os = "android", jnix(package = "net.mullvad.talpid.model"))]
pub struct LocalPhysicalRoute {
    pub destination: LocalPhysicalPrefix,
    pub gateway: Option<IpAddr>,
    pub interface_index: i32,
    pub route_type: i32,
}

/// The existing Kotlin InetNetwork representation, with observation-safe diagnostics.
#[derive(Clone, Eq, PartialEq)]
#[cfg_attr(target_os = "android", derive(FromJava))]
#[cfg_attr(
    target_os = "android",
    jnix(class_name = "net.mullvad.talpid.model.InetNetwork")
)]
pub struct LocalPhysicalPrefix {
    pub address: IpAddr,
    pub prefix_length: i16,
}

impl fmt::Debug for LocalNetworkSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalNetworkSnapshot")
            .field("sequence", &self.sequence)
            .field("observer_running", &self.observer_running)
            .field("network_count", &self.networks.len())
            .finish()
    }
}

impl fmt::Debug for LocalPhysicalNetwork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalPhysicalNetwork")
            .field("transport", &self.transport)
            .field("address_count", &self.addresses.len())
            .field("route_count", &self.routes.len())
            .finish()
    }
}

impl fmt::Debug for LocalPhysicalAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LocalPhysicalAddress(redacted)")
    }
}

impl fmt::Debug for LocalPhysicalRoute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalPhysicalRoute")
            .field("route_type", &self.route_type)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for LocalPhysicalPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LocalPhysicalPrefix(redacted)")
    }
}

#[derive(Clone, Debug, Default)]
pub struct LocalNetworkFeedState {
    pub latest: Option<Arc<LocalNetworkSnapshot>>,
    pub closed: bool,
    sequence: i64,
}

/// One replaceable record, one notification receiver; no per-observation queue.
pub struct LocalNetworkFeed {
    registration: i64,
    sender: watch::Sender<LocalNetworkFeedState>,
    receiver: Mutex<Option<watch::Receiver<LocalNetworkFeedState>>>,
    demand: Mutex<ObservationDemand>,
    publication: Mutex<AuthorityPublication>,
}

/// Revalidation can only retire existing work. A complete, current publication
/// is required before new work can use its observation. The callback must never
/// call the platform or reenter this feed: Kotlin's event lock can be held.
pub enum AuthorityObservation {
    Published(Option<Arc<LocalNetworkSnapshot>>),
    Revalidate(Arc<LocalNetworkSnapshot>),
}

type AuthorityObserver = Arc<dyn Fn(AuthorityObservation) + Send + Sync>;

#[derive(Default)]
struct AuthorityPublication {
    revision: i64,
    observer: Option<AuthorityObserver>,
}

type DemandObserver = Arc<dyn Fn(i64, bool) + Send + Sync>;

#[derive(Default)]
struct ObservationDemand {
    sequence: i64,
    wanted: bool,
    observer: Option<DemandObserver>,
}

impl fmt::Debug for LocalNetworkFeed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalNetworkFeed")
            .field("registration", &self.registration)
            .field("state", &self.latest())
            .finish_non_exhaustive()
    }
}

impl LocalNetworkFeed {
    pub fn new(registration: i64) -> Arc<Self> {
        let (sender, receiver) = watch::channel(LocalNetworkFeedState {
            closed: registration <= 0,
            ..LocalNetworkFeedState::default()
        });
        Arc::new(Self {
            registration,
            sender,
            receiver: Mutex::new(Some(receiver)),
            demand: Mutex::new(ObservationDemand::default()),
            publication: Mutex::new(AuthorityPublication::default()),
        })
    }

    pub fn registration(&self) -> i64 {
        self.registration
    }

    pub fn latest(&self) -> LocalNetworkFeedState {
        self.sender.borrow().clone()
    }

    /// The daemon owns this receiver. Clones of the feed cannot claim a second one.
    pub fn take_receiver(&self) -> Option<watch::Receiver<LocalNetworkFeedState>> {
        self.receiver.lock().unwrap().take()
    }

    /// Install the sole daemon authority consumer before requesting observation.
    /// Serialize its initial sample with all later publication/revocation calls.
    pub fn observe_authority(&self, observer: AuthorityObserver) {
        let mut publication = self.publication.lock().unwrap();
        assert!(publication.observer.is_none(), "one Local authority owner");
        let latest = self
            .latest()
            .latest
            .filter(|snapshot| snapshot.authority_revision == publication.revision);
        observer(AuthorityObservation::Published(latest));
        publication.observer = Some(observer);
    }

    /// Synchronous revocation-only handoff, before Kotlin may coalesce events.
    /// A late full snapshot cannot grant work across a newer witness fence.
    pub fn revalidate(&self, registration: i64, snapshot: LocalNetworkSnapshot) -> bool {
        if registration != self.registration || snapshot.authority_revision <= 0 {
            return false;
        }
        let mut publication = self.publication.lock().unwrap();
        if self.latest().closed || snapshot.authority_revision <= publication.revision {
            return false;
        }
        publication.revision = snapshot.authority_revision;
        if let Some(observer) = &publication.observer {
            observer(AuthorityObservation::Revalidate(Arc::new(snapshot)));
        }
        true
    }

    /// The daemon owns policy demand. The optional platform callback is never
    /// called under a feed lock and cannot turn attachment into a startup gate.
    pub fn observe_policy_demand(&self, observer: DemandObserver) {
        let (sequence, wanted) = {
            let mut demand = self.demand.lock().unwrap();
            demand.observer = Some(observer.clone());
            (demand.sequence, demand.wanted)
        };
        observer(sequence, wanted);
    }

    pub fn set_policy_demand(&self, wanted: bool) {
        let delivery = {
            let mut demand = self.demand.lock().unwrap();
            let wanted = wanted && !self.latest().closed;
            if wanted == demand.wanted {
                return;
            }
            demand.wanted = wanted;
            demand.sequence = demand
                .sequence
                .checked_add(1)
                .expect("Local demand sequence exhausted");
            demand
                .observer
                .clone()
                .map(|observer| (observer, demand.sequence, wanted))
        };
        if let Some((observer, sequence, wanted)) = delivery {
            observer(sequence, wanted);
        }
    }

    /// Optional platform registration never prevents its caller from starting the daemon.
    /// jnix's preload/conversion APIs panic on missing Java classes, hence this boundary.
    pub fn register<E>(&self, attach: impl FnOnce(i64) -> Result<bool, E>) -> bool {
        let attached = self.registration > 0
            && !self.latest().closed
            && matches!(
                catch_unwind(AssertUnwindSafe(|| attach(self.registration))),
                Ok(Ok(true))
            );
        if !attached {
            self.close();
        }
        attached
    }

    pub fn publish(&self, registration: i64, snapshot: LocalNetworkSnapshot) -> bool {
        if registration != self.registration || snapshot.sequence <= 0 {
            return false;
        }
        let mut publication = self.publication.lock().unwrap();
        let mut state = self.latest();
        if state.closed
            || state.sequence >= snapshot.sequence
            || snapshot.authority_revision < publication.revision
        {
            return false;
        }
        publication.revision = snapshot.authority_revision;
        state.sequence = snapshot.sequence;
        state.latest = snapshot.observer_running.then(|| Arc::new(snapshot));
        if let Some(observer) = &publication.observer {
            observer(AuthorityObservation::Published(state.latest.clone()));
        }
        self.sender.send_replace(state);
        true
    }

    /// Close authority and wake its async owner, without invoking platform demand.
    /// Safe for the one-way JNI witness path while Kotlin's event lock is held.
    pub fn invalidate(&self) {
        {
            let publication = self.publication.lock().unwrap();
            if !self.latest().closed {
                if let Some(observer) = &publication.observer {
                    observer(AuthorityObservation::Published(None));
                }
                self.sender.send_modify(|state| {
                    state.latest = None;
                    state.closed = true;
                });
            }
        }
    }

    pub fn close(&self) {
        self.invalidate();
        // Platform demand may reenter Kotlin. Never call it under publication.
        self.set_policy_demand(false);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authority_receives_every_complete_publication_before_status_coalesces() {
        let feed = LocalNetworkFeed::new(7);
        let mut status = feed.take_receiver().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let recorded = seen.clone();
        feed.observe_authority(Arc::new(move |event| match event {
            AuthorityObservation::Published(sample) => {
                recorded.lock().unwrap().push(sample.map(|s| s.sequence))
            }
            AuthorityObservation::Revalidate(_) => panic!("complete-only producer"),
        }));
        for sequence in 1..=100 {
            assert!(feed.publish(7, snapshot(sequence)));
        }
        assert_eq!(
            *seen.lock().unwrap(),
            std::iter::once(None)
                .chain((1..=100).map(Some))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            status.borrow_and_update().latest.as_ref().unwrap().sequence,
            100
        );
        assert!(!status.has_changed().unwrap());
    }

    #[test]
    fn witness_fence_rejects_late_complete_samples_stale_callbacks_and_closed_publication() {
        let feed = LocalNetworkFeed::new(7);
        let seen = Arc::new(Mutex::new(Vec::new()));
        let recorded = seen.clone();
        feed.observe_authority(Arc::new(move |event| {
            recorded.lock().unwrap().push(match event {
                AuthorityObservation::Published(s) => (true, s.map(|s| s.authority_revision)),
                AuthorityObservation::Revalidate(s) => (false, Some(s.authority_revision)),
            });
        }));
        let mut first = snapshot(1);
        first.authority_revision = 1;
        assert!(feed.publish(7, first));
        let mut witness = snapshot(1);
        witness.authority_revision = 3;
        witness.local_ready = false;
        assert!(!feed.revalidate(8, witness.clone()));
        assert!(feed.revalidate(7, witness.clone()));
        assert!(!feed.revalidate(7, witness));
        let mut late = snapshot(100);
        late.authority_revision = 2;
        assert!(!feed.publish(7, late.clone()));
        assert!(!feed.revalidate(7, late));
        assert_eq!(
            feed.latest().latest.unwrap().authority_revision,
            1,
            "witness is not a new granting status sample"
        );
        let mut current = snapshot(2);
        current.authority_revision = 3;
        assert!(feed.publish(7, current.clone()));
        feed.close();
        assert!(!feed.publish(7, current.clone()));
        current.authority_revision = 4;
        assert!(!feed.revalidate(7, current));
        assert_eq!(
            *seen.lock().unwrap(),
            vec![
                (true, None),
                (true, Some(1)),
                (false, Some(3)),
                (true, Some(3)),
                (true, None)
            ]
        );
    }

    #[test]
    fn authority_attached_after_a_witness_cannot_grant_from_an_older_cached_sample() {
        let feed = LocalNetworkFeed::new(7);
        assert!(feed.publish(7, snapshot(1)));
        let mut pending = snapshot(1);
        pending.authority_revision = 1;
        assert!(feed.revalidate(7, pending.clone()));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let recorded = seen.clone();
        feed.observe_authority(Arc::new(move |event| match event {
            AuthorityObservation::Published(s) => recorded
                .lock()
                .unwrap()
                .push(s.map(|s| s.authority_revision)),
            _ => panic!("no new witness"),
        }));
        assert_eq!(*seen.lock().unwrap(), vec![None]);
        pending.sequence = 2;
        assert!(feed.publish(7, pending));
        assert_eq!(*seen.lock().unwrap(), vec![None, Some(1)]);
    }

    #[test]
    fn witness_conversion_failure_invalidates_without_a_platform_demand_callback() {
        let feed = LocalNetworkFeed::new(7);
        let demand = Arc::new(Mutex::new(Vec::new()));
        let recorded = demand.clone();
        feed.observe_policy_demand(Arc::new(move |sequence, wanted| {
            recorded.lock().unwrap().push((sequence, wanted))
        }));
        feed.set_policy_demand(true);
        let authority = Arc::new(Mutex::new(Vec::new()));
        let recorded = authority.clone();
        feed.observe_authority(Arc::new(move |event| match event {
            AuthorityObservation::Published(s) => recorded.lock().unwrap().push(s.is_some()),
            _ => panic!("no callback witness expected"),
        }));
        assert!(feed.publish(7, snapshot(1)));
        feed.invalidate();
        assert!(feed.latest().closed);
        assert_eq!(*authority.lock().unwrap(), vec![false, true, false]);
        assert_eq!(
            *demand.lock().unwrap(),
            vec![(0, false), (1, true)],
            "one-way witness failure must not call back into Kotlin"
        );
        feed.close();
        assert_eq!(
            *demand.lock().unwrap(),
            vec![(0, false), (1, true), (2, false)],
            "async owner closes platform demand after the event lock is released"
        );
    }

    fn snapshot(sequence: i64) -> LocalNetworkSnapshot {
        LocalNetworkSnapshot {
            sequence,
            observer_running: true,
            ..LocalNetworkSnapshot::default()
        }
    }

    #[test]
    fn latest_record_and_single_receiver_coalesce_notifications() {
        let feed = LocalNetworkFeed::new(7);
        let mut receiver = feed.take_receiver().unwrap();
        assert!(feed.take_receiver().is_none());
        for sequence in 1..=100 {
            assert!(feed.publish(7, snapshot(sequence)));
        }
        assert!(receiver.has_changed().unwrap());
        assert_eq!(
            receiver
                .borrow_and_update()
                .latest
                .as_ref()
                .unwrap()
                .sequence,
            100
        );
        assert!(!receiver.has_changed().unwrap());
        assert_eq!(feed.latest().latest.unwrap().sequence, 100);
    }

    #[test]
    fn stale_registration_and_nonincreasing_sequences_are_ignored() {
        let feed = LocalNetworkFeed::new(7);
        let mut receiver = feed.take_receiver().unwrap();
        assert!(feed.publish(7, snapshot(2)));
        receiver.borrow_and_update();
        assert!(!feed.publish(6, snapshot(3)));
        assert!(!feed.publish(7, snapshot(0)));
        assert!(!feed.publish(7, snapshot(1)));
        assert!(!feed.publish(7, snapshot(2)));
        assert_eq!(feed.latest().latest.unwrap().sequence, 2);
        assert!(!receiver.has_changed().unwrap());
        let mut suspended = snapshot(3);
        suspended.observer_running = false;
        assert!(feed.publish(7, suspended));
        assert!(!feed.latest().closed);
        assert!(feed.latest().latest.is_none());
        assert!(!feed.publish(7, snapshot(2)));
        assert!(feed.publish(7, snapshot(4)));
        assert_eq!(feed.latest().latest.unwrap().sequence, 4);
        let demands = Arc::new(Mutex::new(Vec::new()));
        let recorded = demands.clone();
        let weak = Arc::downgrade(&feed);
        feed.set_policy_demand(true);
        feed.observe_policy_demand(Arc::new(move |sequence, wanted| {
            assert!(
                weak.upgrade().unwrap().demand.try_lock().is_ok(),
                "callback under demand lock"
            );
            recorded.lock().unwrap().push((sequence, wanted));
        }));
        feed.set_policy_demand(true);
        feed.set_policy_demand(false);
        feed.set_policy_demand(true);
        feed.close();
        feed.set_policy_demand(true);
        assert_eq!(
            *demands.lock().unwrap(),
            vec![(1, true), (2, false), (3, true), (4, false)]
        );
    }

    #[test]
    fn close_discards_private_record_notifies_once_and_cannot_reopen() {
        let feed = LocalNetworkFeed::new(7);
        let mut receiver = feed.take_receiver().unwrap();
        feed.publish(7, snapshot(1));
        receiver.borrow_and_update();
        feed.close();
        assert!(receiver.has_changed().unwrap());
        assert!(receiver.borrow_and_update().closed);
        assert!(feed.latest().latest.is_none());
        feed.close();
        assert!(!feed.publish(7, snapshot(2)));
        assert!(!receiver.has_changed().unwrap());
    }

    #[test]
    fn attach_error_returns_control_to_startup_with_a_closed_feed() {
        let feed = LocalNetworkFeed::new(7);
        let mut steps = vec!["registration"];
        let ready = feed.register(|registration| {
            assert_eq!(registration, 7);
            Err::<bool, _>("fake attach failed")
        });
        steps.push("daemon startup");
        assert_eq!(steps, ["registration", "daemon startup"]);
        assert!(!ready);
        assert!(feed.latest().closed);
        assert!(!feed.publish(7, snapshot(1)));
    }

    #[test]
    fn refused_or_panicking_registration_closes_but_success_stays_open() {
        let refused = LocalNetworkFeed::new(7);
        assert!(!refused.register(|_| Ok::<_, ()>(false)));
        assert!(refused.latest().closed);
        let panicking = LocalNetworkFeed::new(8);
        assert!(!panicking.register(|_| -> Result<bool, ()> { panic!("missing Java class") }));
        assert!(panicking.latest().closed);
        let ready = LocalNetworkFeed::new(9);
        assert!(ready.register(|_| Ok::<_, ()>(true)));
        assert!(!ready.latest().closed);
    }

    #[test]
    fn stopped_observation_and_invalid_registration_are_unavailable() {
        let feed = LocalNetworkFeed::new(7);
        feed.publish(7, snapshot(1));
        assert!(feed.publish(
            7,
            LocalNetworkSnapshot {
                sequence: 2,
                ..LocalNetworkSnapshot::default()
            }
        ));
        assert!(!feed.latest().closed);
        assert!(feed.latest().latest.is_none());
        assert!(!feed.publish(7, snapshot(1)));
        assert!(feed.publish(7, snapshot(3)));
        let invalid = LocalNetworkFeed::new(0);
        assert!(!invalid.register(|_| -> Result<bool, ()> { panic!("must not attach") }));
        assert!(invalid.latest().closed);
    }

    #[test]
    fn every_observation_debug_and_feed_debug_redacts_identity_and_addresses() {
        let prefix = LocalPhysicalPrefix {
            address: "192.0.2.42".parse().unwrap(),
            prefix_length: 24,
        };
        let address = LocalPhysicalAddress {
            prefix: prefix.clone(),
            usable: true,
        };
        let route = LocalPhysicalRoute {
            destination: prefix.clone(),
            gateway: Some("192.0.2.1".parse().unwrap()),
            interface_index: 4,
            route_type: 1,
        };
        let network = LocalPhysicalNetwork {
            network_handle: 9,
            transport: 1,
            capabilities_fresh: true,
            links_fresh: true,
            blocked: false,
            interface_index: 4,
            addresses: vec![address.clone()],
            routes: vec![route.clone()],
            ssid_hex: Some("736563726574".into()),
        };
        let snapshot = LocalNetworkSnapshot {
            networks: vec![network.clone()],
            ..snapshot(1)
        };
        let feed = LocalNetworkFeed::new(7);
        feed.publish(7, snapshot.clone());
        let output = format!(
            "{prefix:?} {address:?} {route:?} {network:?} {snapshot:?} {feed:?} {:?}",
            feed.latest()
        );
        for secret in ["192.0.2.42", "192.0.2.1", "736563726574", "secret"] {
            assert!(!output.contains(secret));
        }
    }
}
