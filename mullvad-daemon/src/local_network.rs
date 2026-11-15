//! Single actor-owned authority, frontend lifecycle and semantic status publisher.
use crate::local_delivery::{
    self, Delivery, DeliveryAuthority, DeliveryBuffers, DeliveryConfig, FrontendFactory,
    PlatformFactory, SocketPreparer,
};
use mullvad_types::settings::local_network_access::{
    LocalNetworkAccess, eligibility::NetworkObservation, status::LocalNetworkStatus,
};
use mullvad_types::states::TargetState;
use std::sync::Arc;
use talpid_tunnel::packet_attachment::{AttachmentBroker, AttachmentMode, BrokerSnapshot};
use talpid_types::local_network::{LocalNetworkFeed, LocalNetworkFeedState};
use tokio::sync::watch;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TunnelPhase {
    Disconnected,
    Connecting,
    Connected,
    Disconnecting,
    Error,
}

impl From<&mullvad_types::states::TunnelState> for TunnelPhase {
    fn from(state: &mullvad_types::states::TunnelState) -> Self {
        use mullvad_types::states::TunnelState;
        match state {
            TunnelState::Disconnected { .. } => Self::Disconnected,
            TunnelState::Connecting { .. } => Self::Connecting,
            TunnelState::Connected { .. } => Self::Connected,
            TunnelState::Disconnecting(_) => Self::Disconnecting,
            TunnelState::Error(_) => Self::Error,
        }
    }
}

/// Track queued commands until the TSM has observed and joined them. This is
/// shutdown bookkeeping, not a second owner of normal reconnect ordering.
#[derive(Default)]
pub struct ConnectContinuation {
    requested: bool,
    observed_initial: bool,
    joined: bool,
}

impl ConnectContinuation {
    pub fn joined(&self) -> bool {
        self.observed_initial && self.joined
    }
    pub fn disconnected_and_joined(&self, state: &mullvad_types::states::TunnelState) -> bool {
        state.is_disconnected() && self.joined()
    }
    pub fn connect(&mut self) {
        self.requested = true;
    }
    pub fn disconnect(&mut self) {
        self.requested = false;
    }
    pub fn observe(&mut self, phase: TunnelPhase) {
        self.observed_initial = true;
        self.joined = phase == TunnelPhase::Disconnected;
    }
    fn take_connect(&mut self) -> bool {
        let requested = std::mem::take(&mut self.requested);
        if requested {
            self.joined = false;
        }
        requested
    }
}

#[cfg(test)]
impl From<bool> for TunnelPhase {
    fn from(disconnected: bool) -> Self {
        if disconnected {
            Self::Disconnected
        } else {
            Self::Connecting
        }
    }
}

pub struct LocalNetworkRuntime<F: FrontendFactory = PlatformFactory> {
    feed: Option<Arc<LocalNetworkFeed>>,
    receiver: Option<watch::Receiver<LocalNetworkFeedState>>,
    status: LocalNetworkStatus,
    observation: Option<NetworkObservation>,
    delivery: Delivery<F>,
    shutting_down: bool,
    _buffers: DeliveryBuffers,
    broker: AttachmentBroker,
    broker_updates: watch::Receiver<BrokerSnapshot>,
    release_updates: watch::Receiver<u64>,
    suspended: bool,
    phase: Option<TunnelPhase>,
    target_config: Option<talpid_tunnel::packet_attachment::PendingCaptureRequest>,
    blocking_config: Option<BlockingConfiguration>,
    excluded_packages: Option<Vec<String>>,
}

/// Keep Error's prepared safe base separate from its current Local projection.
/// The original operation remains the intent until the effective Local union
/// changes; a failed request is never replaced just because an input woke us.
struct BlockingConfiguration {
    base: talpid_tunnel::tun_provider::TunConfig,
    projection: DeliveryConfig,
}

impl BlockingConfiguration {
    fn reproject(&mut self, routes: Vec<ipnetwork::IpNetwork>) -> DeliveryConfig {
        let projected = talpid_tunnel::tun_provider::transport::router_config(&self.base, routes);
        if !self
            .projection
            .router_config()
            .is_some_and(|current| current.same_android_config(&projected))
        {
            self.projection = DeliveryConfig::Router(projected);
        }
        self.projection.clone()
    }
}

impl LocalNetworkRuntime {
    pub fn new(
        policy: &LocalNetworkAccess,
        feed: Option<Arc<LocalNetworkFeed>>,
        #[cfg(target_os = "android")] platform: Arc<
            talpid_tunnel::tun_provider::local_network::LocalNetworkPlatform,
        >,
    ) -> Self {
        #[cfg(target_os = "android")]
        let (factory, preparer) = (
            PlatformFactory(platform.clone()),
            local_delivery::preparer(platform),
        );
        #[cfg(not(target_os = "android"))]
        let (factory, preparer) = (PlatformFactory, local_delivery::preparer());
        Self::with_factory(policy, feed, factory, preparer)
    }
}

impl<F: FrontendFactory> LocalNetworkRuntime<F> {
    pub(super) fn with_factory(
        policy: &LocalNetworkAccess,
        feed: Option<Arc<LocalNetworkFeed>>,
        factory: F,
        preparer: Arc<SocketPreparer>,
    ) -> Self {
        let receiver = feed.as_ref().and_then(|feed| feed.take_receiver());
        let buffers = DeliveryBuffers::new();
        let broker = AttachmentBroker::new(
            buffers._application.clone(),
            buffers._capture.clone(),
            buffers._control.clone(),
        )
        .expect("fixed runtime broker storage");
        // Select managed ownership and route input before the TSM can open its
        // first target. Descriptor establishment still belongs to that request.
        if factory.supported() || cfg!(target_os = "android") {
            broker
                .set_mode(AttachmentMode::ManagedRequired)
                .expect("fresh runtime broker");
            broker
                .set_local_routes(
                    policy
                        .announced_routes()
                        .iter()
                        .map(|cidr| cidr.network())
                        .collect(),
                )
                .expect("bounded initial Local routes");
        }
        let broker_updates = broker.changes();
        let release_updates = broker.capture_release_changes();
        let mut runtime = Self {
            feed: feed.filter(|_| receiver.is_some()),
            receiver,
            status: LocalNetworkStatus::from_observation(policy, None),
            observation: None,
            delivery: Delivery::new(
                factory,
                Arc::new(DeliveryAuthority::new(policy, preparer)),
                buffers.local.clone(),
                broker.clone(),
            ),
            shutting_down: false,
            _buffers: buffers,
            broker,
            broker_updates,
            release_updates,
            suspended: false,
            phase: None,
            target_config: None,
            blocking_config: None,
            excluded_packages: None,
        };
        runtime.observation = runtime.observation();
        if let Some(feed) = &runtime.feed {
            feed.set_policy_demand(!policy.announced_routes().is_empty());
        }
        // Startup reconciles before exposing real delivery availability. Do not
        // project a failed/not-yet-started owner from the constructor.
        runtime.status = LocalNetworkStatus::from_observation(policy, runtime.observation.as_ref());
        // The initial status is an observable sample even on unsupported platforms.
        runtime.status.revision = 1;
        runtime
    }

    pub fn notifications(
        &mut self,
    ) -> (
        impl Future<Output = ()> + Send + '_,
        impl Future<Output = ()> + Send + '_,
        impl Future<Output = ()> + Send + '_,
    ) {
        (
            feed_changed(&mut self.receiver),
            self.delivery.changed(),
            async {
                tokio::select! {
                    _ = self.broker_updates.changed() => {},
                    _ = self.release_updates.changed() => {},
                }
            },
        )
    }

    pub fn status(&self) -> &LocalNetworkStatus {
        &self.status
    }

    #[cfg(any(target_os = "android", test))]
    pub fn set_excluded_packages(&mut self, packages: Vec<String>) {
        self.excluded_packages = Some(packages);
    }

    fn observation(&self) -> Option<NetworkObservation> {
        self.feed.as_ref().and_then(|feed| {
            let state = feed.latest();
            (!state.closed)
                .then(|| state.latest.as_deref().map(NetworkObservation::from))
                .flatten()
        })
    }

    pub async fn update<P: Into<TunnelPhase>>(
        &mut self,
        policy: &LocalNetworkAccess,
        target: TargetState,
        phase: P,
    ) -> Option<LocalNetworkStatus> {
        let phase = phase.into();
        self.reconcile(policy, target, phase, true).await;
        self.publish(policy, target, phase)
    }

    pub async fn internal_update(
        &mut self,
        policy: &LocalNetworkAccess,
        target: TargetState,
        phase: TunnelPhase,
    ) -> Option<LocalNetworkStatus> {
        self.reconcile(policy, target, phase, false).await;
        self.publish(policy, target, phase)
    }

    // Configuration/admission can run before the daemon's notification pass.
    // It must not consume a semantic status revision: only the publication
    // boundaries return changed samples for delivery to management clients.
    async fn reconcile(
        &mut self,
        policy: &LocalNetworkAccess,
        target: TargetState,
        phase: TunnelPhase,
        external: bool,
    ) {
        self.observation = self.observation();
        if self.feed.as_ref().is_some_and(|feed| feed.latest().closed) {
            self.receiver = None;
            self.feed = None;
        }
        self.delivery
            .authority
            .update(policy, self.observation.clone());
        if let Some(feed) = &self.feed {
            feed.set_policy_demand(!self.shutting_down && !policy.announced_routes().is_empty());
        }
        // The platform may synchronously withdraw its observation on the last
        // demand. Do not publish an old physical identity after that withdrawal.
        let observed = self.observation();
        if observed != self.observation {
            self.observation = observed;
            self.delivery
                .authority
                .update(policy, self.observation.clone());
        }
        let routes = policy
            .announced_routes()
            .iter()
            .map(|route| route.network())
            .collect::<Vec<_>>();
        if routes != self.broker.local_routes() && self.broker.set_local_routes(routes).is_err() {
            self.delivery.fail();
        }
        if target == TargetState::Unsecured && phase == TunnelPhase::Disconnected {
            self.blocking_config = None;
        }
        let partial = || {
            let routes = policy
                .announced_routes()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>();
            (!routes.is_empty()).then_some(DeliveryConfig::Partial(
                talpid_tunnel::tun_provider::PartialConfig {
                    routes,
                    excluded_packages: self.excluded_packages.clone().unwrap_or_default(),
                },
            ))
        };
        let config = if self.shutting_down {
            None
        } else if target == TargetState::Unsecured && phase == TunnelPhase::Disconnected {
            partial()
        } else if self.broker.snapshot().mode == AttachmentMode::ManagedRequired {
            if let Some(request) = self.broker.pending_request() {
                let config = DeliveryConfig::Secured {
                    broker: self.broker.clone(),
                    request: request.clone(),
                };
                if request.purpose() == talpid_tunnel::tun_provider::ConfigurationPurpose::Blocking
                {
                    self.blocking_config = Some(BlockingConfiguration {
                        base: request.target_config().clone(),
                        projection: config.clone(),
                    });
                } else {
                    self.target_config = Some(request);
                    self.blocking_config = None;
                }
                Some(config)
            } else if self.blocking_config.is_some() || phase == TunnelPhase::Error {
                // Reproject only Error's current safe base, never cached target
                // DNS/LAN. Router handover changes Local coverage without issuing
                // another receipt for the original TSM blocking operation. The
                // operation also owns the interval before public Error arrives.
                match self.blocking_config.as_mut() {
                    Some(config) => Some(config.reproject(self.broker.local_routes())),
                    None => self.delivery.pending_or_applied_config(),
                }
            } else if phase != TunnelPhase::Error
                && !self
                    .delivery
                    .pending_or_applied_config()
                    .is_some_and(|config| config.router_config().is_some())
            {
                // No pre-Connect blocking capture. Keep Partial (or no capture)
                // until target parameters create a managed configuration request.
                partial()
            } else {
                let routes = policy
                    .announced_routes()
                    .iter()
                    .map(|route| route.network())
                    .collect();
                let mut config = match &self.target_config {
                    Some(target) => talpid_tunnel::tun_provider::transport::router_config(
                        target.target_config(),
                        routes,
                    ),
                    None => talpid_tunnel::tun_provider::transport::router_blocking_config(routes),
                };
                // A live target request owns full-capture app coverage. Its TSM
                // update can precede the settings acknowledgement; projecting
                // those old settings here would hand the new capture back.
                // Startup/Error still need the actor's current settings when no
                // new target configuration operation supplies their coverage.
                if (phase == TunnelPhase::Error || self.target_config.is_none())
                    && let Some(packages) = &self.excluded_packages
                {
                    config.excluded_packages.clone_from(packages);
                }
                let applied = self.delivery.pending_or_applied_config();
                Some(match applied {
                    Some(applied)
                        if applied
                            .router_config()
                            .is_some_and(|current| current.same_android_config(&config)) =>
                    {
                        applied
                    }
                    _ => DeliveryConfig::Router(config),
                })
            }
        } else {
            None
        };
        let successor = self.broker.pending_request().is_some() && self.delivery.release_ready();
        if !self.shutting_down && (external || !self.delivery.failed() || successor) {
            if external {
                self.delivery.maintain_config(config).await;
            } else {
                self.delivery.reconcile_config(config).await;
            }
        }
        self.set_endpoint(target, phase);
    }

    pub fn owner_changed<P: Into<TunnelPhase>>(
        &mut self,
        policy: &LocalNetworkAccess,
        target: TargetState,
        phase: P,
    ) -> Option<LocalNetworkStatus> {
        let phase = phase.into();
        self.delivery.owner_changed();
        self.set_endpoint(target, phase);
        self.publish(policy, target, phase)
    }

    fn publish(
        &mut self,
        policy: &LocalNetworkAccess,
        target: TargetState,
        phase: TunnelPhase,
    ) -> Option<LocalNetworkStatus> {
        let mut sample = LocalNetworkStatus::from_observation(policy, self.observation.as_ref())
            .with_forwarding(self.availability(policy, target, phase));
        sample.revision = self.status.revision;
        if sample == self.status {
            return None;
        }
        sample.revision = sample
            .revision
            .checked_add(1)
            .expect("local status revision exhausted");
        self.status = sample.clone();
        Some(sample)
    }

    #[cfg(test)]
    pub fn has_owner(&self) -> bool {
        self.delivery.has_owner()
    }

    #[cfg(test)]
    pub(super) fn capture_configuration_ready(&self) -> bool {
        self.delivery.configuration_ready() && self.broker.snapshot().capture_ready
    }

    fn set_endpoint(&mut self, _target: TargetState, _phase: TunnelPhase) {
        // A handover suspends the sink, not the logical Local grant. Queued
        // replies retain their physical sockets and wait for the current sink.
        let ready = !self.shutting_down
            && self.delivery.ready()
            && self.broker.snapshot().session_generation.is_some();
        if ready {
            self.suspended = false;
        }
        self.delivery.authority.endpoint(ready && !self.suspended);
    }

    fn availability(
        &self,
        policy: &LocalNetworkAccess,
        _target: TargetState,
        _phase: TunnelPhase,
    ) -> mullvad_types::settings::local_network_access::status::ForwardingAvailability {
        let endpoint =
            !self.shutting_down && self.delivery.ready() && self.broker.snapshot().capture_ready;
        let expected_teardown = self.suspended && !self.delivery.release_failed();
        local_delivery::availability(
            self.delivery.supported(),
            policy.enabled,
            !policy.announced_routes().is_empty(),
            endpoint && !self.suspended,
            if expected_teardown {
                None
            } else {
                self.delivery.owner_state()
            },
            self.delivery.failed() && !expected_teardown,
        )
    }

    #[cfg(any(target_os = "android", test))]
    pub fn broker(&self) -> AttachmentBroker {
        self.broker.clone()
    }

    /// Successful TSM spawn supplies a current state, not an initial transition.
    pub fn initialize_transport(&mut self, phase: TunnelPhase) -> ConnectContinuation {
        let mut continuation = ConnectContinuation::default();
        self.observe_transport(&mut continuation, phase);
        continuation
    }

    /// Dispatch normal Connect directly. The TSM owns reconnect ordering and
    /// exact request cancellation; capture readiness belongs to its pending open.
    pub fn continue_connect(
        &mut self,
        continuation: &mut ConnectContinuation,
    ) -> Option<talpid_core::tunnel_state_machine::TunnelCommand> {
        use talpid_core::tunnel_state_machine::TunnelCommand;
        if self.is_shutting_down() || !continuation.take_connect() {
            return None;
        }
        // Only explicit Disconnect/shutdown pauses admission. A later explicit
        // Connect releases that stop, without reviving any retired attempt.
        if let Err(error) = self.broker.resume_transport() {
            // Still send the upstream command: its open must report the real
            // failure through the TSM, never strand admission outside it.
            log::error!("Target admission could not resume: {error:?}");
        }
        Some(TunnelCommand::Connect)
    }

    pub fn observe_transport(
        &mut self,
        continuation: &mut ConnectContinuation,
        phase: TunnelPhase,
    ) {
        if phase == TunnelPhase::Disconnected
            || (self.phase == Some(TunnelPhase::Disconnecting)
                && phase != TunnelPhase::Disconnecting)
        {
            // TSM emits the next state only after its tunnel-close future joins.
            // Acknowledge every exact request retained by this owner, including
            // an in-flight successor and a predecessor awaiting cleanup.
            self.delivery.transport_joined();
        } else if phase == TunnelPhase::Disconnecting {
            self.delivery.defer_release();
        }
        self.phase = Some(phase);
        continuation.observe(phase);
    }

    pub fn request_disconnect(
        &mut self,
        continuation: &mut ConnectContinuation,
    ) -> talpid_core::tunnel_state_machine::TunnelCommand {
        continuation.disconnect();
        self.suspend();
        talpid_core::tunnel_state_machine::TunnelCommand::Disconnect
    }

    #[cfg(test)]
    pub fn failed(&self) -> bool {
        self.delivery.failed()
    }
    pub fn is_shutting_down(&self) -> bool {
        self.shutting_down
    }

    pub fn suspend(&mut self) {
        self.delivery.defer_release();
        self.broker.pause_transport();
        if self.phase == Some(TunnelPhase::Disconnected) {
            self.delivery.transport_joined();
        }
    }

    pub fn begin_shutdown(&mut self) {
        if self.shutting_down {
            return;
        }
        self.shutting_down = true;
        self.suspended = true;
        self.delivery.defer_release();
        self.delivery.authority.revoke();
        if let Some(feed) = &self.feed {
            feed.set_policy_demand(false);
        }
        // Preserve provider selection through joined TSM close, including Native.
        self.broker.pause_transport();
    }

    #[cfg(test)]
    pub async fn stop(&mut self) -> std::io::Result<()> {
        self.delivery.stop().await
    }

    pub async fn shutdown(&mut self) -> std::io::Result<()> {
        self.begin_shutdown();
        if !self.delivery.release_ready() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "Transport teardown is not joined",
            ));
        }
        self.broker.close();
        self.delivery.stop().await?;
        self.target_config = None;
        self.blocking_config = None;
        Ok(())
    }

    pub fn transport_shutdown_joined(&self) {
        // The TSM's own completion joined queued commands and monitor cleanup.
        // This acknowledges resource ownership, not a public Disconnected state.
        self.delivery.transport_joined();
    }

    pub async fn shutdown_with_transport(
        &mut self,
        joined: impl std::future::Future<Output = std::io::Result<()>>,
    ) -> std::io::Result<()> {
        self.begin_shutdown();
        self.broker.close();
        joined.await?;
        self.transport_shutdown_joined();
        self.shutdown().await
    }
}

async fn feed_changed(receiver: &mut Option<watch::Receiver<LocalNetworkFeedState>>) {
    match receiver {
        Some(active) => {
            if active.changed().await.is_err() {
                *receiver = None;
            }
        }
        None => std::future::pending().await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mullvad_types::settings::local_network_access::{
        LocalBypassRule,
        status::{InactiveReason, RuleState},
    };
    use talpid_types::local_network::LocalNetworkSnapshot;

    fn policy() -> LocalNetworkAccess {
        LocalNetworkAccess {
            enabled: true,
            rules: vec![LocalBypassRule {
                id: "00000000-0000-0000-0000-000000000000".parse().unwrap(),
                name: String::new(),
                enabled: true,
                cidrs: vec!["10.0.0.0/8".parse().unwrap()],
                ssid_ids: vec![],
            }],
        }
    }

    #[test]
    fn normal_connect_dispatch_is_direct_and_explicit_disconnect_wins() {
        use talpid_core::tunnel_state_machine::TunnelCommand;
        let mut runtime = LocalNetworkRuntime::new(&policy(), None);
        let mut intent = ConnectContinuation::default();
        for phase in [
            TunnelPhase::Disconnected,
            TunnelPhase::Connecting,
            TunnelPhase::Connected,
            TunnelPhase::Disconnecting,
            TunnelPhase::Error,
        ] {
            intent.observe(phase);
            intent.connect();
            assert!(matches!(
                runtime.continue_connect(&mut intent),
                Some(TunnelCommand::Connect)
            ));
            assert!(!intent.joined());
            assert!(runtime.continue_connect(&mut intent).is_none());
            intent.connect();
            assert!(matches!(
                runtime.request_disconnect(&mut intent),
                TunnelCommand::Disconnect
            ));
            assert!(runtime.continue_connect(&mut intent).is_none());
        }
        runtime.begin_shutdown();
        intent.connect();
        assert!(runtime.continue_connect(&mut intent).is_none());
    }

    #[tokio::test]
    async fn shutdown_preserves_native_close_selection_until_tsm_join() {
        let mut runtime = LocalNetworkRuntime::new(&LocalNetworkAccess::default(), None);
        let broker = runtime.broker();
        runtime.begin_shutdown();
        assert_eq!(broker.snapshot().mode, AttachmentMode::Native);
        assert!(!broker.snapshot().closed);
        let closed = std::cell::Cell::new(false);
        talpid_tunnel::tun_provider::transport::TransportMode::selected(Some(&broker))
            .close(|| closed.set(true));
        assert!(
            closed.get(),
            "Native's close callback must not become managed detach"
        );
        runtime.shutdown().await.unwrap();
        assert!(broker.snapshot().closed);
    }

    #[test]
    fn shutdown_waits_for_join_after_connect_is_queued_on_cached_disconnected() {
        use mullvad_types::states::TunnelState;
        let cached = TunnelState::Disconnected {
            location: None,
            #[cfg(not(target_os = "android"))]
            locked_down: false,
        };
        let mut intent = ConnectContinuation::default();
        assert!(!intent.disconnected_and_joined(&cached));
        intent.observe(TunnelPhase::Disconnected);
        assert!(intent.disconnected_and_joined(&cached));
        intent.connect();
        assert!(intent.take_connect());
        intent.disconnect();
        // Ignored shutdown events do not update the cached tunnel state or join.
        for _ignored_event in 0..3 {
            assert!(!intent.disconnected_and_joined(&cached));
        }
        for phase in [TunnelPhase::Connecting, TunnelPhase::Disconnecting] {
            intent.observe(phase);
            assert!(!intent.disconnected_and_joined(&cached));
        }
        intent.observe(TunnelPhase::Disconnected);
        assert!(intent.disconnected_and_joined(&cached));
        let disconnecting =
            TunnelState::Disconnecting(talpid_types::tunnel::ActionAfterDisconnect::Nothing);
        assert!(!intent.disconnected_and_joined(&disconnecting));
    }

    #[tokio::test]
    async fn native_managed_startup_last_rule_routes_and_conditions_use_one_choke_point() {
        use talpid_core::tunnel_state_machine::TunnelCommand;
        for enabled in [false, true] {
            let mut configured = policy();
            configured.enabled = enabled;
            let mut runtime = LocalNetworkRuntime::new(&configured, None);
            let mut intent = runtime.initialize_transport(TunnelPhase::Disconnected);
            let mut conditions = configured.clone();
            conditions.rules[0].name = "renamed".into();
            conditions.rules[0].ssid_ids.push(
                mullvad_types::settings::local_network_access::SsidIdentity::from_bytes(
                    b"other".to_vec(),
                )
                .unwrap(),
            );
            runtime
                .update(&conditions, TargetState::Secured, TunnelPhase::Connected)
                .await;
            assert!(runtime.continue_connect(&mut intent).is_none());
            configured.enabled = !enabled;
            runtime
                .update(&configured, TargetState::Secured, TunnelPhase::Connected)
                .await;
            assert!(runtime.continue_connect(&mut intent).is_none());
            intent.connect();
            assert!(matches!(
                runtime.continue_connect(&mut intent),
                Some(TunnelCommand::Connect)
            ));
            intent.observe(TunnelPhase::Connected);
            configured.enabled = true;
            configured.rules.clear();
            runtime
                .update(&configured, TargetState::Secured, TunnelPhase::Connected)
                .await;
            assert!(runtime.continue_connect(&mut intent).is_none());
            assert!(runtime.broker.local_routes().is_empty());
        }
        let mut runtime = LocalNetworkRuntime::new(&policy(), None);
        let mut intent = runtime.initialize_transport(TunnelPhase::Connected);
        let mut routes = policy();
        routes.rules[0].cidrs = vec!["172.16.0.0/16".parse().unwrap()];
        runtime
            .update(&routes, TargetState::Secured, TunnelPhase::Connected)
            .await;
        assert!(runtime.continue_connect(&mut intent).is_none());
        assert_eq!(
            runtime.broker.local_routes(),
            vec!["172.16.0.0/16".parse().unwrap()]
        );
    }

    #[tokio::test]
    async fn feed_notifications_and_settings_share_one_semantic_revision_owner() {
        let feed = LocalNetworkFeed::new(1);
        let mut policy = policy();
        let mut runtime = LocalNetworkRuntime::new(&policy, Some(feed.clone()));
        assert!(!runtime.status().observer_available);
        assert_eq!(
            runtime.status().rules[0].state,
            RuleState::Inactive(InactiveReason::ObserverUnavailable)
        );
        let first = runtime.status().revision;
        feed.publish(
            1,
            LocalNetworkSnapshot {
                sequence: 1,
                observer_running: true,
                local_ready: true,
                ..Default::default()
            },
        );
        runtime.notifications().0.await;
        let changed = runtime
            .update(&policy, TargetState::Unsecured, true)
            .await
            .unwrap();
        assert_eq!(changed.revision, first + 1);
        assert_eq!(
            changed.rules[0].state,
            RuleState::Inactive(InactiveReason::NoEligibleNetwork)
        );
        feed.publish(
            1,
            LocalNetworkSnapshot {
                sequence: 2,
                observer_running: true,
                local_ready: true,
                ..Default::default()
            },
        );
        runtime.notifications().0.await;
        assert!(
            runtime
                .update(&policy, TargetState::Unsecured, true)
                .await
                .is_none()
        );
        assert_eq!(runtime.status(), &changed);
        policy.enabled = false;
        assert_eq!(
            runtime
                .update(&policy, TargetState::Unsecured, true)
                .await
                .unwrap()
                .revision,
            first + 2
        );
        assert!(
            runtime
                .update(&policy, TargetState::Unsecured, true)
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn closed_feed_discards_observations_and_publishes_unavailable_once() {
        let feed = LocalNetworkFeed::new(1);
        let mut runtime = LocalNetworkRuntime::new(&policy(), Some(feed.clone()));
        feed.publish(
            1,
            LocalNetworkSnapshot {
                sequence: 1,
                observer_running: true,
                ..Default::default()
            },
        );
        runtime
            .update(&policy(), TargetState::Unsecured, true)
            .await;
        feed.close();
        runtime.notifications().0.await;
        let status = runtime
            .update(&policy(), TargetState::Unsecured, true)
            .await
            .unwrap();
        assert!(!status.observer_available);
        assert_eq!(
            status.rules[0].state,
            RuleState::Inactive(InactiveReason::ObserverUnavailable)
        );
        assert!(
            runtime
                .update(&policy(), TargetState::Unsecured, true)
                .await
                .is_none()
        );
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(30),
                runtime.notifications().0
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn unsupported_platform_returns_a_stable_unavailable_status() {
        let mut runtime = LocalNetworkRuntime::new(&policy(), None);
        assert_eq!(runtime.status().revision, 1);
        assert!(!runtime.status().observer_available);
        assert!(
            runtime
                .update(&policy(), TargetState::Unsecured, true)
                .await
                .is_none()
        );
    }
}
