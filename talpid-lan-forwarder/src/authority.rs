//! The consumer owns policy, network choice and socket protection/binding.

use crate::Flow;
use std::net::{IpAddr, SocketAddr};
use std::sync::{
    Arc, Weak,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use talpid_types::relay_flow::{RelayBufferAllocator, RelayBufferReservation};

/// At most one context per retained native input node. This is a storage bound,
/// not a packet-rate quota or a second fragment-assembly table.
pub const MAX_RECEIVE_SCOPES: usize = 4098;

struct ReceiveState {
    id: u64,
    source: IpAddr,
    destination: IpAddr,
    live: AtomicBool,
    _charge: Arc<dyn RelayBufferReservation>,
}

/// Non-authorizing receive identity. It contains no ports or physical socket.
/// Publication revokes it irreversibly before waking a possibly coalescing owner.
#[derive(Clone)]
pub struct ReceiveScope(Arc<ReceiveState>);

#[derive(Clone)]
pub struct WeakReceiveScope(Weak<ReceiveState>);

impl ReceiveScope {
    pub fn new(
        source: IpAddr,
        destination: IpAddr,
        buffers: &dyn RelayBufferAllocator,
    ) -> Result<Self, Refused> {
        if source.is_ipv4() != destination.is_ipv4() {
            return Err(Refused::Denied);
        }
        // Includes the fixed scope, allocator/Arc overhead and the consumer's
        // fixed identity/weak-registration node. Never stores a cloned rule list.
        let charge = buffers.try_reserve(1024).map_err(|_| Refused::Full)?;
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let id = NEXT
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| Refused::Full)?;
        Ok(Self(Arc::new(ReceiveState {
            id,
            source,
            destination,
            live: AtomicBool::new(true),
            _charge: charge,
        })))
    }

    pub fn id(&self) -> u64 {
        self.0.id
    }

    pub fn source(&self) -> IpAddr {
        self.0.source
    }

    pub fn destination(&self) -> IpAddr {
        self.0.destination
    }

    pub fn current(&self) -> bool {
        self.0.live.load(Ordering::Acquire)
    }

    pub fn revoke(&self) {
        self.0.live.store(false, Ordering::Release);
    }

    pub fn downgrade(&self) -> WeakReceiveScope {
        WeakReceiveScope(Arc::downgrade(&self.0))
    }

    /// Keeps fixed consumer registration storage funded even between the last
    /// guard dropping and the consumer pruning its weak registration.
    pub fn registration_credit(&self) -> Arc<dyn RelayBufferReservation> {
        self.0._charge.clone()
    }
}

impl WeakReceiveScope {
    pub fn upgrade(&self) -> Option<ReceiveScope> {
        self.0.upgrade().map(ReceiveScope)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Disposition {
    Local,
    Drop,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Refused {
    UnsupportedMtu,
    Denied,
    Stale,
    Full,
    PreparationFailed,
}

pub trait LocalAuthority: Send + Sync + 'static {
    type Grant: Clone + Send + Sync + 'static;

    /// Cheap triage only; must not prepare sockets.
    fn disposition(&self, destination: IpAddr) -> Disposition;
    /// Acquire provenance without complete-flow authorization or socket work.
    /// Consumers opting into native receive must implement this explicitly.
    fn receive(
        &self,
        _source: IpAddr,
        _destination: IpAddr,
        _buffers: &dyn RelayBufferAllocator,
    ) -> Result<ReceiveScope, Refused> {
        Err(Refused::Denied)
    }
    /// Authorize the complete tuple against its ORIGINAL receive identity, never
    /// a successor physical network. No permissive default grants new authority.
    fn authorize_received(
        &self,
        _flow: Flow,
        _scope: &ReceiveScope,
    ) -> Result<Self::Grant, Refused> {
        Err(Refused::Denied)
    }
    /// Decide without creating, preparing or connecting a socket.
    fn authorize(&self, flow: Flow) -> Result<Self::Grant, Refused>;
    /// Protect and bind under the platform's admission check. Runs off the owner task.
    fn prepare(&self, socket: &socket2::Socket, grant: &Self::Grant) -> Result<(), Refused>;
    /// Re-evaluate the grant against the latest inputs.
    fn current(&self, grant: &Self::Grant) -> bool;
    /// Physical endpoint, including any required IPv6 scope ID.
    fn physical_destination(&self, grant: &Self::Grant, flow: Flow) -> SocketAddr;
}
