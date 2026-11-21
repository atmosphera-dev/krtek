//! Engine-independent, synchronous Local IP boundary.
//!
//! Completion is not admission. Callbacks may only capture bytes into existing
//! funded backing. They never authorize, prepare sockets, wait, reenter native
//! code or unwind through C. Borrowed results cannot outlive the callback;
//! retaining a copy requires its own input/reply credit. A reply captures into
//! one pre-funded batch with an explicit owner; the caller checks its error
//! latch before enqueueing any packet, even if native returns OK.
//!
//! The implementation owns a logical native handle, not a separate lwIP core.
//! One process-global lock, clock, reservation and timer owner cover all handles.
//! All node tags must agree on one still-live handle/scope before completion.
//! Retirement is irreversible; stock timers may reclaim old nodes later. Keep
//! receive guards until scope_refs reaches zero, including after close. Keep
//! native funding until the global core is quiescent, not just handle closure.

use super::ffi;
use crate::{Flow, Transport};
use std::net::{IpAddr, SocketAddr};

/// Numeric receive identity, allocated without reuse for the process lifetime.
/// This is provenance only, never a transport grant or a retained Rust pointer.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ReceiveScopeId(pub u64);

/// Process-relative wrapping lwIP clock. Handle creation must not reset it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MonotonicMillis(pub u32);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ingress {
    /// Input consumed with no retained incomplete datagram. Callback delivery
    /// does not imply transport validation or successful downstream admission.
    Consumed,
    /// No completion reported; input may be retained or discarded. Use
    /// scope_refs for guard lifetime, never this non-authorizing status.
    Pending,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpError {
    Full,
    Malformed,
    Unsupported,
    Oversized,
    Stale,
    Internal,
    /// Rust transport validation only; no native checksum-success assumption.
    Checksum,
}

impl IpError {
    /// Unknown native statuses fail closed, never masquerading as success.
    pub fn from_status(status: i32) -> Result<Ingress, Self> {
        match status {
            ffi::OK => Ok(Ingress::Consumed),
            ffi::PENDING => Ok(Ingress::Pending),
            ffi::FULL => Err(Self::Full),
            ffi::MALFORMED => Err(Self::Malformed),
            ffi::UNSUPPORTED => Err(Self::Unsupported),
            ffi::OVERSIZED => Err(Self::Oversized),
            ffi::STALE => Err(Self::Stale),
            ffi::INTERNAL => Err(Self::Internal),
            _ => Err(Self::Internal),
        }
    }
}

/// Library-described complete segment, INCLUDING the TCP/UDP header. Neither
/// lengths nor transport checksum have yet been validated by Rust. Ports must
/// be read only from this complete segment, never an individual input fragment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CompleteTransport<'a> {
    pub scope: ReceiveScopeId,
    pub source: IpAddr,
    pub destination: IpAddr,
    pub protocol: Transport,
    pub segment: &'a [u8],
}

/// Explicit UDP wire endpoints: already reversed from the original app tuple.
/// The output batch's live grant/owner stays with the caller, not these ports.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplyTuple {
    pub scope: ReceiveScopeId,
    pub source: SocketAddr,
    pub destination: SocketAddr,
}

impl ReplyTuple {
    pub fn from_flow(scope: ReceiveScopeId, flow: Flow) -> Result<Self, IpError> {
        if flow.transport != Transport::Udp {
            return Err(IpError::Unsupported);
        }
        if flow.source.is_ipv4() != flow.destination.is_ipv4() {
            return Err(IpError::Malformed);
        }
        Ok(Self {
            scope,
            source: flow.destination,
            destination: flow.source,
        })
    }

    /// Minimal-header stock-lwIP UDP ceiling, checked before allocation/casts.
    /// Options/extensions, if accepted, consume their actual additional bytes.
    pub fn check_payload_len(self, len: usize) -> Result<(), IpError> {
        if self.source.is_ipv4() != self.destination.is_ipv4() {
            return Err(IpError::Malformed);
        }
        let maximum = if self.source.is_ipv4() {
            65_507
        } else {
            65_487
        };
        if len > maximum {
            return Err(IpError::Oversized);
        }
        Ok(())
    }
}

/// No storage is transferred across this interface. Implementations borrow
/// input and callback buffers for the synchronous call only. Production copies
/// must use the existing funded arenas; fixture Vec storage is test-only.
pub trait LocalIpEngine {
    fn ingest(
        &mut self,
        scope: ReceiveScopeId,
        ip: &[u8],
        completed: &mut dyn FnMut(CompleteTransport<'_>),
    ) -> Result<Ingress, IpError>;
    fn reply(
        &mut self,
        tuple: ReplyTuple,
        payload: &[u8],
        output: &mut dyn FnMut(&[u8]),
    ) -> Result<(), IpError>;
    fn set_mtu(&mut self, mtu: u16) -> Result<(), IpError>;
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "production timers live on the global core, beyond logical handle closure; this method is the synchronous fixture seam"
        )
    )]
    fn poll_time(&mut self, now: MonotonicMillis) -> Result<(), IpError>;
    /// Relative next wake; None maps to native UINT32_MAX. Drive even idle.
    fn next_timeout_ms(&self) -> Option<u32>;
    /// Retained tagged nodes, queryable after close until zero.
    fn scope_refs(&self, scope: ReceiveScopeId) -> usize;
    /// Idempotent retirement. Must not reset the global clock or free funding
    /// still backing retained nodes. Later mutating operations return Stale.
    fn close(&mut self);
}

#[cfg(test)]
pub(crate) mod scripted;
