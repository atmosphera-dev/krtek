//! Non-authorizing packet completion with byte-exact original-packet custody.
//!
//! A selective consumer must not send any fragment before classifying the whole
//! datagram. Completion owns the original packets separately from lwIP's mutable
//! reassembly backing. The consumer can release those originals unchanged, or
//! consume them locally. This is not another tunnel reader, route classifier or
//! socket owner. The selective DNS consumer supplies capture/policy lifetimes.

pub use crate::ip_endpoint::contract::IpError;
use crate::ip_endpoint::{
    capture::{self, OwnedTransport, PacketBatch},
    contract::{LocalIpEngine, ReceiveScopeId, ReplyTuple},
    native::Engine,
};
use crate::{ReceiveScope, Transport, packet};
use smoltcp::wire::{IpProtocol, Ipv4Packet, Ipv6ExtHeader, Ipv6FragmentHeader, Ipv6Packet};
use std::{
    collections::BTreeMap,
    io,
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU16, Ordering},
    },
};
use talpid_types::relay_flow::{
    BUFFER_OVERHEAD, RelayBuffer, RelayBufferAllocator, RelayBufferReservation,
};

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
struct Key {
    source: IpAddr,
    destination: IpAddr,
    ident: u32,
    protocol: u8,
}

struct Pending {
    parent: ReceiveScope,
    scope: ReceiveScope,
    originals: BTreeMap<usize, Original>,
    _metadata: Arc<dyn RelayBufferReservation>,
}

struct Original {
    bytes: RelayBuffer,
    // Separate from RelayBuffer: its constructor refunds unused ticket bytes.
    // Tree nodes are released with their last entry, unlike a retained Vec arena.
    _node: Arc<dyn RelayBufferReservation>,
}

impl Drop for Pending {
    fn drop(&mut self) {
        self.scope.revoke();
    }
}

/// Complete, checksum-validated transport and the exact packets that formed it.
/// Neither the receive scope nor successful validation grants socket/reply I/O.
pub struct CompletedDatagram {
    complete: OwnedTransport,
    pending: Pending,
    receiver: Arc<ReceiverLifetime>,
}

struct ReceiverLifetime {
    live: AtomicBool,
    mtu: AtomicU16,
    _charge: Arc<dyn RelayBufferReservation>,
}

impl CompletedDatagram {
    pub fn packet(&self) -> Result<packet::Packet<'_>, IpError> {
        if !self.current() {
            return Err(IpError::Stale);
        }
        self.complete.validated()
    }

    pub fn current(&self) -> bool {
        self.receiver.live.load(Ordering::Acquire)
            && self.pending.parent.current()
            && self.pending.scope.current()
    }

    /// Release each original only after the caller's current capture/target
    /// check. Packet order is arrival order, including out-of-order fragments.
    pub fn pop_original(&mut self) -> Result<Option<RelayBuffer>, IpError> {
        if !self.current() {
            return Err(IpError::Stale);
        }
        Ok(self
            .pending
            .originals
            .pop_first()
            .map(|(_, original)| original.bytes))
    }
}

/// A funded native UDP reply retaining the exact completed input incarnation.
/// This is NOT a transport grant. The consumer must enclose every synchronous
/// sink write in its retained reply authority and exact capture/sink check.
pub struct DatagramReply {
    output: Option<DatagramOutput>,
}

struct DatagramOutput {
    input: CompletedDatagram,
    batch: PacketBatch,
}

impl DatagramReply {
    /// Lifetime only, never permission to emit into a capture sink.
    pub fn current(&self) -> bool {
        self.output
            .as_ref()
            .is_some_and(|output| output.input.current())
    }

    pub fn has_output(&self) -> bool {
        self.output.is_some()
    }

    /// One checked whole packet per call, yielding between fragments. WouldBlock
    /// retains the same bytes/cursor. Retirement or an obsolete MTU discards the
    /// entire unsent remainder without replaying any already delivered fragment.
    pub fn write_output(
        &mut self,
        sink_mtu: u16,
        write: impl FnOnce(&[u8]) -> io::Result<usize>,
    ) -> io::Result<bool> {
        let Some(output) = self.output.as_mut() else {
            return Ok(false);
        };
        let mtu = usize::from(
            output
                .input
                .receiver
                .mtu
                .load(Ordering::Acquire)
                .min(sink_mtu),
        );
        if !output.input.current() || !output.batch.fits(mtu) {
            self.output.take();
            return Ok(false);
        }
        let bytes = output.batch.packet();
        match write(bytes) {
            Ok(n) if n == bytes.len() => {
                if !output.batch.advance() {
                    self.output.take();
                }
                Ok(true)
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Err(error),
            result => {
                // Fatal/partial writes must never become a replayable packet.
                self.output.take();
                Err(result.err().unwrap_or_else(|| {
                    io::Error::new(io::ErrorKind::WriteZero, "partial IP packet write")
                }))
            }
        }
    }
}

/// One logical handle on the existing process-global native core. Retained
/// originals and metadata use the caller's existing shared byte allocator.
pub struct PacketReceiver {
    engine: Engine,
    buffers: Arc<dyn RelayBufferAllocator>,
    pending: BTreeMap<Key, Pending>,
    live: Arc<ReceiverLifetime>,
}

/// Non-authorizing UDP candidate selection using the same IP boundary as input.
pub fn udp_endpoints(bytes: &[u8]) -> Result<Option<(IpAddr, IpAddr)>, IpError> {
    let endpoints = packet::ip_endpoints(bytes).map_err(|_| IpError::Malformed)?;
    let protocol = if endpoints.0.is_ipv4() {
        Ipv4Packet::new_checked(bytes)
            .map_err(|_| IpError::Malformed)?
            .next_header()
    } else {
        let ip = Ipv6Packet::new_checked(bytes).map_err(|_| IpError::Malformed)?;
        if ip.next_header() == IpProtocol::Ipv6Frag {
            Ipv6ExtHeader::new_checked(ip.payload())
                .map_err(|_| IpError::Malformed)?
                .next_header()
        } else {
            ip.next_header()
        }
    };
    match u8::from(protocol) {
        17 => Ok(Some(endpoints)),
        // Extension-prefixed input is not supported by the native receiver.
        // It must be explicitly refused, never mistaken for non-DNS transit.
        0 | 43 | 51 | 60 => Err(IpError::Unsupported),
        _ => Ok(None),
    }
}

impl PacketReceiver {
    pub fn new(buffers: Arc<dyn RelayBufferAllocator>, mtu: u16) -> Result<Self, IpError> {
        let charge = buffers.try_reserve(1024).map_err(|_| IpError::Full)?;
        Ok(Self {
            engine: Engine::open(buffers.clone(), mtu)?,
            buffers,
            pending: BTreeMap::new(),
            live: Arc::new(ReceiverLifetime {
                live: AtomicBool::new(true),
                mtu: AtomicU16::new(mtu),
                _charge: charge,
            }),
        })
    }

    /// Compatible MTU changes retain the input incarnation, but queued replies
    /// always see this receiver's latest MTU rather than a caller's old snapshot.
    pub fn set_mtu(&mut self, mtu: u16) -> Result<(), IpError> {
        self.engine.set_mtu(mtu)?;
        self.live.mtu.store(mtu, Ordering::Release);
        Ok(())
    }

    /// Generate with the existing pristine-native batch encoder. No physical
    /// socket or Local grant for the intercepted destination is acquired here.
    /// The supplied reply arena must be shared with sibling output producers;
    /// admission preserves the same two maximum TCP peaks as ordinary Local UDP.
    pub fn reply(
        &mut self,
        input: CompletedDatagram,
        payload: &[u8],
        replies: &dyn RelayBufferAllocator,
    ) -> Result<DatagramReply, IpError> {
        if !Arc::ptr_eq(&input.receiver, &self.live) || !input.current() {
            return Err(IpError::Stale);
        }
        let tuple = ReplyTuple::from_flow(input.complete.scope, input.packet()?.flow)?;
        tuple.check_payload_len(payload.len())?;
        let mtu = usize::from(self.live.mtu.load(Ordering::Acquire));
        let batch =
            PacketBatch::reserve_preserving(replies, mtu, crate::forwarder::UDP_REPLY_HEADROOM)?
                .generate(&mut self.engine, tuple, payload)?;
        if !input.current() {
            return Err(IpError::Stale);
        }
        Ok(DatagramReply {
            output: Some(DatagramOutput { input, batch }),
        })
    }

    /// Call only for an already selected candidate destination. This boundary
    /// supports the same canonical IP forms as the existing Local completion
    /// engine; unsupported input is explicit, never a purported pass-through.
    pub fn ingest(
        &mut self,
        parent: &ReceiveScope,
        bytes: &[u8],
    ) -> Result<Option<CompletedDatagram>, IpError> {
        self.revalidate();
        let (key, fragmented) = key(bytes)?;
        if !parent.current()
            || parent.source() != key.source
            || parent.destination() != key.destination
        {
            return Err(IpError::Stale);
        }
        // Different capture/policy scopes may never share a native incarnation,
        // even if Android reuses the complete IP fragment key immediately.
        if self
            .pending
            .get(&key)
            .is_some_and(|p| p.parent.id() != parent.id())
        {
            self.pending.remove(&key);
        }
        let previous = if fragmented {
            self.pending.remove(&key)
        } else {
            None
        };
        let continuing = previous.is_some();
        let mut pending = match previous {
            Some(pending) => pending,
            None => {
                // Covers the map node, scope owner and original-tree metadata.
                // Each packet separately funds its original-tree node.
                let metadata = self.buffers.try_reserve(4096).map_err(|_| IpError::Full)?;
                let scope = ReceiveScope::new(key.source, key.destination, self.buffers.as_ref())
                    .map_err(|_| IpError::Full)?;
                Pending {
                    parent: parent.clone(),
                    scope,
                    originals: BTreeMap::new(),
                    _metadata: metadata,
                }
            }
        };
        let node = self.buffers.try_reserve(1024).map_err(|_| IpError::Full)?;
        let charge = self
            .buffers
            .try_reserve(bytes.len() + BUFFER_OVERHEAD)
            .map_err(|_| IpError::Full)?;
        let original = Original {
            bytes: RelayBuffer::from_reservation(bytes.to_vec(), charge)
                .map_err(|_| IpError::Full)?,
            _node: node,
        };
        pending.originals.insert(pending.originals.len(), original);
        if continuing {
            self.engine.register_retained(&pending.scope)?;
        } else {
            self.engine.register(&pending.scope)?;
        }
        let complete = capture::ingest(
            &mut self.engine,
            ReceiveScopeId(pending.scope.id()),
            bytes,
            self.buffers.as_ref(),
        )?;
        if !pending.parent.current() {
            return Err(IpError::Stale);
        }
        match complete {
            Some(complete) => {
                let parsed = complete.validated()?;
                if parsed.flow.transport != Transport::Udp {
                    return Err(IpError::Unsupported);
                }
                if parsed.flow.source.ip() != key.source
                    || parsed.flow.destination.ip() != key.destination
                {
                    return Err(IpError::Malformed);
                }
                // Stock reassembly can discard an overlapping input while
                // retaining the older assembly. Never release discarded bytes
                // that could let another endpoint reconstruct a different DNS
                // message. Every original range must agree with the exact
                // validated segment; this audits custody, not IP reassembly.
                for original in pending.originals.values() {
                    let (offset, more, body) = fragment_bytes(&original.bytes)?;
                    let end = offset.checked_add(body.len()).ok_or(IpError::Malformed)?;
                    if complete.segment().get(offset..end) != Some(body)
                        || (!more && end != complete.segment().len())
                        || (more && end >= complete.segment().len())
                    {
                        return Err(IpError::Malformed);
                    }
                }
                Ok(Some(CompletedDatagram {
                    complete,
                    pending,
                    receiver: self.live.clone(),
                }))
            }
            None => {
                if fragmented && self.engine.scope_refs(ReceiveScopeId(pending.scope.id())) != 0 {
                    self.pending.insert(key, pending);
                }
                Ok(None)
            }
        }
    }

    /// Also call on authority updates. Native timers own their tagged backing;
    /// revoked/expired packet copies do not need to wait for a new datagram.
    pub fn revalidate(&mut self) {
        self.pending.retain(|_, pending| {
            pending.parent.current()
                && pending.scope.current()
                && self.engine.scope_refs(ReceiveScopeId(pending.scope.id())) != 0
        });
    }

    /// Select alongside ingress and authority changes, so silent incomplete
    /// queries release their original copies after the native expiry horizon.
    /// Cancellation retains the same packet owners; this never drives/resets
    /// native time, whose process-global worker remains the only timer owner.
    pub async fn wait(&mut self) {
        let delay = if self.pending.is_empty() {
            None
        } else {
            self.engine.next_timeout_ms()
        };
        match delay {
            Some(ms) => {
                tokio::time::sleep(std::time::Duration::from_millis(u64::from(ms.max(1)))).await
            }
            None => std::future::pending().await,
        }
        self.revalidate();
    }
}

impl Drop for PacketReceiver {
    fn drop(&mut self) {
        self.live.live.store(false, Ordering::Release);
    }
}

fn fragment_bytes(bytes: &[u8]) -> Result<(usize, bool, &[u8]), IpError> {
    if bytes[0] >> 4 == 4 {
        let ip = Ipv4Packet::new_checked(bytes).map_err(|_| IpError::Malformed)?;
        Ok((usize::from(ip.frag_offset()), ip.more_frags(), ip.payload()))
    } else {
        let ip = Ipv6Packet::new_checked(bytes).map_err(|_| IpError::Malformed)?;
        if ip.next_header() == IpProtocol::Ipv6Frag {
            let extension =
                Ipv6ExtHeader::new_checked(ip.payload()).map_err(|_| IpError::Malformed)?;
            let fragment = Ipv6FragmentHeader::new_checked(extension.payload())
                .map_err(|_| IpError::Malformed)?;
            Ok((
                usize::from(fragment.frag_offset()) * 8,
                fragment.more_frags(),
                &ip.payload()[8..],
            ))
        } else {
            Ok((0, false, ip.payload()))
        }
    }
}

fn key(bytes: &[u8]) -> Result<(Key, bool), IpError> {
    let (source, destination) = packet::ip_endpoints(bytes).map_err(|error| match error {
        packet::PacketRefusal::Checksum => IpError::Checksum,
        _ => IpError::Malformed,
    })?;
    let (ident, protocol, fragmented) = if source.is_ipv4() {
        let ip = Ipv4Packet::new_checked(bytes).map_err(|_| IpError::Malformed)?;
        let fragmented = ip.more_frags() || ip.frag_offset() != 0;
        if fragmented && ip.header_len() != 20 {
            return Err(IpError::Unsupported);
        }
        (
            u32::from(ip.ident()),
            u8::from(ip.next_header()),
            fragmented,
        )
    } else {
        let ip = Ipv6Packet::new_checked(bytes).map_err(|_| IpError::Malformed)?;
        if ip.next_header() == IpProtocol::Ipv6Frag {
            // smoltcp's fragment type describes the six bytes AFTER the generic
            // extension-header prefix. Never interpret tail payload as ports.
            let extension =
                Ipv6ExtHeader::new_checked(ip.payload()).map_err(|_| IpError::Malformed)?;
            let fragment = Ipv6FragmentHeader::new_checked(extension.payload())
                .map_err(|_| IpError::Malformed)?;
            if fragment.frag_offset() == 0 && !fragment.more_frags() {
                return Err(IpError::Unsupported);
            }
            (fragment.ident(), u8::from(extension.next_header()), true)
        } else {
            (0, u8::from(ip.next_header()), false)
        }
    };
    if protocol != u8::from(IpProtocol::Udp) {
        return Err(IpError::Unsupported);
    }
    Ok((
        Key {
            source,
            destination,
            ident,
            protocol,
        },
        fragmented,
    ))
}

#[cfg(test)]
#[path = "packet_receiver_tests.rs"]
mod tests;
