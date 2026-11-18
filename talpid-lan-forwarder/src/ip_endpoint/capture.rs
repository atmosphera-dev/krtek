//! Funded synchronous callback capture. No callback grants transport authority.

use super::contract::{CompleteTransport, IpError, LocalIpEngine, ReceiveScopeId, ReplyTuple};
use crate::{Transport, packet};
use std::{net::IpAddr, sync::Arc};
use talpid_types::relay_flow::{
    BUFFER_OVERHEAD, RelayBuffer, RelayBufferAllocator, RelayBufferReservation,
};

/// Stock IPv4 output at MTU 68: ceil(65515 / 48) packets, including the last tail.
const MAX_BATCH_PACKETS: usize = 1365;
const MAX_BATCH_WIRE_BYTES: usize = 65515 + MAX_BATCH_PACKETS * 20;
pub(crate) const BATCH_RESERVATION: usize = 192 * 1024;

#[derive(Clone, Copy)]
struct PacketRange {
    start: u32,
    end: u32,
}

const _: () = assert!(
    MAX_BATCH_WIRE_BYTES
        + MAX_BATCH_PACKETS * size_of::<PacketRange>()
        + BUFFER_OVERHEAD * 2
        + size_of::<PacketBatch>()
        <= BATCH_RESERVATION
);

/// One output job, not one queue slot/allocation per IP fragment. The ticket
/// covers BOTH backing capacities, descriptors and owner/allocation overhead.
pub(crate) struct PacketBatch {
    bytes: Vec<u8>,
    packets: Vec<PacketRange>,
    next: usize,
    mtu: usize,
    failure: Option<IpError>,
    _charge: Arc<dyn RelayBufferReservation>,
}

impl PacketBatch {
    /// Must succeed before consuming a physical UDP datagram.
    pub(crate) fn reserve(buffers: &dyn RelayBufferAllocator, mtu: usize) -> Result<Self, IpError> {
        let charge = buffers
            .try_reserve(BATCH_RESERVATION)
            .map_err(|_| IpError::Full)?;
        let mut bytes = Vec::new();
        let mut packets = Vec::new();
        bytes
            .try_reserve_exact(MAX_BATCH_WIRE_BYTES)
            .map_err(|_| IpError::Full)?;
        packets
            .try_reserve_exact(MAX_BATCH_PACKETS)
            .map_err(|_| IpError::Full)?;
        // Rust's allocator may round capacity upward. Account actual capacities,
        // rather than assuming try_reserve_exact guarantees an exact capacity.
        if bytes.capacity()
            + packets.capacity() * size_of::<PacketRange>()
            + BUFFER_OVERHEAD * 2
            + size_of::<Self>()
            > charge.bytes()
        {
            return Err(IpError::Full);
        }
        Ok(Self {
            bytes,
            packets,
            next: 0,
            mtu,
            failure: None,
            _charge: charge,
        })
    }

    fn capture(&mut self, packet: &[u8]) {
        if self.failure.is_some() {
            return;
        }
        let Some(end) = self.bytes.len().checked_add(packet.len()) else {
            self.failure = Some(IpError::Full);
            return;
        };
        if packet.is_empty() || packet.len() > self.mtu {
            self.failure = Some(IpError::Internal);
        } else if end > MAX_BATCH_WIRE_BYTES || self.packets.len() == MAX_BATCH_PACKETS {
            self.failure = Some(IpError::Full);
        } else {
            self.packets.push(PacketRange {
                start: self.bytes.len() as u32,
                end: end as u32,
            });
            self.bytes.extend_from_slice(packet);
        }
    }

    pub(crate) fn generate(
        mut self,
        engine: &mut impl LocalIpEngine,
        tuple: ReplyTuple,
        payload: &[u8],
    ) -> Result<Self, IpError> {
        tuple.check_payload_len(payload.len())?;
        engine.reply(tuple, payload, &mut |packet| self.capture(packet))?;
        // A native OK is insufficient: stock fragmentation ignores netif errors.
        if let Some(error) = self.failure {
            return Err(error);
        }
        if self.packets.is_empty() {
            return Err(IpError::Internal);
        }
        Ok(self)
    }

    pub(crate) fn packet(&self) -> &[u8] {
        let range = self.packets[self.next];
        &self.bytes[range.start as usize..range.end as usize]
    }

    /// Only the owner calls this, AFTER a whole-packet successful sink write.
    pub(crate) fn advance(&mut self) -> bool {
        self.next += 1;
        self.next < self.packets.len()
    }

    /// MTU shrink cancels the entire unsent remainder if any packet is obsolete.
    /// It never regenerates/replays an already partially emitted UDP datagram.
    pub(crate) fn fits(&self, mtu: usize) -> bool {
        self.packets[self.next..]
            .iter()
            .all(|range| (range.end - range.start) as usize <= mtu)
    }
}

pub(crate) struct OwnedTransport {
    pub(crate) scope: ReceiveScopeId,
    source: IpAddr,
    destination: IpAddr,
    protocol: Transport,
    segment: RelayBuffer,
}

impl OwnedTransport {
    pub(crate) fn validated(&self) -> Result<packet::Packet<'_>, IpError> {
        packet::parse_complete_transport(
            self.source,
            self.destination,
            self.protocol,
            &self.segment,
        )
    }

    /// smoltcp only sees a minimal, validated complete TCP packet. The original
    /// native transport copy retains separate credit for this allocation peak.
    pub(crate) fn tcp_packet(
        &self,
        buffers: &dyn RelayBufferAllocator,
    ) -> Result<RelayBuffer, IpError> {
        let parsed = self.validated()?;
        if self.protocol != Transport::Tcp {
            return Err(IpError::Unsupported);
        }
        let len = self.segment.len() + if self.source.is_ipv4() { 20 } else { 40 };
        let charge = buffers
            .try_reserve(len + BUFFER_OVERHEAD)
            .map_err(|_| IpError::Full)?;
        let (mut bytes, offset) = packet::ip_packet(
            parsed.flow.source,
            parsed.flow.destination,
            smoltcp::wire::IpProtocol::Tcp,
            self.segment.len(),
        )
        .map_err(|_| IpError::Malformed)?;
        bytes[offset..].copy_from_slice(&self.segment);
        RelayBuffer::from_reservation(bytes, charge).map_err(|_| IpError::Full)
    }
}

/// Callbacks only copy into charged backing. Complete validation and receive
/// context rechecking happen after returning from the serialized native call.
pub(crate) fn ingest(
    engine: &mut impl LocalIpEngine,
    scope: ReceiveScopeId,
    ip: &[u8],
    buffers: &dyn RelayBufferAllocator,
) -> Result<Option<OwnedTransport>, IpError> {
    let mut captured = None;
    let mut failure = None;
    engine.ingest(scope, ip, &mut |complete: CompleteTransport<'_>| {
        if failure.is_some() {
            return;
        }
        if captured.is_some()
            || complete.scope != scope
            || complete.source.is_ipv4() != complete.destination.is_ipv4()
        {
            failure = Some(IpError::Malformed);
            return;
        }
        if complete.segment.len() > 65535 - if complete.source.is_ipv4() { 20 } else { 40 } {
            failure = Some(IpError::Oversized);
            return;
        }
        match RelayBuffer::copy_from(complete.segment, buffers) {
            Ok(segment) => {
                captured = Some(OwnedTransport {
                    scope,
                    source: complete.source,
                    destination: complete.destination,
                    protocol: complete.protocol,
                    segment,
                });
            }
            Err(_) => failure = Some(IpError::Full),
        }
    })?;
    if let Some(error) = failure {
        return Err(error);
    }
    Ok(captured)
}
