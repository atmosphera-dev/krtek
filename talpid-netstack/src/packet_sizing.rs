//! Checked emission and sender-side PMTU feedback, using application credit.
use crate::address_translation::{
    Header, ParseContext, TranslationError, checksum, is_icmp_error, set_transport_checksum, word,
};
use std::{
    collections::VecDeque,
    io,
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use talpid_types::relay_flow::{
    BUFFER_OVERHEAD, RelayAttempt, RelayBuffer, RelayBufferAllocator, RelayBufferReservation,
    RelayPacket, RelaySink, RelayWriteOutcome,
};

pub struct Emission {
    packets: VecDeque<RelayPacket>,
    _metadata: Arc<dyn RelayBufferReservation>,
}

impl Emission {
    pub fn pop(&mut self) -> Option<RelayPacket> {
        self.packets.pop_front()
    }
    pub fn len(&self) -> usize {
        self.packets.len()
    }
    pub fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }
}

pub(crate) fn needs_feedback(bytes: &[u8], header: &Header, mtu: u16) -> bool {
    bytes.len() > usize::from(mtu)
        && (!header.ipv4 || word(bytes, 6) & 0x4000 != 0 || usize::from(mtu) < header.transport + 8)
}

/// Size only this translated packet. The caller retains the original invocation
/// for feedback; no earlier fragment confers authority to emit IPv6 fragments.
pub(crate) fn emit(
    bytes: RelayBuffer,
    header: &Header,
    mtu: u16,
    attempt: &RelayAttempt,
    buffers: &dyn RelayBufferAllocator,
) -> Result<Emission, TranslationError> {
    if needs_feedback(&bytes, header, mtu) {
        return Err(TranslationError::PacketTooBig);
    }
    if bytes.len() <= usize::from(mtu) {
        let metadata = buffers.try_reserve(std::mem::size_of::<RelayPacket>() + BUFFER_OVERHEAD)?;
        let mut packets = VecDeque::with_capacity(1);
        packets.push_back(attempt.packet(bytes)?);
        return Ok(Emission {
            packets,
            _metadata: metadata,
        });
    }
    let prefix = header.transport;
    let (options, option_length) = copied_options(&bytes[..prefix])?;
    let original_offset = usize::from(word(&bytes, 6) & 0x1fff) * 8;
    let original_more = word(&bytes, 6) & 0x2000 != 0;
    let payload = &bytes[prefix..];
    // Walk twice: preflight every size/offset and reserve the complete allocation
    // peak before creating any output. A later refusal cannot partially emit.
    let pieces = || {
        let mut offset = 0;
        std::iter::from_fn(move || {
            if offset == payload.len() {
                return None;
            }
            let ip = if original_offset + offset == 0 {
                prefix
            } else {
                20 + option_length
            };
            let capacity = usize::from(mtu) - ip;
            let remaining = payload.len() - offset;
            let length = if remaining > capacity {
                capacity / 8 * 8
            } else {
                remaining
            };
            let start = offset;
            offset += length;
            Some((start, ip, length))
        })
    };
    let mut count = 0;
    let mut total = 0;
    for (offset, ip, length) in pieces() {
        if length == 0
            || original_offset + offset > 0x1fff * 8
            || original_offset + offset + length + prefix > 65_535
        {
            return Err(TranslationError::Malformed);
        }
        count += 1;
        total += ip + length + BUFFER_OVERHEAD;
    }
    let metadata =
        buffers.try_reserve(count * std::mem::size_of::<RelayPacket>() + BUFFER_OVERHEAD)?;
    let mut peak = buffers.try_reserve(total)?;
    let mut packets = VecDeque::with_capacity(count);
    for (offset, ip, length) in pieces() {
        let size = ip + length + BUFFER_OVERHEAD;
        total -= size;
        // Split off one ticket at a time, avoiding the allocator's bounded
        // partition-list size even for a legal 65 KiB packet at a small MTU.
        let mut parts = peak.partition(&[size, total])?;
        peak = parts.pop().expect("remaining peak ticket");
        let charge = parts.pop().expect("current packet ticket");
        let mut output = vec![0; ip + length];
        output[..20].copy_from_slice(&bytes[..20]);
        if original_offset + offset == 0 {
            output[20..ip].copy_from_slice(&bytes[20..prefix]);
        } else {
            output[20..ip].copy_from_slice(&options[..option_length]);
        }
        output[0] = 0x40 | (ip / 4) as u8;
        output[2..4].copy_from_slice(&((ip + length) as u16).to_be_bytes());
        let more = offset + length < payload.len() || original_more;
        output[6..8].copy_from_slice(
            &(((original_offset + offset) / 8) as u16 | if more { 0x2000 } else { 0 })
                .to_be_bytes(),
        );
        output[10..12].fill(0);
        let sum = checksum(&[&output[..ip]]);
        output[10..12].copy_from_slice(&sum.to_be_bytes());
        output[ip..].copy_from_slice(&payload[offset..offset + length]);
        packets.push_back(attempt.packet(RelayBuffer::from_reservation(output, charge)?)?);
    }
    Ok(Emission {
        packets,
        _metadata: metadata,
    })
}

/// Canonical copied options, in wire order, without a heap allocation.
fn copied_options(header: &[u8]) -> Result<([u8; 40], usize), TranslationError> {
    let mut result = [0; 40];
    let mut length = 0;
    let mut offset = 20;
    while offset < header.len() {
        let kind = header[offset];
        if kind == 0 {
            break;
        }
        if kind == 1 {
            offset += 1;
            continue;
        }
        let size = usize::from(*header.get(offset + 1).ok_or(TranslationError::Malformed)?);
        if size < 2 || offset + size > header.len() {
            return Err(TranslationError::Malformed);
        }
        if kind & 0x80 != 0 {
            result[length..length + size].copy_from_slice(&header[offset..offset + size]);
            length += size;
        }
        offset += size;
    }
    Ok((result, length.div_ceil(4) * 4))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FeedbackSide {
    App,
    Target,
}

pub(crate) struct FeedbackRoute {
    pub source: IpAddr,
    pub mtu: u16,
    pub return_mtu: u16,
    pub side: FeedbackSide,
}

struct Slot(Arc<AtomicUsize>);
impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Private construction is the feedback producer capability. App bytes cannot
/// label themselves as assigned-source feedback. Writes retain authority/credit.
pub struct Feedback {
    packet: RelayPacket,
    side: FeedbackSide,
    _slot: Slot,
    buffers: Arc<dyn RelayBufferAllocator>,
}
impl Feedback {
    pub fn buffers(&self) -> Arc<dyn RelayBufferAllocator> {
        self.buffers.clone()
    }
    pub fn attempt(&self) -> RelayAttempt {
        self.packet.view().attempt().clone()
    }
    pub fn side(&self) -> FeedbackSide {
        self.side
    }
    /// The consumer must also check the current output sink/session in `write`.
    /// This callback is the final whole-packet syscall or target handoff.
    pub fn write(&mut self, write: impl FnOnce(&[u8]) -> io::Result<usize>) -> RelayWriteOutcome {
        self.packet.write(write)
    }
    pub fn write_to(
        &mut self,
        sink: &RelaySink,
        write: impl FnOnce(&[u8]) -> io::Result<usize>,
    ) -> RelayWriteOutcome {
        self.packet.write_to(sink, write)
    }
    pub fn handoff<T>(
        self,
        operation: impl FnOnce(&[u8]) -> T,
    ) -> Result<T, talpid_types::relay_flow::RelayFlowError> {
        self.packet.handoff(operation)
    }
}

pub(crate) struct FeedbackQueue {
    pending: VecDeque<Feedback>,
    slots: Arc<AtomicUsize>,
    buffers: Arc<dyn RelayBufferAllocator>,
    tokens: u8,
    refill: Option<Instant>,
    _metadata: Arc<dyn RelayBufferReservation>,
}

const REFILL: Duration = Duration::from_millis(125);

impl FeedbackQueue {
    pub fn new(application: &dyn RelayBufferAllocator) -> Result<Self, TranslationError> {
        let region = application.try_reserve(64 * 1024)?;
        let buffers = region.allocator()?;
        let metadata =
            buffers.try_reserve(16 * std::mem::size_of::<Feedback>() + 2 * BUFFER_OVERHEAD)?;
        Ok(Self {
            pending: VecDeque::with_capacity(16),
            slots: Arc::new(AtomicUsize::new(0)),
            buffers,
            tokens: 8,
            refill: None,
            _metadata: metadata,
        })
    }
    pub fn pop(&mut self) -> Option<Feedback> {
        self.pending.pop_front()
    }
    pub fn pop_side(&mut self, side: FeedbackSide) -> Option<Feedback> {
        let index = self
            .pending
            .iter()
            .position(|feedback| feedback.side == side)?;
        self.pending.remove(index)
    }
    pub fn clear(&mut self) {
        self.pending.clear();
    }
    pub fn deadline(&self) -> Option<Instant> {
        self.refill
    }
    pub fn maintain(&mut self, now: Instant) {
        if let Some(deadline) = self.refill.filter(|deadline| *deadline <= now) {
            let steps = 1 + now.duration_since(deadline).as_nanos() / REFILL.as_nanos();
            self.tokens = (u128::from(self.tokens) + steps).min(8) as u8;
            self.refill = if self.tokens == 8 {
                None
            } else {
                Some(deadline + REFILL * steps as u32)
            };
        }
    }
    pub fn generate(
        &mut self,
        invoking: &[u8],
        header: &Header,
        route: FeedbackRoute,
        attempt: &RelayAttempt,
        now: Instant,
    ) -> Result<(), TranslationError> {
        let FeedbackRoute {
            source,
            mtu,
            return_mtu,
            side,
        } = route;
        if suppress(invoking, header) {
            return Err(TranslationError::Suppressed);
        }
        self.maintain(now);
        if self.slots.load(Ordering::Acquire) >= 16 {
            return Err(TranslationError::FeedbackFull);
        }
        if self.tokens == 0 {
            return Err(TranslationError::RateLimited);
        }
        let ip = if header.ipv4 { 20 } else { 40 };
        let bound = usize::from(return_mtu).min(if header.ipv4 { 576 } else { 1280 });
        let quote = invoking.len().min(
            bound
                .checked_sub(ip + 8)
                .ok_or(TranslationError::PacketTooBig)?,
        );
        let required = if header.ipv4 {
            header.transport + 8
        } else {
            40
        };
        if quote < required {
            return Err(TranslationError::PacketTooBig);
        }
        let length = ip + 8 + quote;
        let charge = self.buffers.try_reserve(length + BUFFER_OVERHEAD)?;
        let mut output = vec![0; length];
        match (source, header.source) {
            (IpAddr::V4(source), IpAddr::V4(destination)) => {
                output[0] = 0x45;
                output[2..4].copy_from_slice(&(length as u16).to_be_bytes());
                output[8] = 64;
                output[9] = 1;
                output[12..16].copy_from_slice(&source.octets());
                output[16..20].copy_from_slice(&destination.octets());
                output[20] = 3;
                output[21] = 4;
                output[26..28].copy_from_slice(&mtu.to_be_bytes());
                let sum = checksum(&[&output[..20]]);
                output[10..12].copy_from_slice(&sum.to_be_bytes());
            }
            (IpAddr::V6(source), IpAddr::V6(destination)) => {
                output[0] = 0x60;
                output[4..6].copy_from_slice(&((length - 40) as u16).to_be_bytes());
                output[6] = 58;
                output[7] = 64;
                output[8..24].copy_from_slice(&source.octets());
                output[24..40].copy_from_slice(&destination.octets());
                output[40] = 2;
                output[44..48].copy_from_slice(&u32::from(mtu).to_be_bytes());
            }
            _ => return Err(TranslationError::Family),
        }
        output[ip + 8..].copy_from_slice(&invoking[..quote]);
        let outer = Header::parse(&output, ParseContext::Received)?;
        set_transport_checksum(&mut output, &outer);
        let packet = attempt.packet(RelayBuffer::from_reservation(output, charge)?)?;
        self.slots.fetch_add(1, Ordering::AcqRel);
        self.pending.push_back(Feedback {
            packet,
            side,
            _slot: Slot(self.slots.clone()),
            buffers: self.buffers.clone(),
        });
        self.tokens -= 1;
        if self.refill.is_none() {
            self.refill = Some(now + REFILL);
        }
        Ok(())
    }
}

fn suppress(bytes: &[u8], header: &Header) -> bool {
    if !header.non_initial && is_icmp_error(bytes, header) {
        return true;
    }
    match (header.source, header.destination) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            header.non_initial
                || source.octets()[0] == 0
                || source.is_loopback()
                || source.octets()[0] >= 224
                || destination.is_multicast()
                || destination.is_broadcast()
        }
        (IpAddr::V6(source), _) => {
            // PTB is the RFC4443 multicast-destination exception. Multicast
            // sources, other errors and Redirect never generate another error.
            source.is_unspecified()
                || source.is_multicast()
                || source.is_loopback()
                || (!header.non_initial
                    && header.protocol == 58
                    && bytes
                        .get(header.transport)
                        .is_some_and(|kind| *kind < 128 || *kind == 137))
        }
        _ => true,
    }
}
