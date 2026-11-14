//! Stateless one-to-one address rewrites owned by one tunnel attempt.
//!
//! Capture establishes plain TUN bytes (no PI, virtio/GSO or partial checksum
//! metadata). Checksum *values* do not establish that representation. Endpoints,
//! not this adapter, validate incoming checksums, flags and transport messages.
//! ESP stays opaque: tunnel mode works; encrypted transport-mode pseudoheaders
//! cannot be repaired without the SA. NAT-T uses the ordinary UDP rewrite.
use std::{net::IpAddr, sync::Arc};
use talpid_types::relay_flow::{
    BUFFER_OVERHEAD, MAX_RELAY_PACKET_SIZE, RelayAttempt, RelayBuffer, RelayBufferAllocator,
    RelayBufferReservation, RelayFlowError, RelayPacket, RelaySources,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    Outbound,
    Inbound,
}

/// Configuration is not authority. The retained attempt is checked separately.
#[derive(Clone, Copy, Debug)]
pub struct TargetConfig {
    pub target_id: u64,
    pub fixed: RelaySources,
    pub assigned: RelaySources,
    pub mtu: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub enum TranslationError {
    Malformed,
    Checksum,
    Endpoint,
    Family,
    UnsupportedTranslation,
    BackendRefused,
    Full,
    Stale,
    ShortHeader,
}

impl From<RelayFlowError> for TranslationError {
    fn from(error: RelayFlowError) -> Self {
        match error {
            RelayFlowError::Full => Self::Full,
            RelayFlowError::Stale | RelayFlowError::Closed => Self::Stale,
            RelayFlowError::Invalid => Self::Malformed,
        }
    }
}

/// Fixed-size, saturating per-attempt counters; no per-packet log or status RPC.
#[derive(Clone, Debug, Default)]
pub struct TranslationSummary {
    pub translated: u64,
    refusals: [u64; 9],
}

impl TranslationSummary {
    pub fn refused(&self, reason: TranslationError) -> u64 {
        self.refusals[reason as usize]
    }

    pub(crate) fn refuse(&mut self, reason: TranslationError) {
        let count = &mut self.refusals[reason as usize];
        *count = count.saturating_add(1);
    }
}

pub struct AddressTranslator {
    config: TargetConfig,
    attempt: RelayAttempt,
    buffers: Arc<dyn RelayBufferAllocator>,
    summary: TranslationSummary,
    _metadata: Arc<dyn RelayBufferReservation>,
}

impl AddressTranslator {
    pub fn new(
        config: TargetConfig,
        attempt: RelayAttempt,
        buffers: Arc<dyn RelayBufferAllocator>,
    ) -> Result<Self, TranslationError> {
        if config.target_id == 0
            || (config.assigned.ipv4.is_none() && config.assigned.ipv6.is_none())
            || (config.assigned.ipv4.is_some() && config.fixed.ipv4.is_none())
            || (config.assigned.ipv6.is_some() && config.fixed.ipv6.is_none())
        {
            return Err(TranslationError::Malformed);
        }
        let metadata = buffers.try_reserve(BUFFER_OVERHEAD)?;
        Ok(Self {
            config,
            attempt,
            buffers,
            summary: TranslationSummary::default(),
            _metadata: metadata,
        })
    }

    pub fn config(&self) -> TargetConfig {
        self.config
    }

    pub fn summary(&self) -> &TranslationSummary {
        &self.summary
    }

    pub fn backend_refused(&mut self) {
        self.summary.refuse(TranslationError::BackendRefused);
    }

    pub fn translate(
        &mut self,
        bytes: &[u8],
        direction: Direction,
    ) -> Result<RelayPacket, TranslationError> {
        let result = (|| {
            let rewrite = self.inspect(bytes, direction)?;
            let mut output = RelayBuffer::copy_from(bytes, self.buffers.as_ref())?;
            rewrite.apply(&mut output);
            Ok(self.attempt.packet(output)?)
        })();
        self.record(result)
    }

    /// Preserve the input attempt and its unique backing. A retained immutable
    /// view requires a credited copy; it never observes the rewrite in place.
    pub fn translate_owned(
        &mut self,
        packet: RelayPacket,
        direction: Direction,
    ) -> Result<RelayPacket, TranslationError> {
        let result = packet.try_rewrite(&self.attempt, self.buffers.as_ref(), |bytes| {
            let rewrite = self.inspect(bytes, direction)?;
            rewrite.apply(bytes);
            Ok(())
        });
        self.record(result)
    }

    fn record(
        &mut self,
        result: Result<RelayPacket, TranslationError>,
    ) -> Result<RelayPacket, TranslationError> {
        match &result {
            Ok(_) => self.summary.translated = self.summary.translated.saturating_add(1),
            Err(reason) => self.summary.refuse(*reason),
        }
        result
    }

    fn inspect(
        &self,
        bytes: &[u8],
        direction: Direction,
    ) -> Result<crate::icmp_quotation::PacketRewrite, TranslationError> {
        if !self.attempt.current() {
            return Err(TranslationError::Stale);
        }
        let ip = crate::raw_packet::inspect(bytes)?;
        if direction == Direction::Outbound
            && ip.source().is_some_and(|source| match source {
                IpAddr::V4(_) => self.config.assigned.ipv4.is_none(),
                IpAddr::V6(_) => self.config.assigned.ipv6.is_none(),
            })
        {
            return Err(TranslationError::Family);
        }
        crate::icmp_quotation::inspect(
            bytes,
            direction == Direction::Outbound,
            self.config,
            self.buffers.as_ref(),
        )
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Header {
    pub ipv4: bool,
    pub source: IpAddr,
    pub destination: IpAddr,
    pub transport: usize,
    pub transport_known: bool,
    pub protocol: u8,
    pub declared: usize,
    pub non_initial: bool,
    pub fragment: Option<FragmentHeader>,
    /// Address locations used by the pseudoheader, including source routing and
    /// Mobile IPv6. None means that the present bytes do not determine it.
    pub pseudo_source: Option<usize>,
    pub pseudo_destination: Option<usize>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct FragmentHeader {
    pub offset: usize,
    pub more: bool,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum ParseContext {
    Received,
    Quotation,
}

impl Header {
    pub(crate) fn partial(&self) -> bool {
        self.non_initial || self.fragment.is_some_and(|fragment| fragment.more)
    }

    pub(crate) fn base(bytes: &[u8]) -> Result<Self, TranslationError> {
        let ipv4 = match bytes.first().map(|byte| byte >> 4) {
            Some(4) if bytes.len() >= 20 => true,
            Some(6) if bytes.len() >= 40 => false,
            _ => return Err(TranslationError::Malformed),
        };
        if bytes.len() > MAX_RELAY_PACKET_SIZE {
            return Err(TranslationError::Malformed);
        }
        let source_offset = if ipv4 { 12 } else { 8 };
        let destination_offset = if ipv4 { 16 } else { 24 };
        let fragment = if ipv4 {
            let flags = word(bytes, 6);
            (flags & 0x3fff != 0).then_some(FragmentHeader {
                offset: usize::from(flags & 0x1fff) * 8,
                more: flags & 0x2000 != 0,
            })
        } else {
            None
        };
        Ok(Self {
            ipv4,
            source: ip_address(bytes, source_offset, ipv4),
            destination: ip_address(bytes, destination_offset, ipv4),
            transport: if ipv4 {
                usize::from(bytes[0] & 15) * 4
            } else {
                40
            },
            transport_known: true,
            protocol: bytes[if ipv4 { 9 } else { 6 }],
            declared: if ipv4 {
                usize::from(word(bytes, 2))
            } else {
                40 + usize::from(word(bytes, 4))
            },
            non_initial: fragment.is_some_and(|fragment| fragment.offset != 0),
            fragment,
            pseudo_source: Some(source_offset),
            pseudo_destination: Some(destination_offset),
        })
    }

    #[cfg(test)]
    pub(crate) fn parse(bytes: &[u8], context: ParseContext) -> Result<Self, TranslationError> {
        Self::base(bytes)?.locate(bytes, context)
    }

    /// Walk only the IP header chain. Declared lengths bound field discovery;
    /// they neither truncate output nor require equality with the backing bytes.
    pub(crate) fn locate(
        mut self,
        bytes: &[u8],
        context: ParseContext,
    ) -> Result<Self, TranslationError> {
        let quoted = context == ParseContext::Quotation;
        let end = bytes.len().min(self.declared);
        if self.transport < if self.ipv4 { 20 } else { 40 } || self.declared < self.transport {
            return Err(TranslationError::Malformed);
        }
        if self.ipv4 {
            self.options(bytes, 20, self.transport, true, quoted)?;
            self.transport_known = self.transport <= end;
            if !self.transport_known && !quoted {
                return Err(TranslationError::ShortHeader);
            }
            return Ok(self);
        }
        while matches!(self.protocol, 0 | 43 | 44 | 60) {
            let offset = self.transport;
            let protocol = self.protocol;
            if offset + 2 > end {
                if !quoted {
                    return Err(TranslationError::ShortHeader);
                }
                self.transport_known = false;
                break;
            }
            let length = if protocol == 44 {
                8
            } else {
                (usize::from(bytes[offset + 1]) + 1) * 8
            };
            let next = offset
                .checked_add(length)
                .ok_or(TranslationError::Malformed)?;
            if next > self.declared {
                return Err(if self.partial() && !quoted {
                    TranslationError::ShortHeader
                } else {
                    TranslationError::Malformed
                });
            }
            match protocol {
                0 | 60 => self.options(bytes, offset + 2, next, false, quoted)?,
                43 if offset + 4 <= end && bytes[offset + 3] != 0 => {
                    // RFC 8200 pseudo-destination: RH0/RH2's last address,
                    // RFC 8754 SRH's Segment List[0]. Other active formats do
                    // not supply a known stateless pseudoheader location here.
                    self.pseudo_destination = match bytes[offset + 2] {
                        0 | 2 if length >= 24 => Some(next - 16),
                        4 if length >= 24 => Some(offset + 8),
                        _ => None,
                    }
                    .filter(|start| start + 16 <= end);
                }
                43 if offset + 4 > end => self.pseudo_destination = None,
                44 => {
                    if next > end {
                        if !quoted {
                            return Err(TranslationError::ShortHeader);
                        }
                        self.transport_known = false;
                        break;
                    }
                    let flags = word(bytes, offset + 2);
                    self.fragment = Some(FragmentHeader {
                        offset: usize::from(flags & 0xfff8),
                        more: flags & 1 != 0,
                    });
                    self.non_initial = flags & 0xfff8 != 0;
                }
                _ => (),
            }
            if next > end {
                if !quoted {
                    return Err(TranslationError::ShortHeader);
                }
                self.transport_known = false;
                break;
            }
            self.protocol = bytes[offset];
            self.transport = next;
            if self.non_initial {
                break;
            }
        }
        Ok(self)
    }

    fn options(
        &mut self,
        bytes: &[u8],
        mut offset: usize,
        declared: usize,
        ipv4: bool,
        quoted: bool,
    ) -> Result<(), TranslationError> {
        let end = bytes.len().min(self.declared).min(declared);
        while offset < declared {
            if offset >= end {
                if quoted {
                    break;
                }
                return Err(TranslationError::ShortHeader);
            }
            let kind = bytes[offset];
            if ipv4 && kind == 0 {
                break;
            }
            if (ipv4 && kind == 1) || (!ipv4 && kind == 0) {
                offset += 1;
                continue;
            }
            if offset + 2 > end {
                if ipv4 && matches!(kind, 131 | 137) {
                    self.pseudo_destination = None;
                }
                if !ipv4 && kind == 201 {
                    self.pseudo_source = None;
                }
                if quoted {
                    break;
                }
                return Err(TranslationError::ShortHeader);
            }
            let length = usize::from(bytes[offset + 1]) + if ipv4 { 0 } else { 2 };
            let next = offset
                .checked_add(length)
                .ok_or(TranslationError::Malformed)?;
            if length < 2 || next > declared {
                return Err(TranslationError::Malformed);
            }
            if ipv4 && matches!(kind, 131 | 137) {
                // Only an active source route replaces the pseudo-destination.
                if length < 7 || (length - 3) % 4 != 0 || offset + 3 > end {
                    self.pseudo_destination = None;
                } else if usize::from(bytes[offset + 2]) <= length {
                    self.pseudo_destination = (next <= end).then_some(next - 4);
                }
            }
            if !ipv4 && kind == 201 {
                self.pseudo_source = (length == 18 && next <= end).then_some(offset + 2);
            }
            if next > end && !quoted {
                return Err(TranslationError::ShortHeader);
            }
            offset = next; // Every non-pad option advances by at least two bytes.
        }
        Ok(())
    }
}

pub(crate) fn word(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

pub(crate) fn ip_address(bytes: &[u8], offset: usize, ipv4: bool) -> IpAddr {
    if ipv4 {
        <[u8; 4]>::try_from(&bytes[offset..offset + 4])
            .unwrap()
            .into()
    } else {
        <[u8; 16]>::try_from(&bytes[offset..offset + 16])
            .unwrap()
            .into()
    }
}

pub(crate) fn address_bytes(address: IpAddr) -> VecAddress {
    match address {
        IpAddr::V4(value) => {
            let mut bytes = [0; 16];
            bytes[..4].copy_from_slice(&value.octets());
            VecAddress { bytes, length: 4 }
        }
        IpAddr::V6(value) => VecAddress {
            bytes: value.octets(),
            length: 16,
        },
    }
}

pub(crate) struct VecAddress {
    bytes: [u8; 16],
    length: usize,
}

impl std::ops::Deref for VecAddress {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.bytes[..self.length]
    }
}

/// RFC 1624, including complete checksum words in partial quotations.
pub(crate) fn adjusted(value: u16, old: &[u8], new: &[u8]) -> u16 {
    let mut sum = u32::from(!value);
    for (old, new) in old.chunks_exact(2).zip(new.chunks_exact(2)) {
        sum += u32::from(!u16::from_be_bytes([old[0], old[1]]));
        sum += u32::from(u16::from_be_bytes([new[0], new[1]]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

pub(crate) fn is_icmp_error(bytes: &[u8], header: &Header) -> bool {
    !header.non_initial
        && header.transport_known
        && header.transport < bytes.len().min(header.declared)
        && ((header.ipv4
            && header.protocol == 1
            && matches!(bytes[header.transport], 3..=5 | 11 | 12))
            || (!header.ipv4 && header.protocol == 58 && matches!(bytes[header.transport], 1..=4)))
}

/// Known address-dependent checksum layouts, not an admission allowlist.
/// DCCP (RFC 4340), UDP-Lite (RFC 3828), Mobility (RFC 6275), HIP (RFC 7401).
pub(crate) fn checksum_offset(header: &Header, bytes: &[u8]) -> Option<usize> {
    match header.protocol {
        6 => Some(16),
        17 | 33 | 136 => Some(6),
        135 | 139 => Some(4),
        1 if header.ipv4 => Some(2),
        58 if !header.ipv4 => Some(2),
        89 if !header.ipv4 && bytes.get(header.transport) == Some(&3) => Some(12),
        103 if !header.ipv4
            && bytes
                .get(header.transport)
                .is_some_and(|byte| byte >> 4 == 2) =>
        {
            Some(2)
        }
        112 if bytes
            .get(header.transport)
            .is_some_and(|byte| byte >> 4 == 3) =>
        {
            Some(6)
        }
        _ => None, // GRE/SCTP/ESP, encapsulation and opaque independent payloads.
    }
}

#[cfg(test)]
mod fragment_tests;
#[cfg(test)]
mod parity_tests;
#[cfg(test)]
mod path_tests;
#[cfg(test)]
mod quotation_tests;
#[cfg(test)]
mod tests;

mod path;
pub use path::TargetPacketPath;
