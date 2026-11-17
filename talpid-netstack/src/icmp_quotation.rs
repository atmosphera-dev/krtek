//! Parse once into rewrite locations. Nested quotations are walked iteratively;
//! their description storage is byte-credited and depth is bounded by input.
use crate::address_translation::{
    Header, ParseContext, TargetConfig, TranslationError, address_bytes, adjusted, checksum_offset,
    ip_address, is_icmp_error, word,
};
use std::{mem::size_of, net::IpAddr, sync::Arc};
use talpid_types::relay_flow::{BUFFER_OVERHEAD, RelayBufferAllocator, RelayBufferReservation};

struct Layer {
    start: usize,
    end: usize,
    header: Header,
    source: bool,
    base_swap: bool,
    pseudo_swap: bool,
    old: IpAddr,
    new: IpAddr,
    checksum: Option<usize>,
    required_checksum_end: Option<usize>,
    address_checksum: bool,
}

pub(crate) struct PacketRewrite {
    outer: Layer,
    quotes: Vec<Layer>,
    _charge: Option<Arc<dyn RelayBufferReservation>>,
}

impl Layer {
    fn inspect(
        bytes: &[u8],
        start: usize,
        source: bool,
        config: TargetConfig,
        context: ParseContext,
    ) -> Result<Self, TranslationError> {
        let base = Header::base(bytes)?;
        let address = |sources: talpid_types::relay_flow::RelaySources| {
            if base.ipv4 {
                sources.ipv4.map(IpAddr::V4)
            } else {
                sources.ipv6.map(IpAddr::V6)
            }
        };
        // Source/destination alternate in quotes; old -> new does not.
        let (old, new) = match (address(config.fixed), address(config.assigned)) {
            (Some(old), Some(new)) => (old, new),
            _ => (base.source, base.source),
        };
        let actual = if source {
            base.source
        } else {
            base.destination
        };
        let base_swap = old != new && actual == old;
        let base_checksum = checksum_offset(&base, bytes);
        let base_dependent = base_checksum.is_some() && !(base.ipv4 && base.protocol == 1);
        // An unlocatable no-swap packet is opaque native input. There is no
        // changed field whose access could justify rejecting it.
        let header = match base.clone().locate(bytes, context) {
            Ok(header) => header,
            Err(_)
                if !base_swap
                    || (base.ipv4
                        && (source || (!base_dependent && !is_icmp_error(bytes, &base)))) =>
            {
                let mut opaque = base;
                // IPv4 source deltas do not depend on destination options.
                // Even a bad option length cannot hide the IHL-located word.
                opaque.transport_known = source
                    && opaque.ipv4
                    && opaque.transport >= 20
                    && opaque.transport <= bytes.len().min(opaque.declared);
                opaque
            }
            Err(error) => return Err(error),
        };
        let pseudo = if source {
            header.pseudo_source
        } else {
            header.pseudo_destination
        };
        let pseudo_swap = old != new
            && pseudo.is_some_and(|offset| ip_address(bytes, offset, header.ipv4) == old);
        let field = checksum_offset(&header, bytes);
        let dependent = field.is_some() && !(header.ipv4 && header.protocol == 1);
        if (base_swap || pseudo_swap) && header.protocol == 51 {
            return Err(TranslationError::UnsupportedTranslation); // AH covers changed addresses, key unavailable.
        }
        if base_swap && dependent && pseudo.is_none() {
            return Err(TranslationError::UnsupportedTranslation); // Unavailable routed/Home Address pseudo-endpoint.
        }
        let mut checksum = None;
        let mut required_checksum_end = None;
        if header.transport_known
            && let Some(field) = field
        {
            // IPv4 fragment offsets unambiguously locate even a TCP checksum
            // in a later fragment. IPv6 tails may start inside extensions.
            let fragment_offset = if header.ipv4 {
                header.fragment.map_or(0, |fragment| fragment.offset)
            } else {
                0
            };
            if (!header.non_initial || header.ipv4)
                && !(header.non_initial && header.protocol == 1)
                && let Some(relative) = field.checked_sub(fragment_offset)
            {
                let offset = header.transport + relative;
                required_checksum_end = Some(offset + 2);
                let end = bytes.len().min(header.declared);
                if offset + 2 <= end {
                    checksum = Some(offset);
                } else if pseudo_swap
                    && context == ParseContext::Received
                    && (!header.ipv4 || !header.partial() || offset < end)
                {
                    return Err(TranslationError::ShortHeader);
                }
            }
        }
        Ok(Self {
            start,
            end: start + bytes.len().min(header.declared),
            header,
            source,
            base_swap,
            pseudo_swap,
            old,
            new,
            checksum,
            required_checksum_end,
            address_checksum: pseudo_swap && dependent,
        })
    }

    fn apply(&self, bytes: &mut [u8], delta: &mut ChangedWords) {
        let packet = &mut bytes[self.start..];
        if let Some(offset) = self.checksum {
            let previous = word(packet, offset);
            let mut value = delta.apply(previous);
            if self.address_checksum && !(matches!(self.header.protocol, 17 | 136) && previous == 0)
            {
                value = adjusted(value, &address_bytes(self.old), &address_bytes(self.new));
                if matches!(self.header.protocol, 17 | 136) && value == 0 {
                    value = u16::MAX;
                }
            }
            delta.replace(packet, offset, &value.to_be_bytes());
        }
        let base = match (self.header.ipv4, self.source) {
            (true, true) => 12,
            (true, false) => 16,
            (false, true) => 8,
            (false, false) => 24,
        };
        let pseudo = if self.source {
            self.header.pseudo_source
        } else {
            self.header.pseudo_destination
        };
        let previous_ip = self.header.ipv4.then(|| word(packet, 10));
        let mut ip_delta = ChangedWords::default();
        for offset in [
            self.base_swap.then_some(base),
            pseudo.filter(|offset| self.pseudo_swap && *offset != base),
        ]
        .into_iter()
        .flatten()
        {
            let new = address_bytes(self.new);
            ip_delta.record(&packet[offset..offset + new.len()], &new, offset);
            delta.replace(packet, offset, &new);
        }
        if let Some(previous) = previous_ip {
            let value = ip_delta.apply(previous);
            delta.replace(packet, 10, &value.to_be_bytes());
        }
    }
}

pub(crate) fn inspect(
    bytes: &[u8],
    source: bool,
    mut config: TargetConfig,
    buffers: &dyn RelayBufferAllocator,
) -> Result<PacketRewrite, TranslationError> {
    // Normalize old -> new once; quoting alternates the selected address side.
    if !source {
        std::mem::swap(&mut config.fixed, &mut config.assigned);
    }
    let outer = Layer::inspect(bytes, 0, source, config, ParseContext::Received)?;
    let outer_fragmented = outer.header.partial();
    let mut result = PacketRewrite {
        outer,
        quotes: Vec::new(),
        _charge: None,
    };
    loop {
        let parent = result.quotes.last().unwrap_or(&result.outer);
        let view = &bytes[parent.start..parent.end];
        if !is_icmp_error(view, &parent.header) {
            break;
        }
        let start = parent.start + parent.header.transport + 8;
        if start > parent.end {
            if outer_fragmented && (parent.base_swap || parent.pseudo_swap) {
                return Err(TranslationError::ShortHeader);
            }
            break;
        }
        // RFC 4884's original-datagram length excludes the appended extension
        // structure. It is type-specific: PTB MTUs and parameter pointers must
        // never be mistaken for lengths. Zero retains the legacy full quote.
        let transport = parent.header.transport;
        let length = match (parent.header.ipv4, view[transport]) {
            (true, 3 | 11 | 12) => usize::from(view[transport + 5]) * 4,
            (false, 1 | 3) => usize::from(view[transport + 4]) * 8,
            _ => 0,
        };
        let end = if length == 0 {
            parent.end
        } else {
            parent.end.min(start + length)
        };
        let quoted = &bytes[start..end];
        if quoted.len()
            < if quoted.first().is_some_and(|byte| byte >> 4 == 6) {
                40
            } else {
                20
            }
        {
            if outer_fragmented && (parent.base_swap || parent.pseudo_swap) {
                return Err(TranslationError::ShortHeader);
            }
            break;
        }
        if !quoted
            .first()
            .is_some_and(|byte| matches!(byte >> 4, 4 | 6))
        {
            break;
        }
        let layer = Layer::inspect(
            quoted,
            start,
            !parent.source,
            config,
            ParseContext::Quotation,
        )?;
        if outer_fragmented
            && (layer.base_swap || layer.pseudo_swap)
            && ((!layer.header.transport_known
                && (!layer.header.ipv4 || layer.address_checksum || layer.header.protocol == 1))
                || (layer.address_checksum
                    && layer.checksum.is_none()
                    && layer
                        .required_checksum_end
                        .is_some_and(|end| end <= layer.header.declared)))
        {
            return Err(TranslationError::ShortHeader);
        }
        if result._charge.is_none() {
            // Each additional layer consumes >=20 IP + 8 ICMP bytes. This is
            // packet-derived capacity, not an extension/depth admission quota.
            let capacity = bytes.len() / 28 + 1;
            result._charge =
                Some(buffers.try_reserve(capacity * size_of::<Layer>() + BUFFER_OVERHEAD)?);
            result.quotes = Vec::with_capacity(capacity);
            if result.quotes.capacity() * size_of::<Layer>() + BUFFER_OVERHEAD
                > result._charge.as_ref().unwrap().bytes()
            {
                return Err(TranslationError::Full);
            }
        }
        result.quotes.push(layer);
    }
    Ok(result)
}

impl PacketRewrite {
    pub(crate) fn apply(&self, bytes: &mut [u8]) {
        let mut delta = ChangedWords::default();
        for layer in self.quotes.iter().rev().chain(std::iter::once(&self.outer)) {
            layer.apply(bytes, &mut delta);
        }
    }
}

/// Additive one's-complement delta. Fold after each record so arbitrarily deep
/// present quotations need neither recursion nor a growing changed-word array.
#[derive(Default)]
struct ChangedWords {
    sum: u32,
}

impl ChangedWords {
    fn record(&mut self, old: &[u8], new: &[u8], offset: usize) {
        for (old, new) in old.chunks_exact(2).zip(new.chunks_exact(2)) {
            // Source-route option addresses can start on an odd byte. Their
            // wire/header delta is byte-rotated; pseudoheader addresses are not.
            let old = u16::from_be_bytes([old[0], old[1]])
                .rotate_right(if offset.is_multiple_of(2) { 0 } else { 8 });
            let new = u16::from_be_bytes([new[0], new[1]])
                .rotate_right(if offset.is_multiple_of(2) { 0 } else { 8 });
            self.sum += u32::from(!old);
            self.sum += u32::from(new);
            self.sum = (self.sum & 0xffff) + (self.sum >> 16);
        }
    }
    fn replace(&mut self, bytes: &mut [u8], offset: usize, new: &[u8]) {
        if &bytes[offset..offset + new.len()] != new {
            self.record(&bytes[offset..offset + new.len()], new, offset);
            bytes[offset..offset + new.len()].copy_from_slice(new);
        }
    }
    fn apply(&self, value: u16) -> u16 {
        if self.sum == 0 || self.sum == 0xffff {
            return value;
        }
        let mut sum = u32::from(!value) + self.sum;
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }
}
