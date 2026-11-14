//! A quotation is a view of the original packet, never a zero-padded datagram.
//! Only complete fields present on the wire are updated. Nested errors are
//! refused rather than recursing through attacker-controlled quotations.
use crate::address_translation::{
    Direction, Header, ParseContext, TranslationError, address_bytes, adjusted, checksum_field,
    is_icmp_error, rewrite_endpoint, word,
};
use std::net::IpAddr;

pub(crate) struct Quotation {
    start: usize,
    header: Header,
    source: bool,
    checksum: Option<usize>,
}

pub(crate) fn inspect(
    bytes: &[u8],
    outer: &Header,
    direction: Direction,
    old: IpAddr,
    _new: IpAddr,
) -> Result<Option<Quotation>, TranslationError> {
    if !is_icmp_error(bytes, outer) {
        return Ok(None);
    }
    let icmp = &bytes[outer.transport..];
    let valid_code = match (outer.ipv4, icmp[0]) {
        (true, 3) => icmp[1] <= 15,
        (true, 11) => icmp[1] <= 1,
        (true, 12) => icmp[1] <= 2,
        (false, 1) => icmp[1] <= 7,
        (false, 2) => icmp[1] == 0,
        (false, 3) => icmp[1] <= 1,
        (false, 4) => icmp[1] <= 2,
        _ => false,
    };
    if !valid_code {
        return Err(TranslationError::Malformed);
    }
    let start = outer.transport + 8;
    let quoted = &bytes[start..];
    let header = Header::parse(quoted, ParseContext::Quotation).map_err(|error| {
        if outer.partial()
            && error == TranslationError::Malformed
            && quoted.len() < if outer.ipv4 { 20 } else { 40 }
        {
            TranslationError::ShortHeader
        } else {
            error
        }
    })?;
    if header.ipv4 != outer.ipv4 {
        return Err(TranslationError::Family);
    }
    let source = direction == Direction::Inbound;
    if (if source {
        header.source
    } else {
        header.destination
    }) != old
    {
        return Err(TranslationError::Endpoint);
    }
    // An outbound error returns to the sender of the quoted incoming packet.
    if !source && header.source != outer.destination {
        return Err(TranslationError::Endpoint);
    }
    let available = quoted.len().min(header.declared);
    if header.transport_known && !header.non_initial {
        if is_icmp_error(&quoted[..available], &header) {
            return Err(TranslationError::UnsupportedTranslation);
        }
        let transport = &quoted[header.transport..available];
        let minimum = match header.protocol {
            6 => 20,
            1 | 17 | 58 | 50 => 8,
            47 => 4,
            132 => 12,
            _ => 0,
        };
        if !header.partial() && header.declared - header.transport < minimum {
            return Err(TranslationError::Malformed);
        }
        match header.protocol {
            6 => {
                if (!header.partial() && header.declared < header.transport + 20)
                    || (transport.len() > 12
                        && (transport[12] >> 4 < 5
                            || (!header.partial()
                                && usize::from(transport[12] >> 4) * 4
                                    > header.declared - header.transport)))
                {
                    return Err(TranslationError::Malformed);
                }
            }
            17 if transport.len() >= 6
                && !header.partial()
                && usize::from(word(transport, 4)) != header.declared - header.transport =>
            {
                return Err(TranslationError::Malformed);
            }
            17 if transport.len() >= 6 && word(transport, 4) < 8 => {
                return Err(TranslationError::Malformed);
            }
            1 if header.ipv4
                && ((!transport.is_empty() && !matches!(transport[0], 0 | 8 | 13..=18))
                    || (transport.len() >= 2 && transport[1] != 0)) =>
            {
                return Err(TranslationError::UnsupportedTranslation);
            }
            58 if !header.ipv4
                && ((!transport.is_empty() && !matches!(transport[0], 128 | 129))
                    || (transport.len() >= 2 && transport[1] != 0)) =>
            {
                return Err(TranslationError::UnsupportedTranslation);
            }
            _ => (),
        }
        if header.protocol == 17 && !header.ipv4 && transport.len() >= 8 && word(transport, 6) == 0
        {
            return Err(TranslationError::Checksum);
        }
    }
    let checksum = checksum_field(&header, quoted)?;
    // A complete outer message may legally quote a truncated original. A first
    // outer fragment cannot omit a field that will arrive later and need a
    // rewrite: the tail is deliberately opaque and there is no retained state.
    if outer.partial()
        && (!header.transport_known
            || (!header.non_initial
                && matches!(header.protocol, 6 | 17 | 1 | 58)
                && checksum.is_none()))
    {
        return Err(TranslationError::ShortHeader);
    }
    Ok(Some(Quotation {
        start,
        header,
        source,
        checksum,
    }))
}

/// At most eight endpoint words, one IPv4 header word and one L4 word change.
/// The delta is bounded stack data, not a copy/recalculation of the ICMP body.
pub(crate) struct ChangedWords {
    old: [u8; 20],
    new: [u8; 20],
    length: usize,
}

impl ChangedWords {
    fn record(&mut self, old: &[u8], new: &[u8]) {
        let end = self.length + old.len();
        self.old[self.length..end].copy_from_slice(old);
        self.new[self.length..end].copy_from_slice(new);
        self.length = end;
    }

    pub(crate) fn apply(&self, value: u16) -> u16 {
        adjusted(value, &self.old[..self.length], &self.new[..self.length])
    }
}

pub(crate) fn rewrite(
    bytes: &mut [u8],
    quote: &Quotation,
    old: IpAddr,
    new: IpAddr,
) -> Result<ChangedWords, TranslationError> {
    let quoted = &mut bytes[quote.start..];
    let mut delta = ChangedWords {
        old: [0; 20],
        new: [0; 20],
        length: 0,
    };
    if let Some(offset) = quote.checksum {
        let previous = word(quoted, offset);
        if !(quote.header.ipv4
            && (quote.header.protocol == 1 || (quote.header.protocol == 17 && previous == 0)))
        {
            let mut value = adjusted(previous, &address_bytes(old), &address_bytes(new));
            if quote.header.protocol == 17 && value == 0 {
                value = u16::MAX;
            }
            quoted[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
            delta.record(&previous.to_be_bytes(), &value.to_be_bytes());
        }
    }
    let old_ip_checksum = quote.header.ipv4.then(|| word(quoted, 10));
    rewrite_endpoint(quoted, &quote.header, quote.source, new)?;
    delta.record(&address_bytes(old), &address_bytes(new));
    if let Some(previous) = old_ip_checksum {
        delta.record(&previous.to_be_bytes(), &word(quoted, 10).to_be_bytes());
    }
    Ok(delta)
}
