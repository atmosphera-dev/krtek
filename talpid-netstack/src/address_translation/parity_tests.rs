//! Native acceptance, with independent byte/checksum and ownership consumers.
use super::{tests::*, *};
use gotatun::packet::Packet;
use talpid_types::relay_flow::RelayWriteOutcome;

fn endpoints(v4: bool, direction: Direction) -> (IpAddr, IpAddr, IpAddr, IpAddr) {
    let (old, new) = if direction == Direction::Outbound {
        (address(FIXED, v4), address(ASSIGNED, v4))
    } else {
        (address(ASSIGNED, v4), address(FIXED, v4))
    };
    if direction == Direction::Outbound {
        (old, remote(v4), new, remote(v4))
    } else {
        (remote(v4), old, remote(v4), new)
    }
}

// Exercise upstream itself, not the production adapter's inspection helper.
// Nonmatching outbound no-swap probes still convert, but SourceFilter rejects
// their sources in either address domain. Authenticated inbound has no filter.
fn native_accepts(bytes: &[u8], allowed: RelaySources, direction: Direction) -> bool {
    let packet = Packet::copy_from(bytes)
        .try_into_ip()
        .expect("native IP conversion");
    direction == Direction::Inbound
        || packet.source().is_some_and(|source| match source {
            IpAddr::V4(ip) => allowed.ipv4 == Some(ip),
            IpAddr::V6(ip) => allowed.ipv6 == Some(ip),
        })
}

fn delivered(mapper: &mut AddressTranslator, bytes: &[u8], direction: Direction) -> Vec<u8> {
    let accepted = native_accepts(bytes, mapper.config().fixed, direction);
    let mut output = Vec::new();
    let mut packet = mapper.translate(bytes, direction).unwrap();
    assert!(matches!(
        packet.write(|bytes| {
            output.extend_from_slice(bytes);
            Ok(bytes.len())
        }),
        RelayWriteOutcome::Written
    ));
    assert_eq!(
        native_accepts(&output, mapper.config().assigned, direction),
        accepted
    );
    output
}

fn error(quote: &[u8], source: IpAddr, destination: IpAddr, kind: u8, code: u8) -> Vec<u8> {
    let mut body = vec![kind, code, 0, 0, 0, 0, 5, 0];
    body.extend_from_slice(quote);
    packet(
        source,
        destination,
        if source.is_ipv4() { 1 } else { 58 },
        &body,
    )
}

#[test]
fn translation_accepts_address_independent_protocols_and_icmp_types() {
    let (mut mapper, _capture, _attempt, _) = mapper();
    for v4 in [true, false] {
        for direction in [Direction::Outbound, Direction::Inbound] {
            let (src, dst, ns, nd) = endpoints(v4, direction);
            for protocol in [2, 4, 41, 47, 50, 89, 103, 112, 132, 253, 254] {
                for length in [0, 1, 32] {
                    let body = vec![0x5a; length];
                    let original = packet(src, dst, protocol, &body);
                    assert_eq!(
                        delivered(&mut mapper, &original, direction),
                        packet(ns, nd, protocol, &body)
                    );
                }
            }
            for (protocol, field) in [
                (33, 6),
                (136, 6),
                (135, 4),
                (139, 4),
                (89, 12),
                (103, 2),
                (112, 6),
            ] {
                if v4 && matches!(protocol, 89 | 103) {
                    continue;
                }
                let with_checksum = |src, dst| {
                    let mut bytes = packet(src, dst, protocol, &[0x5a; 32]);
                    let ip = if v4 { 20 } else { 40 };
                    if let Some(version) = match protocol {
                        89 => Some(3),
                        103 => Some(0x20),
                        112 => Some(0x30),
                        _ => None,
                    } {
                        bytes[ip] = version;
                    }
                    bytes[ip + field..ip + field + 2].fill(0);
                    let value = wire_checksum(&bytes, ip, protocol);
                    bytes[ip + field..ip + field + 2].copy_from_slice(&value.to_be_bytes());
                    bytes
                };
                let output = delivered(&mut mapper, &with_checksum(src, dst), direction);
                assert_eq!(output, with_checksum(ns, nd));
            }
            let protocol = if v4 { 1 } else { 58 };
            for kind in if v4 {
                vec![0, 5, 8, 9, 10, 13, 14, 17, 18, 42]
            } else {
                vec![128, 129, 130, 133, 134, 135, 136, 137, 200]
            } {
                let mut body = segment(protocol);
                body[0] = kind;
                body[1] = 201; // Code is endpoint policy, not translation policy.
                let original = packet(src, dst, protocol, &body);
                let output = delivered(&mut mapper, &original, direction);
                assert_eq!(output, packet(ns, nd, protocol, &body));
                assert_eq!(
                    wire_checksum(&output, if v4 { 20 } else { 40 }, protocol),
                    0
                );
            }
        }
    }
}

#[test]
fn translation_walks_options_and_long_extensions_by_packet_bounds() {
    let (mut mapper, _capture, _attempt, _) = mapper();
    // Review regression: the option walk is irrelevant to an inbound ICMPv4
    // echo's address-independent checksum. Only base destination/IP sum change.
    let echo = |destination| {
        let mut body = segment(1);
        body[0] = 0;
        let mut bytes = packet(remote(true), destination, 1, &body);
        bytes.splice(20..20, [30, 0, 0, 0]);
        bytes[0] = 0x46;
        let length = bytes.len() as u16;
        bytes[2..4].copy_from_slice(&length.to_be_bytes());
        fix_checksums(&mut bytes, 24, 1);
        bytes
    };
    let original = echo(address(ASSIGNED, true));
    assert!(native_accepts(&original, ASSIGNED, Direction::Inbound));
    let output = delivered(&mut mapper, &original, Direction::Inbound);
    assert_eq!(output, echo(address(FIXED, true)));
    assert_eq!(oracle(&output[..24]), oracle(&original[..24]));
    assert_eq!(
        wire_checksum(&output, 24, 1),
        wire_checksum(&original, 24, 1)
    );
    assert_eq!(&output[20..], &original[20..]);
    // An ICMP error still needs the quotation walk; this is not a blanket
    // malformed-option bypass for every ICMPv4 packet.
    let mut quoted = original.clone();
    quoted[24] = 3;
    fix_checksums(&mut quoted, 24, 1);
    assert!(native_accepts(&quoted, ASSIGNED, Direction::Inbound));
    assert!(mapper.translate(&quoted, Direction::Inbound).is_err());
    // UDP with an unavailable source-route pseudo-destination still cannot
    // apply the required address-dependent checksum delta safely.
    let mut routed = packet(remote(true), address(ASSIGNED, true), 17, &segment(17));
    routed.splice(20..20, [131, 4, 4, 0]);
    routed[0] = 0x46;
    let length = routed.len() as u16;
    routed[2..4].copy_from_slice(&length.to_be_bytes());
    fix_checksums(&mut routed, 24, 17);
    assert!(native_accepts(&routed, ASSIGNED, Direction::Inbound));
    assert!(matches!(
        mapper.translate(&routed, Direction::Inbound),
        Err(TranslationError::UnsupportedTranslation)
    ));
    for direction in [Direction::Outbound, Direction::Inbound] {
        for v4 in [true, false] {
            let (src, dst, ns, nd) = endpoints(v4, direction);
            let extend = |src, dst| {
                let mut bytes = packet(src, dst, 17, &segment(17));
                if v4 {
                    bytes.splice(20..20, [30, 4, 0x12, 0x34]);
                    bytes[0] = 0x46;
                    let length = bytes.len() as u16;
                    bytes[2..4].copy_from_slice(&length.to_be_bytes());
                    fix_checksums(&mut bytes, 24, 17);
                } else {
                    for _ in 0..32 {
                        let next = bytes[6];
                        bytes.splice(40..40, [next, 0, 30, 4, 0x12, 0x34, 0x56, 0x78]);
                        bytes[6] = 60;
                    }
                    let length = (bytes.len() - 40) as u16;
                    bytes[4..6].copy_from_slice(&length.to_be_bytes());
                }
                bytes
            };
            let original = extend(src, dst);
            assert_eq!(delivered(&mut mapper, &original, direction), extend(ns, nd));
            let mut malformed = original.clone();
            malformed[if v4 { 21 } else { 41 }] = 255;
            if v4 && direction == Direction::Outbound {
                let residual = wire_checksum(&malformed, 24, 17);
                let output = delivered(&mut mapper, &malformed, direction);
                assert_eq!(wire_checksum(&output, 24, 17), residual);
                assert_eq!(&output[20..24], &malformed[20..24]);
            } else {
                assert!(mapper.translate(&malformed, direction).is_err());
            }
            for end in 0..if v4 { 24 } else { 48 } {
                // Bounds probes: errors are fine, panics are not.
                let _ = mapper.translate(&original[..end], direction);
            }
        }
    }
}

#[test]
fn translation_does_not_validate_endpoint_owned_checksums_or_flags() {
    let (mut mapper, _capture, _attempt, _) = mapper();
    for v4 in [true, false] {
        let ip = if v4 { 20 } else { 40 };
        for direction in [Direction::Outbound, Direction::Inbound] {
            let (src, dst, _, _) = endpoints(v4, direction);
            for protocol in [6, 17, if v4 { 1 } else { 58 }] {
                let mut original = packet(src, dst, protocol, &segment(protocol));
                *original.last_mut().unwrap() ^= 0x51;
                if v4 {
                    original[6] = 0x80; // Reserved flag, not a translator firewall.
                    original[10] ^= 0x42;
                }
                let residual = wire_checksum(&original, ip, protocol);
                let ip_residual = v4.then(|| oracle(&original[..ip]));
                let output = delivered(&mut mapper, &original, direction);
                assert_eq!(wire_checksum(&output, ip, protocol), residual);
                if let Some(residual) = ip_residual {
                    assert_eq!(oracle(&output[..ip]), residual);
                }
                let mut trailing = original.clone();
                trailing.extend_from_slice(b"native trailing bytes");
                let output_with_tail = delivered(&mut mapper, &trailing, direction);
                assert_eq!(&output_with_tail[..original.len()], &output);
                assert_eq!(
                    &output_with_tail[original.len()..],
                    b"native trailing bytes"
                );
            }
            let mut zero = packet(src, dst, 17, &segment(17));
            zero[ip + 6..ip + 8].fill(0);
            let output = delivered(&mut mapper, &zero, direction);
            assert_eq!(
                &output[ip + 6..ip + 8],
                &[0, 0],
                "do not manufacture a checksum"
            );
        }
    }
}

#[test]
fn translation_rewrites_only_matching_outer_and_quoted_endpoints() {
    let (mut mapper, _capture, _attempt, _) = mapper();
    for v4 in [true, false] {
        let ip = if v4 { 20 } else { 40 };
        let protocol = if v4 { 1 } else { 58 };
        for direction in [Direction::Outbound, Direction::Inbound] {
            let (src, dst, ns, nd) = endpoints(v4, direction);
            let opaque = packet(remote(v4), remote(v4), 51, &[0xff; 24]);
            assert_eq!(delivered(&mut mapper, &opaque, direction), opaque);
            for kind in if v4 {
                vec![3, 11, 12]
            } else {
                vec![1, 2, 3, 4]
            } {
                let unrelated = packet(remote(v4), remote(v4), 6, &segment(6));
                let input = error(&unrelated, src, dst, kind, 213);
                assert_eq!(
                    delivered(&mut mapper, &input, direction),
                    error(&unrelated, ns, nd, kind, 213)
                );
                let quote = packet(dst, src, 6, &segment(6));
                let expected = packet(nd, ns, 6, &segment(6));
                for end in [ip, ip + 8, ip + 17, ip + 18, quote.len()] {
                    let input = error(&quote[..end], src, dst, kind, 213);
                    let output = delivered(&mut mapper, &input, direction);
                    let mut prefix = expected[..end].to_vec();
                    if end < ip + 18 {
                        prefix[ip..].copy_from_slice(&quote[ip..end]);
                    }
                    assert_eq!(output, error(&prefix, ns, nd, kind, 213));
                    assert_eq!(wire_checksum(&output, ip, protocol), 0);
                }
            }
            // More nested errors than the old extension quota, without recursion.
            let mut input = packet(src, dst, 17, &segment(17));
            let mut expected = packet(ns, nd, 17, &segment(17));
            for depth in 0..40 {
                let (s, d, s2, d2) = if depth % 2 == 0 {
                    (dst, src, nd, ns)
                } else {
                    (src, dst, ns, nd)
                };
                input = error(&input, s, d, if v4 { 11 } else { 3 }, 0);
                expected = error(&expected, s2, d2, if v4 { 11 } else { 3 }, 0);
            }
            let output = delivered(&mut mapper, &input, direction);
            assert_eq!(output, expected);
            assert_eq!(wire_checksum(&output, ip, protocol), 0);
        }
    }
}

#[test]
fn translation_adjusts_present_fragment_words_without_complete_transport_headers() {
    let (mut mapper, _capture, _attempt, _) = mapper();
    for direction in [Direction::Outbound, Direction::Inbound] {
        let (src, dst, ns, nd) = endpoints(true, direction);
        let original = packet(src, dst, 6, &segment(6));
        let expected = packet(ns, nd, 6, &segment(6));
        let mut joined = expected[..20].to_vec();
        for (index, body) in original[20..].chunks(8).enumerate().rev() {
            let mut piece = original[..20].to_vec();
            piece.extend_from_slice(body);
            let length = piece.len() as u16;
            piece[2..4].copy_from_slice(&length.to_be_bytes());
            let flags = index as u16
                | if (index + 1) * 8 < original.len() - 20 {
                    0x2000
                } else {
                    0
                };
            piece[6..8].copy_from_slice(&flags.to_be_bytes());
            piece[10..12].fill(0);
            let sum = oracle(&piece[..20]);
            piece[10..12].copy_from_slice(&sum.to_be_bytes());
            let output = delivered(&mut mapper, &piece, direction);
            assert_eq!(oracle(&output[..20]), 0);
            joined.resize(joined.len().max(20 + index * 8 + body.len()), 0);
            joined[20 + index * 8..20 + index * 8 + body.len()].copy_from_slice(&output[20..]);
        }
        assert_eq!(joined, expected);
        assert_eq!(wire_checksum(&joined, 20, 6), 0);
        for v4 in [true, false] {
            let (src, dst, _, _) = endpoints(v4, direction);
            let ip = if v4 { 20 } else { 40 };
            let mut body = segment(6);
            body[12] = 0xf0; // TCP options need not be complete to fix word 16.
            let mut input = packet(src, dst, 6, &body);
            input.truncate(ip + 18);
            if v4 {
                input[2..4].copy_from_slice(&((ip + 18) as u16).to_be_bytes());
            } else {
                input[4..6].copy_from_slice(&18u16.to_be_bytes());
            }
            assert_eq!(delivered(&mut mapper, &input, direction).len(), input.len());
            input.pop(); // A present half-word cannot be rewritten correctly.
            if v4 {
                input[2..4].copy_from_slice(&((ip + 17) as u16).to_be_bytes());
            } else {
                input[4..6].copy_from_slice(&17u16.to_be_bytes());
            }
            assert!(matches!(
                mapper.translate(&input, direction),
                Err(TranslationError::ShortHeader)
            ));
        }
    }
}

#[test]
fn translation_refuses_only_unrepresentable_address_dependent_forms() {
    let (mut mapper, _capture, _attempt, budget) = mapper();
    for v4 in [true, false] {
        for direction in [Direction::Outbound, Direction::Inbound] {
            let (src, dst, _, _) = endpoints(v4, direction);
            let input = packet(src, dst, 51, &[0; 24]);
            let before = budget.used();
            assert!(matches!(
                mapper.translate(&input, direction),
                Err(TranslationError::UnsupportedTranslation)
            ));
            assert_eq!(
                budget.used(),
                before,
                "AH cannot authenticate a changed endpoint without its key"
            );
            let no_swap = packet(remote(v4), remote(v4), 51, &[0; 24]);
            assert_eq!(delivered(&mut mapper, &no_swap, direction), no_swap);
        }
    }
    for (v4, source, kind) in [
        (true, false, 131),
        (true, false, 137),
        (false, true, 201),
        (false, false, 0),
        (false, false, 2),
        (false, false, 4),
    ] {
        let direction = if source {
            Direction::Outbound
        } else {
            Direction::Inbound
        };
        let (src, dst, ns, nd) = endpoints(v4, direction);
        let old = if source { src } else { dst };
        let new = if source { ns } else { nd };
        let original = routed_packet(v4, source, kind, src, dst, old);
        let expected = routed_packet(v4, source, kind, ns, nd, new);
        assert_eq!(delivered(&mut mapper, &original, direction), expected);
        let error_kind = if v4 { 11 } else { 3 };
        let nested = error(
            &error(&original, dst, src, error_kind, 0),
            src,
            dst,
            error_kind,
            0,
        );
        let nested_expected = error(
            &error(&expected, nd, ns, error_kind, 0),
            ns,
            nd,
            error_kind,
            0,
        );
        assert_eq!(delivered(&mut mapper, &nested, direction), nested_expected);
        // A locator swap does not change a different routed/Home pseudo-endpoint.
        let original = routed_packet(v4, source, kind, src, dst, remote(v4));
        let expected = routed_packet(v4, source, kind, ns, nd, remote(v4));
        assert_eq!(delivered(&mut mapper, &original, direction), expected);
    }
    let mut unknown_route = routed_packet(
        false,
        false,
        2,
        remote(false),
        address(ASSIGNED, false),
        address(ASSIGNED, false),
    );
    unknown_route[42] = 99;
    let before = budget.used();
    assert!(matches!(
        mapper.translate(&unknown_route, Direction::Inbound),
        Err(TranslationError::UnsupportedTranslation)
    ));
    assert_eq!(budget.used(), before);
    unknown_route[24..40].copy_from_slice(&address_bytes(remote(false)));
    assert_eq!(
        delivered(&mut mapper, &unknown_route, Direction::Inbound),
        unknown_route
    );
    let mut unavailable_home = routed_packet(
        false,
        true,
        201,
        address(FIXED, false),
        remote(false),
        address(FIXED, false),
    );
    unavailable_home[43] = 15;
    assert!(matches!(
        mapper.translate(&unavailable_home, Direction::Outbound),
        Err(TranslationError::UnsupportedTranslation)
    ));
    assert_eq!(budget.used(), before);
    for mtu in [0, 1, 67, 1279] {
        let mut config = mapper.config();
        config.mtu = mtu;
        let low_mtu =
            AddressTranslator::new(config, mapper.attempt.clone(), Arc::new(budget.clone()))
                .unwrap();
        drop(low_mtu);
        assert_eq!(budget.used(), before);
    }
    drop(mapper);
    owned_rewrite_contract();
}

fn routed_packet(
    v4: bool,
    source: bool,
    kind: u8,
    src: IpAddr,
    dst: IpAddr,
    pseudo: IpAddr,
) -> Vec<u8> {
    let mut bytes = packet(src, dst, 17, &segment(17));
    let ip;
    if v4 {
        let mut option = vec![kind, 7, 4];
        option.extend_from_slice(&address_bytes(pseudo));
        option.push(0);
        bytes.splice(20..20, option);
        bytes[0] = 0x47;
        let length = bytes.len() as u16;
        bytes[2..4].copy_from_slice(&length.to_be_bytes());
        ip = 28;
    } else {
        let mut extension = vec![0; 24];
        extension[0] = 17;
        extension[1] = 2;
        if source {
            extension[2] = 201;
            extension[3] = 16;
            extension[4..20].copy_from_slice(&address_bytes(pseudo));
            bytes[6] = 60;
        } else {
            extension[2] = kind;
            extension[3] = 1;
            extension[8..24].copy_from_slice(&address_bytes(pseudo));
            bytes[6] = 43;
        }
        bytes.splice(40..40, extension);
        let length = (bytes.len() - 40) as u16;
        bytes[4..6].copy_from_slice(&length.to_be_bytes());
        ip = 64;
    }
    let mut receiver = bytes.clone();
    let offset = match (v4, source) {
        (true, true) => 12,
        (true, false) => 16,
        (false, true) => 8,
        (false, false) => 24,
    };
    receiver[offset..offset + address_bytes(pseudo).len()].copy_from_slice(&address_bytes(pseudo));
    receiver[ip + 6..ip + 8].fill(0);
    let value = wire_checksum(&receiver, ip, 17);
    bytes[ip + 6..ip + 8].copy_from_slice(&value.to_be_bytes());
    if v4 {
        bytes[10..12].fill(0);
        let value = oracle(&bytes[..ip]);
        bytes[10..12].copy_from_slice(&value.to_be_bytes());
    }
    bytes
}

fn owned_rewrite_contract() {
    for v4 in [true, false] {
        for direction in [Direction::Outbound, Direction::Inbound] {
            let (mut mapper, _capture, attempt, budget) = mapper();
            let (src, dst, ns, nd) = endpoints(v4, direction);
            let original = packet(src, dst, 17, &segment(17));
            let expected = packet(ns, nd, 17, &segment(17));
            let idle = budget.used();
            let input = attempt
                .capability()
                .packet(RelayBuffer::copy_from(&original, &budget).unwrap())
                .unwrap();
            let pointer = input.view().bytes().as_ptr();
            let charged = budget.used();
            let all = budget.reserve(budget.limit() - charged).unwrap();
            let output = mapper.translate_owned(input, direction).unwrap();
            assert_eq!(
                output.view().bytes().as_ptr(),
                pointer,
                "unique backing is reused with no free credit"
            );
            assert_eq!(output.view().bytes(), expected);
            assert_eq!(budget.used(), budget.limit());
            drop((all, output));
            assert_eq!(budget.used(), idle);

            let input = attempt
                .capability()
                .packet(RelayBuffer::copy_from(&original, &budget).unwrap())
                .unwrap();
            let view = input.view();
            let charged = budget.used();
            let all = budget.reserve(budget.limit() - charged).unwrap();
            assert!(matches!(
                mapper.translate_owned(input, direction),
                Err(TranslationError::Full)
            ));
            assert_eq!(view.bytes(), original);
            drop(all);
            assert_eq!(
                budget.used(),
                charged,
                "last immutable owner retains the original ticket"
            );
            drop(view);
            assert_eq!(budget.used(), idle);

            let input = attempt
                .capability()
                .packet(RelayBuffer::copy_from(&original, &budget).unwrap())
                .unwrap();
            let view = input.view();
            let mut output = mapper.translate_owned(input, direction).unwrap();
            assert_ne!(view.bytes().as_ptr(), output.view().bytes().as_ptr());
            assert_eq!(view.bytes(), original);
            assert_eq!(output.view().bytes(), expected);
            assert_eq!(budget.used(), idle + 2 * (original.len() + BUFFER_OVERHEAD));
            assert!(matches!(
                output.write(|bytes| Ok(bytes.len())),
                RelayWriteOutcome::Written
            ));
            assert!(matches!(
                mapper.translate_owned(output, direction),
                Err(TranslationError::Stale)
            ));
            assert_eq!(budget.used(), charged);
            drop(view);
            assert_eq!(budget.used(), idle);

            let (mut other, _other_capture, _other_attempt, _) = super::tests::mapper();
            let input = attempt
                .capability()
                .packet(RelayBuffer::copy_from(&original, &budget).unwrap())
                .unwrap();
            assert!(
                matches!(
                    other.translate_owned(input, direction),
                    Err(TranslationError::Stale)
                ),
                "identical addresses cannot transfer attempt authority"
            );
            assert_eq!(budget.used(), idle);
        }
    }
}
