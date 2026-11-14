//! Direct mapper vectors. Fragment creation/rejoining and checksum oracles are
//! test receivers, independent of the production parser and RFC 1624 updater.
use super::{tests::*, *};

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

fn ip_checksum(bytes: &mut [u8]) {
    let ihl = usize::from(bytes[0] & 15) * 4;
    bytes[10..12].fill(0);
    let value = oracle(&bytes[..ihl]);
    bytes[10..12].copy_from_slice(&value.to_be_bytes());
}

fn fragments(bytes: &[u8], quantum: usize, boundary: usize) -> Vec<Vec<u8>> {
    assert!(quantum.is_multiple_of(8));
    let v4 = bytes[0] >> 4 == 4;
    let start = if v4 {
        usize::from(bytes[0] & 15) * 4
    } else {
        boundary
    };
    let next_field = if boundary == 40 { 6 } else { 40 };
    let mut output = Vec::new();
    for (index, part) in bytes[start..].chunks(quantum).enumerate() {
        let offset = index * quantum;
        let more = offset + part.len() < bytes.len() - start;
        let mut fragment = bytes[..start].to_vec();
        if v4 {
            fragment[4..6].copy_from_slice(&0x4567u16.to_be_bytes());
            let flags = (offset / 8) as u16 | if more { 0x2000 } else { 0 };
            fragment[6..8].copy_from_slice(&flags.to_be_bytes());
        } else {
            fragment[next_field] = 44;
            fragment.extend_from_slice(&[bytes[next_field], 0]);
            let flags = offset as u16 | u16::from(more);
            fragment.extend_from_slice(&flags.to_be_bytes());
            fragment.extend_from_slice(&0x12345678u32.to_be_bytes());
        }
        fragment.extend_from_slice(part);
        if v4 {
            let size = fragment.len() as u16;
            fragment[2..4].copy_from_slice(&size.to_be_bytes());
            ip_checksum(&mut fragment);
        } else {
            let size = (fragment.len() - 40) as u16;
            fragment[4..6].copy_from_slice(&size.to_be_bytes());
        }
        output.push(fragment);
    }
    output
}

fn rejoin(pieces: &[Vec<u8>], boundary: usize) -> Vec<u8> {
    let first = &pieces[0];
    let v4 = first[0] >> 4 == 4;
    let start = if v4 {
        usize::from(first[0] & 15) * 4
    } else {
        boundary
    };
    let mut whole = first[..start].to_vec();
    if v4 {
        whole[4..8].fill(0);
    } else {
        whole[if boundary == 40 { 6 } else { 40 }] = first[boundary];
    }
    for piece in pieces {
        let offset = if v4 {
            usize::from(u16::from_be_bytes([piece[6], piece[7]]) & 0x1fff) * 8
        } else {
            usize::from(u16::from_be_bytes([piece[boundary + 2], piece[boundary + 3]]) & 0xfff8)
        };
        let data = &piece[start + if v4 { 0 } else { 8 }..];
        assert_eq!(
            whole.len(),
            start + offset,
            "receiver sees exact contiguous offsets"
        );
        whole.extend_from_slice(data);
    }
    if v4 {
        let size = whole.len() as u16;
        whole[2..4].copy_from_slice(&size.to_be_bytes());
        ip_checksum(&mut whole);
    } else {
        let size = (whole.len() - 40) as u16;
        whole[4..6].copy_from_slice(&size.to_be_bytes());
    }
    whole
}

fn map_pieces(
    mapper: &mut AddressTranslator,
    pieces: &[Vec<u8>],
    direction: Direction,
) -> Vec<Vec<u8>> {
    pieces
        .iter()
        .map(|piece| {
            let output = mapper
                .translate(piece, direction)
                .expect("valid independent fragment");
            let view = output.view();
            view.bytes().to_vec()
        })
        .collect()
}

fn vectors(protocols: impl Fn(bool) -> u8) {
    let (mut mapper, _capture, _attempt, _) = mapper();
    for v4 in [true, false] {
        for direction in [Direction::Outbound, Direction::Inbound] {
            let protocol = protocols(v4);
            let (src, dst, new_src, new_dst) = endpoints(v4, direction);
            let mut payload = segment(protocol);
            payload.extend(0..=127);
            if protocol == 17 {
                let size = payload.len() as u16;
                payload[4..6].copy_from_slice(&size.to_be_bytes());
            }
            let with_options = |src, dst| {
                let mut bytes = packet(src, dst, protocol, &payload);
                if v4 {
                    bytes.splice(20..20, [148, 4, 0, 0]);
                    bytes[0] = 0x46;
                    let length = bytes.len() as u16;
                    bytes[2..4].copy_from_slice(&length.to_be_bytes());
                    fix_checksums(&mut bytes, 24, protocol);
                }
                bytes
            };
            let original = with_options(src, dst);
            let expected = with_options(new_src, new_dst);
            let pieces = fragments(&original, 32, 40);
            let translated = map_pieces(&mut mapper, &pieces, direction);
            let received = rejoin(&translated, 40);
            assert_eq!(
                wire_checksum(&received, if v4 { 24 } else { 40 }, protocol),
                0,
                "independent fragment receiver checksum"
            );
            assert_eq!(translated, fragments(&expected, 32, 40));
            assert_eq!(received, expected, "exact tuple, options, IDs and payload");
            if v4 {
                assert_eq!(oracle(&received[..24]), 0);
            }
        }
    }
}

#[test]
fn fragment_tcp_checksum_vectors() {
    vectors(|_| 6);
}

#[test]
fn fragment_udp_checksum_vectors() {
    vectors(|_| 17);
}

#[test]
fn fragment_icmp_checksum_vectors() {
    vectors(|v4| if v4 { 1 } else { 58 });
}

#[test]
fn fragment_checksum_carry_and_udp_zero() {
    // RFC 1624 section 4: the old RFC 1141 expression yields negative zero.
    assert_eq!(adjusted(0xdd2f, &[0x55, 0x55], &[0x32, 0x85]), 0);
    assert_eq!(
        adjusted(0x1234, &[0xff, 0xff, 0xff, 0xfe], &[0, 1, 0, 3]),
        0x122f
    );
    let (mut mapper, _capture, _attempt, _) = mapper();
    for v4 in [true, false] {
        for direction in [Direction::Outbound, Direction::Inbound] {
            let (src, dst, new_src, new_dst) = endpoints(v4, direction);
            let ip = if v4 { 20 } else { 40 };
            let mut target = packet(
                new_src,
                new_dst,
                17,
                &[
                    0, 1, 0, 2, 0, 24, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                ],
            );
            target[ip + 6..ip + 8].fill(0);
            let correction = wire_checksum(&target, ip, 17);
            target[ip + 8..ip + 10].copy_from_slice(&correction.to_be_bytes());
            fix_checksums(&mut target, ip, 17);
            assert_eq!(&target[ip + 6..ip + 8], &[255, 255]);
            let mut original = packet(src, dst, 17, &target[ip..]);
            assert_ne!(&original[ip + 6..ip + 8], &[0, 0]);
            let output = map_pieces(&mut mapper, &fragments(&original, 16, 40), direction);
            assert_eq!(rejoin(&output, 40), target);
            original[ip + 6..ip + 8].fill(0);
            let pieces = fragments(&original, 16, 40);
            let output = map_pieces(&mut mapper, &pieces, direction);
            let transport = ip + if v4 { 0 } else { 8 };
            assert_eq!(&output[0][transport + 6..transport + 8], &[0, 0]);
        }
    }
}

#[test]
fn fragment_noninitial_payload_is_opaque() {
    let (mut mapper, _capture, _attempt, _) = mapper();
    for v4 in [true, false] {
        for direction in [Direction::Outbound, Direction::Inbound] {
            let (src, dst, new_src, new_dst) = endpoints(v4, direction);
            for protocol in [6, 17, 1, 58, 60, 44, 47, 50, 51, 132, 253] {
                let mut data = [255; 64]; // Invalid extension or TCP data offset.
                // A later ICMP fragment can look like an error but has no quote.
                if (v4 && protocol == 1) || (!v4 && protocol == 58) {
                    data[32] = if v4 { 3 } else { 2 };
                }
                let original = fragments(&packet(src, dst, protocol, &data), 32, 40);
                let expected = fragments(&packet(new_src, new_dst, protocol, &data), 32, 40);
                if protocol == 51 {
                    expect_refusal(
                        &mut mapper,
                        &original[1],
                        direction,
                        TranslationError::UnsupportedTranslation,
                    );
                } else {
                    let output = mapper.translate(&original[1], direction).unwrap();
                    assert_eq!(output.view().bytes(), expected[1]);
                }
                if matches!(protocol, 47 | 50 | 132) {
                    let output = mapper.translate(&original[0], direction).unwrap();
                    assert_eq!(output.view().bytes(), expected[0]);
                }
            }
            for protocol in [51, 253] {
                let original = fragments(&packet(src, dst, protocol, &[0; 64]), 32, 40);
                if protocol == 51 {
                    expect_refusal(
                        &mut mapper,
                        &original[0],
                        direction,
                        TranslationError::UnsupportedTranslation,
                    );
                } else {
                    let expected = fragments(&packet(new_src, new_dst, protocol, &[0; 64]), 32, 40);
                    let output = mapper.translate(&original[0], direction).unwrap();
                    assert_eq!(output.view().bytes(), expected[0]);
                }
            }
        }
    }
}

fn expect_refusal(
    mapper: &mut AddressTranslator,
    bytes: &[u8],
    direction: Direction,
    reason: TranslationError,
) {
    let before = mapper.summary().refused(reason);
    assert!(matches!(mapper.translate(bytes, direction), Err(actual) if actual == reason));
    assert_eq!(mapper.summary().refused(reason), before + 1);
}

#[test]
fn fragment_initial_headers_require_only_present_rewrite_words() {
    let (mut mapper, _capture, _attempt, budget) = mapper();
    for v4 in [true, false] {
        for direction in [Direction::Outbound, Direction::Inbound] {
            let (src, dst, _, _) = endpoints(v4, direction);
            for (protocol, count) in [
                (6, 8),
                (6, 16),
                (6, 24),
                (17, 0),
                (17, 4),
                (if v4 { 1 } else { 58 }, 0),
                (if v4 { 1 } else { 58 }, 4),
            ] {
                let mut body = segment(protocol);
                if protocol == 6 && count == 24 {
                    body[12] = 0x80;
                }
                let mut first = fragments(&packet(src, dst, protocol, &body), 32, 40)[0].clone();
                let start = if v4 { 20 } else { 48 };
                first.truncate(start + count);
                if v4 {
                    first[2..4].copy_from_slice(&((start + count) as u16).to_be_bytes());
                    ip_checksum(&mut first);
                } else {
                    first[4..6].copy_from_slice(&((start + count - 40) as u16).to_be_bytes());
                }
                let before = budget.used();
                let required = match protocol {
                    6 => 18,
                    17 => 8,
                    _ => 4,
                };
                if !v4 && count < required {
                    expect_refusal(
                        &mut mapper,
                        &first,
                        direction,
                        TranslationError::ShortHeader,
                    );
                } else {
                    let output = mapper.translate(&first, direction).unwrap();
                    assert_eq!(output.view().bytes().len(), first.len());
                }
                assert_eq!(budget.used(), before, "short initial cannot retain data");
            }
            if !v4 {
                let mut first = fragments(
                    &packet(
                        src,
                        dst,
                        60,
                        &[6, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                    ),
                    8,
                    40,
                )[0]
                .clone();
                first[40] = 60;
                expect_refusal(
                    &mut mapper,
                    &first,
                    direction,
                    TranslationError::ShortHeader,
                );
            } else {
                for count in [8, 16] {
                    let mut body = segment(1);
                    body[0] = 13; // Timestamp's required header is 20 bytes.
                    let first = fragments(&packet(src, dst, 1, &body), count, 40)[0].clone();
                    let output = mapper.translate(&first, direction).unwrap();
                    assert_eq!(&output.view().bytes()[20..], &first[20..]);
                }
            }
            let mut udp = segment(17);
            udp[4..6].copy_from_slice(&7u16.to_be_bytes());
            let first = fragments(&packet(src, dst, 17, &udp), 16, 40)[0].clone();
            let output = mapper.translate(&first, direction).unwrap();
            assert_eq!(output.view().bytes().len(), first.len());
            drop(output);
            for overflow in [false, true] {
                let mut first = fragments(&packet(src, dst, 6, &segment(6)), 32, 40)[0].clone();
                if overflow {
                    if v4 {
                        first[6..8].copy_from_slice(&0x1fffu16.to_be_bytes());
                        ip_checksum(&mut first);
                    } else {
                        first[42..44].copy_from_slice(&0xfff8u16.to_be_bytes());
                    }
                } else {
                    first.pop();
                    if v4 {
                        let size = first.len() as u16;
                        first[2..4].copy_from_slice(&size.to_be_bytes());
                        ip_checksum(&mut first);
                    } else {
                        let size = (first.len() - 40) as u16;
                        first[4..6].copy_from_slice(&size.to_be_bytes());
                    }
                }
                let output = mapper.translate(&first, direction).unwrap();
                assert_eq!(output.view().bytes().len(), first.len());
            }
        }
    }
}

fn extensions(mut bytes: Vec<u8>, before: bool, after: bool) -> (Vec<u8>, usize, usize) {
    let protocol = bytes[6];
    if after {
        bytes.splice(40..40, [protocol, 0, 1, 4, 0, 0, 0, 0]);
        bytes[6] = 60;
    }
    if before {
        let next = bytes[6];
        bytes.splice(40..40, [next, 0, 5, 2, 0, 0, 0, 0]);
        bytes[6] = 0;
    }
    let size = (bytes.len() - 40) as u16;
    bytes[4..6].copy_from_slice(&size.to_be_bytes());
    (
        bytes,
        if before { 48 } else { 40 },
        40 + 8 * (usize::from(before) + usize::from(after)),
    )
}

#[test]
fn fragment_ipv6_extensions_and_atomic_headers() {
    let (mut mapper, _capture, _attempt, _) = mapper();
    for direction in [Direction::Outbound, Direction::Inbound] {
        let (src, dst, new_src, new_dst) = endpoints(false, direction);
        for before in [false, true] {
            for after in [false, true] {
                let (original, boundary, transport) =
                    extensions(packet(src, dst, 6, &segment(6)), before, after);
                let (expected, _, _) =
                    extensions(packet(new_src, new_dst, 6, &segment(6)), before, after);
                for quantum in [32, 1024] {
                    let pieces = fragments(&original, quantum, boundary);
                    let output = map_pieces(&mut mapper, &pieces, direction);
                    assert_eq!(
                        output,
                        fragments(&expected, quantum, boundary),
                        "atomic Fragment header must remain"
                    );
                    let received = rejoin(&output, boundary);
                    assert_eq!(received, expected);
                    assert_eq!(wire_checksum(&received, transport, 6), 0);
                    if quantum == 1024 {
                        let mut corrupt = pieces[0].clone();
                        *corrupt.last_mut().unwrap() ^= 1;
                        let output = mapper.translate(&corrupt, direction).unwrap();
                        assert_ne!(wire_checksum(output.view().bytes(), transport + 8, 6), 0);
                    }
                }
            }
        }
        let mut too_many = packet(src, dst, 6, &segment(6));
        for _ in 0..9 {
            let next = too_many[6];
            too_many.splice(40..40, [next, 0, 0, 0, 0, 0, 0, 0]);
            too_many[6] = 60;
        }
        let size = (too_many.len() - 40) as u16;
        too_many[4..6].copy_from_slice(&size.to_be_bytes());
        let output = mapper.translate(&too_many, direction).unwrap();
        assert_eq!(&output.view().bytes()[40..112], &too_many[40..112]);
        assert_eq!(wire_checksum(output.view().bytes(), 112, 6), 0);
        let mut duplicate = fragments(&packet(src, dst, 6, &segment(6)), 1024, 40)[0].clone();
        duplicate[40] = 44;
        let output = mapper.translate(&duplicate, direction).unwrap();
        assert_eq!(&output.view().bytes()[40..], &duplicate[40..]);
        let mut bad_alignment = fragments(&packet(src, dst, 6, &segment(6)), 32, 40)[0].clone();
        bad_alignment.pop();
        let size = (bad_alignment.len() - 40) as u16;
        bad_alignment[4..6].copy_from_slice(&size.to_be_bytes());
        let output = mapper.translate(&bad_alignment, direction).unwrap();
        assert_eq!(output.view().bytes().len(), bad_alignment.len());
    }
}

fn quoted_endpoints(v4: bool, direction: Direction) -> (IpAddr, IpAddr, IpAddr, IpAddr) {
    let (src, dst, new_src, new_dst) = endpoints(v4, direction);
    (dst, src, new_dst, new_src)
}

fn error(quote: &[u8], v4: bool, direction: Direction, kind: u8) -> Vec<u8> {
    let (src, dst, _, _) = endpoints(v4, direction);
    let mut body = vec![kind, if v4 && kind == 3 { 4 } else { 0 }, 0, 0, 0, 0, 5, 0];
    body.extend_from_slice(quote);
    packet(src, dst, if v4 { 1 } else { 58 }, &body)
}

fn check_error(
    mapper: &mut AddressTranslator,
    quote: &[u8],
    expected: &[u8],
    v4: bool,
    direction: Direction,
) {
    let ip = if v4 { 20 } else { 40 };
    let original = error(quote, v4, direction, if v4 { 3 } else { 2 });
    let output = mapper.translate(&original, direction).unwrap();
    let view = output.view();
    assert_eq!(&view.bytes()[ip + 8..], expected);
    assert_eq!(&view.bytes()[ip..ip + 2], &original[ip..ip + 2]);
    assert_eq!(&view.bytes()[ip + 4..ip + 8], &original[ip + 4..ip + 8]);
    assert_eq!(wire_checksum(view.bytes(), ip, if v4 { 1 } else { 58 }), 0);
    if v4 {
        assert_eq!(oracle(&view.bytes()[..ip]), 0);
    }
}

#[test]
fn fragment_quotation_first_and_noninitial() {
    let (mut mapper, _capture, _attempt, _) = mapper();
    for v4 in [true, false] {
        for direction in [Direction::Outbound, Direction::Inbound] {
            let (src, dst, new_src, new_dst) = quoted_endpoints(v4, direction);
            for protocol in [6, 17, if v4 { 1 } else { 58 }, 253] {
                let mut payload = segment(protocol);
                payload.extend_from_slice(&[0x57; 64]);
                if protocol == 17 {
                    let size = payload.len() as u16;
                    payload[4..6].copy_from_slice(&size.to_be_bytes());
                }
                let original = fragments(&packet(src, dst, protocol, &payload), 32, 40);
                let expected = fragments(&packet(new_src, new_dst, protocol, &payload), 32, 40);
                if protocol != 253 {
                    check_error(&mut mapper, &original[0], &expected[0], v4, direction);
                }
                check_error(&mut mapper, &original[1], &expected[1], v4, direction);
            }
        }
    }
}

#[test]
fn fragment_quotation_truncation() {
    let (mut mapper, _capture, _attempt, _) = mapper();
    for v4 in [true, false] {
        for direction in [Direction::Outbound, Direction::Inbound] {
            let (src, dst, new_src, new_dst) = quoted_endpoints(v4, direction);
            for protocol in [6, 17, if v4 { 1 } else { 58 }] {
                let original = fragments(&packet(src, dst, protocol, &segment(protocol)), 32, 40);
                let expected = fragments(
                    &packet(new_src, new_dst, protocol, &segment(protocol)),
                    32,
                    40,
                );
                let start = if v4 { 20 } else { 48 };
                let field = match protocol {
                    6 => 16,
                    17 => 6,
                    _ => 2,
                };
                for length in [start, start + field, start + field + 1, start + field + 2] {
                    let mut prefix = expected[0][..length].to_vec();
                    if length < start + field + 2 {
                        prefix[start..].copy_from_slice(&original[0][start..length]);
                    }
                    check_error(&mut mapper, &original[0][..length], &prefix, v4, direction);
                }
            }
            let with_options = |src, dst| {
                let mut bytes = packet(src, dst, 6, &segment(6));
                if v4 {
                    bytes.splice(20..20, [148, 4, 0, 0]);
                    bytes[0] = 0x46;
                    let size = bytes.len() as u16;
                    bytes[2..4].copy_from_slice(&size.to_be_bytes());
                    fix_checksums(&mut bytes, 24, 6);
                } else {
                    bytes = extensions(bytes, false, true).0;
                }
                bytes
            };
            let original = with_options(src, dst);
            let expected = with_options(new_src, new_dst);
            for length in if v4 {
                vec![20, 21, 22, 23, 24]
            } else {
                vec![40, 41, 42, 43, 47, 48]
            } {
                check_error(
                    &mut mapper,
                    &original[..length],
                    &expected[..length],
                    v4,
                    direction,
                );
            }
        }
    }
}

#[test]
fn fragment_outer_icmp_incremental_checksum() {
    let (mut mapper, _capture, _attempt, _) = mapper();
    for v4 in [true, false] {
        for direction in [Direction::Outbound, Direction::Inbound] {
            let (src, dst, new_src, new_dst) = quoted_endpoints(v4, direction);
            for protocol in [6, 17, if v4 { 1 } else { 58 }] {
                let mut payload = segment(protocol);
                payload.extend_from_slice(&[0x65; 64]);
                if protocol == 17 {
                    let size = payload.len() as u16;
                    payload[4..6].copy_from_slice(&size.to_be_bytes());
                }
                let quote = packet(src, dst, protocol, &payload);
                let expected_quote = packet(new_src, new_dst, protocol, &payload);
                for kind in if v4 {
                    vec![3, 11, 12]
                } else {
                    vec![1, 2, 3, 4]
                } {
                    let original = error(&quote, v4, direction, kind);
                    let mut expected = error(&expected_quote, v4, direction, kind);
                    let (s, d, ns, nd) = endpoints(v4, direction);
                    assert_ne!((s, d), (ns, nd));
                    let ip = if v4 { 20 } else { 40 };
                    expected = packet(ns, nd, if v4 { 1 } else { 58 }, &expected[ip..]);
                    let pieces = fragments(&original, 72, 40);
                    assert!(pieces.len() >= 2);
                    let output = map_pieces(&mut mapper, &pieces, direction);
                    let received = rejoin(&output, 40);
                    assert_eq!(
                        wire_checksum(&received, ip, if v4 { 1 } else { 58 }),
                        0,
                        "independent outer ICMP receiver checksum"
                    );
                    assert_eq!(output, fragments(&expected, 72, 40));
                    assert_eq!(
                        received, expected,
                        "type/code/MTU/pointer and quoted tuple intact"
                    );
                    assert_eq!(wire_checksum(&received[ip + 8..], ip, protocol), 0);
                }
            }
        }
    }
}

#[test]
fn fragment_outer_icmp_incomplete_rewrite_drops() {
    let (mut mapper, _capture, _attempt, budget) = mapper();
    for v4 in [true, false] {
        for direction in [Direction::Outbound, Direction::Inbound] {
            let (src, dst, _, _) = quoted_endpoints(v4, direction);
            let quote = packet(src, dst, 6, &segment(6));
            let outer = error(&quote, v4, direction, if v4 { 3 } else { 2 });
            for quantum in if v4 {
                vec![8, 16, 24, 40]
            } else {
                vec![8, 16, 24, 40, 64]
            } {
                let pieces = fragments(&outer, quantum, 40);
                let before = budget.used();
                expect_refusal(
                    &mut mapper,
                    &pieces[0],
                    direction,
                    TranslationError::ShortHeader,
                );
                assert_eq!(budget.used(), before);
                let tail = mapper.translate(&pieces[1], direction).unwrap();
                assert_eq!(tail.view().bytes().len(), pieces[1].len());
            }
            if !v4 {
                let quote = extensions(quote, false, true).0;
                let pieces = fragments(&error(&quote, false, direction, 2), 48, 40);
                expect_refusal(
                    &mut mapper,
                    &pieces[0],
                    direction,
                    TranslationError::ShortHeader,
                );
            } else {
                // The quoted TCP checksum can live in a *later* IPv4 fragment.
                // Its required offset is relative to that fragment, not byte 16
                // of an absent reassembled transport header.
                let mut with_options = packet(src, dst, 6, &segment(6));
                with_options.splice(20..20, [148, 4, 0, 0]);
                with_options[0] = 0x46;
                let size = with_options.len() as u16;
                with_options[2..4].copy_from_slice(&size.to_be_bytes());
                fix_checksums(&mut with_options, 24, 6);
                let quoted_tail = fragments(&with_options, 8, 40).remove(2);
                let outer = error(&quoted_tail, true, direction, 3);
                let first = fragments(&outer, 32, 40).remove(0);
                expect_refusal(
                    &mut mapper,
                    &first,
                    direction,
                    TranslationError::ShortHeader,
                );
            }
            // The received outer fragment, not an inner quotation's own MF bit,
            // determines whether absent nested rewrite words will arrive later.
            let (outer_src, outer_dst, _, _) = endpoints(v4, direction);
            let inner = packet(outer_src, outer_dst, 6, &segment(6));
            let mut body = vec![if v4 { 11 } else { 3 }, 0, 0, 0, 0, 0, 0, 0];
            body.extend_from_slice(&inner);
            let middle = packet(outer_dst, outer_src, if v4 { 1 } else { 58 }, &body);
            let outer = error(&middle, v4, direction, if v4 { 11 } else { 3 });
            let first = fragments(&outer, if v4 { 72 } else { 112 }, 40).remove(0);
            expect_refusal(
                &mut mapper,
                &first,
                direction,
                TranslationError::ShortHeader,
            );
        }
    }
}

#[test]
fn fragment_nonmatches_preserve_budget_and_exact_attempt_refusals() {
    let (mut mapper, capture, attempt, budget) = mapper();
    for v4 in [true, false] {
        for direction in [Direction::Outbound, Direction::Inbound] {
            let (src, dst, _, _) = endpoints(v4, direction);
            let pieces = fragments(&packet(src, dst, 6, &segment(6)), 32, 40);
            let before = budget.used();
            let all = budget.reserve(budget.limit() - before).unwrap();
            for piece in &pieces {
                expect_refusal(&mut mapper, piece, direction, TranslationError::Full);
            }
            let wrong = fragments(&packet(remote(v4), remote(v4), 6, &segment(6)), 32, 40);
            for piece in &wrong {
                expect_refusal(&mut mapper, piece, direction, TranslationError::Full);
            }
            drop(all);
            for piece in &wrong {
                let output = mapper.translate(piece, direction).unwrap();
                assert_eq!(output.view().bytes(), piece);
            }
            if !v4 {
                mapper.config.assigned.ipv6 = None;
                for piece in &pieces {
                    if direction == Direction::Outbound {
                        expect_refusal(&mut mapper, piece, direction, TranslationError::Family);
                    } else {
                        let output = mapper.translate(piece, direction).unwrap();
                        assert_eq!(output.view().bytes(), piece);
                    }
                }
                mapper.config.assigned = ASSIGNED;
            }
            assert_eq!(budget.used(), before);
        }
    }
    let pieces = fragments(
        &packet(address(FIXED, true), remote(true), 6, &segment(6)),
        32,
        40,
    );
    let queued = mapper.translate(&pieces[0], Direction::Outbound).unwrap();
    attempt.retire();
    assert!(matches!(
        queued.handoff(|_| panic!("old fragment emitted")),
        Err(RelayFlowError::Stale)
    ));
    let successor = capture.open_attempt(&budget).unwrap();
    successor.activate().unwrap();
    for piece in &pieces {
        expect_refusal(
            &mut mapper,
            piece,
            Direction::Outbound,
            TranslationError::Stale,
        );
    }
}
