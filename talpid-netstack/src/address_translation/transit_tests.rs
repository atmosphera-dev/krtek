//! Whole-target consumers. Reassembly is a test receiver only.
use super::*;
use talpid_types::relay_flow::RelayCaptureGeneration;

fn endpoints(v4: bool, direction: Direction) -> (IpAddr, IpAddr) {
    if direction == Direction::Outbound {
        (address(FIXED, v4), remote(v4))
    } else {
        (remote(v4), address(ASSIGNED, v4))
    }
}

fn endpoint_delivery_matrix(direction: Direction) {
    // Keep the historical missing-return vector first: source fragments larger
    // than the kernel's transmit MTU must still reach its receive/rejoin side.
    let (mut path, _capture, _attempt, _) = path();
    let whole = datagram(false, direction, 3080);
    let fragments = source_fragments(&whole, 1328, 40);
    assert_eq!(fragments[0].len(), 1376);
    let mut output = Vec::new();
    for input in &fragments {
        let received = forward(&mut path, input, direction);
        assert_eq!(received.len(), 1, "one endpoint output per arrival");
        layout(input, &received[0], direction);
        output.extend(received);
    }
    let joined = rejoin(&output, 40);
    assert_eq!(
        wire_checksum(&joined, 40, 17),
        0,
        "independent receiver checksum"
    );
    assert_eq!(&joined[48..], &whole[48..]);

    for mtu in [576, 1280, 1380] {
        for v4 in [true, false] {
            if !v4 && mtu < 1280 {
                continue;
            }
            let (old, _capture, attempt, budget) = super::path();
            let mut config = old.config();
            config.mtu = mtu;
            if mtu < 1280 {
                config.assigned.ipv6 = None;
            }
            drop(old);
            let mut path =
                TargetPacketPath::new(config, attempt.capability(), Arc::new(budget)).unwrap();
            let ip = if v4 { 20 } else { 40 };
            let (source, destination) = endpoints(v4, direction);
            for protocol in [6, 17, if v4 { 1 } else { 58 }] {
                for size in [64, 3200] {
                    let mut body = segment(protocol);
                    body.resize(size, 0x5b);
                    if protocol == 17 {
                        body[4..6].copy_from_slice(&(size as u16).to_be_bytes());
                    }
                    let whole = packet(source, destination, protocol, &body);
                    let mut sets = vec![vec![whole.clone()], source_fragments(&whole, 1328, 40)];
                    if !v4 {
                        sets.push(source_fragments(&whole, 65528, 40));
                    }
                    if v4 {
                        let mut df = whole.clone();
                        df[6] = 0x40;
                        fix_checksums(&mut df, ip, protocol);
                        sets.push(vec![df]);
                    }
                    for inputs in sets {
                        let fragmented = if v4 {
                            word(&inputs[0], 6) & 0x3fff != 0
                        } else {
                            inputs[0][6] == 44
                        };
                        let mut received = Vec::new();
                        for input in &inputs {
                            let output = forward(&mut path, input, direction);
                            assert_eq!(output.len(), 1);
                            assert_eq!(output[0].len(), input.len());
                            // All original IP layout bytes remain, including
                            // DF/ID/offset/MF and IPv6 Fragment/atomic fields.
                            if v4 {
                                assert_eq!(&output[0][..10], &input[..10]);
                            } else {
                                assert_eq!(&output[0][..8], &input[..8]);
                                if input[6] == 44 {
                                    assert_eq!(&output[0][40..48], &input[40..48]);
                                }
                            }
                            received.extend(output);
                        }
                        let joined = if fragmented {
                            rejoin(&received, 40)
                        } else {
                            received.remove(0)
                        };
                        assert_eq!(
                            wire_checksum(&joined, ip, protocol),
                            0,
                            "independent receiver checksum"
                        );
                        assert_eq!(
                            &joined[ip + if protocol == 6 { 24 } else { 8 }..],
                            &whole[ip + if protocol == 6 { 24 } else { 8 }..]
                        );
                    }
                }
            }
            // Real peer-supplied errors are data, even when larger than MTU.
            let quoted = if direction == Direction::Inbound {
                large(v4, address(ASSIGNED, v4), remote(v4), false)
            } else {
                large(v4, remote(v4), address(FIXED, v4), false)
            };
            let protocol = if v4 { 1 } else { 58 };
            let mut body = vec![
                if v4 { 3 } else { 2 },
                if v4 { 4 } else { 0 },
                0,
                0,
                0,
                0,
                5,
                0,
            ];
            body.extend_from_slice(&quoted);
            let input = packet(source, destination, protocol, &body);
            let output = forward(&mut path, &input, direction);
            assert_eq!(output.len(), 1);
            assert_eq!(output[0].len(), input.len());
            assert_eq!(&output[0][ip..ip + 2], &input[ip..ip + 2]);
            assert_eq!(&output[0][ip + 4..ip + 8], &input[ip + 4..ip + 8]);
            assert_eq!(wire_checksum(&output[0], ip, protocol), 0);
            assert_eq!(wire_checksum(&output[0][ip + 8..], ip, 17), 0);
        }
    }
}

#[test]
fn inbound_delivery_is_not_limited_by_transmit_mtu() {
    endpoint_delivery_matrix(Direction::Inbound);
}

#[test]
fn outbound_delivery_defers_sizing_to_native_carrier() {
    endpoint_delivery_matrix(Direction::Outbound);
}

fn datagram(v4: bool, direction: Direction, length: usize) -> Vec<u8> {
    let (source, destination) = endpoints(v4, direction);
    let mut body = segment(17);
    body.resize(length, 0x5a);
    body[4..6].copy_from_slice(&(length as u16).to_be_bytes());
    packet(source, destination, 17, &body)
}

fn forward(path: &mut TargetPacketPath, bytes: &[u8], direction: Direction) -> Vec<Vec<u8>> {
    receive(path.process(bytes, direction).unwrap())
}

fn layout(input: &[u8], output: &[u8], direction: Direction) {
    assert_eq!(input.len(), output.len());
    let v4 = input[0] >> 4 == 4;
    let original = Header::parse(input, ParseContext::Received).unwrap();
    let header = Header::parse(output, ParseContext::Received).unwrap();
    assert_eq!(
        header.source,
        if direction == Direction::Outbound {
            address(ASSIGNED, v4)
        } else {
            original.source
        }
    );
    assert_eq!(
        header.destination,
        if direction == Direction::Inbound {
            address(FIXED, v4)
        } else {
            original.destination
        }
    );
    let ip = if v4 {
        usize::from(input[0] & 15) * 4
    } else {
        48
    };
    if v4 {
        assert_eq!(&input[..2], &output[..2]);
        assert_eq!(&input[2..10], &output[2..10]);
        assert_eq!(&input[20..ip], &output[20..ip]);
        assert_eq!(oracle(&output[..ip]), 0);
    } else {
        assert_eq!(&input[..8], &output[..8]);
        assert_eq!(&input[40..48], &output[40..48]);
    }
    // Only a present initial UDP checksum may differ within payload.
    if header.non_initial {
        assert_eq!(&input[ip..], &output[ip..]);
    } else {
        assert_eq!(&input[ip..ip + 6], &output[ip..ip + 6]);
        assert_eq!(&input[ip + 8..], &output[ip + 8..]);
    }
}

#[test]
fn transit_orders_forward_immediately() {
    for v4 in [true, false] {
        for direction in [Direction::Outbound, Direction::Inbound] {
            let (mut path, _capture, _attempt, _) = path();
            let bytes = datagram(v4, direction, 2400);
            let pieces = source_fragments(&bytes, 800, 40);
            for order in [vec![0, 1, 2], vec![2, 1, 0], vec![2], vec![1, 2]] {
                let mut received = Vec::new();
                for index in &order {
                    let output = forward(&mut path, &pieces[*index], direction);
                    assert_eq!(
                        output.len(),
                        1,
                        "one output at each arrival, not after completion"
                    );
                    layout(&pieces[*index], &output[0], direction);
                    received.extend(output);
                }
                if order.len() == pieces.len() {
                    let joined = rejoin(&received, 40);
                    assert_eq!(wire_checksum(&joined, if v4 { 20 } else { 40 }, 17), 0);
                    assert_eq!(
                        &joined[if v4 { 28 } else { 48 }..],
                        &bytes[if v4 { 28 } else { 48 }..]
                    );
                }
            }
        }
    }
}

#[test]
fn transit_duplicates_and_overlaps_preserve_bytes() {
    for v4 in [true, false] {
        for direction in [Direction::Outbound, Direction::Inbound] {
            let (mut path, _capture, _attempt, _) = path();
            let pieces = source_fragments(&datagram(v4, direction, 2400), 800, 40);
            let mut overlap = pieces[1].clone();
            if v4 {
                overlap[6..8].copy_from_slice(&0x2032u16.to_be_bytes());
                overlap[10..12].fill(0);
                let sum = oracle(&overlap[..20]);
                overlap[10..12].copy_from_slice(&sum.to_be_bytes());
            } else {
                overlap[42..44].copy_from_slice(&401u16.to_be_bytes());
            }
            let last = overlap.len() - 1;
            overlap[last] ^= 0xff;
            for input in [&pieces[0], &pieces[0], &pieces[1], &overlap, &pieces[2]] {
                let output = forward(&mut path, input, direction);
                assert_eq!(output.len(), 1);
                layout(input, &output[0], direction);
            }
        }
    }
}

#[test]
fn transit_id_reuse_has_no_history() {
    for v4 in [true, false] {
        for direction in [Direction::Outbound, Direction::Inbound] {
            let (mut path, _capture, _attempt, budget) = path();
            let idle = budget.used();
            let pieces = source_fragments(&datagram(v4, direction, 1600), 800, 40);
            for id in (0u16..1100).chain([0, 0, 1099]) {
                for piece in &pieces {
                    let mut input = piece.clone();
                    if v4 {
                        input[4..6].copy_from_slice(&id.to_be_bytes());
                        input[10..12].fill(0);
                        let sum = oracle(&input[..20]);
                        input[10..12].copy_from_slice(&sum.to_be_bytes());
                    } else {
                        input[44..48].copy_from_slice(&u32::from(id).to_be_bytes());
                    }
                    let output = forward(&mut path, &input, direction);
                    assert_eq!(output.len(), 1);
                    layout(&input, &output[0], direction);
                }
                assert_eq!(budget.used(), idle);
            }
            assert_eq!(path.summary().translated, 2206);
        }
    }
}

#[test]
fn transit_no_fragment_reservation_or_deadline() {
    let (mut path, capture, attempt, budget) = path();
    // Capture, attempt and mapper metadata only: no packet child or timer.
    assert_eq!(budget.used(), 3 * BUFFER_OVERHEAD);
    let idle = budget.used();
    let fragments = source_fragments(&datagram(true, Direction::Outbound, 1600), 800, 40);
    for input in fragments.iter().cycle().take(70) {
        let packet = path.process(input, Direction::Outbound).unwrap();
        assert_eq!(budget.used(), idle + input.len() + BUFFER_OVERHEAD);
        drop(packet);
        assert_eq!(budget.used(), idle);
    }
    // The only per-packet allocation is the owned wire buffer. Refusal and
    // success both refund completely, without splitter/queue metadata.
    struct Recording {
        budget: BufferBudget,
        requests: std::sync::Mutex<Vec<(usize, bool)>>,
    }
    impl RelayBufferAllocator for Recording {
        fn try_reserve(
            &self,
            bytes: usize,
        ) -> Result<Arc<dyn RelayBufferReservation>, RelayFlowError> {
            let result = RelayBufferAllocator::try_reserve(&self.budget, bytes);
            self.requests.lock().unwrap().push((bytes, result.is_ok()));
            result
        }
    }
    let config = path.config();
    drop(path);
    let recorded = Arc::new(Recording {
        budget: budget.clone(),
        requests: std::sync::Mutex::new(Vec::new()),
    });
    let mut path = TargetPacketPath::new(config, attempt.capability(), recorded.clone()).unwrap();
    assert_eq!(budget.used(), idle);
    let input = datagram(true, Direction::Outbound, 6000);
    let input_charge = input.len() + BUFFER_OVERHEAD;
    let available = input_charge - 1;
    let all = budget.reserve(budget.limit() - idle - available).unwrap();
    let held = budget.used();
    recorded.requests.lock().unwrap().clear();
    assert!(matches!(
        path.process(&input, Direction::Outbound),
        Err(TranslationError::Full)
    ));
    assert_eq!(*recorded.requests.lock().unwrap(), [(input_charge, false)]);
    assert_eq!(budget.used(), held, "refused packet retains no allocation");
    drop(all);
    assert_eq!(budget.used(), idle);
    recorded.requests.lock().unwrap().clear();
    let packet = path.process(&input, Direction::Outbound).unwrap();
    assert_eq!(packet.view().bytes().len(), input.len());
    assert_eq!(budget.used(), idle + input_charge);
    assert_eq!(*recorded.requests.lock().unwrap(), [(input_charge, true)]);
    drop(packet);
    assert_eq!(budget.used(), idle);
    drop((path, recorded, capture, attempt));
    assert_eq!(budget.used(), 0);
}

#[test]
fn transit_mtu_metadata_does_not_change_packet_layout() {
    for mtu in [576, 1280, 1380] {
        for v4 in [true, false] {
            if !v4 && mtu < 1280 {
                continue;
            }
            for direction in [Direction::Outbound, Direction::Inbound] {
                let (old, capture, attempt, budget) = path();
                let mut config = old.config();
                config.mtu = mtu;
                if mtu == 576 {
                    config.assigned.ipv6 = None;
                }
                drop(old);
                let mut path =
                    TargetPacketPath::new(config, attempt.capability(), Arc::new(budget.clone()))
                        .unwrap();
                let original = datagram(v4, direction, 4800);
                let pieces = source_fragments(&original, 512, 40);
                let mut outputs = Vec::new();
                for input in &pieces {
                    let output = forward(&mut path, input, direction);
                    assert_eq!(output.len(), 1);
                    layout(input, &output[0], direction);
                    outputs.extend(output);
                }
                let joined = rejoin(&outputs, 40);
                assert_eq!(wire_checksum(&joined, if v4 { 20 } else { 40 }, 17), 0);
                let whole = datagram(v4, direction, 1320);
                let output = forward(&mut path, &whole, direction);
                assert_eq!(output.len(), 1);
                assert_eq!(output[0].len(), whole.len());
                assert_eq!(
                    &output[0][..if v4 { 10 } else { 8 }],
                    &whole[..if v4 { 10 } else { 8 }]
                );
                assert_eq!(wire_checksum(&output[0], if v4 { 20 } else { 40 }, 17), 0);
                drop(capture);
            }
        }
    }
}

#[test]
fn transit_ipv4_delivery_preserves_offset_mf_options() {
    for direction in [Direction::Outbound, Direction::Inbound] {
        let (old, _capture, attempt, budget) = path();
        let mut config = old.config();
        config.mtu = 576;
        config.assigned.ipv6 = None;
        drop(old);
        let mut path =
            TargetPacketPath::new(config, attempt.capability(), Arc::new(budget)).unwrap();
        let mut original = datagram(true, direction, 4800);
        original.splice(20..20, [7, 7, 4, 0, 0, 0, 0, 1, 148, 4, 0, 0]);
        original[0] = 0x48;
        let length = original.len() as u16;
        original[2..4].copy_from_slice(&length.to_be_bytes());
        fix_checksums(&mut original, 32, 17);
        for inputs in [
            vec![original.clone()],
            source_fragments(&original, 1600, 40),
        ] {
            let mut all = Vec::new();
            for input in inputs {
                let output = forward(&mut path, &input, direction);
                assert_eq!(output.len(), 1);
                layout(&input, &output[0], direction);
                assert_eq!(&output[0][2..10], &input[2..10]);
                assert_eq!(&output[0][20..32], &input[20..32]);
                all.extend(output);
            }
            let joined = rejoin(&all, 40);
            assert_eq!(wire_checksum(&joined, 32, 17), 0);
            assert_eq!(&joined[40..], &original[40..]);
        }
    }
}

#[test]
fn transit_ipv6_oversize_preserves_received_layout() {
    for direction in [Direction::Outbound, Direction::Inbound] {
        for multicast in [false, true] {
            let (mut path, _capture, _attempt, _) = path();
            let mut whole = datagram(false, direction, 4800);
            if multicast {
                // Outbound is the direction admitting a multicast destination.
                if direction == Direction::Inbound {
                    continue;
                }
                whole[24..40]
                    .copy_from_slice(&"ff02::1".parse::<std::net::Ipv6Addr>().unwrap().octets());
                fix_checksums(&mut whole, 40, 17);
            }
            let mut inputs = vec![whole.clone(), source_fragments(&whole, 65528, 40).remove(0)];
            inputs.extend(source_fragments(&whole, 1600, 40));
            for input in inputs {
                let output = forward(&mut path, &input, direction);
                assert_eq!(output.len(), 1);
                assert_eq!(output[0].len(), input.len());
                assert_eq!(&output[0][..8], &input[..8]);
                assert_eq!(&output[0][40..46], &input[40..46]);
                if input[6] == 44 {
                    assert_eq!(&output[0][40..48], &input[40..48]);
                    layout(&input, &output[0], direction);
                } else {
                    assert_eq!(&output[0][48..], &input[48..]);
                    assert_eq!(wire_checksum(&output[0], 40, 17), 0);
                }
            }
        }
    }
}

#[test]
fn transit_real_errors_preserve_current_quotation() {
    for v4 in [true, false] {
        for direction in [Direction::Outbound, Direction::Inbound] {
            let (mut path, _capture, _attempt, _) = path();
            let (source, destination) = endpoints(v4, direction);
            let (quote_source, quote_destination) = if direction == Direction::Inbound {
                (address(ASSIGNED, v4), remote(v4))
            } else {
                (remote(v4), address(FIXED, v4))
            };
            let quote = large(v4, quote_source, quote_destination, true);
            let protocol = if v4 { 1 } else { 58 };
            let mut body = vec![
                if v4 { 3 } else { 2 },
                if v4 { 4 } else { 0 },
                0,
                0,
                0,
                0,
                5,
                0,
            ];
            body.extend_from_slice(&quote);
            let input = packet(source, destination, protocol, &body);
            let output = forward(&mut path, &input, direction);
            assert_eq!(output.len(), 1);
            assert_eq!(output[0].len(), input.len());
            let ip = if v4 { 20 } else { 40 };
            assert_eq!(&output[0][ip + 4..ip + 8], &input[ip + 4..ip + 8]);
            assert_eq!(&output[0][ip + 8 + ip + 8..], &quote[ip + 8..]);
            assert_eq!(wire_checksum(&output[0], ip, protocol), 0);
            assert_eq!(wire_checksum(&output[0][ip + 8..], ip, 17), 0);
            let quoted = Header::parse(&output[0][ip + 8..], ParseContext::Received).unwrap();
            assert_eq!(
                if direction == Direction::Inbound {
                    quoted.source
                } else {
                    quoted.destination
                },
                address(
                    if direction == Direction::Inbound {
                        FIXED
                    } else {
                        ASSIGNED
                    },
                    v4
                )
            );
        }
    }
    // A non-initial fragment with the maximum IPv4 header keeps its full layout.
    let (mut path, _capture, _attempt, _) = path();
    let tail = source_fragments(&datagram(true, Direction::Inbound, 2400), 800, 40).remove(1);
    let mut tail = tail;
    tail.splice(20..20, [1; 40]);
    tail[0] = 0x4f;
    let length = tail.len() as u16;
    tail[2..4].copy_from_slice(&length.to_be_bytes());
    tail[10..12].fill(0);
    let sum = oracle(&tail[..60]);
    tail[10..12].copy_from_slice(&sum.to_be_bytes());
    let output = forward(&mut path, &tail, Direction::Inbound);
    assert_eq!(output.len(), 1);
    layout(&tail, &output[0], Direction::Inbound);
    for v4 in [true, false] {
        for source in if v4 {
            vec!["0.0.0.0", "127.0.0.1", "239.1.1.1"]
        } else {
            vec!["::", "::1", "ff02::1"]
        } {
            let (mut path, _capture, _attempt, _) = super::path();
            let mut input = datagram(v4, Direction::Inbound, 2000);
            match source.parse::<IpAddr>().unwrap() {
                IpAddr::V4(address) => {
                    input[12..16].copy_from_slice(&address.octets());
                    input[6] = 0x40;
                }
                IpAddr::V6(address) => input[8..24].copy_from_slice(&address.octets()),
            }
            fix_checksums(&mut input, if v4 { 20 } else { 40 }, 17);
            let output = forward(&mut path, &input, Direction::Inbound);
            assert_eq!(output.len(), 1);
            assert_eq!(output[0].len(), input.len());
            assert_eq!(
                Header::parse(&output[0], ParseContext::Received)
                    .unwrap()
                    .source,
                source.parse::<IpAddr>().unwrap()
            );
            assert_eq!(wire_checksum(&output[0], if v4 { 20 } else { 40 }, 17), 0);
        }
    }
}

#[test]
fn transit_queued_fragments_keep_attempt_and_session() {
    for v4 in [true, false] {
        let (mut path, capture, attempt, budget) = path();
        let input = source_fragments(&datagram(v4, Direction::Outbound, 1600), 800, 40).remove(0);
        let mut queued = path.process(&input, Direction::Outbound).unwrap();
        let charged = budget.used();
        assert!(matches!(
            queued.write(|_| Err(io::ErrorKind::WouldBlock.into())),
            RelayWriteOutcome::Retry
        ));
        assert_eq!(budget.used(), charged);
        attempt.retire();
        let successor = capture.open_attempt(&budget).unwrap();
        successor.activate().unwrap();
        assert!(matches!(
            queued.write(|_| panic!("old attempt wrote")),
            RelayWriteOutcome::Stale
        ));
        drop(queued);
        let mut next = TargetPacketPath::new(
            path.config(),
            successor.capability(),
            Arc::new(budget.clone()),
        )
        .unwrap();
        let tail = source_fragments(&datagram(v4, Direction::Outbound, 1600), 800, 40).remove(1);
        assert_eq!(forward(&mut next, &tail, Direction::Outbound).len(), 1);
        let mut queued = next.process(&tail, Direction::Outbound).unwrap();
        capture.retire();
        let replacement = RelayCaptureOwner::new(
            RelayCaptureGeneration::fresh().unwrap(),
            "tun-new",
            44,
            FIXED,
            1280,
            &budget,
        )
        .unwrap();
        assert!(matches!(
            queued.write(|_| panic!("old session wrote")),
            RelayWriteOutcome::Stale
        ));
        drop((queued, next, path, successor, capture, attempt, replacement));
        assert_eq!(budget.used(), 0);
    }
}

#[test]
fn transit_short_first_has_no_tombstone() {
    for v4 in [true, false] {
        for direction in [Direction::Outbound, Direction::Inbound] {
            let (mut path, _capture, _attempt, _) = path();
            let (source, destination) = endpoints(v4, direction);
            let mut body = segment(6);
            body.extend_from_slice(&[0x65; 64]);
            let whole = packet(source, destination, 6, &body);
            let tiny = source_fragments(&whole, 8, 40).remove(0);
            if v4 {
                assert_eq!(forward(&mut path, &tiny, direction).len(), 1);
                assert_eq!(path.summary().refused(TranslationError::ShortHeader), 0);
            } else {
                assert!(matches!(
                    path.process(&tiny, direction),
                    Err(TranslationError::ShortHeader)
                ));
                assert_eq!(path.summary().refused(TranslationError::ShortHeader), 1);
            }
            let valid = source_fragments(&whole, 24, 40);
            assert_eq!(forward(&mut path, &valid[1], direction).len(), 1);
            assert_eq!(forward(&mut path, &valid[0], direction).len(), 1);
            let mut overflow = valid[1].clone();
            if v4 {
                overflow[6..8].copy_from_slice(&0x3fffu16.to_be_bytes());
                overflow[10..12].fill(0);
                let sum = oracle(&overflow[..20]);
                overflow[10..12].copy_from_slice(&sum.to_be_bytes());
            } else {
                overflow[42..44].copy_from_slice(&0xfff9u16.to_be_bytes());
            }
            assert_eq!(forward(&mut path, &overflow, direction).len(), 1);
            assert_eq!(forward(&mut path, &valid[0], direction).len(), 1);
        }
    }
}
