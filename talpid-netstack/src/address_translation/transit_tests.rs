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

fn datagram(v4: bool, direction: Direction, length: usize) -> Vec<u8> {
    let (source, destination) = endpoints(v4, direction);
    let mut body = segment(17);
    body.resize(length, 0x5a);
    body[4..6].copy_from_slice(&(length as u16).to_be_bytes());
    packet(source, destination, 17, &body)
}

fn forward(
    path: &mut TargetPacketPath,
    bytes: &[u8],
    direction: Direction,
    mtu: u16,
) -> Vec<Vec<u8>> {
    receive(packets(
        path.process(bytes, direction, mtu, Instant::now()).unwrap(),
    ))
}

fn layout(input: &[u8], output: &[u8], direction: Direction) {
    assert_eq!(input.len(), output.len());
    let v4 = input[0] >> 4 == 4;
    let header = Header::parse(output, ParseContext::Received).unwrap();
    assert_eq!(
        header.source,
        if direction == Direction::Outbound {
            address(ASSIGNED, v4)
        } else {
            remote(v4)
        }
    );
    assert_eq!(
        header.destination,
        if direction == Direction::Inbound {
            address(FIXED, v4)
        } else {
            remote(v4)
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
                    let output = forward(&mut path, &pieces[*index], direction, 1280);
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
                let output = forward(&mut path, input, direction, 1280);
                assert_eq!(output.len(), 1);
                layout(input, &output[0], direction);
            }
            assert_eq!(path.deadline(), None);
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
                    let output = forward(&mut path, &input, direction, 1280);
                    assert_eq!(output.len(), 1);
                    layout(&input, &output[0], direction);
                }
                assert_eq!(budget.used(), idle);
                assert_eq!(path.deadline(), None);
            }
            assert_eq!(path.summary().translated, 2206);
        }
    }
}

#[test]
fn transit_no_fragment_reservation_or_deadline() {
    let (mut path, capture, attempt, budget) = path();
    // Capture, attempt, mapper metadata and the only child: reserved feedback.
    assert_eq!(budget.used(), 64 * 1024 + 3 * BUFFER_OVERHEAD);
    let idle = budget.used();
    let fragments = source_fragments(&datagram(true, Direction::Outbound, 1600), 800, 40);
    for input in fragments.iter().cycle().take(70) {
        let emission = packets(
            path.process(input, Direction::Outbound, 1280, Instant::now())
                .unwrap(),
        );
        assert!(budget.used() > idle);
        drop(emission);
        assert_eq!(budget.used(), idle);
        assert_eq!(path.deadline(), None);
    }
    // Record the actual reservation boundary, so input-copy refusal cannot
    // masquerade as the full splitter-output preflight refusal.
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
    let quantum = (1280 - 20) / 8 * 8;
    let count = 6000usize.div_ceil(quantum);
    let metadata =
        count * std::mem::size_of::<talpid_types::relay_flow::RelayPacket>() + BUFFER_OVERHEAD;
    let output_peak = 6000 + count * (20 + BUFFER_OVERHEAD);
    let one_piece = 20 + quantum + BUFFER_OVERHEAD;
    assert!(one_piece < output_peak);
    let available = input_charge + metadata + one_piece;
    let all = budget.reserve(budget.limit() - idle - available).unwrap();
    let held = budget.used();
    recorded.requests.lock().unwrap().clear();
    assert!(matches!(
        path.process(&input, Direction::Outbound, 1280, Instant::now()),
        Err(TranslationError::Full)
    ));
    assert_eq!(
        *recorded.requests.lock().unwrap(),
        [(input_charge, true), (metadata, true), (output_peak, false)]
    );
    assert!(path.take_feedback().is_none());
    assert_eq!(
        budget.used(),
        held,
        "failed preflight refunds input and metadata"
    );
    drop(all);
    assert_eq!(budget.used(), idle);
    recorded.requests.lock().unwrap().clear();
    let emission = packets(
        path.process(&input, Direction::Outbound, 1280, Instant::now())
            .unwrap(),
    );
    assert_eq!(emission.len(), count);
    assert_eq!(budget.used(), idle + metadata + output_peak);
    assert_eq!(
        *recorded.requests.lock().unwrap(),
        [(input_charge, true), (metadata, true), (output_peak, true)]
    );
    drop(emission);
    assert_eq!(budget.used(), idle);
    assert_eq!(path.deadline(), None);
    drop((path, recorded, capture, attempt));
    assert_eq!(budget.used(), 0);
}

#[test]
fn transit_mtu_matrix_is_packet_local() {
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
                    let output = forward(&mut path, input, direction, mtu);
                    assert_eq!(output.len(), 1);
                    layout(input, &output[0], direction);
                    outputs.extend(output);
                }
                let joined = rejoin(&outputs, 40);
                assert_eq!(wire_checksum(&joined, if v4 { 20 } else { 40 }, 17), 0);
                let whole = datagram(v4, direction, 1320);
                let output = path
                    .process(&whole, direction, 1280, Instant::now())
                    .unwrap();
                let limit = if direction == Direction::Outbound {
                    mtu
                } else {
                    1280
                };
                if v4 || limit == 1380 {
                    assert!(
                        receive(packets(output))
                            .iter()
                            .all(|p| p.len() <= usize::from(limit))
                    );
                } else {
                    assert!(matches!(output, TranslationOutcome::FeedbackQueued(_)));
                }
                drop(capture);
            }
        }
    }
}

#[test]
fn transit_ipv4_resplit_preserves_offset_mf_options() {
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
                let base = usize::from(word(&input, 6) & 0x1fff) * 8;
                let output = forward(&mut path, &input, direction, 576);
                assert!(output.len() > 1);
                let mut offset = base;
                for (index, fragment) in output.iter().enumerate() {
                    let ip = usize::from(fragment[0] & 15) * 4;
                    assert!(fragment.len() <= 576);
                    assert_eq!(word(fragment, 4), word(&input, 4));
                    assert_eq!(
                        usize::from(word(fragment, 6) & 0x1fff) * 8,
                        offset,
                        "independent consumer fragment offset"
                    );
                    assert_eq!(
                        word(fragment, 6) & 0x2000 != 0,
                        index + 1 < output.len() || word(&input, 6) & 0x2000 != 0
                    );
                    assert_eq!(oracle(&fragment[..ip]), 0);
                    if offset == 0 {
                        assert_eq!(&fragment[20..ip], &original[20..32]);
                    } else {
                        assert_eq!(&fragment[20..ip], &[148, 4, 0, 0]);
                    }
                    if word(fragment, 6) & 0x2000 != 0 {
                        assert!((fragment.len() - ip).is_multiple_of(8));
                    }
                    offset += fragment.len() - ip;
                }
                assert_eq!(offset, base + input.len() - 32);
                all.extend(output);
            }
            let joined = rejoin(&all, 40);
            assert_eq!(wire_checksum(&joined, 32, 17), 0);
            assert_eq!(&joined[40..], &original[40..]);
        }
    }
}

#[test]
fn transit_ipv6_oversize_always_returns_ptb() {
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
                assert!(matches!(
                    path.process(&input, direction, 1280, Instant::now()),
                    Ok(TranslationOutcome::FeedbackQueued(_))
                ));
                let mut feedback = path.take_feedback().unwrap();
                assert!(matches!(
                    feedback.write(|bytes| {
                        assert_eq!(&bytes[40..42], &[2, 0]);
                        assert_eq!(&bytes[48..], &input[..bytes.len() - 48]);
                        assert_eq!(wire_checksum(bytes, 40, 58), 0);
                        Ok(bytes.len())
                    }),
                    RelayWriteOutcome::Written
                ));
            }
        }
    }
}

#[test]
fn transit_feedback_quotes_current_packet() {
    for v4 in [true, false] {
        for direction in [Direction::Outbound, Direction::Inbound] {
            let (mut path, _capture, _attempt, _) = path();
            let mut input = datagram(v4, direction, 2000);
            if v4 {
                input[6] = 0x40;
                fix_checksums(&mut input, 20, 17);
            }
            assert!(matches!(
                path.process(&input, direction, 1280, Instant::now()),
                Ok(TranslationOutcome::FeedbackQueued(_))
            ));
            let mut feedback = path.take_feedback().unwrap();
            assert_eq!(
                feedback.side(),
                if direction == Direction::Outbound {
                    FeedbackSide::App
                } else {
                    FeedbackSide::Target
                }
            );
            assert!(matches!(
                feedback.write(|bytes| {
                    let ip = if v4 { 20 } else { 40 };
                    let outer = Header::parse(bytes, ParseContext::Received).unwrap();
                    assert_eq!(
                        outer.destination,
                        Header::parse(&input, ParseContext::Received)
                            .unwrap()
                            .source
                    );
                    if v4 && direction == Direction::Outbound {
                        assert_eq!(outer.source, remote(true));
                        assert_ne!(outer.source, address(FIXED, true));
                    }
                    assert_eq!(&bytes[ip + 8..], &input[..bytes.len() - ip - 8]);
                    assert_eq!(wire_checksum(bytes, ip, if v4 { 1 } else { 58 }), 0);
                    Ok(bytes.len())
                }),
                RelayWriteOutcome::Written
            ));
        }
    }
    // Non-initial IPv4 DF=0 remains splittable at the minimum supported MTU.
    let (mut path, _capture, _attempt, _) = path();
    let tail = source_fragments(&datagram(true, Direction::Inbound, 2400), 800, 40).remove(1);
    // A 60-byte header leaves exactly one 8-byte quantum at MTU 68.
    let mut tail = tail;
    tail.splice(20..20, [1; 40]);
    tail[0] = 0x4f;
    let length = tail.len() as u16;
    tail[2..4].copy_from_slice(&length.to_be_bytes());
    tail[10..12].fill(0);
    let sum = oracle(&tail[..60]);
    tail[10..12].copy_from_slice(&sum.to_be_bytes());
    // At least one complete quantum fits, so this remains splittable.
    assert!(matches!(
        path.process(&tail, Direction::Inbound, 68, Instant::now()),
        Ok(TranslationOutcome::Packets(_))
    ));
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
            assert!(matches!(
                path.process(&input, Direction::Inbound, 1280, Instant::now()),
                Err(TranslationError::Suppressed)
            ));
            assert!(path.take_feedback().is_none());
        }
    }
}

#[test]
fn transit_queued_fragments_keep_attempt_and_session() {
    for v4 in [true, false] {
        let (mut path, capture, attempt, budget) = path();
        let input = source_fragments(&datagram(v4, Direction::Outbound, 1600), 800, 40).remove(0);
        let mut queued = packets(
            path.process(&input, Direction::Outbound, 1280, Instant::now())
                .unwrap(),
        )
        .pop()
        .unwrap();
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
        assert_eq!(
            forward(&mut next, &tail, Direction::Outbound, 1280).len(),
            1
        );
        let mut queued = packets(
            next.process(&tail, Direction::Outbound, 1280, Instant::now())
                .unwrap(),
        )
        .pop()
        .unwrap();
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
            assert!(matches!(
                path.process(&tiny, direction, 1280, Instant::now()),
                Err(TranslationError::ShortHeader)
            ));
            assert_eq!(path.summary().refused(TranslationError::ShortHeader), 1);
            let valid = source_fragments(&whole, 24, 40);
            assert_eq!(forward(&mut path, &valid[1], direction, 1280).len(), 1);
            assert_eq!(forward(&mut path, &valid[0], direction, 1280).len(), 1);
            let mut overflow = valid[1].clone();
            if v4 {
                overflow[6..8].copy_from_slice(&0x3fffu16.to_be_bytes());
                overflow[10..12].fill(0);
                let sum = oracle(&overflow[..20]);
                overflow[10..12].copy_from_slice(&sum.to_be_bytes());
            } else {
                overflow[42..44].copy_from_slice(&0xfff9u16.to_be_bytes());
            }
            assert!(matches!(
                path.process(&overflow, direction, 1280, Instant::now()),
                Err(TranslationError::Malformed)
            ));
            assert_eq!(forward(&mut path, &valid[0], direction, 1280).len(), 1);
            assert_eq!(path.deadline(), None);
        }
    }
}
