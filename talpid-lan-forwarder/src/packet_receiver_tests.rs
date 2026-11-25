use super::*;
use crate::{Flow, forwarder::tests::stock_udp_wire, packet::tests::flow};
use talpid_netstack::buffer_budget::BufferBudget;

fn isolated(name: &str) -> bool {
    let name = format!("packet_receiver::tests::{name}");
    if std::env::var("KRTEK_PACKET_CUSTODY_CHILD").as_deref() == Ok(name.as_str()) {
        let parent: u32 = std::env::var("KRTEK_PACKET_CUSTODY_PARENT")
            .unwrap()
            .parse()
            .unwrap();
        assert_ne!(std::process::id(), parent);
        return false;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", &name, "--nocapture", "--color", "never"])
        .env("KRTEK_PACKET_CUSTODY_CHILD", &name)
        .env(
            "KRTEK_PACKET_CUSTODY_PARENT",
            std::process::id().to_string(),
        )
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    println!("{stdout}{}", String::from_utf8_lossy(&output.stderr));
    assert!(
        output.status.success(),
        "isolated custody fixture failed: {name}"
    );
    assert!(stdout.contains("test result: ok. 1 passed; 0 failed; 0 ignored;"));
    true
}

fn setup(ipv6: bool) -> (Arc<BufferBudget>, PacketReceiver, ReceiveScope) {
    let buffers = Arc::new(BufferBudget::new(32 * 1024 * 1024));
    let receiver = PacketReceiver::new(buffers.clone(), 1280).unwrap();
    let flow = flow(ipv6, Transport::Udp);
    let scope =
        ReceiveScope::new(flow.source.ip(), flow.destination.ip(), buffers.as_ref()).unwrap();
    (buffers, receiver, scope)
}

fn originals(mut complete: CompletedDatagram) -> Vec<Vec<u8>> {
    let mut packets = vec![];
    while let Some(packet) = complete.pop_original().unwrap() {
        packets.push(packet.to_vec());
    }
    packets
}

#[test]
fn packet_custody_complete_datagram_keeps_every_original_byte() {
    if isolated("packet_custody_complete_datagram_keeps_every_original_byte") {
        return;
    }
    for ipv6 in [false, true] {
        let (_buffers, mut receiver, scope) = setup(ipv6);
        let wire = stock_udp_wire(flow(ipv6, Transport::Udp), b"client wire", 1280);
        let complete = receiver.ingest(&scope, &wire[0]).unwrap().unwrap();
        assert_eq!(complete.packet().unwrap().payload, b"client wire");
        assert_eq!(complete.packet().unwrap().flow, flow(ipv6, Transport::Udp));
        assert_eq!(originals(complete), wire);
        assert!(receiver.pending.is_empty());
    }
}

#[test]
fn packet_custody_interleaved_reverse_fragments_release_only_their_datagram() {
    if isolated("packet_custody_interleaved_reverse_fragments_release_only_their_datagram") {
        return;
    }
    for ipv6 in [false, true] {
        let (_buffers, mut receiver, scope) = setup(ipv6);
        let a = vec![1; 4096];
        let b = vec![2; 4096];
        let mut wa = stock_udp_wire(flow(ipv6, Transport::Udp), &a, 1280);
        let mut wb = stock_udp_wire(flow(ipv6, Transport::Udp), &b, 1280);
        wa.reverse();
        wb.reverse();
        assert_eq!(wa.len(), wb.len());
        for index in 0..wa.len() - 1 {
            assert!(receiver.ingest(&scope, &wa[index]).unwrap().is_none());
            assert!(receiver.ingest(&scope, &wb[index]).unwrap().is_none());
        }
        let ca = receiver
            .ingest(&scope, wa.last().unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(ca.packet().unwrap().payload, a);
        assert_eq!(originals(ca), wa);
        let cb = receiver
            .ingest(&scope, wb.last().unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(cb.packet().unwrap().payload, b);
        assert_eq!(originals(cb), wb);
        assert!(receiver.pending.is_empty());
    }
}

#[test]
fn packet_custody_revocation_suppresses_completed_and_incomplete_release() {
    if isolated("packet_custody_revocation_suppresses_completed_and_incomplete_release") {
        return;
    }
    for ipv6 in [false, true] {
        let (_buffers, mut receiver, scope) = setup(ipv6);
        let wire = stock_udp_wire(flow(ipv6, Transport::Udp), &vec![3; 4096], 1280);
        assert!(receiver.ingest(&scope, &wire[0]).unwrap().is_none());
        assert_eq!(receiver.pending.len(), 1);
        scope.revoke();
        receiver.revalidate();
        assert!(receiver.pending.is_empty());
        assert!(matches!(
            receiver.ingest(&scope, &wire[1]),
            Err(IpError::Stale)
        ));
        let fresh = ReceiveScope::new(
            scope.source(),
            scope.destination(),
            receiver.buffers.as_ref(),
        )
        .unwrap();
        let small = stock_udp_wire(flow(ipv6, Transport::Udp), b"done", 1280);
        let mut complete = receiver.ingest(&fresh, &small[0]).unwrap().unwrap();
        fresh.revoke();
        assert!(!complete.current());
        assert!(matches!(complete.packet(), Err(IpError::Stale)));
        assert!(matches!(complete.pop_original(), Err(IpError::Stale)));
        let live = ReceiveScope::new(
            scope.source(),
            scope.destination(),
            receiver.buffers.as_ref(),
        )
        .unwrap();
        let mut completed_before_retirement = receiver.ingest(&live, &small[0]).unwrap().unwrap();
        drop(receiver);
        assert!(
            live.current(),
            "receiver retirement is independent of parent revocation"
        );
        assert!(!completed_before_retirement.current());
        assert!(matches!(
            completed_before_retirement.pop_original(),
            Err(IpError::Stale)
        ));
    }
}

#[test]
fn packet_custody_successor_scope_cannot_complete_predecessor_fragments() {
    if isolated("packet_custody_successor_scope_cannot_complete_predecessor_fragments") {
        return;
    }
    for ipv6 in [false, true] {
        let (buffers, mut receiver, scope) = setup(ipv6);
        let wire = stock_udp_wire(flow(ipv6, Transport::Udp), &vec![4; 4096], 1280);
        assert!(receiver.ingest(&scope, &wire[0]).unwrap().is_none());
        let successor =
            ReceiveScope::new(scope.source(), scope.destination(), buffers.as_ref()).unwrap();
        for packet in &wire[1..] {
            assert!(!matches!(receiver.ingest(&successor, packet), Ok(Some(_))));
        }
    }
}

#[test]
fn packet_custody_bad_checksum_or_wrong_parent_never_releases_packets() {
    if isolated("packet_custody_bad_checksum_or_wrong_parent_never_releases_packets") {
        return;
    }
    for ipv6 in [false, true] {
        let (_buffers, mut receiver, scope) = setup(ipv6);
        let mut wire = stock_udp_wire(flow(ipv6, Transport::Udp), b"bad", 1280).remove(0);
        *wire.last_mut().unwrap() ^= 1;
        assert!(matches!(
            receiver.ingest(&scope, &wire),
            Err(IpError::Checksum)
        ));
        assert!(receiver.pending.is_empty());
        let wrong = ReceiveScope::new(
            scope.destination(),
            scope.source(),
            receiver.buffers.as_ref(),
        )
        .unwrap();
        assert!(matches!(
            receiver.ingest(&wrong, &wire),
            Err(IpError::Stale)
        ));
    }
}

#[test]
fn packet_custody_byte_exhaustion_does_not_leave_unfunded_copies() {
    if isolated("packet_custody_byte_exhaustion_does_not_leave_unfunded_copies") {
        return;
    }
    let (buffers, mut receiver, scope) = setup(false);
    let wire = stock_udp_wire(flow(false, Transport::Udp), b"credit", 1280).remove(0);
    let before = buffers.used();
    let hold = buffers.reserve(buffers.limit() - before).unwrap();
    assert!(matches!(receiver.ingest(&scope, &wire), Err(IpError::Full)));
    assert!(receiver.pending.is_empty());
    drop(hold);
    assert_eq!(buffers.used(), before);
    let complete = receiver.ingest(&scope, &wire).unwrap().unwrap();
    assert_eq!(complete.packet().unwrap().payload, b"credit");
    drop(complete);
    assert_eq!(buffers.used(), before);
}

#[test]
fn packet_custody_protocol_sized_both_family_messages_keep_original_fragments() {
    if isolated("packet_custody_protocol_sized_both_family_messages_keep_original_fragments") {
        return;
    }
    for ipv6 in [false, true] {
        let (_buffers, mut receiver, scope) = setup(ipv6);
        let payload = vec![5; if ipv6 { 65487 } else { 65507 }];
        let mut wire = stock_udp_wire(flow(ipv6, Transport::Udp), &payload, 1280);
        wire.reverse();
        for packet in &wire[..wire.len() - 1] {
            assert!(receiver.ingest(&scope, packet).unwrap().is_none());
        }
        let complete = receiver
            .ingest(&scope, wire.last().unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(complete.packet().unwrap().payload, payload);
        assert_eq!(originals(complete), wire);
        assert!(receiver.pending.is_empty());
    }
}

#[tokio::test]
async fn packet_custody_idle_expiry_refunds_originals_without_new_ingress() {
    if isolated("packet_custody_idle_expiry_refunds_originals_without_new_ingress") {
        return;
    }
    let (buffers, mut receiver, scope) = setup(false);
    let before = buffers.used();
    let wire = stock_udp_wire(flow(false, Transport::Udp), &vec![6; 4096], 1280);
    assert!(receiver.ingest(&scope, &wire[0]).unwrap().is_none());
    assert!(buffers.used() > before);
    // The real native worker owns its unchanged stock IPv4 expiry countdown.
    // No synthetic clock advance, fresh fragment or authority event drives it.
    tokio::time::timeout(std::time::Duration::from_secs(24), async {
        while !receiver.pending.is_empty() {
            receiver.wait().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(buffers.used(), before);
}

#[test]
fn packet_custody_conflicting_overlap_can_never_release_an_alternate_message() {
    if isolated("packet_custody_conflicting_overlap_can_never_release_an_alternate_message") {
        return;
    }
    for ipv6 in [false, true] {
        let (_buffers, mut receiver, scope) = setup(ipv6);
        let wire = stock_udp_wire(flow(ipv6, Transport::Udp), &vec![7; 4096], 1280);
        assert!(receiver.ingest(&scope, &wire[0]).unwrap().is_none());
        let mut conflict = wire[0].clone();
        // Header/checksum are untouched. Only overlapping UDP body differs.
        *conflict.last_mut().unwrap() ^= 1;
        assert!(!matches!(receiver.ingest(&scope, &conflict), Ok(Some(_))));
        let mut terminal = Ok(None);
        for packet in &wire[1..] {
            terminal = receiver.ingest(&scope, packet);
            assert!(
                !matches!(terminal, Ok(Some(_))),
                "no alternate reconstruction may escape the classification boundary"
            );
        }
        if !ipv6 {
            assert!(
                matches!(terminal, Err(IpError::Malformed)),
                "IPv4 keeps the earlier assembly; the custody audit must reject the conflicting copy"
            );
        }
    }
}

fn completed(receiver: &mut PacketReceiver, scope: &ReceiveScope) -> CompletedDatagram {
    let flow = Flow {
        source: std::net::SocketAddr::new(scope.source(), 49152),
        destination: std::net::SocketAddr::new(scope.destination(), 53),
        transport: Transport::Udp,
    };
    receiver
        .ingest(scope, &stock_udp_wire(flow, b"question", 1280)[0])
        .unwrap()
        .unwrap()
}

#[test]
fn packet_custody_reply_native_maxima_reach_complete_consumer_with_original_tuple() {
    if isolated("packet_custody_reply_native_maxima_reach_complete_consumer_with_original_tuple") {
        return;
    }
    for (ipv6, mtu) in [(false, 68), (false, 1280), (true, 1280)] {
        let (buffers, mut receiver, scope) = setup(ipv6);
        receiver.set_mtu(mtu).unwrap();
        let input = completed(&mut receiver, &scope);
        let original = input.packet().unwrap().flow;
        let payload = vec![39; if ipv6 { 65487 } else { 65507 }];
        let mut output = receiver.reply(input, &payload, buffers.as_ref()).unwrap();
        let mut consumer = PacketReceiver::new(buffers.clone(), mtu).unwrap();
        let reverse =
            ReceiveScope::new(scope.destination(), scope.source(), buffers.as_ref()).unwrap();
        let mut delivered = None;
        let mut count = 0;
        while output.has_output() {
            assert!(
                output
                    .write_output(mtu, |bytes| {
                        assert!(bytes.len() <= usize::from(mtu));
                        count += 1;
                        if let Some(complete) = consumer.ingest(&reverse, bytes).unwrap() {
                            assert!(delivered.is_none());
                            let parsed = complete.packet().unwrap();
                            assert_eq!(parsed.flow.source, original.destination);
                            assert_eq!(parsed.flow.destination, original.source);
                            assert_eq!(parsed.payload, payload);
                            delivered = Some(complete);
                        }
                        Ok(bytes.len())
                    })
                    .unwrap()
            );
        }
        assert!(delivered.is_some());
        assert!(count > 1);
        if mtu == 68 {
            assert_eq!(count, 1365);
        }
        assert!(
            !output
                .write_output(mtu, |_| panic!("drained replay"))
                .unwrap()
        );
    }
}

#[test]
fn packet_custody_reply_retry_and_revocation_keep_exact_output_owner() {
    if isolated("packet_custody_reply_retry_and_revocation_keep_exact_output_owner") {
        return;
    }
    for retire_receiver in [false, true] {
        let (buffers, mut receiver, scope) = setup(false);
        let input = completed(&mut receiver, &scope);
        let mut output = receiver
            .reply(input, &[41; 4096], buffers.as_ref())
            .unwrap();
        let funded = buffers.used();
        let mut first = Vec::new();
        for _ in 0..2 {
            assert_eq!(
                output
                    .write_output(1280, |bytes| {
                        if first.is_empty() {
                            first = bytes.to_vec();
                        }
                        assert_eq!(bytes, first);
                        Err(io::ErrorKind::WouldBlock.into())
                    })
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::WouldBlock
            );
            assert_eq!(buffers.used(), funded);
        }
        assert!(
            output
                .write_output(1280, |bytes| {
                    assert_eq!(bytes, first);
                    Ok(bytes.len())
                })
                .unwrap()
        );
        if retire_receiver {
            drop(receiver);
        } else {
            scope.revoke();
        }
        assert!(
            !output
                .write_output(1280, |_| panic!("retired tail"))
                .unwrap()
        );
        assert!(!output.has_output());
        assert!(buffers.used() < funded);
    }
}

#[test]
fn packet_custody_reply_requires_same_receiver_and_live_input() {
    if isolated("packet_custody_reply_requires_same_receiver_and_live_input") {
        return;
    }
    let (buffers, mut receiver, scope) = setup(false);
    let mut successor = PacketReceiver::new(buffers.clone(), 1280).unwrap();
    let input = completed(&mut receiver, &scope);
    assert!(matches!(
        successor.reply(input, b"wrong owner", buffers.as_ref()),
        Err(IpError::Stale)
    ));
    let input = completed(&mut receiver, &scope);
    scope.revoke();
    assert!(matches!(
        receiver.reply(input, b"retired", buffers.as_ref()),
        Err(IpError::Stale)
    ));
}

#[test]
fn packet_custody_reply_funding_preserves_tcp_peaks_and_refunds_on_drop() {
    if isolated("packet_custody_reply_funding_preserves_tcp_peaks_and_refunds_on_drop") {
        return;
    }
    let (buffers, mut receiver, scope) = setup(false);
    let needed =
        crate::ip_endpoint::capture::BATCH_RESERVATION + crate::forwarder::UDP_REPLY_HEADROOM;
    let replies = BufferBudget::new(needed - 1);
    let input = completed(&mut receiver, &scope);
    assert!(matches!(
        receiver.reply(input, b"unfunded", &replies),
        Err(IpError::Full)
    ));
    assert_eq!(replies.used(), 0);
    let replies = BufferBudget::new(needed);
    let input = completed(&mut receiver, &scope);
    let output = receiver.reply(input, b"funded", &replies).unwrap();
    let headroom = replies
        .reserve(crate::forwarder::UDP_REPLY_HEADROOM)
        .unwrap();
    assert_eq!(replies.used(), needed);
    drop(headroom);
    drop(output);
    assert_eq!(replies.used(), 0);
    assert!(buffers.used() < buffers.limit());
}

#[test]
fn packet_custody_reply_mtu_shrink_discards_obsolete_remainder_without_replay() {
    if isolated("packet_custody_reply_mtu_shrink_discards_obsolete_remainder_without_replay") {
        return;
    }
    for update_receiver in [false, true] {
        let (buffers, mut receiver, scope) = setup(false);
        let input = completed(&mut receiver, &scope);
        let mut output = receiver
            .reply(input, &[43; 4096], buffers.as_ref())
            .unwrap();
        assert!(output.write_output(1280, |bytes| Ok(bytes.len())).unwrap());
        let sink_mtu = if update_receiver {
            receiver.set_mtu(68).unwrap();
            1280
        } else {
            68
        };
        assert!(
            !output
                .write_output(sink_mtu, |_| panic!("oversized remainder"))
                .unwrap()
        );
        assert!(!output.has_output());
    }
    let (buffers, mut receiver, scope) = setup(false);
    let input = completed(&mut receiver, &scope);
    let mut output = receiver
        .reply(input, &[44; 1296], buffers.as_ref())
        .unwrap();
    assert!(output.write_output(1280, |bytes| Ok(bytes.len())).unwrap());
    receiver.set_mtu(68).unwrap();
    assert!(
        output
            .write_output(68, |bytes| {
                assert!(bytes.len() <= 68);
                Ok(bytes.len())
            })
            .unwrap()
    );
    assert!(!output.has_output());
}

#[test]
fn packet_custody_reply_oversized_and_partial_write_never_shorten_or_replay() {
    if isolated("packet_custody_reply_oversized_and_partial_write_never_shorten_or_replay") {
        return;
    }
    for ipv6 in [false, true] {
        let (buffers, mut receiver, scope) = setup(ipv6);
        let input = completed(&mut receiver, &scope);
        assert!(matches!(
            receiver.reply(
                input,
                &vec![0; if ipv6 { 65488 } else { 65508 }],
                buffers.as_ref()
            ),
            Err(IpError::Oversized)
        ));
        for fatal in [false, true] {
            let input = completed(&mut receiver, &scope);
            let mut output = receiver
                .reply(input, b"whole packet only", buffers.as_ref())
                .unwrap();
            assert!(
                output
                    .write_output(1280, |bytes| {
                        if fatal {
                            Err(io::ErrorKind::BrokenPipe.into())
                        } else {
                            Ok(bytes.len() - 1)
                        }
                    })
                    .is_err()
            );
            assert!(!output.has_output());
            assert!(
                !output
                    .write_output(1280, |_| panic!("fatal replay"))
                    .unwrap()
            );
        }
    }
}
