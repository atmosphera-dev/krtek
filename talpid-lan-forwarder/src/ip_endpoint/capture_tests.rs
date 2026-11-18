use super::{
    capture::*,
    contract::{scripted::*, *},
};
use crate::{
    Transport,
    packet::{
        self, TcpFlags,
        tests::{flow, tcp_packet, udp_packet},
    },
};
use talpid_netstack::buffer_budget::BufferBudget;
use talpid_types::relay_flow::RelayBufferAllocator;

const SCOPE: ReceiveScopeId = ReceiveScopeId(91);

#[test]
fn stock_lwip_batch_funds_1365_packets_as_one_job() {
    let budget = BufferBudget::new(BATCH_RESERVATION);
    let tuple = ReplyTuple::from_flow(SCOPE, flow(false, Transport::Udp)).unwrap();
    // Callback capture mechanics only, NOT an IP fragmentation wire oracle.
    let packets: Vec<Vec<u8>> = (0..1365)
        .map(|n| vec![n as u8; if n == 1364 { 63 } else { 68 }])
        .collect();
    let mut engine = ScriptedEngine::new([Step::Reply {
        tuple,
        payload: vec![0x5a; 65507],
        packets: packets.clone(),
        result: Ok(()),
    }]);
    let mut batch = PacketBatch::reserve(&budget, 68)
        .unwrap()
        .generate(&mut engine, tuple, &vec![0x5a; 65507])
        .unwrap();
    assert_eq!(budget.used(), BATCH_RESERVATION);
    assert!(PacketBatch::reserve(&budget, 68).is_err());
    for (n, packet) in packets.iter().enumerate() {
        assert_eq!(batch.packet(), packet);
        // Merely inspecting/retrying the current packet never advances it.
        assert_eq!(batch.packet(), packet);
        assert_eq!(batch.advance(), n + 1 < packets.len());
    }
    engine.assert_finished();
    drop(batch);
    assert_eq!(budget.used(), 0);
}

#[test]
fn stock_lwip_batch_capture_failure_overrides_native_success() {
    for packets in [vec![], vec![vec![0; 69]], vec![vec![0; 68]; 1366]] {
        let budget = BufferBudget::new(BATCH_RESERVATION);
        let tuple = ReplyTuple::from_flow(SCOPE, flow(false, Transport::Udp)).unwrap();
        let mut engine = ScriptedEngine::new([Step::Reply {
            tuple,
            payload: vec![],
            packets,
            result: Ok(()),
        }]);
        assert!(
            PacketBatch::reserve(&budget, 68)
                .unwrap()
                .generate(&mut engine, tuple, &[])
                .is_err()
        );
        engine.assert_finished();
        assert_eq!(budget.used(), 0);
    }
}

#[test]
fn stock_lwip_batch_mtu_checks_every_unsent_packet() {
    let budget = BufferBudget::new(BATCH_RESERVATION);
    let tuple = ReplyTuple::from_flow(SCOPE, flow(false, Transport::Udp)).unwrap();
    let mut engine = ScriptedEngine::new([Step::Reply {
        tuple,
        payload: vec![],
        packets: vec![vec![1; 68], vec![2; 100], vec![3; 68]],
        result: Ok(()),
    }]);
    let mut batch = PacketBatch::reserve(&budget, 1280)
        .unwrap()
        .generate(&mut engine, tuple, &[])
        .unwrap();
    assert!(
        !batch.fits(68),
        "a small current packet cannot hide an obsolete tail"
    );
    assert!(batch.fits(1280));
    assert!(batch.advance());
    assert!(!batch.fits(68));
    assert!(batch.advance());
    assert!(batch.fits(68));
    engine.assert_finished();
}

#[test]
fn stock_lwip_complete_capture_validates_both_families_before_admission() {
    for ipv6 in [false, true] {
        for protocol in [Transport::Udp, Transport::Tcp] {
            let flow = flow(ipv6, protocol);
            let ip = if protocol == Transport::Udp {
                udp_packet(flow, b"complete outcome")
            } else {
                tcp_packet(
                    flow,
                    TcpFlags {
                        syn: true,
                        ..TcpFlags::default()
                    },
                    b"complete outcome",
                )
            };
            let segment = ip[if ipv6 { 40 } else { 20 }..].to_vec();
            let budget = BufferBudget::new(200000);
            let mut engine = ScriptedEngine::new([Step::Ingest {
                scope: SCOPE,
                ip: ip.clone(),
                completions: vec![Completion {
                    scope: SCOPE,
                    source: flow.source.ip(),
                    destination: flow.destination.ip(),
                    protocol,
                    segment,
                }],
                result: Ok(Ingress::Consumed),
            }]);
            let complete = ingest(&mut engine, SCOPE, &ip, &budget).unwrap().unwrap();
            assert_eq!(complete.scope, SCOPE);
            assert_eq!(complete.validated().unwrap(), packet::parse(&ip).unwrap());
            if protocol == Transport::Tcp {
                let normalized = complete.tcp_packet(&budget).unwrap();
                assert_eq!(
                    packet::parse(&normalized).unwrap(),
                    packet::parse(&ip).unwrap()
                );
            }
            engine.assert_finished();
            drop(complete);
            assert_eq!(budget.used(), 0);
        }
    }
}

#[test]
fn stock_lwip_complete_capture_preserves_checksum_refusal_and_credit() {
    for ipv6 in [false, true] {
        let flow = flow(ipv6, Transport::Udp);
        let ip = udp_packet(flow, b"corrupt complete");
        let mut segment = ip[if ipv6 { 40 } else { 20 }..].to_vec();
        *segment.last_mut().unwrap() ^= 1;
        let budget = BufferBudget::new(100000);
        let mut engine = ScriptedEngine::new([Step::Ingest {
            scope: SCOPE,
            ip: vec![],
            completions: vec![Completion {
                scope: SCOPE,
                source: flow.source.ip(),
                destination: flow.destination.ip(),
                protocol: Transport::Udp,
                segment,
            }],
            result: Ok(Ingress::Consumed),
        }]);
        let complete = ingest(&mut engine, SCOPE, &[], &budget).unwrap().unwrap();
        assert_eq!(complete.validated(), Err(IpError::Checksum));
        drop(complete);
        assert_eq!(budget.used(), 0);
        engine.assert_finished();
    }
}

#[test]
fn stock_lwip_complete_capture_refuses_wrong_scope_or_unfunded_copy() {
    for wrong_scope in [false, true] {
        let flow = flow(false, Transport::Udp);
        let budget = BufferBudget::new(100000);
        let all_credit = budget.try_reserve(100000).unwrap();
        let mut engine = ScriptedEngine::new([Step::Ingest {
            scope: SCOPE,
            ip: vec![],
            completions: vec![Completion {
                scope: if wrong_scope {
                    ReceiveScopeId(92)
                } else {
                    SCOPE
                },
                source: flow.source.ip(),
                destination: flow.destination.ip(),
                protocol: Transport::Udp,
                segment: vec![0; 8],
            }],
            result: Ok(Ingress::Consumed),
        }]);
        assert!(
            matches!(ingest(&mut engine, SCOPE, &[], &budget), Err(error)
            if error == if wrong_scope {IpError::Malformed} else {IpError::Full})
        );
        engine.assert_finished();
        drop(all_credit);
        assert_eq!(budget.used(), 0);
    }
}
