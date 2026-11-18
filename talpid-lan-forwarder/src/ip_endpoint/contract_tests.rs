use super::{contract::*, ffi};
use crate::{Flow, Transport};
use scripted::{Completion, ScriptedEngine, Step};
use std::mem::{align_of, offset_of, size_of};

const SCOPE: ReceiveScopeId = ReceiveScopeId(11);

fn flow(ipv6: bool) -> Flow {
    Flow {
        source: if ipv6 {
            "[fd00::2]:1234"
        } else {
            "192.0.2.2:1234"
        }
        .parse()
        .unwrap(),
        destination: if ipv6 {
            "[fd00::3]:18081"
        } else {
            "192.0.2.3:18081"
        }
        .parse()
        .unwrap(),
        transport: Transport::Udp,
    }
}

#[test]
fn stock_lwip_contract_ffi_layout() {
    assert_eq!(size_of::<ffi::Handle>(), 8);
    assert_eq!(offset_of!(ffi::Transport, scope), 0);
    assert_eq!(offset_of!(ffi::Transport, family), 8);
    assert_eq!(offset_of!(ffi::Transport, protocol), 9);
    assert_eq!(offset_of!(ffi::Transport, source), 10);
    assert_eq!(offset_of!(ffi::Transport, destination), 26);
    let (size, alignment) = if cfg!(target_arch = "x86") {
        (44, 4)
    } else {
        (48, 8)
    };
    assert_eq!(size_of::<ffi::Transport>(), size);
    assert_eq!(align_of::<ffi::Transport>(), alignment);
    assert_eq!(size_of::<ffi::Callbacks>(), 2 * size_of::<usize>());
    assert_eq!(align_of::<ffi::Callbacks>(), align_of::<usize>());
    assert_eq!(offset_of!(ffi::Callbacks, complete), 0);
    assert_eq!(offset_of!(ffi::Callbacks, output), size_of::<usize>());
    let callbacks = ffi::Callbacks {
        complete: None,
        output: None,
    };
    assert!(callbacks.complete.is_none() && callbacks.output.is_none());
}

#[test]
fn stock_lwip_contract_statuses_match_c_header() {
    let header = include_str!("../../native/krtek_lwip.h");
    assert!(header.lines().any(|line| line
        == format!(
            "#define KRTEK_LWIP_ABI_VERSION UINT32_C({})",
            ffi::ABI_VERSION
        )));
    for (name, value) in [
        ("OK", ffi::OK),
        ("PENDING", ffi::PENDING),
        ("FULL", ffi::FULL),
        ("MALFORMED", ffi::MALFORMED),
        ("UNSUPPORTED", ffi::UNSUPPORTED),
        ("OVERSIZED", ffi::OVERSIZED),
        ("STALE", ffi::STALE),
        ("INTERNAL", ffi::INTERNAL),
    ] {
        let expected = if value < 0 {
            format!("#define KRTEK_LWIP_{name} (-INT32_C({}))", -value)
        } else {
            format!("#define KRTEK_LWIP_{name} INT32_C({value})")
        };
        assert!(header.lines().any(|line| line == expected), "{expected}");
    }
    for (value, expected) in [
        (ffi::OK, Ok(Ingress::Consumed)),
        (ffi::PENDING, Ok(Ingress::Pending)),
        (ffi::FULL, Err(IpError::Full)),
        (ffi::MALFORMED, Err(IpError::Malformed)),
        (ffi::UNSUPPORTED, Err(IpError::Unsupported)),
        (ffi::OVERSIZED, Err(IpError::Oversized)),
        (ffi::STALE, Err(IpError::Stale)),
        (ffi::INTERNAL, Err(IpError::Internal)),
        (2, Err(IpError::Internal)),
        (i32::MIN, Err(IpError::Internal)),
    ] {
        assert_eq!(IpError::from_status(value), expected);
    }
    assert_ne!(IpError::Checksum, IpError::Malformed);
}

#[test]
fn stock_lwip_contract_reply_is_explicitly_reversed_once() {
    for ipv6 in [false, true] {
        let original = flow(ipv6);
        let tuple = ReplyTuple::from_flow(SCOPE, original).unwrap();
        assert_eq!(tuple.scope, SCOPE);
        assert_eq!(tuple.source, original.destination);
        assert_eq!(tuple.destination, original.source);
        let maximum = if ipv6 { 65_487 } else { 65_507 };
        for length in [0, 4096, maximum] {
            assert_eq!(tuple.check_payload_len(length), Ok(()));
        }
        for length in [maximum + 1, usize::MAX] {
            assert_eq!(tuple.check_payload_len(length), Err(IpError::Oversized));
        }
    }
    let mut original = flow(false);
    original.transport = Transport::Tcp;
    assert_eq!(
        ReplyTuple::from_flow(SCOPE, original),
        Err(IpError::Unsupported)
    );
    original.transport = Transport::Udp;
    original.destination = flow(true).destination;
    assert_eq!(
        ReplyTuple::from_flow(SCOPE, original),
        Err(IpError::Malformed)
    );
    let mixed = ReplyTuple {
        scope: SCOPE,
        source: original.source,
        destination: original.destination,
    };
    assert_eq!(mixed.check_payload_len(0), Err(IpError::Malformed));
}

#[test]
fn stock_lwip_contract_script_pending_then_complete_borrow() {
    let original = flow(false);
    let segment = vec![0, 1, 0, 2, 0, 8, 0, 0];
    let mut engine = ScriptedEngine::new([
        Step::Ingest {
            scope: SCOPE,
            ip: vec![1],
            completions: vec![],
            result: Ok(Ingress::Pending),
        },
        Step::Ingest {
            scope: SCOPE,
            ip: vec![2],
            completions: vec![Completion {
                scope: SCOPE,
                source: original.source.ip(),
                destination: original.destination.ip(),
                protocol: Transport::Udp,
                segment: segment.clone(),
            }],
            result: Ok(Ingress::Consumed),
        },
    ]);
    // Object safety keeps fixtures and the real wrapper on the same interface.
    let interface: &mut dyn LocalIpEngine = &mut engine;
    assert_eq!(
        interface.ingest(SCOPE, &[1], &mut |_| panic!("premature completion")),
        Ok(Ingress::Pending)
    );
    let mut copies = Vec::new();
    assert_eq!(
        interface.ingest(SCOPE, &[2], &mut |complete| {
            assert_eq!(complete.scope, SCOPE);
            assert_eq!(complete.source, original.source.ip());
            assert_eq!(complete.destination, original.destination.ip());
            assert_eq!(complete.protocol, Transport::Udp);
            copies.push(complete.segment.to_vec());
        }),
        Ok(Ingress::Consumed)
    );
    assert_eq!(copies, [segment]);
    engine.assert_finished();
}

#[test]
fn stock_lwip_contract_script_output_capture_failure_is_independent() {
    let tuple = ReplyTuple::from_flow(SCOPE, flow(true)).unwrap();
    let mut engine = ScriptedEngine::new([Step::Reply {
        tuple,
        payload: vec![],
        packets: vec![vec![1, 2], vec![3, 4]],
        result: Ok(()),
    }]);
    let mut seen = 0;
    let mut capture_error = None;
    assert_eq!(
        engine.reply(tuple, &[], &mut |_| {
            seen += 1;
            capture_error = Some(IpError::Full);
        }),
        Ok(())
    );
    assert_eq!(seen, 2);
    assert_eq!(capture_error, Some(IpError::Full));
    engine.assert_finished();
}

#[test]
fn stock_lwip_contract_script_clock_mtu_and_retired_references() {
    let mut engine = ScriptedEngine::new([
        Step::SetMtu(68, Ok(())),
        Step::PollTime(MonotonicMillis(u32::MAX), Ok(())),
        Step::PollTime(MonotonicMillis(0), Ok(())),
        Step::Close,
    ]);
    engine.timeout_ms = Some(0);
    engine.references.push((SCOPE, 2));
    assert_eq!(engine.set_mtu(68), Ok(()));
    assert_eq!(engine.poll_time(MonotonicMillis(u32::MAX)), Ok(()));
    assert_eq!(engine.poll_time(MonotonicMillis(0)), Ok(()));
    assert_eq!(engine.next_timeout_ms(), Some(0));
    engine.timeout_ms = None;
    assert_eq!(engine.next_timeout_ms(), None);
    engine.close();
    engine.close();
    assert_eq!(engine.scope_refs(SCOPE), 2);
    assert_eq!(engine.scope_refs(ReceiveScopeId(12)), 0);
    assert_eq!(
        engine.ingest(SCOPE, &[], &mut |_| panic!("retired callback")),
        Err(IpError::Stale)
    );
    assert_eq!(engine.set_mtu(1280), Err(IpError::Stale));
    assert_eq!(engine.poll_time(MonotonicMillis(1)), Err(IpError::Stale));
    assert_eq!(
        engine.reply(
            ReplyTuple::from_flow(SCOPE, flow(false)).unwrap(),
            &[],
            &mut |_| panic!("retired output")
        ),
        Err(IpError::Stale)
    );
    engine.references.clear();
    assert_eq!(engine.scope_refs(SCOPE), 0);
    engine.assert_finished();
}
