//! C4 independent wire inputs and end-consumer assertions. The production core's
//! clock is never changed here; synthetic stock timers live in the C driver.
use super::*;
use crate::ip_endpoint::{capture, contract::*, native::Engine};
use talpid_netstack::buffer_budget::BufferBudget;

fn patterned(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i * 31 + i / 32) as u8).collect()
}

fn isolated_reassembly(name: &str) -> bool {
    // Logical handles share stock entry/pbuf limits. Independent success cases
    // must not evict one another under the test runner's parallel scheduling.
    // Pressure and simultaneous-handle scenarios still share one core INSIDE
    // each fixture; only unrelated fixtures get separate processes.
    isolated_native_budget(&format!("stock_lwip_tests::{name}"))
}

#[test]
fn stock_lwip_reassembly_fixture_process_isolation_preserves_other_handles() {
    if isolated_reassembly(
        "stock_lwip_reassembly_fixture_process_isolation_preserves_other_handles",
    ) {
        return;
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let (mut forwarder, peer, flow, payload, pieces, scope) = runtime.block_on(async {
        let peer = UdpSocket::bind(loopback(false)).await.unwrap();
        let flow = target(peer.local_addr().unwrap(), Transport::Udp);
        let authority = Arc::new(Authority::default());
        let mut forwarder = Forwarder::with_mtu(
            authority.clone(),
            Arc::new(BufferBudget::new(128 * 1024 * 1024)),
            68,
        )
        .unwrap();
        let payload = patterned(65507);
        let pieces = stock_udp_wire(flow, &payload, 68);
        assert_eq!(pieces.len(), 1365);
        for piece in &pieces[..1024] {
            forwarder.ingest(piece);
        }
        no_admission(&mut forwarder, &authority, &peer);
        let scope = authority.receive.lock().unwrap()[0].upgrade().unwrap();
        assert_eq!(
            forwarder
                .native
                .as_ref()
                .unwrap()
                .scope_refs(ReceiveScopeId(scope.id())),
            1024
        );
        (forwarder, peer, flow, payload, pieces, scope)
    });

    // A no-pressure success fixture must not consume another test's shared
    // reassembly capacity. Without process isolation, its 1365-piece case
    // crosses the 2048-pbuf ceiling and stock lwIP evicts this older assembly.
    stock_lwip_full_consumer_size_mtu_order_matrix();
    assert_eq!(
        forwarder
            .native
            .as_ref()
            .unwrap()
            .scope_refs(ReceiveScopeId(scope.id())),
        1024,
        "an independent fixture must not evict this handle's retained fragments"
    );
    runtime.block_on(async {
        for piece in &pieces[1024..] {
            forwarder.ingest(piece);
        }
        echo_exact(&mut forwarder, &peer, flow, &payload, 68).await;
        forwarder.close_all().await;
    });
}

fn no_admission(forwarder: &mut Forwarder<Authority>, authority: &Authority, peer: &UdpSocket) {
    forwarder.process();
    assert_eq!(authority.authorizations.load(Ordering::SeqCst), 0);
    assert_eq!(authority.preparations.load(Ordering::SeqCst), 0);
    assert!(forwarder.pending.is_empty());
    assert!(forwarder.udp.is_empty());
    assert!(forwarder.tcp.is_empty());
    assert!(!forwarder.has_output());
    assert_eq!(
        peer.try_recv(&mut [0; 65536]).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
}

async fn receive_exact(
    forwarder: &mut Forwarder<Authority>,
    peer: &UdpSocket,
    payload: &[u8],
) -> std::net::SocketAddr {
    until(forwarder, settled).await;
    let mut buffer = vec![0; 65536];
    let (n, source) = tokio::time::timeout(Duration::from_secs(2), peer.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        &buffer[..n],
        payload,
        "one complete datagram at the real peer"
    );
    assert_eq!(
        peer.try_recv(&mut buffer).unwrap_err().kind(),
        io::ErrorKind::WouldBlock,
        "no duplicate physical request"
    );
    source
}

async fn echo_exact(
    forwarder: &mut Forwarder<Authority>,
    peer: &UdpSocket,
    flow: Flow,
    payload: &[u8],
    mtu: usize,
) {
    let source = receive_exact(forwarder, peer, payload).await;
    assert_eq!(peer.send_to(payload, source).await.unwrap(), payload.len());
    until(forwarder, Forwarder::has_output).await;
    assert_eq!(
        forwarder.output.len(),
        1,
        "one byte-funded job, not one per fragment"
    );
    let count = if payload.len() + if flow.source.is_ipv6() { 48 } else { 28 } <= mtu {
        1
    } else {
        (payload.len() + 8).div_ceil((mtu - if flow.source.is_ipv6() { 48 } else { 20 }) & !7)
    };
    let mut packets = Vec::new();
    while forwarder.has_output() {
        if [0, count / 2, count - 1].contains(&packets.len()) {
            let mut retained = None;
            for _ in 0..2 {
                assert_eq!(
                    forwarder
                        .write_output(|bytes| {
                            if let Some(previous) = &retained {
                                assert_eq!(previous, bytes);
                            }
                            retained = Some(bytes.to_vec());
                            Err(io::ErrorKind::WouldBlock.into())
                        })
                        .unwrap_err()
                        .kind(),
                    io::ErrorKind::WouldBlock
                );
            }
        }
        assert!(
            forwarder
                .write_output(|bytes| {
                    packets.push(bytes.to_vec());
                    Ok(bytes.len())
                })
                .unwrap()
        );
    }
    assert_eq!(packets.len(), count);
    stock_audit_udp(
        Flow {
            source: flow.destination,
            destination: flow.source,
            transport: Transport::Udp,
        },
        payload,
        mtu,
        &packets,
    );
    assert_eq!(forwarder.stats().oversized_reply, 0);
}

#[tokio::test]
async fn stock_lwip_full_consumer_size_mtu_order_matrix() {
    if isolated_reassembly("stock_lwip_full_consumer_size_mtu_order_matrix") {
        return;
    }
    let mut cases = 0;
    for ipv6 in [false, true] {
        let maximum = if ipv6 { 65487 } else { 65507 };
        for mtu in if ipv6 {
            vec![1280, 65535]
        } else {
            vec![68, 1280, 65535]
        } {
            let fit = mtu - if ipv6 { 48 } else { 28 };
            let mut sizes = vec![
                0,
                1,
                31,
                fit.min(maximum),
                (fit + 1).min(maximum),
                4096,
                4097,
                maximum,
            ];
            sizes.sort_unstable();
            sizes.dedup();
            for size in sizes {
                let peer = UdpSocket::bind(loopback(ipv6)).await.unwrap();
                let flow = target(peer.local_addr().unwrap(), Transport::Udp);
                let authority = Arc::new(Authority::default());
                let mut forwarder = Forwarder::with_mtu(
                    authority.clone(),
                    Arc::new(BufferBudget::new(128 * 1024 * 1024)),
                    mtu,
                )
                .unwrap();
                let payload = patterned(size);
                let pieces = stock_udp_wire(flow, &payload, mtu);
                let mut order: Vec<usize> = (0..pieces.len()).collect();
                match cases % 3 {
                    0 => {}
                    1 => order.reverse(),
                    _ => order.rotate_right(1),
                }
                for (n, index) in order.iter().enumerate() {
                    forwarder.ingest(&pieces[*index]);
                    if n + 1 != pieces.len() {
                        no_admission(&mut forwarder, &authority, &peer);
                    }
                }
                echo_exact(&mut forwarder, &peer, flow, &payload, mtu).await;
                assert_eq!(authority.preparations.load(Ordering::SeqCst), 1);
                println!(
                    "stock-lwip C4 full consumer family={} size={size} mtu={mtu} pieces={}",
                    if ipv6 { 6 } else { 4 },
                    pieces.len()
                );
                forwarder.close_all().await;
                cases += 1;
            }
        }
    }
    assert_eq!(cases, 36);
}

#[tokio::test]
async fn stock_lwip_holes_and_interleaved_ids_do_not_authorize_early() {
    if isolated_reassembly("stock_lwip_holes_and_interleaved_ids_do_not_authorize_early") {
        return;
    }
    for ipv6 in [false, true] {
        for missing in [0, 1, 3] {
            let peer = UdpSocket::bind(loopback(ipv6)).await.unwrap();
            let flow = target(peer.local_addr().unwrap(), Transport::Udp);
            let authority = Arc::new(Authority::default());
            let mut forwarder = test_forwarder(authority.clone());
            let first = patterned(4096);
            let second: Vec<_> = first.iter().map(|byte| byte ^ 0x55).collect();
            let a = stock_udp_wire(flow, &first, 1280);
            let b = stock_udp_wire(flow, &second, 1280);
            assert_eq!(a.len(), 4);
            assert_eq!(b.len(), 4);
            for i in (0..4).rev().filter(|i| *i != missing) {
                forwarder.ingest(&a[i]);
                forwarder.ingest(&b[i]);
                no_admission(&mut forwarder, &authority, &peer);
            }
            forwarder.ingest(&a[missing]);
            receive_exact(&mut forwarder, &peer, &first).await;
            forwarder.ingest(&b[missing]);
            receive_exact(&mut forwarder, &peer, &second).await;
            assert_eq!(
                authority.preparations.load(Ordering::SeqCst),
                1,
                "same complete flow reuses one socket"
            );
            forwarder.close_all().await;
        }
    }
}

#[tokio::test]
async fn stock_lwip_altered_duplicates_keep_first_bytes_not_whole_assembly_rejection() {
    if isolated_reassembly(
        "stock_lwip_altered_duplicates_keep_first_bytes_not_whole_assembly_rejection",
    ) {
        return;
    }
    for ipv6 in [false, true] {
        let peer = UdpSocket::bind(loopback(ipv6)).await.unwrap();
        let flow = target(peer.local_addr().unwrap(), Transport::Udp);
        let authority = Arc::new(Authority::default());
        let mut forwarder = test_forwarder(authority.clone());
        let payload = patterned(4097);
        let pieces = stock_udp_wire(flow, &payload, 1280);
        forwarder.ingest(&pieces[0]);
        forwarder.ingest(&pieces[0]);
        let mut altered = pieces[0].clone();
        *altered.last_mut().unwrap() ^= 0x80;
        forwarder.ingest(&altered);
        no_admission(&mut forwarder, &authority, &peer);
        for piece in &pieces[1..] {
            forwarder.ingest(piece);
        }
        echo_exact(&mut forwarder, &peer, flow, &payload, 1280).await;
        forwarder.close_all().await;
    }
}

#[tokio::test]
async fn stock_lwip_completed_corrupt_udp_tcp_and_ipv6_zero_checksum_never_authorize() {
    if isolated_reassembly(
        "stock_lwip_completed_corrupt_udp_tcp_and_ipv6_zero_checksum_never_authorize",
    ) {
        return;
    }
    for ipv6 in [false, true] {
        for protocol in [Transport::Udp, Transport::Tcp] {
            let peer = UdpSocket::bind(loopback(ipv6)).await.unwrap();
            let flow = target(peer.local_addr().unwrap(), protocol);
            let authority = Arc::new(Authority::default());
            let mut forwarder = test_forwarder(authority.clone());
            if protocol == Transport::Udp {
                let mut pieces = stock_udp_wire(flow, &patterned(4097), 1280);
                *pieces.last_mut().unwrap().last_mut().unwrap() ^= 1;
                for piece in pieces.iter().rev() {
                    forwarder.ingest(piece);
                }
                if ipv6 {
                    let mut zero = stock_udp_wire(flow, b"zero checksum", 1280).remove(0);
                    zero[46..48].fill(0);
                    forwarder.ingest(&zero);
                }
            } else {
                let mut ip = syn(flow);
                *ip.last_mut().unwrap() ^= 1;
                forwarder.ingest(&ip);
            }
            no_admission(&mut forwarder, &authority, &peer);
            assert_eq!(
                forwarder.stats().bad_checksum,
                if ipv6 && protocol == Transport::Udp {
                    2
                } else {
                    1
                }
            );
            forwarder.close_all().await;
        }
    }
}

#[tokio::test]
async fn stock_lwip_conflicting_terminal_lengths_cannot_authorize_a_shortened_udp() {
    if isolated_reassembly(
        "stock_lwip_conflicting_terminal_lengths_cannot_authorize_a_shortened_udp",
    ) {
        return;
    }
    for ipv6 in [false, true] {
        let peer = UdpSocket::bind(loopback(ipv6)).await.unwrap();
        let flow = target(peer.local_addr().unwrap(), Transport::Udp);
        let authority = Arc::new(Authority::default());
        let mut forwarder = test_forwarder(authority.clone());
        let pieces = stock_udp_wire(flow, &patterned(4096), 1280);
        let mut short = pieces.last().unwrap().clone();
        short.truncate(short.len() - 8);
        let length = short.len();
        if ipv6 {
            short[4..6].copy_from_slice(&((length - 40) as u16).to_be_bytes());
        } else {
            short[2..4].copy_from_slice(&(length as u16).to_be_bytes());
            short[10..12].fill(0);
            let check = stock_checksum(&short[..20]);
            short[10..12].copy_from_slice(&check.to_be_bytes());
        }
        // Stock retains the first accepted terminal and discards the same-start
        // longer duplicate. Complete UDP length validation must still refuse it.
        forwarder.ingest(&short);
        forwarder.ingest(pieces.last().unwrap());
        no_admission(&mut forwarder, &authority, &peer);
        for piece in &pieces[..pieces.len() - 1] {
            forwarder.ingest(piece);
        }
        no_admission(&mut forwarder, &authority, &peer);
        assert_eq!(forwarder.stats().malformed, 1);
        forwarder.close_all().await;
    }
}

#[tokio::test]
async fn stock_lwip_real_reply_limit_and_next_valid_reply_use_the_same_socket() {
    let peer = UdpSocket::bind(loopback(true)).await.unwrap();
    let flow = target(peer.local_addr().unwrap(), Transport::Udp);
    let mut forwarder = test_forwarder(Arc::new(Authority::default()));
    forwarder.ingest(&stock_udp_wire(flow, b"reply limit", 1280)[0]);
    let client = receive_exact(&mut forwarder, &peer, b"reply limit").await;
    peer.send_to(&patterned(65488), client).await.unwrap();
    forwarder.udp[&flow].physical.readable().await.unwrap();
    forwarder.process();
    assert!(
        !forwarder.has_output(),
        "no shortened prefix or fragment escapes"
    );
    assert_eq!(forwarder.stats().oversized_reply, 1);
    let body = patterned(4096);
    peer.send_to(&body, client).await.unwrap();
    until(&mut forwarder, Forwarder::has_output).await;
    let mut output = Vec::new();
    while let Some(bytes) = forwarder.next_output() {
        output.push(bytes);
    }
    stock_audit_udp(
        Flow {
            source: flow.destination,
            destination: flow.source,
            transport: Transport::Udp,
        },
        &body,
        1280,
        &output,
    );
    forwarder.close_all().await;
}

#[tokio::test]
async fn stock_lwip_scope_revoke_close_and_simultaneous_handles_never_transfer_old_pieces() {
    if isolated_reassembly(
        "stock_lwip_scope_revoke_close_and_simultaneous_handles_never_transfer_old_pieces",
    ) {
        return;
    }
    for ipv6 in [false, true] {
        for close in [false, true] {
            let peer = UdpSocket::bind(loopback(ipv6)).await.unwrap();
            let flow = target(peer.local_addr().unwrap(), Transport::Udp);
            let authority = Arc::new(Authority::default());
            let mut forwarder = test_forwarder(authority.clone());
            let payload = patterned(4096);
            let old = stock_udp_wire(flow, &payload, 1280);
            forwarder.ingest(&old[0]);
            no_admission(&mut forwarder, &authority, &peer);
            let old_scope = authority.receive.lock().unwrap()[0].upgrade().unwrap();
            if close {
                forwarder.close_all().await;
                forwarder = test_forwarder(authority.clone());
            } else {
                old_scope.revoke();
                // Off/on can coalesce before any forwarder poll. Revocation is
                // irreversible; a new same-address scope cannot adopt old bytes.
                authority.deny.store(true, Ordering::SeqCst);
                authority.deny.store(false, Ordering::SeqCst);
            }
            for piece in &old[1..] {
                forwarder.ingest(piece);
            }
            no_admission(&mut forwarder, &authority, &peer);
            let fresh = stock_udp_wire(flow, &payload, 1280);
            let mut other = test_forwarder(Arc::new(Authority::default()));
            // Independent IDs coexist across live logical handles in one core.
            let other_peer = UdpSocket::bind(loopback(ipv6)).await.unwrap();
            let other_flow = target(other_peer.local_addr().unwrap(), Transport::Udp);
            let interleaved = stock_udp_wire(other_flow, &payload, 1280);
            for (a, b) in fresh.iter().zip(&interleaved) {
                forwarder.ingest(a);
                other.ingest(b);
            }
            receive_exact(&mut forwarder, &peer, &payload).await;
            receive_exact(&mut other, &other_peer, &payload).await;
            forwarder.close_all().await;
            other.close_all().await;
        }
    }
}

#[tokio::test]
async fn stock_lwip_compatible_mtu_updates_retain_assembly_and_cancel_only_obsolete_udp() {
    if isolated_reassembly(
        "stock_lwip_compatible_mtu_updates_retain_assembly_and_cancel_only_obsolete_udp",
    ) {
        return;
    }
    for ipv6 in [false, true] {
        for emitted in [0, 1, 2, 3] {
            let peer = UdpSocket::bind(loopback(ipv6)).await.unwrap();
            let flow = target(peer.local_addr().unwrap(), Transport::Udp);
            let authority = Arc::new(Authority::default());
            let mut forwarder = Forwarder::with_mtu(
                authority,
                Arc::new(BufferBudget::new(128 * 1024 * 1024)),
                1500,
            )
            .unwrap();
            let body = patterned(4096);
            let pieces = stock_udp_wire(flow, &body, 1500);
            forwarder.ingest(&pieces[0]);
            forwarder.set_mtu(1280).unwrap();
            for piece in &pieces[1..] {
                forwarder.ingest(piece);
            }
            let source = receive_exact(&mut forwarder, &peer, &body).await;
            forwarder.set_mtu(1500).unwrap();
            peer.send_to(&body, source).await.unwrap();
            until(&mut forwarder, Forwarder::has_output).await;
            let mut output = Vec::new();
            for _ in 0..emitted {
                output.push(forwarder.next_output().unwrap());
            }
            if forwarder.has_output() {
                forwarder
                    .write_output(|_| Err(io::ErrorKind::WouldBlock.into()))
                    .unwrap_err();
                forwarder.set_mtu(1280).unwrap();
                if emitted < 2 {
                    assert!(
                        !forwarder
                            .write_output(|_| panic!("obsolete UDP after shrink"))
                            .unwrap()
                    );
                } else {
                    assert!(
                        forwarder
                            .write_output(|bytes| {
                                assert!(bytes.len() <= 1280);
                                output.push(bytes.to_vec());
                                Ok(bytes.len())
                            })
                            .unwrap(),
                        "already fitting tail remains eligible"
                    );
                }
                assert!(!forwarder.has_output());
            }
            if emitted >= 2 {
                stock_audit_udp(
                    Flow {
                        source: flow.destination,
                        destination: flow.source,
                        transport: Transport::Udp,
                    },
                    &body,
                    1500,
                    &output,
                );
            }
            // Increase never replays an abandoned physical message.
            forwarder.set_mtu(1500).unwrap();
            forwarder.process();
            assert!(!forwarder.has_output());
            peer.send_to(b"same socket survives", source).await.unwrap();
            until(&mut forwarder, Forwarder::has_output).await;
            let reply = forwarder.next_output().unwrap();
            assert_eq!(
                packet::parse(&reply).unwrap().payload,
                b"same socket survives"
            );
            forwarder.close_all().await;
        }
    }
}

#[test]
fn stock_lwip_typed_family_size_refusals_precede_capture_and_narrowing() {
    for ipv6 in [false, true] {
        let budget = Arc::new(BufferBudget::new(32 * 1024 * 1024));
        let flow = flow(ipv6, Transport::Udp);
        let scope =
            crate::ReceiveScope::new(flow.source.ip(), flow.destination.ip(), &*budget).unwrap();
        let id = ReceiveScopeId(scope.id());
        let mut engine = Engine::open(budget.clone(), 1280).unwrap();
        engine.register(&scope).unwrap();
        let tuple = ReplyTuple::from_flow(id, flow).unwrap();
        let payload = patterned(if ipv6 { 65488 } else { 65508 });
        assert_eq!(
            engine.reply(tuple, &payload, &mut |_| panic!("oversized output")),
            Err(IpError::Oversized)
        );
        let pieces = stock_udp_wire(flow, &payload, 1280);
        assert!(matches!(
            capture::ingest(&mut engine, id, pieces.last().unwrap(), &*budget),
            Err(IpError::Oversized)
        ));
        assert_eq!(engine.scope_refs(id), 0);
        engine.close();
    }
}

#[tokio::test]
async fn stock_lwip_tcp_queued_syn_data_fin_survive_mtu_change_and_small_peer_mss() {
    for ipv6 in [false, true] {
        for stage in ["syn", "data", "fin", "small-mss"] {
            println!(
                "stock-lwip queued TCP family={} stage={stage}",
                if ipv6 { 6 } else { 4 }
            );
            let listener = TcpListener::bind(loopback(ipv6)).await.unwrap();
            let flow = target(listener.local_addr().unwrap(), Transport::Tcp);
            let body = patterned(8193);
            let expected = body.clone();
            let (release, start_reply) = tokio::sync::oneshot::channel();
            let (close_peer, finish_reply) = tokio::sync::oneshot::channel();
            let (peer_complete, mut peer_received) = tokio::sync::oneshot::channel();
            let peer = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut all = Vec::new();
                let mut scratch = [0; 1024];
                while all.len() < expected.len() {
                    let n = read(&stream, &mut scratch).await;
                    assert!(n > 0);
                    all.extend_from_slice(&scratch[..n]);
                }
                assert_eq!(
                    all, expected,
                    "complete application stream at physical peer"
                );
                peer_complete.send(()).unwrap();
                start_reply.await.unwrap();
                write(&stream, &expected).await;
                finish_reply.await.unwrap();
                stream
                    .into_std()
                    .unwrap()
                    .shutdown(std::net::Shutdown::Write)
                    .unwrap();
                all
            });
            let mut forwarder = Forwarder::with_mtu(
                Arc::new(Authority::default()),
                Arc::new(BufferBudget::new(128 * 1024 * 1024)),
                1500,
            )
            .unwrap();
            let mut app = App::new(flow);
            app.stack.set_mtu(1500);
            app.stack.poll(forwarder.stack_now());
            while let Some(bytes) = app.stack.device.outgoing.pop_front() {
                let mut syn = bytes.to_vec();
                if stage == "small-mss" {
                    let h = if ipv6 { 40 } else { 20 };
                    let end = h + ((syn[h + 12] >> 4) as usize) * 4;
                    let option = (h + 20..end - 3)
                        .find(|i| syn[*i..*i + 2] == [2, 4])
                        .unwrap();
                    syn[option + 2..option + 4].copy_from_slice(&64u16.to_be_bytes());
                    syn[h + 16..h + 18].fill(0);
                    let mut pseudo = stock_pseudo(flow, syn.len() - h);
                    pseudo[if ipv6 { 39 } else { 9 }] = 6;
                    pseudo.extend_from_slice(&syn[h..]);
                    let checksum = stock_checksum(&pseudo);
                    syn[h + 16..h + 18].copy_from_slice(&checksum.to_be_bytes());
                }
                forwarder.ingest(&syn);
            }
            until(&mut forwarder, Forwarder::has_output).await;
            assert!(
                forwarder.output.iter().any(|o| packet::parse(&o.bytes)
                    .unwrap()
                    .tcp_flags
                    .unwrap()
                    .syn)
            );
            if stage == "syn" {
                forwarder
                    .write_output(|_| Err(io::ErrorKind::WouldBlock.into()))
                    .unwrap_err();
                forwarder.set_mtu(1280).unwrap();
                app.stack.set_mtu(1280);
            }
            app.until(&mut forwarder, |app, _| app.socket().can_send())
                .await;
            let mut sent = 0;
            {
                // Sending into the app ring is not physical delivery. Keep
                // driving both stacks until the real peer's completion signal,
                // and include that signal in the scheduler's actual wait set.
                let mut pumping = Box::pin(app.until(&mut forwarder, |app, _| {
                    if sent < body.len() && app.socket().can_send() {
                        sent += app.socket().send_slice(&body[sent..]).unwrap();
                    }
                    false
                }));
                tokio::select! {
                    result = &mut peer_received => result.unwrap(),
                    _ = &mut pumping => unreachable!("peer completion owns this phase"),
                }
            }
            release.send(()).unwrap();
            if stage == "data" {
                until(&mut forwarder, |f| {
                    f.output
                        .iter()
                        .any(|o| !packet::parse(&o.bytes).unwrap().payload.is_empty())
                })
                .await;
                assert!(forwarder.output.iter().any(|o| o.bytes.len() > 1280));
                forwarder
                    .write_output(|_| Err(io::ErrorKind::WouldBlock.into()))
                    .unwrap_err();
                forwarder.set_mtu(1280).unwrap();
                app.stack.set_mtu(1280);
            }
            consume_tcp_observed(
                &mut app,
                &mut forwarder,
                &body,
                if stage == "small-mss" { Some(64) } else { None },
            )
            .await;
            close_peer.send(()).unwrap();
            if stage == "fin" {
                // The peer has closed its write half; wait without delivering
                // the queued FIN, then change MTU before the checked retry.
                until(&mut forwarder, |f| {
                    f.output
                        .iter()
                        .any(|o| packet::parse(&o.bytes).unwrap().tcp_flags.unwrap().fin)
                })
                .await;
                assert!(!forwarder.tcp[&flow].fin_delivered);
                forwarder
                    .write_output(|_| Err(io::ErrorKind::WouldBlock.into()))
                    .unwrap_err();
                assert!(!forwarder.tcp[&flow].fin_delivered);
                forwarder.set_mtu(1280).unwrap();
                app.stack.set_mtu(1280);
            }
            app.socket().close();
            app.until(&mut forwarder, |app, f| {
                !app.socket().is_open() && f.stats().tcp_flows == 0
            })
            .await;
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(2), peer)
                    .await
                    .unwrap()
                    .unwrap(),
                body
            );
            forwarder.close_all().await;
        }
    }
}

async fn consume_tcp_observed(
    app: &mut App,
    forwarder: &mut Forwarder<Authority>,
    expected: &[u8],
    mss: Option<usize>,
) {
    let mut received = Vec::new();
    let mut largest = 0;
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let mtu = forwarder.mtu;
            app.exchange_observed(forwarder, |_| {}, |bytes| {
                assert!(bytes.len() <= mtu, "TCP packet exceeds exact current sink MTU");
                let parsed = packet::parse(bytes).unwrap();
                assert!(!parsed.tcp_flags.unwrap().rst, "MTU change must not reset TCP");
                largest = largest.max(parsed.payload.len());
                if let Some(mss) = mss { assert!(parsed.payload.len() <= mss, "peer MSS must bound each TCP data segment"); }
            });
            let mut bytes = [0; 256];
            while app.socket().can_recv() {
                let n = app.socket().recv_slice(&mut bytes).unwrap();
                received.extend_from_slice(&bytes[..n]);
            }
            if received.len() == expected.len() { break; }
            let delay = app.stack.interface.poll_delay(forwarder.stack_now(), &app.stack.sockets);
            tokio::select! {
                _ = forwarder.wait() => {},
                _ = async {
                    if let Some(delay) = delay { tokio::time::sleep_until(Instant::now()+Duration::from_millis(delay.total_millis())).await; }
                    else { std::future::pending::<()>().await; }
                } => {},
            }
        }
    }).await.expect("observed TCP consumer deadline");
    assert!(largest > 0);
    assert_eq!(
        received, expected,
        "complete reply stream at application consumer"
    );
}
