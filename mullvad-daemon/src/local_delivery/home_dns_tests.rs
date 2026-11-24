use super::*;
use crate::local_delivery::tests::{flow, observation, policy};
use mullvad_types::settings::local_network_access::{SsidIdentity, split_dns::SplitDnsPolicy};
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use talpid_lan_forwarder::Transport;

fn configured() -> LocalNetworkAccess {
    let mut policy = policy();
    policy.rules[0].ssid_ids = vec![SsidIdentity::from_bytes(b"synthetic".to_vec()).unwrap()];
    let mut unrelated = policy.rules[0].clone();
    unrelated.id = "00000000-0000-0000-0000-000000000002".parse().unwrap();
    unrelated.ssid_ids.clear();
    policy.rules.push(unrelated);
    policy.split_dns = SplitDnsPolicy {
        enabled: true,
        suffixes: vec!["home.".into()],
        home_resolver: Some("10.0.2.2".parse().unwrap()),
        local_rule_id: Some(policy.rules[0].id),
    };
    policy
}

fn query_flow(transport: Transport) -> Flow {
    let mut flow = flow(transport, 49152);
    flow.destination.set_port(53);
    flow
}

#[cfg(any(target_os = "android", target_os = "linux"))]
#[test]
fn split_dns_admission_revalidates_only_its_key_against_the_current_capture() {
    use crate::local_delivery::tests::broker;
    use talpid_tunnel::tun_provider::transport::ROUTER_SOURCES;

    let on = configured();
    let authority = DeliveryAuthority::new(&on, Arc::new(|_, _| Ok(())));
    authority.update(&on, Some(observation()));
    let broker = broker();
    let open = || {
        let lease = broker.open_capture(None).unwrap();
        lease
            .bind_observed_identity("tun-owned", 101_u64 << 32, ROUTER_SOURCES, 1280)
            .unwrap();
        lease
    };
    let first = open();
    let local = flow(Transport::Udp, 49152);
    let source = local.source.ip();
    let resolver = "192.0.2.53".parse().unwrap();
    let other = "192.0.2.54".parse().unwrap();
    authority.install(CaptureAuthority::new(
        vec![source],
        Some(broker.clone()),
        vec![],
    ));
    let budget = BufferBudget::new(65536);
    let old = authority.dns_input(source, resolver, &budget).unwrap();
    let local_scope = authority
        .receive_for(
            &mut authority.inputs.write().unwrap(),
            source,
            local.destination.ip(),
            ReceivePurpose::Local,
            &budget,
        )
        .unwrap();

    first.retire();
    let successor = open();
    assert_ne!(first.generation(), successor.generation());
    let unrelated = authority.dns_input(source, other, &budget).unwrap();
    assert!(
        local_scope.current(),
        "DNS admission swept Local registrations"
    );
    assert!(
        old.scope().current(),
        "DNS admission swept unrelated live DNS registrations"
    );

    let current = authority.dns_input(source, resolver, &budget).unwrap();
    assert_ne!(old.scope().id(), current.scope().id());
    assert!(
        !old.scope().current(),
        "the old registration must be revoked before replacement"
    );
    // A late last-guard drop must not evict the new registration for this key.
    drop(old);
    let same = authority.dns_input(source, resolver, &budget).unwrap();
    assert_eq!(current.scope().id(), same.scope().id());

    authority.endpoint(false);
    assert!(!local_scope.current());
    assert!(!current.scope().current());
    assert!(!unrelated.scope().current());
}

#[test]
fn split_dns_admission_reclaims_dropped_registrations_across_keys() {
    let authority = DeliveryAuthority::new(&configured(), Arc::new(|_, _| Ok(())));
    let source = query_flow(Transport::Udp).source.ip();
    let budget = BufferBudget::new(1024);
    for host in 1..=16 {
        let resolver = std::net::Ipv4Addr::new(192, 0, 2, host).into();
        let input = authority.dns_input(source, resolver, &budget).unwrap();
        assert!(input.scope().current());
        assert_eq!(authority.inputs.read().unwrap().dns_inputs.len(), 1);
    }
}

#[test]
fn split_dns_configured_home_requires_the_original_classification_context() {
    use hickory_proto::{
        op::{Message, Query},
        rr::{Name, RecordType},
    };
    use mullvad_types::settings::local_network_access::split_dns::DnsLane;

    let on = configured();
    let source = query_flow(Transport::Udp).source;
    let resolver = "192.0.2.53".parse().unwrap();
    let buffers = BufferBudget::new(128 * 1024);
    let prepared = Arc::new(AtomicUsize::new(0));
    let count = prepared.clone();
    let authority = DeliveryAuthority::new(
        &on,
        Arc::new(move |_, _| {
            count.fetch_add(1, SeqCst);
            Ok(())
        }),
    );
    let mut replacement = on.clone();
    // The physical resolver remains identical. Only the classification changes.
    replacement.split_dns.suffixes = vec!["new.home.".into()];
    let request = |name: &str| {
        let mut request = Message::query();
        request.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
        request
    };
    for transport in [Transport::Udp, Transport::Tcp] {
        authority.update(&on, Some(observation()));
        let input = authority
            .dns_input(source.ip(), resolver, &buffers)
            .unwrap();
        assert_eq!(
            input.matcher().classify(&request("old.home.")).unwrap(),
            DnsLane::Home
        );
        authority.update_policy(&replacement);
        assert!(!input.scope().current());
        assert!(
            authority
                .home_dns_authorize_configured(&input, source, transport, &buffers)
                .is_err(),
            "classification under a retired policy issued a configured Home grant for {transport:?}"
        );
        let input = authority
            .dns_input(source.ip(), resolver, &buffers)
            .unwrap();
        assert_eq!(
            input.matcher().classify(&request("old.home.")).unwrap(),
            DnsLane::Ordinary
        );
        assert_eq!(
            input.matcher().classify(&request("new.home.")).unwrap(),
            DnsLane::Home
        );
        let query = authority
            .home_dns_authorize_configured(&input, source, transport, &buffers)
            .unwrap();
        let (kind, protocol) = match transport {
            Transport::Udp => (socket2::Type::DGRAM, socket2::Protocol::UDP),
            Transport::Tcp => (socket2::Type::STREAM, socket2::Protocol::TCP),
        };
        let socket = socket2::Socket::new(socket2::Domain::IPV4, kind, Some(protocol)).unwrap();
        authority.home_dns_prepare(&socket, &query).unwrap();
    }
    assert_eq!(prepared.load(SeqCst), 2);
}

#[test]
fn split_dns_home_query_app_and_home_address_families_are_independent() {
    for home_v6 in [false, true] {
        for client_v6 in [false, true] {
            let mut on = configured();
            let home: IpAddr = if home_v6 { "fe80::2" } else { "10.0.2.2" }
                .parse()
                .unwrap();
            on.split_dns.home_resolver = Some(home);
            assert!(on.validate().is_ok());
            let authority = DeliveryAuthority::new(
                &on,
                Arc::new(move |_, lease| {
                    assert_eq!(lease.destination, home);
                    Ok(())
                }),
            );
            authority.update(&on, Some(observation()));
            let buffers = BufferBudget::new(65536);
            let source: SocketAddr = if client_v6 {
                "[fdf0:ce4a:801d::172:27:1:1]:49152"
            } else {
                "172.27.1.1:49152"
            }
            .parse()
            .unwrap();
            let resolver = if client_v6 { "fd00::53" } else { "192.0.2.53" }
                .parse()
                .unwrap();
            let input = authority
                .dns_input(source.ip(), resolver, &buffers)
                .unwrap();
            let query = authority
                .home_dns_authorize_configured(&input, source, Transport::Udp, &buffers)
                .expect("Home's two legs must not require one IP packet family");
            assert_eq!(query.0.scope.source(), source.ip());
            assert_eq!(query.0.scope.destination(), home);
            let socket = socket2::Socket::new(
                socket2::Domain::for_address(query.destination()),
                socket2::Type::DGRAM,
                Some(socket2::Protocol::UDP),
            )
            .unwrap();
            authority.home_dns_prepare(&socket, &query).unwrap();
            let mut off = on.clone();
            off.split_dns.enabled = false;
            authority.update_policy(&off);
            authority.update_policy(&on);
            assert!(!authority.home_dns_current(&query));
            if home_v6 != client_v6 {
                assert!(
                    matches!(
                        ReceiveScope::new(source.ip(), home, &buffers),
                        Err(Refused::Denied)
                    ),
                    "ordinary Local packet scopes stay single-family"
                );
            }
        }
    }
}

#[tokio::test]
async fn split_dns_home_query_hickory_runtime_retains_exact_resolver_and_revocation_fence() {
    use crate::split_dns::{home_io::HomeIoOwner, transport::Protocol};
    use hickory_net::runtime::RuntimeProvider;
    let prepared = Arc::new(AtomicUsize::new(0));
    let count = prepared.clone();
    let authority = Arc::new(DeliveryAuthority::new(
        &configured(),
        Arc::new(move |_, lease| {
            assert_eq!(lease.network_handle, 71);
            assert_eq!(lease.destination, "10.0.2.2".parse::<IpAddr>().unwrap());
            count.fetch_add(1, SeqCst);
            Ok(())
        }),
    ));
    authority.update(&configured(), Some(observation()));
    let budget = Arc::new(BufferBudget::new(65536));
    let flow = query_flow(Transport::Udp);
    let grant = authority.home_dns_authorize(flow, &*budget).unwrap();
    let owner = HomeIoOwner::new(budget);
    let runtime = owner.runtime(authority.clone(), grant.clone()).unwrap();
    assert!(
        runtime
            .bind_udp(
                "0.0.0.0:0".parse().unwrap(),
                "10.0.2.53:53".parse().unwrap()
            )
            .await
            .is_err()
    );
    assert!(
        runtime
            .connect_tcp(flow.destination, None, None)
            .await
            .is_err(),
        "UDP grant authorized TCP"
    );
    assert_eq!(prepared.load(SeqCst), 0);
    let socket = runtime
        .bind_udp("0.0.0.0:0".parse().unwrap(), flow.destination)
        .await
        .unwrap();
    assert_eq!(prepared.load(SeqCst), 1);
    grant.retire();
    use hickory_net::runtime::DnsUdpSocket;
    assert_eq!(
        socket
            .send_to(b"must not send", flow.destination)
            .await
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::PermissionDenied
    );
    drop(socket);
    assert!(
        runtime
            .bind_udp("0.0.0.0:0".parse().unwrap(), flow.destination)
            .await
            .is_err()
    );
    let mut request = hickory_proto::op::Message::query();
    request.add_query(hickory_proto::op::Query::query(
        hickory_proto::rr::Name::from_ascii("home.").unwrap(),
        hickory_proto::rr::RecordType::A,
    ));
    assert!(
        runtime
            .exchange(Protocol::Udp, std::time::Duration::from_secs(2), request)
            .await
            .is_err()
    );
    assert!(owner.runtime(authority, grant).is_err());
    drop(runtime);
    owner.close().await.unwrap();
}

#[tokio::test]
async fn split_dns_home_query_authority_retirement_wakes_pending_io_without_network_readiness() {
    let on = configured();
    let authority = Arc::new(DeliveryAuthority::new(&on, Arc::new(|_, _| Ok(()))));
    authority.update(&on, Some(observation()));
    let buffers = BufferBudget::new(65536);
    let query = authority
        .home_dns_authorize(query_flow(Transport::Udp), &buffers)
        .unwrap();
    let waiting = authority.home_dns_retired(&query);
    tokio::pin!(waiting);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(10), &mut waiting)
            .await
            .is_err()
    );
    let mut off = on.clone();
    off.split_dns.enabled = false;
    authority.update_policy(&off);
    authority.update_policy(&on);
    tokio::time::timeout(std::time::Duration::from_secs(1), waiting)
        .await
        .unwrap();
    assert!(!authority.home_dns_current(&query));
}

#[test]
fn split_dns_home_query_uses_only_associated_rule_and_prepares_exact_original_network() {
    let count = Arc::new(AtomicUsize::new(0));
    let prepared = count.clone();
    let authority = DeliveryAuthority::new(
        &configured(),
        Arc::new(move |_, lease| {
            assert_eq!(lease.network_handle, 71);
            assert_eq!(lease.sequence, 9);
            assert_eq!(lease.rule_ids, vec![configured().rules[0].id]);
            prepared.fetch_add(1, SeqCst);
            Ok(())
        }),
    );
    authority.update(&configured(), Some(observation()));
    let buffers = BufferBudget::new(65536);
    for protocol in [Transport::Udp, Transport::Tcp] {
        let query = authority
            .home_dns_authorize(query_flow(protocol), &buffers)
            .unwrap();
        assert_eq!(query.destination(), "10.0.2.2:53".parse().unwrap());
        assert!(authority.home_dns_current(&query));
        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            if protocol == Transport::Tcp {
                socket2::Type::STREAM
            } else {
                socket2::Type::DGRAM
            },
            None,
        )
        .unwrap();
        authority.home_dns_prepare(&socket, &query).unwrap();
    }
    assert_eq!(count.load(SeqCst), 2);
    let mut away = observation();
    away.networks[0].ssid = Some(SsidIdentity::from_bytes(b"guest".to_vec()).unwrap());
    authority.update(&configured(), Some(away));
    assert!(
        authority.authorize(query_flow(Transport::Udp)).is_ok(),
        "ordinary Local still has its Any-network rule"
    );
    assert!(matches!(
        authority.home_dns_authorize(query_flow(Transport::Udp), &buffers),
        Err(Refused::Denied)
    ));
    assert_eq!(count.load(SeqCst), 2);
}

#[test]
fn split_dns_home_query_off_on_and_network_loss_return_never_revive_old_work() {
    let on = configured();
    let authority = DeliveryAuthority::new(&on, Arc::new(|_, _| Ok(())));
    authority.update(&on, Some(observation()));
    let buffers = BufferBudget::new(65536);
    let local = authority
        .receive(
            "172.27.1.1".parse().unwrap(),
            "10.0.2.2".parse().unwrap(),
            &buffers,
        )
        .unwrap();
    let query = authority
        .home_dns_authorize(query_flow(Transport::Udp), &buffers)
        .unwrap();
    assert_ne!(
        query.0.scope.id(),
        local.id(),
        "Home and ordinary Local scopes must not replace each other"
    );
    let mut off = on.clone();
    off.split_dns.enabled = false;
    authority.update(&off, Some(observation()));
    authority.update(&on, Some(observation()));
    assert!(!authority.home_dns_current(&query));
    assert!(
        local.current(),
        "DNS policy cannot revoke ordinary Local receive scope"
    );
    let next = authority
        .home_dns_authorize(query_flow(Transport::Tcp), &buffers)
        .unwrap();
    authority.update(&on, None);
    authority.update(&on, Some(observation()));
    assert!(!authority.home_dns_current(&next));
    let current = authority
        .home_dns_authorize(query_flow(Transport::Tcp), &buffers)
        .unwrap();
    assert!(authority.home_dns_current(&current));
    assert_ne!(current.0.scope.id(), next.0.scope.id());
}

#[test]
fn split_dns_home_query_policy_replacement_and_capture_loss_are_irreversible() {
    let on = configured();
    let authority = DeliveryAuthority::new(&on, Arc::new(|_, _| Ok(())));
    authority.update(&on, Some(observation()));
    let buffers = BufferBudget::new(65536);
    for change in 0..3 {
        let query = authority
            .home_dns_authorize(query_flow(Transport::Udp), &buffers)
            .unwrap();
        let mut other = on.clone();
        match change {
            0 => other.split_dns.suffixes = vec!["new.home.".into()],
            1 => other.split_dns.local_rule_id = Some(other.rules[1].id),
            _ => other.split_dns.home_resolver = Some("10.0.2.53".parse().unwrap()),
        };
        authority.update(&other, Some(observation()));
        authority.update(&on, Some(observation()));
        assert!(!authority.home_dns_current(&query));
    }
    let query = authority
        .home_dns_authorize(query_flow(Transport::Udp), &buffers)
        .unwrap();
    authority.revoke();
    authority.install(CaptureAuthority::partial());
    assert!(!authority.home_dns_current(&query));
}

#[test]
fn split_dns_home_query_refuses_wrong_source_port_target_disabled_rule_and_unfunded_work() {
    let on = configured();
    let authority =
        DeliveryAuthority::new(&on, Arc::new(|_, _| panic!("denied Home query prepared")));
    authority.update(&on, Some(observation()));
    let buffers = BufferBudget::new(65536);
    let mut wrong = query_flow(Transport::Udp);
    wrong.source.set_ip("172.27.1.2".parse().unwrap());
    assert!(matches!(
        authority.home_dns_authorize(wrong, &buffers),
        Err(Refused::Denied)
    ));
    wrong = query_flow(Transport::Udp);
    wrong.destination.set_port(5353);
    assert!(matches!(
        authority.home_dns_authorize(wrong, &buffers),
        Err(Refused::Denied)
    ));
    wrong = query_flow(Transport::Udp);
    wrong.destination.set_ip("10.0.2.53".parse().unwrap());
    assert!(matches!(
        authority.home_dns_authorize(wrong, &buffers),
        Err(Refused::Denied)
    ));
    assert!(matches!(
        authority.home_dns_authorize(query_flow(Transport::Udp), &BufferBudget::new(0)),
        Err(Refused::Full)
    ));
    let mut disabled = on;
    disabled.rules[0].enabled = false;
    authority.update(&disabled, Some(observation()));
    assert!(matches!(
        authority.home_dns_authorize(query_flow(Transport::Udp), &buffers),
        Err(Refused::Denied)
    ));
}

#[test]
fn split_dns_home_query_revocation_during_prepare_is_checked_after_the_platform_returns() {
    let shared: Arc<Mutex<Option<std::sync::Weak<DeliveryAuthority>>>> = Arc::new(Mutex::new(None));
    let captured = shared.clone();
    let authority = Arc::new(DeliveryAuthority::new(
        &configured(),
        Arc::new(move |_, _| {
            let authority = captured
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .upgrade()
                .unwrap();
            authority.update(&configured(), None);
            authority.update(&configured(), Some(observation()));
            Ok(())
        }),
    ));
    *shared.lock().unwrap() = Some(Arc::downgrade(&authority));
    authority.update(&configured(), Some(observation()));
    let buffers = BufferBudget::new(65536);
    for transport in [Transport::Udp, Transport::Tcp] {
        let query = authority
            .home_dns_authorize(query_flow(transport), &buffers)
            .unwrap();
        let socket =
            socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None).unwrap();
        assert_eq!(
            authority.home_dns_prepare(&socket, &query),
            Err(Refused::Stale)
        );
        assert!(!authority.home_dns_current(&query));
    }
}

#[test]
fn split_dns_home_query_ipv6_scope_and_last_provider_clone_retain_funded_ownership() {
    let mut on = configured();
    on.split_dns.home_resolver = Some("fe80::53".parse().unwrap());
    let authority = DeliveryAuthority::new(&on, Arc::new(|_, _| Ok(())));
    authority.update(&on, Some(observation()));
    let buffers = BufferBudget::new(65536);
    let mut selected = query_flow(Transport::Udp);
    selected.source.set_ip(ROUTER_IPV6.into());
    selected.destination.set_ip("fe80::53".parse().unwrap());
    let query = authority.home_dns_authorize(selected, &buffers).unwrap();
    assert_eq!(query.destination(), "[fe80::53%15]:53".parse().unwrap());
    let used = buffers.used();
    assert!(used >= size_of::<HomeQuery>() + 4096 + 1024);
    let provider = query.clone();
    drop(query);
    assert_eq!(buffers.used(), used);
    assert!(authority.home_dns_current(&provider));
    drop(provider);
    authority.update(&on, Some(observation()));
    assert_eq!(
        buffers.used(),
        0,
        "retired weak registration and last query backing both refund"
    );
}

#[test]
fn split_dns_home_query_receive_slot_does_not_take_a_native_local_scope_slot() {
    let mut on = configured();
    on.split_dns.home_resolver = Some("fe80::53".parse().unwrap());
    let authority = DeliveryAuthority::new(&on, Arc::new(|_, _| Ok(())));
    authority.update(&on, Some(observation()));
    let buffers = BufferBudget::new((MAX_RECEIVE_SCOPES + 16) * 1024);
    let source = IpAddr::from(ROUTER_IPV6);
    let mut selected = query_flow(Transport::Udp);
    selected.source.set_ip(source);
    selected.destination.set_ip("fe80::53".parse().unwrap());
    let home = authority.home_dns_authorize(selected, &buffers).unwrap();
    let mut scopes = Vec::new();
    for index in 1..=MAX_RECEIVE_SCOPES {
        let destination = IpAddr::from(std::net::Ipv6Addr::new(
            0xfe80,
            0,
            0,
            0,
            0,
            0,
            0,
            index as u16,
        ));
        scopes.push(authority.receive(source, destination, &buffers).unwrap());
    }
    assert!(authority.home_dns_current(&home));
    assert_eq!(
        authority.inputs.read().unwrap().receive.len(),
        MAX_RECEIVE_SCOPES + 1
    );
    assert!(matches!(
        authority.receive(source, "fe80::fefe".parse().unwrap(), &buffers),
        Err(Refused::Full)
    ));
    assert!(scopes.iter().all(ReceiveScope::current));
    drop((home, scopes));
    authority.update(&on, Some(observation()));
    assert_eq!(buffers.used(), 0);
}

#[tokio::test]
async fn split_dns_home_query_cancellation_is_per_query_irreversible_and_wakes_io() {
    let on = configured();
    let authority = DeliveryAuthority::new(
        &on,
        Arc::new(|_, _| panic!("query cancellation must not prepare a socket")),
    );
    authority.update(&on, Some(observation()));
    let buffers = BufferBudget::new(65536);
    let first = authority
        .home_dns_authorize(query_flow(Transport::Udp), &buffers)
        .unwrap();
    let sibling = authority
        .home_dns_authorize(query_flow(Transport::Tcp), &buffers)
        .unwrap();
    assert_eq!(first.0.scope.id(), sibling.0.scope.id());
    let provider = first.clone();
    let waiting = provider.retired();
    tokio::pin!(waiting);
    assert!(futures::poll!(waiting.as_mut()).is_pending());
    first.retire();
    tokio::time::timeout(std::time::Duration::from_secs(1), waiting)
        .await
        .unwrap();
    assert!(!authority.home_dns_current(&first));
    assert!(!authority.home_dns_current(&provider));
    assert!(authority.home_dns_current(&sibling));
    authority.update(&on, Some(observation()));
    assert!(!authority.home_dns_current(&first));
    assert!(
        authority.home_dns_current(
            &authority
                .home_dns_authorize(query_flow(Transport::Udp), &buffers)
                .unwrap()
        )
    );
}
