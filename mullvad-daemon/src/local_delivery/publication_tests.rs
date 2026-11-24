//! Producer-boundary reproduction. No direct DeliveryAuthority update publishes
//! the loss/off state: the real feed/settings producer must retain revocation.
use super::*;
use mullvad_types::settings::local_network_access::split_dns::SplitDnsPolicy;
use talpid_types::local_network::{
    AuthorityObservation, LocalPhysicalAddress, LocalPhysicalNetwork,
};

fn configured() -> LocalNetworkAccess {
    let mut on = policy();
    on.rules[0].ssid_ids = vec![SsidIdentity::from_bytes(b"synthetic".to_vec()).unwrap()];
    on.split_dns = SplitDnsPolicy {
        enabled: true,
        suffixes: vec!["home.".into()],
        home_resolver: Some("10.0.2.2".parse().unwrap()),
        local_rule_id: Some(on.rules[0].id),
    };
    on
}

fn snapshot(sequence: i64) -> LocalNetworkSnapshot {
    let observed = observation();
    let network = &observed.networks[0];
    LocalNetworkSnapshot {
        sequence,
        authority_revision: 0,
        observer_running: true,
        local_ready: true,
        fine_ready: true,
        background_ready: true,
        location_enabled: true,
        location_allowed: true,
        networks: vec![LocalPhysicalNetwork {
            network_handle: network.handle,
            transport: 1,
            capabilities_fresh: true,
            links_fresh: true,
            blocked: false,
            interface_index: network.interface_index,
            addresses: network
                .addresses
                .iter()
                .map(|address| LocalPhysicalAddress {
                    prefix: LocalPhysicalPrefix {
                        address: address.prefix.ip(),
                        prefix_length: i16::from(address.prefix.prefix()),
                    },
                    usable: address.usable,
                })
                .collect(),
            routes: network.routes.clone(),
            ssid_hex: Some("73796e746865746963".into()),
        }],
    }
}

fn home_flow() -> Flow {
    let mut request = flow(Transport::Udp, 49200);
    request.destination.set_port(53);
    request
}

#[test]
fn pr20_witness_cannot_revive_a_transport_whose_receive_scope_stays_live() {
    let mut on = configured();
    let mut fallback = on.rules[0].clone();
    fallback.id = "00000000-0000-0000-0000-000000000002".parse().unwrap();
    fallback.ssid_ids.clear();
    on.rules.push(fallback);
    let feed = LocalNetworkFeed::new(1);
    assert!(feed.publish(1, snapshot(9)));
    let authority = authority();
    authority.update_policy(&on);
    let observe = authority.clone();
    feed.observe_authority(Arc::new(move |event| observe.observe(event)));
    let flow = home_flow();
    let buffers = BufferBudget::new(65536);
    let scope = authority
        .receive(flow.source.ip(), flow.destination.ip(), &buffers)
        .unwrap();
    let issued = authority.authorize_received(flow, &scope).unwrap();
    assert_eq!(issued.physical.rule_ids.len(), 2);

    let mut refresh = snapshot(9);
    refresh.authority_revision = 1;
    assert!(feed.revalidate(1, refresh.clone()));
    assert!(
        authority.current(&issued),
        "same facts at the same sequence keep the grant"
    );

    let mut changed = refresh.clone();
    changed.authority_revision = 2;
    changed.networks[0].ssid_hex = Some("6f74686572".into());
    assert!(feed.revalidate(1, changed));
    assert!(
        scope.current(),
        "the fallback rule keeps the receive scope live"
    );
    assert!(!authority.current(&issued));

    refresh.authority_revision = 3;
    assert!(feed.revalidate(1, refresh.clone()));
    assert!(scope.current());
    assert!(
        !authority.current(&issued),
        "returned witness revived a retired transport"
    );
    refresh.sequence += 1;
    assert!(feed.publish(1, refresh));
    assert!(!authority.current(&issued));
    let confirmed = authority.authorize_received(flow, &scope).unwrap();
    assert!(authority.current(&confirmed));
    assert_eq!(confirmed.physical.rule_ids, issued.physical.rule_ids);
}

#[tokio::test]
async fn pr20_witness_keeps_only_live_unexpired_held_udp_until_confirmation() {
    for (retire, expire) in [(false, false), (true, false), (false, true)] {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer.local_addr().unwrap();
        let preparations = Arc::new(AtomicUsize::new(0));
        let called = preparations.clone();
        let on = policy();
        let authority = Arc::new(DeliveryAuthority::new(
            &on,
            Arc::new(move |_, _| {
                if called.fetch_add(1, SeqCst) == 0 {
                    Err(Refused::Stale)
                } else {
                    Ok(())
                }
            }),
        ));
        authority.observe(AuthorityObservation::Published(Some(Arc::new(snapshot(9)))));
        let mut forwarder = Forwarder::new(
            Arc::new(LoopbackAuthority {
                authority: authority.clone(),
                peer: Some((peer_addr, peer_addr)),
            }),
            DeliveryBuffers::new().local,
        )
        .unwrap();
        forwarder.ingest(&udp_packet(home_flow(), b"held across confirmation"));
        while forwarder.stats().stale == 0 {
            bounded(forwarder.wait()).await;
        }
        tokio::time::pause();
        let mut witness = snapshot(9);
        witness.authority_revision = 1;
        witness.local_ready = !retire;
        authority.observe(AuthorityObservation::Revalidate(Arc::new(witness)));
        forwarder.revalidate();
        assert_eq!(
            preparations.load(SeqCst),
            1,
            "a witness cannot prepare a new socket"
        );
        if expire {
            tokio::time::advance(Duration::from_secs(2)).await;
        }
        authority.observe(AuthorityObservation::Published(Some(Arc::new(snapshot(
            10,
        )))));
        forwarder.revalidate();
        let mut buffer = [0; 32];
        if !retire && !expire {
            tokio::time::resume();
            let length = bounded(async {
                loop {
                    tokio::select! {
                        length = peer.recv(&mut buffer) => break length.unwrap(),
                        _ = forwarder.wait() => {},
                    }
                }
            })
            .await;
            assert_eq!(&buffer[..length], b"held across confirmation");
        }
        forwarder.close_all().await;
        assert_eq!(
            preparations.load(SeqCst),
            if retire || expire { 1 } else { 2 }
        );
        assert!(
            peer.try_recv(&mut buffer).is_err(),
            "held UDP delivered more than once or after retirement"
        );
        if retire || expire {
            tokio::time::resume();
        }
    }
}

#[tokio::test]
async fn split_dns_publication_witness_retains_benign_scopes_but_cannot_grant_or_revive_work() {
    let on = configured();
    let feed = LocalNetworkFeed::new(1);
    assert!(feed.publish(1, snapshot(9)));
    let control = Arc::new(Control::default());
    let mut runtime = make_runtime(Some(feed.clone()), control.clone());
    runtime.update(&on, TargetState::Unsecured, true).await;
    let authority = control.authority.lock().unwrap().clone().unwrap();
    let buffers = BufferBudget::new(65536);
    let home = authority.home_dns_authorize(home_flow(), &buffers).unwrap();
    let local = authority
        .receive(
            home_flow().source.ip(),
            home_flow().destination.ip(),
            &buffers,
        )
        .unwrap();
    let transport = authority.authorize_received(home_flow(), &local).unwrap();
    let mut benign = snapshot(9);
    benign.authority_revision = 1;
    benign.networks[0].routes.push(route("192.168.9.0", 24));
    assert!(feed.revalidate(1, benign.clone()));
    assert!(
        local.current() && authority.home_dns_current(&home),
        "benign facts retain already eligible work"
    );
    assert!(
        authority.current(&transport),
        "already issued Local transport keeps benign continuity"
    );
    assert_eq!(
        authority
            .receive(
                home_flow().source.ip(),
                home_flow().destination.ip(),
                &buffers
            )
            .unwrap()
            .id(),
        local.id(),
        "existing ingress/fragment ownership continues during a benign witness"
    );
    assert!(
        matches!(
            authority.authorize_received(home_flow(), &local),
            Err(Refused::AwaitingConfirmation)
        ),
        "the retained scope alone cannot issue a new transport from incomplete facts"
    );
    assert!(
        matches!(
            authority.home_dns_authorize(home_flow(), &buffers),
            Err(Refused::Stale)
        ),
        "an incomplete witness cannot admit new work"
    );
    assert!(
        !feed.publish(1, snapshot(100)),
        "old full publication cannot cross a newer event fence"
    );
    runtime.update(&on, TargetState::Unsecured, true).await;
    assert!(
        matches!(
            authority.home_dns_authorize(home_flow(), &buffers),
            Err(Refused::Stale)
        ),
        "latest-status reconciliation cannot override pending producer authority"
    );
    benign.sequence = 10;
    assert!(feed.publish(1, benign.clone()));
    assert!(local.current() && authority.home_dns_current(&home));
    let mut denied = benign.clone();
    denied.authority_revision = 2;
    denied.local_ready = false;
    assert!(feed.revalidate(1, denied.clone()));
    assert!(!local.current() && !authority.home_dns_current(&home));
    benign.authority_revision = 3;
    assert!(feed.revalidate(1, benign.clone()));
    assert!(
        !local.current() && !authority.home_dns_current(&home),
        "return cannot revive retired work"
    );
    assert!(
        !authority.current(&transport),
        "per-I/O checks cannot revive a transport before the async owner notices loss/return"
    );
    benign.sequence = 11;
    assert!(feed.publish(1, benign));
    let successor = authority.home_dns_authorize(home_flow(), &buffers).unwrap();
    assert!(authority.home_dns_current(&successor));
    assert!(
        !feed.revalidate(1, denied),
        "stale callback must not revoke its successor"
    );
    assert!(authority.home_dns_current(&successor));
    runtime.stop().await.unwrap();
}

#[tokio::test]
async fn split_dns_publication_reset_and_generic_settings_write_share_the_committed_listener() {
    use crate::settings::SettingsPersister;
    use mullvad_types::settings::SettingsKeyList;
    let directory = std::env::temp_dir().join(format!(
        "krtek-dns-publication-{:016x}",
        rand::random::<u64>()
    ));
    std::fs::create_dir(&directory).unwrap();
    let mut settings = SettingsPersister::load(&directory).await;
    let on = configured();
    settings
        .set_local_network_access(on.clone(), None)
        .await
        .unwrap();
    let feed = LocalNetworkFeed::new(1);
    assert!(feed.publish(1, snapshot(9)));
    let control = Arc::new(Control::default());
    let mut runtime = make_runtime(Some(feed), control.clone());
    runtime.update(&on, TargetState::Unsecured, true).await;
    runtime.observe_settings(&mut settings);
    let authority = control.authority.lock().unwrap().clone().unwrap();
    let buffers = BufferBudget::new(65536);
    let old = authority.home_dns_authorize(home_flow(), &buffers).unwrap();
    let local = authority
        .receive(
            home_flow().source.ip(),
            home_flow().destination.ip(),
            &buffers,
        )
        .unwrap();
    settings.reset(SettingsKeyList::default()).await.unwrap();
    settings
        .update(|settings| settings.local_network_access = on.clone())
        .await
        .unwrap();
    assert!(!authority.home_dns_current(&old) && !local.current());
    let successor = authority.home_dns_authorize(home_flow(), &buffers).unwrap();
    assert!(authority.home_dns_current(&successor));
    assert!(
        !settings.set_local_network_access(on, None).await.unwrap(),
        "no-op is silent"
    );
    assert!(authority.home_dns_current(&successor));
    runtime.stop().await.unwrap();
    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn split_dns_publication_feed_loss_return_revokes_home_and_local_before_latest_reconcile() {
    let on = configured();
    let feed = LocalNetworkFeed::new(1);
    assert!(feed.publish(1, snapshot(9)));
    let control = Arc::new(Control::default());
    let mut runtime = make_runtime(Some(feed.clone()), control.clone());
    runtime.update(&on, TargetState::Unsecured, true).await;
    let authority = control.authority.lock().unwrap().clone().unwrap();
    let buffers = BufferBudget::new(65536);
    let home = authority.home_dns_authorize(home_flow(), &buffers).unwrap();
    let local = authority
        .receive(
            home_flow().source.ip(),
            home_flow().destination.ip(),
            &buffers,
        )
        .unwrap();
    assert!(authority.home_dns_current(&home) && local.current());

    let mut loss = snapshot(10);
    loss.observer_running = false;
    loss.networks.clear();
    assert!(feed.publish(1, loss));
    assert!(feed.publish(1, snapshot(11)));
    // Exactly one runtime notification can be consumed after both publications.
    bounded(runtime.notifications().0).await;
    runtime.update(&on, TargetState::Unsecured, true).await;
    let retained = (authority.home_dns_current(&home), local.current());
    let successor = authority.home_dns_authorize(home_flow(), &buffers).unwrap();
    assert!(
        authority.home_dns_current(&successor),
        "fresh Home work remains eligible"
    );
    runtime.stop().await.unwrap();
    assert_eq!(
        retained,
        (false, false),
        "(old Home query, old Local scope) survived feed loss/return"
    );
}

#[tokio::test]
async fn split_dns_publication_feed_permission_loss_revokes_before_daemon_notification() {
    let on = configured();
    let feed = LocalNetworkFeed::new(1);
    assert!(feed.publish(1, snapshot(9)));
    let control = Arc::new(Control::default());
    let mut runtime = make_runtime(Some(feed.clone()), control.clone());
    runtime.update(&on, TargetState::Unsecured, true).await;
    let authority = control.authority.lock().unwrap().clone().unwrap();
    let buffers = BufferBudget::new(65536);
    let home = authority.home_dns_authorize(home_flow(), &buffers).unwrap();
    let local = authority
        .receive(
            home_flow().source.ip(),
            home_flow().destination.ip(),
            &buffers,
        )
        .unwrap();
    let mut denied = snapshot(10);
    denied.local_ready = false;
    assert!(feed.publish(1, denied));
    let retained_before_notification = (authority.home_dns_current(&home), local.current());
    bounded(runtime.notifications().0).await;
    runtime.update(&on, TargetState::Unsecured, true).await;
    assert!(
        !authority.home_dns_current(&home) && !local.current(),
        "control: consuming the loss revokes"
    );
    runtime.stop().await.unwrap();
    assert_eq!(
        retained_before_notification,
        (false, false),
        "(Home query, Local scope) still admitted after accepted permission loss"
    );
}

#[tokio::test]
async fn split_dns_publication_persisted_off_on_revokes_home_and_local_before_latest_settings_read()
{
    use crate::{InternalDaemonEvent, settings::SettingsPersister};
    let directory = std::env::temp_dir().join(format!(
        "krtek-dns-publication-{:016x}",
        rand::random::<u64>()
    ));
    std::fs::create_dir(&directory).unwrap();
    let mut settings = SettingsPersister::load(&directory).await;
    let on = configured();
    settings
        .set_local_network_access(on.clone(), None)
        .await
        .unwrap();
    let feed = LocalNetworkFeed::new(1);
    assert!(feed.publish(1, snapshot(9)));
    let control = Arc::new(Control::default());
    let mut runtime = make_runtime(Some(feed.clone()), control.clone());
    runtime
        .update(&settings.local_network_access, TargetState::Unsecured, true)
        .await;
    runtime.observe_settings(&mut settings);
    let authority = control.authority.lock().unwrap().clone().unwrap();
    let buffers = BufferBudget::new(65536);
    let home = authority.home_dns_authorize(home_flow(), &buffers).unwrap();
    let local = authority
        .receive(
            home_flow().source.ip(),
            home_flow().destination.ip(),
            &buffers,
        )
        .unwrap();
    let (events, mut received) = mpsc::unbounded_channel();
    // Same payload-free publication as Daemon::start's generic listener.
    settings.register_change_listener(move |_| {
        let _ = events.send(InternalDaemonEvent::SettingsChanged);
    });
    let mut off = on.clone();
    off.enabled = false;
    assert!(
        settings
            .set_local_network_access(off, Some(on.clone()))
            .await
            .unwrap()
    );
    assert!(
        settings
            .set_local_network_access(on.clone(), None)
            .await
            .unwrap()
    );
    assert_eq!(
        SettingsPersister::read_only(&directory)
            .await
            .local_network_access,
        on
    );
    for _ in 0..2 {
        assert!(matches!(
            received.try_recv().unwrap(),
            InternalDaemonEvent::SettingsChanged
        ));
        // The real event handler reads current settings, not the changed policy.
        runtime
            .update(&settings.local_network_access, TargetState::Unsecured, true)
            .await;
    }
    assert!(received.try_recv().is_err());
    let retained = (authority.home_dns_current(&home), local.current());
    runtime.stop().await.unwrap();
    std::fs::remove_dir_all(&directory).unwrap();
    assert_eq!(
        retained,
        (false, false),
        "(old Home query, old Local scope) survived committed policy off/on"
    );
}
