//! Home association uses the existing Local eligibility evaluator, not any
//! matching rule or a separate less restrictive network-selection path.

use super::tests::{observation, policy, route};
use super::*;
use crate::settings::local_network_access::split_dns::SplitDnsPolicy;

fn home_policy() -> LocalNetworkAccess {
    let mut home = policy(true);
    let mut unrelated = home.rules[0].clone();
    unrelated.id = Uuid::from_u128(2);
    unrelated.ssid_ids.clear();
    home.rules.push(unrelated);
    home.split_dns = SplitDnsPolicy {
        enabled: true,
        suffixes: vec!["home.".into()],
        home_resolver: Some("10.0.2.53".parse().unwrap()),
        local_rule_id: Some(home.rules[0].id),
    };
    home
}

fn associated(
    policy: &LocalNetworkAccess,
    observed: &NetworkObservation,
) -> Result<NetworkLease, DeliveryRefusal> {
    evaluate_associated(
        policy,
        observed,
        policy.split_dns.home_resolver.unwrap(),
        policy.split_dns.local_rule_id.unwrap(),
    )
}

#[test]
fn split_dns_home_association_cannot_borrow_an_unrelated_any_network_rule() {
    let configured = home_policy();
    let mut observed = observation();
    observed.networks[0].ssid = Some(SsidIdentity::from_bytes(b"guest-wifi".to_vec()).unwrap());
    assert!(
        evaluate(
            &configured,
            &observed,
            configured.split_dns.home_resolver.unwrap()
        )
        .is_ok()
    );
    assert_eq!(
        associated(&configured, &observed),
        Err(DeliveryRefusal::DifferentWifi)
    );
    observed.networks[0].ssid = None;
    assert_eq!(
        associated(&configured, &observed),
        Err(DeliveryRefusal::WifiNameUnavailable)
    );
    observed.permissions.as_mut().unwrap().precise_location = false;
    assert_eq!(
        associated(&configured, &observed),
        Err(DeliveryRefusal::WifiNameUnavailable)
    );
}

#[test]
fn split_dns_home_association_keeps_ordinary_union_but_returns_only_selected_rule() {
    let configured = home_policy();
    let observed = observation();
    let home = associated(&configured, &observed).unwrap();
    let ordinary = evaluate(&configured, &observed, home.destination).unwrap();
    assert_eq!(home.rule_ids, vec![Uuid::from_u128(1)]);
    assert_eq!(
        ordinary.rule_ids,
        vec![Uuid::from_u128(1), Uuid::from_u128(2)]
    );
    assert_eq!(home.network_handle, ordinary.network_handle);
    assert_eq!(home.interface_index, ordinary.interface_index);
    assert!(home.needs_wifi_name);
    assert!(!ordinary.needs_wifi_name);
    assert_eq!(home.sequence, observed.sequence);
    assert!(home.is_current_associated(&configured, &observed, Uuid::from_u128(1)));
    assert!(
        !home.is_current(&configured, &observed),
        "ordinary union contains an additional rule, not this scoped grant"
    );
    assert!(!ordinary.is_current_associated(&configured, &observed, Uuid::from_u128(1)));
    assert!(!home.is_current_associated(&configured, &observed, Uuid::from_u128(2)));
    let mut successor = observed.clone();
    successor.sequence += 1;
    assert!(home.is_current_associated(&configured, &successor, Uuid::from_u128(1)));
    successor.networks[0].handle += 1;
    assert!(!home.is_current_associated(&configured, &successor, Uuid::from_u128(1)));
}

#[test]
fn split_dns_home_association_requires_enabled_covered_existing_rule_and_master() {
    let mut configured = home_policy();
    let observed = observation();
    configured.rules[0].enabled = false;
    assert_eq!(
        associated(&configured, &observed),
        Err(DeliveryRefusal::NoMatchingRule)
    );
    assert!(
        evaluate(
            &configured,
            &observed,
            configured.split_dns.home_resolver.unwrap()
        )
        .is_ok()
    );
    configured.rules[0].enabled = true;
    configured.rules[0].cidrs = vec!["192.168.0.0/16".parse().unwrap()];
    assert_eq!(
        associated(&configured, &observed),
        Err(DeliveryRefusal::NoMatchingRule)
    );
    configured.rules.remove(0);
    assert_eq!(
        associated(&configured, &observed),
        Err(DeliveryRefusal::NoMatchingRule)
    );
    configured.enabled = false;
    assert_eq!(
        associated(&configured, &observed),
        Err(DeliveryRefusal::PolicyOff)
    );
}

#[test]
fn split_dns_home_association_never_selects_cellular_or_ambiguous_home_networks() {
    let configured = home_policy();
    let mut observed = observation();
    observed.networks[0].transport = PhysicalTransport::Other;
    assert_eq!(
        associated(&configured, &observed),
        Err(DeliveryRefusal::NoEligibleNetwork)
    );
    observed = observation();
    let mut second = observed.networks[0].clone();
    second.handle += 1;
    observed.networks.push(second);
    assert_eq!(
        associated(&configured, &observed),
        Err(DeliveryRefusal::MultipleNetworks)
    );
    observed.networks[1].ssid = Some(SsidIdentity::from_bytes(b"other-wifi".to_vec()).unwrap());
    assert_eq!(
        associated(&configured, &observed).unwrap().network_handle,
        observed.networks[0].handle
    );
    // The unconditioned ordinary rule still sees both networks, unchanged.
    assert_eq!(
        evaluate(
            &configured,
            &observed,
            configured.split_dns.home_resolver.unwrap()
        ),
        Err(DeliveryRefusal::MultipleNetworks)
    );
}

#[test]
fn split_dns_home_association_retains_link_scope_and_physical_route_refusals() {
    let mut configured = home_policy();
    configured.split_dns.home_resolver = Some("fe80::53".parse().unwrap());
    let mut observed = observation();
    observed.networks[0].addresses.push(PhysicalAddress {
        prefix: "fe80::1/64".parse().unwrap(),
        usable: true,
    });
    observed.networks[0]
        .routes
        .push(route("fe80::/64", RTN_UNICAST, None));
    let grant = associated(&configured, &observed).unwrap();
    assert_eq!(grant.scope_id, 15);
    observed.networks[0].routes.last_mut().unwrap().route_type = RTN_UNREACHABLE;
    assert_eq!(
        associated(&configured, &observed),
        Err(DeliveryRefusal::NoEligibleNetwork)
    );
    observed.networks[0].routes.last_mut().unwrap().route_type = 0;
    assert_eq!(
        associated(&configured, &observed),
        Err(DeliveryRefusal::RouteUnknown)
    );
}
