//! Ordered internal DNS slots, separate from interface and real resolver IPs.

use std::{
    collections::HashSet,
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use ipnetwork::IpNetwork;

use super::{
    AndroidTunConfig,
    transport::{ROUTER_IPV4, ROUTER_IPV6},
};

const V4_POOLS: &[(&str, u32)] = &[
    ("198.18.0.0/15", 53),
    ("192.0.2.0/24", 53),
    ("198.51.100.0/24", 53),
    ("203.0.113.0/24", 53),
];
const V6_POOLS: &[(&str, u32)] = &[
    ("fd71:7274:656b:53::/64", 0x53),
    ("fd71:7274:656b:54::/64", 0x53),
    ("fd71:7274:656b:55::/64", 0x53),
];

#[derive(Clone, Eq, PartialEq)]
pub struct ResolverSlot {
    pub endpoint: IpAddr,
    pub ordinary: Option<IpAddr>,
}

impl fmt::Debug for ResolverSlot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResolverSlot")
            .field("ipv6", &self.endpoint.is_ipv6())
            .field("has_ordinary", &self.ordinary.is_some())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("no disjoint internal DNS endpoint is available")]
pub struct EndpointCollision;

fn number(address: IpAddr) -> u128 {
    match address {
        IpAddr::V4(ip) => u32::from(ip).into(),
        IpAddr::V6(ip) => u128::from(ip),
    }
}

fn address(value: u128, ipv6: bool) -> IpAddr {
    if ipv6 {
        Ipv6Addr::from(value).into()
    } else {
        Ipv4Addr::from(u32::try_from(value).expect("IPv4 pool bounds")).into()
    }
}

fn last(prefix: IpNetwork) -> u128 {
    let host_bits = if prefix.is_ipv6() { 128 } else { 32 } - u32::from(prefix.prefix());
    let mask = if host_bits == 128 {
        u128::MAX
    } else {
        (1u128 << host_bits) - 1
    };
    number(prefix.network()) | mask
}

fn allocate_one(
    ipv6: bool,
    used: &HashSet<IpAddr>,
    reserved: &[IpNetwork],
) -> Result<IpAddr, EndpointCollision> {
    for (text, offset) in if ipv6 { V6_POOLS } else { V4_POOLS } {
        let pool: IpNetwork = text.parse().expect("constant synthetic DNS pool");
        let end = last(pool);
        let mut candidate = number(pool.network()) + u128::from(*offset);
        while candidate <= end {
            let ip = address(candidate, ipv6);
            let collision_end = reserved
                .iter()
                .filter(|prefix| prefix.is_ipv6() == ipv6 && prefix.contains(ip))
                .map(|prefix| last(*prefix))
                .max();
            if let Some(collision_end) = collision_end {
                let Some(next) = collision_end.checked_add(1) else {
                    break;
                };
                candidate = next;
            } else if used.contains(&ip) {
                candidate += 1;
            } else {
                return Ok(ip);
            }
        }
    }
    Err(EndpointCollision)
}

/// Allocate before applying a capture profile. The caller supplies actual target
/// assignments and gateway/SOCKS reservations, not default capture routes.
/// Deterministic equal inputs retain equal endpoints across reconciliation.
/// Real resolver IPs are never globally reserved from Local by this operation.
pub fn allocate_slots(
    ordinary: &[IpAddr],
    home: IpAddr,
    target_addresses: &[IpAddr],
    target_reservations: &[IpNetwork],
) -> Result<Vec<ResolverSlot>, EndpointCollision> {
    let mut used: HashSet<_> = [IpAddr::V4(ROUTER_IPV4), IpAddr::V6(ROUTER_IPV6), home]
        .into_iter()
        .chain(ordinary.iter().copied())
        .chain(target_addresses.iter().copied())
        .collect();
    let mut slots = Vec::with_capacity(ordinary.len().max(1));
    for resolver in ordinary
        .iter()
        .copied()
        .map(Some)
        .chain(ordinary.is_empty().then_some(None))
    {
        let endpoint = allocate_one(
            resolver.unwrap_or(home).is_ipv6(),
            &used,
            target_reservations,
        )?;
        used.insert(endpoint);
        slots.push(ResolverSlot {
            endpoint,
            ordinary: resolver,
        });
    }
    Ok(slots)
}

/// One indivisible projection retains the original platform configuration as
/// well as its internal DNS mapping. In particular a caller must still submit
/// the original DNS values to platform validation; valid internal endpoints
/// must not hide an invalid custom DNS configuration or its blocking outcome.
#[derive(Clone, Eq, PartialEq)]
pub struct DnsCaptureProjection {
    original: AndroidTunConfig,
    capture: AndroidTunConfig,
    slots: Vec<ResolverSlot>,
}

/// Full capture must keep a DNS-only family blocked outside explicitly admitted
/// receivers. Partial capture retains its ordinary, unsecured routing behavior.
/// This is capture scope, not permission to use an ordinary target or socket.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsCaptureScope {
    Partial,
    Full,
}

impl fmt::Debug for DnsCaptureProjection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DnsCaptureProjection")
            .field("slot_count", &self.slots.len())
            .finish_non_exhaustive()
    }
}

impl DnsCaptureProjection {
    /// `ordinary` is the already family-filtered target list, or the explicit
    /// pre-proxy non-VPN list for Partial. Never feed advertised proxy addresses
    /// back into this constructor. Target assignment/reservations are distinct
    /// from the capture's default routes and Local prefix union.
    pub fn new(
        original: AndroidTunConfig,
        scope: DnsCaptureScope,
        ordinary: &[IpAddr],
        home: IpAddr,
        target_addresses: &[IpAddr],
        target_reservations: &[IpNetwork],
    ) -> Result<Self, EndpointCollision> {
        let slots = allocate_slots(ordinary, home, target_addresses, target_reservations)?;
        let mut capture = original.clone();
        capture.dns_servers = slots.iter().map(|slot| slot.endpoint).collect();
        for slot in &slots {
            // A synthetic destination is routed into the sole capture owner,
            // never assigned as the interface identity or exposed as a listener.
            capture.routes.push(slot.endpoint.into());
            if !capture
                .addresses
                .iter()
                .any(|address| address.is_ipv6() == slot.endpoint.is_ipv6())
            {
                capture.addresses.push(if slot.endpoint.is_ipv6() {
                    ROUTER_IPV6.into()
                } else {
                    ROUTER_IPV4.into()
                });
                if scope == DnsCaptureScope::Full {
                    // As in router_config's Local family union, adding an
                    // address must not permit uncaptured internet in a family
                    // that the original full profile blocked. Existing target
                    // family routes/LAN subtraction are left unchanged.
                    capture.routes.push(
                        if slot.endpoint.is_ipv6() {
                            "::/0"
                        } else {
                            "0.0.0.0/0"
                        }
                        .parse()
                        .expect("default route"),
                    );
                }
            }
        }
        if capture.addresses.iter().any(IpAddr::is_ipv6) {
            capture.mtu = capture.mtu.max(1280);
        }
        Ok(Self {
            original,
            capture: capture.normalized(),
            slots,
        })
    }

    pub fn original(&self) -> &AndroidTunConfig {
        &self.original
    }
    pub fn capture(&self) -> &AndroidTunConfig {
        &self.capture
    }
    pub fn slots(&self) -> &[ResolverSlot] {
        &self.slots
    }

    /// Only the active internal endpoints are reserved from Local. Neither the
    /// ordinary resolver list nor the Home address is globally reserved.
    pub fn internal_destination(&self, address: IpAddr) -> bool {
        self.slots.iter().any(|slot| slot.endpoint == address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_dns_slots_keep_order_duplicates_family_and_original_destination() {
        let ordinary = ["100.64.0.3", "fd00::1", "100.64.0.3"].map(|ip| ip.parse().unwrap());
        let home = "10.77.10.53".parse().unwrap();
        let slots = allocate_slots(&ordinary, home, &[], &[]).unwrap();
        assert_eq!(
            slots
                .iter()
                .map(|slot| slot.ordinary.unwrap())
                .collect::<Vec<_>>(),
            ordinary
        );
        assert_eq!(slots[0].endpoint, "198.18.0.53".parse::<IpAddr>().unwrap());
        assert_eq!(
            slots[1].endpoint,
            "fd71:7274:656b:53::53".parse::<IpAddr>().unwrap()
        );
        assert_eq!(slots[2].endpoint, "198.18.0.54".parse::<IpAddr>().unwrap());
        assert_eq!(slots, allocate_slots(&ordinary, home, &[], &[]).unwrap());
    }

    #[test]
    fn split_dns_empty_ordinary_list_keeps_one_home_capable_endpoint_without_upstream() {
        for home in ["10.77.10.53", "fd71:7274:656b:10::53"] {
            let home: IpAddr = home.parse().unwrap();
            let slots = allocate_slots(&[], home, &[], &[]).unwrap();
            assert_eq!(slots.len(), 1);
            assert_eq!(slots[0].ordinary, None);
            assert_eq!(slots[0].endpoint.is_ipv6(), home.is_ipv6());
        }
    }

    #[test]
    fn split_dns_slots_skip_home_resolvers_targets_and_real_reservations() {
        let home = "198.18.0.53".parse().unwrap();
        let ordinary = ["198.18.0.54".parse().unwrap()];
        let targets = ["198.18.0.55".parse().unwrap()];
        let reserved = ["198.18.0.56/31".parse().unwrap()];
        let slots = allocate_slots(&ordinary, home, &targets, &reserved).unwrap();
        assert_eq!(slots[0].endpoint, "198.18.0.58".parse::<IpAddr>().unwrap());
        assert_eq!(slots[0].ordinary, Some(ordinary[0]));
        assert_ne!(slots[0].endpoint, IpAddr::V4(ROUTER_IPV4));
        assert_ne!(slots[0].endpoint, IpAddr::V6(ROUTER_IPV6));
    }

    #[test]
    fn split_dns_reserved_pool_uses_disjoint_pool_or_explicit_failure() {
        let ordinary = ["1.1.1.1".parse().unwrap()];
        let home = "10.77.10.53".parse().unwrap();
        let slots =
            allocate_slots(&ordinary, home, &[], &["198.18.0.0/15".parse().unwrap()]).unwrap();
        assert_eq!(slots[0].endpoint, "192.0.2.53".parse::<IpAddr>().unwrap());
        assert_eq!(
            allocate_slots(&ordinary, home, &[], &["0.0.0.0/0".parse().unwrap()]),
            Err(EndpointCollision)
        );
    }

    #[test]
    fn split_dns_slots_preserve_every_blocker_destination_without_reserving_real_dns() {
        let home = "10.77.10.53".parse().unwrap();
        for bits in 0..64 {
            let resolver = IpAddr::V4(Ipv4Addr::new(100, 64, 0, bits));
            let slots =
                allocate_slots(&[resolver], home, &[], &[super::super::SOCKS_PROXIES]).unwrap();
            assert_eq!(slots.len(), 1);
            assert_eq!(slots[0].ordinary, Some(resolver));
            assert_eq!(slots[0].endpoint, "198.18.0.53".parse::<IpAddr>().unwrap());
            assert_ne!(slots[0].endpoint, resolver);
        }
    }

    #[test]
    fn split_dns_slots_expose_only_actual_endpoint_families_not_home_transport_family() {
        let home4 = "10.77.10.53".parse().unwrap();
        let home6 = "fd71:7274:656b:10::53".parse().unwrap();
        for home in [home4, home6] {
            for resolver in ["1.1.1.1", "fd00::53"] {
                let resolver: IpAddr = resolver.parse().unwrap();
                let slots = allocate_slots(&[resolver], home, &[], &[]).unwrap();
                assert_eq!(slots[0].endpoint.is_ipv6(), resolver.is_ipv6());
            }
        }
    }

    #[test]
    fn split_dns_ipv6_slots_skip_entire_colliding_prefix_without_searching_each_host() {
        let resolver = "fd00::53".parse().unwrap();
        let home = "fd71:7274:656b:53::53".parse().unwrap();
        let reserved = ["fd71:7274:656b:53::/64".parse().unwrap()];
        let slots = allocate_slots(&[resolver], home, &[], &reserved).unwrap();
        assert_eq!(
            slots[0].endpoint,
            "fd71:7274:656b:54::53".parse::<IpAddr>().unwrap()
        );
        assert_eq!(slots[0].ordinary, Some(resolver));
        assert_eq!(
            allocate_slots(&[resolver], home, &[], &["::/0".parse().unwrap()]),
            Err(EndpointCollision)
        );
    }

    fn capture_v4() -> AndroidTunConfig {
        AndroidTunConfig {
            addresses: vec![ROUTER_IPV4.into()],
            dns_servers: vec![],
            routes: vec!["10.77.10.53/32".parse().unwrap()],
            excluded_packages: vec!["ordinary.excluded".into()],
            mtu: 576,
        }
    }

    #[test]
    fn split_dns_projection_dns_only_family_adds_host_route_not_ordinary_connectivity() {
        let original = capture_v4();
        let home = "fd71:7274:656b:10::53".parse().unwrap();
        let projection = DnsCaptureProjection::new(
            original.clone(),
            DnsCaptureScope::Partial,
            &[],
            home,
            &[],
            &[],
        )
        .unwrap();
        assert_eq!(projection.original(), &original);
        let slot = &projection.slots()[0];
        assert_eq!(slot.ordinary, None);
        assert_eq!(projection.capture().dns_servers, vec![slot.endpoint]);
        assert_eq!(
            projection.capture().addresses,
            vec![IpAddr::from(ROUTER_IPV4), IpAddr::from(ROUTER_IPV6)]
        );
        assert_eq!(projection.capture().mtu, 1280);
        assert_eq!(original.mtu, 576);
        assert_eq!(
            projection.capture().excluded_packages,
            original.excluded_packages
        );
        assert_eq!(projection.capture().routes.len(), 2);
        assert!(
            projection
                .capture()
                .routes
                .contains(&IpNetwork::from(slot.endpoint))
        );
        assert!(
            !projection
                .capture()
                .routes
                .iter()
                .any(|route| route.prefix() == 0)
        );
        assert!(projection.internal_destination(slot.endpoint));
        assert!(!projection.internal_destination(home));
        assert!(!projection.internal_destination(ROUTER_IPV6.into()));
    }

    #[test]
    fn split_dns_projection_uses_filtered_order_and_keeps_target_assignment_unchanged() {
        let mut target = super::super::blocking_config(
            #[cfg(target_os = "windows")]
            std::path::PathBuf::new(),
        );
        target.addresses = vec!["10.64.2.3".parse().unwrap()];
        target.routes = vec!["0.0.0.0/0".parse().unwrap()];
        target.ipv6_gateway = None;
        target.dns_servers = Some(vec![
            "1.1.1.1".parse().unwrap(),
            "fd00::53".parse().unwrap(),
            "100.64.0.63".parse().unwrap(),
        ]);
        target.mtu = 576;
        let before = target.clone();
        let original = super::super::transport::router_config(&target, vec![]);
        let original = AndroidTunConfig::new(&original);
        let expected = ["1.1.1.1".parse().unwrap(), "100.64.0.63".parse().unwrap()];
        assert_eq!(original.dns_servers, expected);
        let projection = DnsCaptureProjection::new(
            original.clone(),
            DnsCaptureScope::Full,
            &original.dns_servers,
            "fd71:7274:656b:10::53".parse().unwrap(),
            &target.addresses,
            &target
                .gateways()
                .into_iter()
                .map(IpNetwork::from)
                .collect::<Vec<_>>(),
        )
        .unwrap();
        assert_eq!(target, before);
        assert_eq!(
            projection
                .slots()
                .iter()
                .map(|slot| slot.ordinary.unwrap())
                .collect::<Vec<_>>(),
            expected
        );
        assert_eq!(projection.capture().addresses, original.addresses);
        assert_eq!(projection.capture().mtu, 576);
        assert_eq!(projection.capture().routes, original.routes);
        assert!(!projection.capture().addresses.iter().any(IpAddr::is_ipv6));
        for resolver in expected {
            assert!(!projection.internal_destination(resolver));
        }
    }

    #[test]
    fn split_dns_projection_retains_invalid_originals_for_real_platform_validation() {
        let mut original = capture_v4();
        original.dns_servers = vec!["0.0.0.0".parse().unwrap(), "127.0.0.1".parse().unwrap()];
        let projection = DnsCaptureProjection::new(
            original.clone(),
            DnsCaptureScope::Full,
            &original.dns_servers,
            "10.77.10.53".parse().unwrap(),
            &[],
            &[],
        )
        .unwrap();
        assert_eq!(projection.original(), &original);
        assert_eq!(
            projection
                .slots()
                .iter()
                .map(|slot| slot.ordinary.unwrap())
                .collect::<Vec<_>>(),
            original.dns_servers
        );
        assert!(
            projection
                .capture()
                .dns_servers
                .iter()
                .all(|server| !server.is_unspecified() && !server.is_loopback())
        );
        assert!(!format!("{projection:?}").contains("127.0.0.1"));
    }

    #[test]
    fn split_dns_projection_secured_dns_only_family_retains_full_capture_blocking() {
        let mut observations = Vec::new();
        for ipv6 in [false, true] {
            let original = AndroidTunConfig {
                addresses: vec![if ipv6 {
                    ROUTER_IPV6.into()
                } else {
                    ROUTER_IPV4.into()
                }],
                dns_servers: vec![],
                routes: vec![if ipv6 { "::/0" } else { "0.0.0.0/0" }.parse().unwrap()],
                excluded_packages: vec!["ordinary.excluded".into()],
                mtu: 1280,
            };
            let home: IpAddr = if ipv6 {
                "10.77.10.53"
            } else {
                "fd71:7274:656b:10::53"
            }
            .parse()
            .unwrap();
            let assigned = [if ipv6 { "fd00::2" } else { "10.64.2.3" }.parse().unwrap()];
            let projection = DnsCaptureProjection::new(
                original.clone(),
                DnsCaptureScope::Full,
                &[],
                home,
                &assigned,
                &[],
            )
            .unwrap();
            let missing_default = if ipv6 { "0.0.0.0/0" } else { "::/0" }.parse().unwrap();
            assert_eq!(projection.original(), &original);
            assert_eq!(projection.slots()[0].ordinary, None);
            assert_eq!(
                projection.capture().excluded_packages,
                original.excluded_packages
            );
            observations.push(projection.capture().routes.contains(&missing_default));
        }
        assert_eq!(
            observations,
            vec![true, true],
            "DNS must not open an otherwise blocked target family"
        );
    }

    #[test]
    fn split_dns_projection_collision_fails_before_any_profile_is_applied() {
        let original = capture_v4();
        assert_eq!(
            DnsCaptureProjection::new(
                original.clone(),
                DnsCaptureScope::Partial,
                &["1.1.1.1".parse().unwrap()],
                "10.77.10.53".parse().unwrap(),
                &[],
                &["0.0.0.0/0".parse().unwrap()]
            ),
            Err(EndpointCollision)
        );
        assert_eq!(original, capture_v4());
    }
}
