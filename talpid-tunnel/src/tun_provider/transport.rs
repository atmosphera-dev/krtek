//! Android userspace transport selection, before any native descriptor operation.
use super::TunConfig;
use crate::packet_attachment::{
    AttachmentBroker, AttachmentError, AttachmentMode, ConfigurationRequest, TransportCleanup,
};

pub const ROUTER_IPV4: std::net::Ipv4Addr = std::net::Ipv4Addr::new(172, 27, 1, 1);
pub const ROUTER_IPV6: std::net::Ipv6Addr =
    std::net::Ipv6Addr::new(0xfdf0, 0xce4a, 0x801d, 0, 0x172, 0x27, 0x1, 0x1);
pub const LOCAL_ONLY_MTU: u16 = 1280;

pub const ROUTER_SOURCES: talpid_types::relay_flow::RelaySources =
    talpid_types::relay_flow::RelaySources {
        ipv4: Some(ROUTER_IPV4),
        ipv6: Some(ROUTER_IPV6),
    };

pub enum TransportMode {
    Native,
    Managed {
        broker: AttachmentBroker,
        cleanup: TransportCleanup,
    },
}

pub enum UserspaceTun<T> {
    Native(T),
    Managed(ManagedTun),
}

/// Configuration ownership only. No descriptor is acquired or retained here.
pub struct ManagedTun {
    pub broker: AttachmentBroker,
    /// Actual target assignment, before app-facing platform projection.
    pub config: TunConfig,
    pub capture_config: TunConfig,
    pub request: ConfigurationRequest,
}

impl ManagedTun {
    pub fn request(broker: AttachmentBroker, config: TunConfig) -> Result<Self, AttachmentError> {
        let target_config = config.clone();
        #[cfg(target_os = "android")]
        let config = router_config(&config, broker.local_routes());
        let request = broker.request_target_capture(target_config.clone(), config.clone())?;
        Ok(Self {
            broker,
            config: target_config,
            capture_config: config,
            request,
        })
    }
}

/// App-side projection only. The target retains its actual assignment and MTU.
/// Only Local can add a family absent upstream. Its ordinary traffic is captured
/// fail-closed, never mistaken for a supported target family.
pub fn router_config(target: &TunConfig, local_routes: Vec<ipnetwork::IpNetwork>) -> TunConfig {
    let mut config = target.clone();
    let effective = super::AndroidTunConfig::new(target);
    config.routes = effective.routes;
    config.dns_servers = Some(effective.dns_servers);
    config.addresses = effective
        .addresses
        .into_iter()
        .map(|ip| {
            if ip.is_ipv4() {
                ROUTER_IPV4.into()
            } else {
                ROUTER_IPV6.into()
            }
        })
        .collect();
    for (ipv6, route) in [(false, "0.0.0.0/0"), (true, "::/0")] {
        if !target.addresses.iter().any(|ip| ip.is_ipv6() == ipv6)
            && local_routes.iter().any(|route| route.is_ipv6() == ipv6)
        {
            config.addresses.push(if ipv6 {
                ROUTER_IPV6.into()
            } else {
                ROUTER_IPV4.into()
            });
            config.routes.push(route.parse().expect("default route"));
        }
    }
    // Android cannot enable Local IPv6 below its minimum. Never change the
    // target's own carrier MTU or introduce receive-side sizing for this floor.
    if config.addresses.iter().any(std::net::IpAddr::is_ipv6)
        && !target.addresses.iter().any(std::net::IpAddr::is_ipv6)
    {
        config.mtu = config.mtu.max(1280);
    }
    config.routes.extend(local_routes);
    config.routes = super::android_config::normalize_routes(config.routes);
    config.addresses.sort();
    config.addresses.dedup();
    config.allow_lan = false;
    config
}

/// Before target parameters exist, capture both families and a dummy resolver.
pub fn router_blocking_config(local_routes: Vec<ipnetwork::IpNetwork>) -> TunConfig {
    let mut config = super::blocking_config(
        #[cfg(target_os = "windows")]
        std::path::PathBuf::new(),
    );
    config.dns_servers = Some(vec!["192.0.2.1".parse().expect("dummy resolver")]);
    router_config(&config, local_routes)
}

impl TransportMode {
    pub fn selected(attachment: Option<&AttachmentBroker>) -> Self {
        match attachment {
            Some(broker)
                if {
                    let state = broker.snapshot();
                    state.closed || state.mode == AttachmentMode::ManagedRequired
                } =>
            {
                Self::Managed {
                    broker: broker.clone(),
                    cleanup: broker.transport_cleanup(),
                }
            }
            _ => Self::Native,
        }
    }

    pub fn open<T, E>(
        self,
        config: TunConfig,
        managed_error: impl FnOnce(AttachmentError) -> E,
        native: impl FnOnce() -> Result<T, E>,
    ) -> Result<UserspaceTun<T>, E> {
        match self {
            Self::Managed { broker, .. } => ManagedTun::request(broker, config)
                .map(UserspaceTun::Managed)
                .map_err(managed_error),
            Self::Native => native().map(UserspaceTun::Native),
        }
    }

    pub fn reconfigure<E>(
        self,
        config: TunConfig,
        purpose: super::ConfigurationPurpose,
        forced: bool,
        native: impl FnOnce(bool) -> Result<(), E>,
    ) -> Result<Option<ConfigurationRequest>, E>
    where
        E: From<AttachmentError>,
    {
        match self {
            Self::Managed { broker, cleanup } => {
                cleanup.cancel();
                cleanup.tsm_joined();
                let projected = router_config(&config, broker.local_routes());
                broker
                    .request_configuration(config, projected, purpose)
                    .map(Some)
                    .map_err(E::from)
            }
            Self::Native => native(forced).map(|()| None),
        }
    }

    pub fn close(self, native: impl FnOnce()) {
        match self {
            Self::Managed { cleanup, .. } => cleanup.cancel(),
            Self::Native => native(),
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::{cell::Cell, os::fd::AsRawFd, os::unix::net::UnixStream, sync::Arc};
    use talpid_netstack::buffer_budget::BufferBudget;

    #[test]
    fn router_projection_separates_assignments_without_recapturing_resolvers_or_unused_families() {
        let mut target = super::super::blocking_config();
        target.addresses = vec!["10.64.2.3".parse().unwrap()];
        target.routes = vec!["0.0.0.0/0".parse().unwrap()];
        target.dns_servers = Some(vec!["10.0.2.53".parse().unwrap()]);
        target.excluded_packages = vec!["unrelated.excluded.app".into()];
        let saved = target.clone();
        let projected = router_config(&target, vec!["10.0.2.2/32".parse().unwrap()]);
        assert_eq!(target, saved, "projection mutated the target assignment");
        assert_eq!(
            projected.addresses,
            vec!["172.27.1.1".parse::<std::net::IpAddr>().unwrap()]
        );
        assert_eq!(projected.mtu, target.mtu);
        assert_eq!(projected.routes, vec!["0.0.0.0/0".parse().unwrap()]);
        assert_eq!(projected.dns_servers, target.dns_servers);
        assert_eq!(projected.excluded_packages, target.excluded_packages);
        target.addresses[0] = "10.64.9.8".parse().unwrap();
        assert_eq!(
            router_config(&target, vec!["10.0.2.2/32".parse().unwrap()]),
            projected,
            "target assignment rotation leaked into the capture"
        );
        target.mtu = 1420;
        assert_eq!(router_config(&target, vec![]).mtu, 1420);
        let blocking = router_blocking_config(vec!["10.0.2.2/32".parse().unwrap()]);
        assert_eq!(
            blocking.addresses,
            vec![
                std::net::IpAddr::from(ROUTER_IPV4),
                std::net::IpAddr::from(ROUTER_IPV6)
            ]
        );
        assert_eq!(blocking.mtu, 1380);
        for route in ["0.0.0.0/0", "::/0"] {
            assert!(blocking.routes.contains(&route.parse().unwrap()));
        }
        assert_eq!(
            blocking.dns_servers.unwrap(),
            vec!["192.0.2.1".parse::<std::net::IpAddr>().unwrap()]
        );
    }

    #[test]
    fn projection_matches_upstream_mtu_dns_routes_without_local_rules() {
        use super::super::AndroidTunConfig;
        for dual in [false, true] {
            for allow_lan in [false, true] {
                for mtu in [576, 1280, 1380, 1420] {
                    for dns in [
                        None,
                        Some(vec![]),
                        Some(vec!["10.0.2.53".parse().unwrap()]),
                        Some(vec![
                            "1.1.1.1".parse().unwrap(),
                            "fd42::53".parse().unwrap(),
                        ]),
                    ] {
                        let mut target = super::super::blocking_config();
                        target.addresses = vec!["10.64.2.3".parse().unwrap()];
                        target.routes = vec!["0.0.0.0/0".parse().unwrap()];
                        if dual {
                            target.addresses.push("fc00::2".parse().unwrap());
                            target.routes.push("::/0".parse().unwrap());
                            target.ipv6_gateway = Some("fc00::1".parse().unwrap());
                        }
                        target.allow_lan = allow_lan;
                        target.mtu = mtu;
                        target.dns_servers = dns;
                        let upstream = AndroidTunConfig::new(&target);
                        let projected = router_config(&target, vec![]);
                        let actual = AndroidTunConfig::new(&projected);
                        assert_eq!(actual.mtu, upstream.mtu);
                        assert_eq!(actual.dns_servers, upstream.dns_servers);
                        assert_eq!(
                            actual.routes,
                            super::super::android_config::normalize_routes(upstream.routes)
                        );
                        assert_eq!(actual.excluded_packages, upstream.excluded_packages);
                        assert_eq!(
                            actual.addresses,
                            if dual {
                                vec![
                                    std::net::IpAddr::from(ROUTER_IPV4),
                                    std::net::IpAddr::from(ROUTER_IPV6),
                                ]
                            } else {
                                vec![std::net::IpAddr::from(ROUTER_IPV4)]
                            }
                        );
                        assert_eq!(
                            actual.dns_servers.iter().any(std::net::IpAddr::is_ipv6),
                            dual && target
                                .dns_servers
                                .as_ref()
                                .is_some_and(|dns| dns.iter().any(std::net::IpAddr::is_ipv6))
                                || dual && target.dns_servers.is_none()
                        );
                        let routed = |ip: &str| {
                            actual
                                .routes
                                .iter()
                                .any(|route| route.contains(ip.parse().unwrap()))
                        };
                        assert!(routed("1.1.1.1"));
                        assert!(routed("10.64.0.1"));
                        assert!(routed("10.124.0.1"));
                        assert_eq!(routed("10.0.2.53"), !allow_lan);
                        if dual {
                            assert!(routed("fc00::1"));
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn managed_configuration_reconfigure_close_and_failure_exclude_native_fd_operations() {
        let root = BufferBudget::new(64 * 1024 * 1024);
        let broker = AttachmentBroker::new(
            Arc::new(root.reserve(22 * 1024 * 1024).unwrap().region().unwrap()),
            Arc::new(root.reserve(2 * 1024 * 1024).unwrap().region().unwrap()),
            Arc::new(root.reserve(8 * 1024 * 1024).unwrap().region().unwrap()),
        )
        .unwrap();
        let opens = Cell::new(0);
        let duplicates = Cell::new(0);
        let closes = Cell::new(0);
        let native = || -> Result<_, AttachmentError> {
            opens.set(opens.get() + 1);
            let (fd, peer) = UnixStream::pair().unwrap();
            let copy = fd.try_clone().unwrap();
            assert_ne!(fd.as_raw_fd(), copy.as_raw_fd());
            duplicates.set(duplicates.get() + 1);
            Ok((fd, copy, peer))
        };
        let config = super::super::blocking_config();
        // Native control really acquires and duplicates descriptors.
        let UserspaceTun::Native(fds) = TransportMode::selected(Some(&broker))
            .open(config.clone(), |error| error, native)
            .unwrap()
        else {
            panic!("native selection")
        };
        TransportMode::selected(Some(&broker))
            .reconfigure(
                config.clone(),
                super::super::ConfigurationPurpose::Blocking,
                false,
                |forced| {
                    assert!(!forced);
                    drop(native()?);
                    Ok::<_, AttachmentError>(())
                },
            )
            .unwrap();
        TransportMode::selected(Some(&broker))
            .reconfigure(
                config.clone(),
                super::super::ConfigurationPurpose::ForcedRefresh,
                true,
                |forced| {
                    assert!(forced);
                    drop(native()?);
                    Ok::<_, AttachmentError>(())
                },
            )
            .unwrap();
        TransportMode::selected(Some(&broker)).close(|| {
            drop(fds);
            closes.set(closes.get() + 1);
        });
        assert_eq!((opens.get(), duplicates.get(), closes.get()), (3, 3, 1));

        broker.set_mode(AttachmentMode::ManagedRequired).unwrap();
        for forced in [false, true] {
            let UserspaceTun::Managed(mut source) = TransportMode::selected(Some(&broker))
                .open(config.clone(), |error| error, native)
                .unwrap()
            else {
                panic!("managed selection")
            };
            assert_eq!(broker.pending_request().unwrap().config(), &config);
            let operation = TransportMode::selected(Some(&broker))
                .reconfigure(
                    config.clone(),
                    super::super::ConfigurationPurpose::Blocking,
                    forced,
                    |_| {
                        drop(native()?);
                        Ok::<_, AttachmentError>(())
                    },
                )
                .unwrap();
            assert!(futures::executor::block_on(source.request.configured()).is_err());
            assert!(
                operation.is_some(),
                "cancellation is not a completed configuration"
            );
            drop(operation);
            TransportMode::selected(Some(&broker)).close(|| closes.set(closes.get() + 1));
        }
        let UserspaceTun::Managed(mut source) = TransportMode::selected(Some(&broker))
            .open(config.clone(), |error| error, native)
            .unwrap()
        else {
            panic!("managed selection")
        };
        TransportMode::selected(Some(&broker)).close(|| closes.set(closes.get() + 1));
        assert!(futures::executor::block_on(source.request.configured()).is_err());
        broker.close();
        assert!(
            TransportMode::selected(Some(&broker))
                .open(config, |error| error, native)
                .is_err()
        );
        TransportMode::selected(Some(&broker)).close(|| closes.set(closes.get() + 1));
        assert_eq!((opens.get(), duplicates.get(), closes.get()), (3, 3, 1));
    }
}
