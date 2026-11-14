//! Pure upstream VpnService projection, shared by JNI and host-compiled proofs.
use super::{SOCKS_PROXIES, TunConfig};
use ipnetwork::IpNetwork;
use std::net::IpAddr;
use talpid_types::net::{
    ALLOWED_LAN_MULTICAST_NETS, ALLOWED_LAN_NETS, ipnetwork_sub::IpNetworkSub,
};

/// Only fields consumed by Android's Builder, not target assignment metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AndroidTunConfig {
    pub addresses: Vec<IpAddr>,
    pub dns_servers: Vec<IpAddr>,
    pub routes: Vec<IpNetwork>,
    pub excluded_packages: Vec<String>,
    pub mtu: u16,
}

impl AndroidTunConfig {
    pub fn new(config: &TunConfig) -> Self {
        Self {
            addresses: config.addresses.clone(),
            dns_servers: Self::resolve_dns_servers(config),
            routes: Self::resolve_routes(config),
            excluded_packages: config.excluded_packages.clone(),
            mtu: config.mtu,
        }
    }

    /// Normalize set-like inputs, retaining upstream's ordered DNS list.
    pub fn normalized(mut self) -> Self {
        self.addresses.sort();
        self.addresses.dedup();
        self.excluded_packages.sort();
        self.excluded_packages.dedup();
        self.routes = normalize_routes(self.routes);
        self
    }

    /// Return custom DNS servers, or gateways if unspecified. An empty list disables DNS.
    fn resolve_dns_servers(config: &TunConfig) -> Vec<IpAddr> {
        // Upstream: any IPv6 DNS setting would enable IPv6 when it is unavailable.
        let want_ipv6 = |ip: &IpAddr| config.ipv6_gateway.is_some() || !ip.is_ipv6();
        config
            .dns_servers
            .clone()
            .unwrap_or_else(|| config.gateways())
            .into_iter()
            .filter(want_ipv6)
            .collect()
    }

    /// Upstream LAN subtraction, retaining relay gateways and SOCKS destinations.
    fn resolve_routes(config: &TunConfig) -> Vec<IpNetwork> {
        if !config.allow_lan {
            return config.routes.clone();
        }
        let required_ipv4_routes = vec![
            IpNetwork::from(IpAddr::from(config.ipv4_gateway)),
            SOCKS_PROXIES,
        ];
        let required_ipv6_routes = config
            .ipv6_gateway
            .map(|addr| IpNetwork::from(IpAddr::from(addr)))
            .into_iter()
            .collect::<Vec<IpNetwork>>();
        let (original_lan_ipv4_networks, original_lan_ipv6_networks) = Self::allowed_lan_networks()
            .cloned()
            .partition::<Vec<_>, _>(|network| network.is_ipv4());
        let lan_ipv4_networks = original_lan_ipv4_networks
            .into_iter()
            .flat_map(|network| network.sub_all(required_ipv4_routes.clone()))
            .collect::<Vec<_>>();
        let lan_ipv6_networks = original_lan_ipv6_networks
            .into_iter()
            .flat_map(|network| network.sub_all(required_ipv6_routes.clone()))
            .collect::<Vec<_>>();
        config
            .routes
            .iter()
            .flat_map(|&route| {
                if route.is_ipv4() {
                    route.sub_all(lan_ipv4_networks.clone())
                } else {
                    route.sub_all(lan_ipv6_networks.clone())
                }
            })
            .collect()
    }

    fn allowed_lan_networks() -> impl Iterator<Item = &'static IpNetwork> {
        ALLOWED_LAN_NETS
            .iter()
            .chain(ALLOWED_LAN_MULTICAST_NETS.iter())
    }
}

pub(super) fn normalize_routes(routes: Vec<IpNetwork>) -> Vec<IpNetwork> {
    let mut routes = routes
        .into_iter()
        .map(|route| IpNetwork::new(route.network(), route.prefix()).expect("valid network"))
        .collect::<Vec<_>>();
    routes.sort();
    routes.dedup();
    routes
        .iter()
        .copied()
        .filter(|route| {
            !routes.iter().any(|other| {
                other.is_ipv4() == route.is_ipv4()
                    && other.prefix() < route.prefix()
                    && other.contains(route.network())
            })
        })
        .collect()
}
