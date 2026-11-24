#![cfg(target_os = "android")]
//! See [AndroidDnsResolver].

use async_trait::async_trait;
use hickory_resolver::Resolver;
use hickory_resolver::config::*;
use mullvad_api::DnsResolver;
use std::{
    io,
    net::SocketAddr,
    os::fd::{AsRawFd, BorrowedFd},
};
use talpid_core::connectivity_listener::ConnectivityListener;
use talpid_tunnel::tun_provider::local_network::LocalNetworkPlatform;

pub(crate) use crate::android_dns_io::DnsTarget;
use crate::android_dns_io::{DnsPlatform, DnsRuntime, PhysicalDns};

impl DnsPlatform for LocalNetworkPlatform {
    fn with_capture<T>(&self, action: impl FnOnce(i64) -> io::Result<T>) -> io::Result<T> {
        self.with_dns_capture_epoch(action)
            .map_err(io::Error::other)?
    }

    fn physical_dns(&self) -> io::Result<Option<PhysicalDns>> {
        Ok(self
            .own_dns_snapshot()
            .map_err(io::Error::other)?
            .map(|snapshot| PhysicalDns {
                token: snapshot.token,
                interface: snapshot.interface_index as u32,
                servers: snapshot.dns_servers,
            }))
    }

    fn own_socket(&self, epoch: i64, token: i64, fd: Option<BorrowedFd<'_>>) -> io::Result<bool> {
        self.own_dns_socket(epoch, token, fd.map(|fd| fd.as_raw_fd()))
            .map_err(io::Error::other)
    }
}

/// A non-blocking DNS resolver. The default resolver uses `getaddrinfo`, which often prevents the
/// tokio runtime from being dropped, since it waits indefinitely on blocking threads. This is
/// particularly bad on Android, so we use a non-blocking resolver instead.
#[derive(Clone)]
pub struct AndroidDnsResolver {
    connectivity_listener: ConnectivityListener,
    platform: LocalNetworkPlatform,
    target: DnsTarget,
}

impl AndroidDnsResolver {
    pub(crate) fn new(
        connectivity_listener: ConnectivityListener,
        platform: LocalNetworkPlatform,
        target: DnsTarget,
    ) -> Self {
        Self {
            connectivity_listener,
            platform,
            target,
        }
    }

    fn upstream_servers(&self) -> io::Result<Vec<std::net::IpAddr>> {
        self.connectivity_listener
            .current_dns_servers()
            .map_err(|err| io::Error::other(format!("Failed to retrieve current servers: {err}")))
    }
}

#[async_trait]
impl DnsResolver for AndroidDnsResolver {
    async fn resolve(&self, host: String) -> io::Result<Vec<SocketAddr>> {
        let (runtime, ips) =
            DnsRuntime::select(self.platform.clone(), self.target.clone(), || {
                self.upstream_servers()
            })?;
        let group = ips.into_iter().map(NameServerConfig::udp_and_tcp).collect();
        let config = ResolverConfig::from_parts(None, vec![], group);

        let mut opts = ResolverOpts::default();
        opts.attempts = 0;
        opts.use_hosts_file = ResolveHosts::Never;

        let resolver = Resolver::builder_with_config(config, runtime.clone())
            .with_options(opts)
            .build()
            .map_err(|err| io::Error::other(format!("Failed to create DNS resolver: {err}")))?;

        let lookup = resolver
            .lookup_ip(host)
            .await
            .map_err(|err| io::Error::other(format!("lookup_ip failed: {err}")))?;

        runtime.run(|| Ok(lookup.iter().map(|ip| (ip, 0).into()).collect()))
    }
}
