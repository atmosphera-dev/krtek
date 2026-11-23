use super::*;
use std::sync::atomic::{AtomicI64, AtomicUsize};
use talpid_netstack::buffer_budget::BufferBudget;
use talpid_tunnel::android_frontend::{CaptureConfig, CaptureHandover, SystemDnsSnapshot};
use talpid_types::{
    capture_network::{CaptureExpectation, CaptureNetworkFeed},
    relay_flow::{RelayCaptureGeneration, RelayCaptureOwner, RelaySources},
};

struct Platform {
    token: AtomicI64,
    lockdown: AtomicBool,
    checks: AtomicUsize,
    prepares: AtomicUsize,
}
impl FrontendPlatform for Platform {
    fn system_dns(&self) -> Option<SystemDnsSnapshot> {
        Some(SystemDnsSnapshot {
            token: self.token.load(Ordering::Acquire),
            dns_servers: vec!["10.77.10.54".parse().unwrap(), "fe80::54".parse().unwrap()],
            interface_index: 17,
        })
    }
    fn system_dns_current(&self, token: i64) -> bool {
        self.checks.fetch_add(1, Ordering::Relaxed);
        token == self.token.load(Ordering::Acquire) && !self.lockdown.load(Ordering::Acquire)
    }
    fn prepare_system_dns(&self, _: i32, token: i64) -> io::Result<()> {
        if !self.system_dns_current(token) {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        self.prepares.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
    fn open(
        &self,
        _: i64,
        _: &CaptureConfig,
    ) -> io::Result<talpid_tunnel::tun_provider::AppliedTun> {
        unreachable!()
    }
    fn handover(&self, _: i64, _: i64, _: &CaptureConfig) -> CaptureHandover {
        unreachable!()
    }
    fn capture_feed(&self) -> Arc<CaptureNetworkFeed> {
        unreachable!()
    }
    fn expectation(&self, _: &CaptureConfig, _: String) -> io::Result<CaptureExpectation> {
        unreachable!()
    }
    fn bind(&self, _: i64, _: &str) -> io::Result<bool> {
        unreachable!()
    }
    fn closed(&self, _: i64) -> io::Result<()> {
        unreachable!()
    }
}
fn fixture() -> (SystemIo, Arc<Platform>, RelayCaptureOwner, ReceiveScope) {
    let platform = Arc::new(Platform {
        token: AtomicI64::new(7),
        lockdown: AtomicBool::new(false),
        checks: AtomicUsize::new(0),
        prepares: AtomicUsize::new(0),
    });
    let buffers = Arc::new(BufferBudget::new(4 * 1024 * 1024));
    let owner = RelayCaptureOwner::with_identity(
        RelayCaptureGeneration::fresh().unwrap(),
        "partial",
        None,
        RelaySources {
            ipv4: Some("172.27.1.1".parse().unwrap()),
            ipv6: Some("fdf0:ce4a:801d::172:27:1:1".parse().unwrap()),
        },
        1280,
        &*buffers,
    )
    .unwrap();
    let scope = ReceiveScope::new(
        "172.27.1.1".parse().unwrap(),
        "10.77.10.54".parse().unwrap(),
        &*buffers,
    )
    .unwrap();
    let system = SystemIo::new(platform.clone(), buffers);
    system.partial.store(true, Ordering::Release);
    (system, platform, owner, scope)
}
#[test]
fn split_dns_partial_queries_read_lockdown_and_never_revive_denied_work() {
    let (system, platform, capture, scope) = fixture();
    for tcp in [false, true] {
        let query = system
            .authorize(
                "10.77.10.54:53".parse().unwrap(),
                tcp,
                scope.clone(),
                capture.capability(),
            )
            .unwrap();
        assert!(query.current());
        platform.lockdown.store(true, Ordering::Release);
        assert!(!query.current());
        assert!(
            system
                .authorize(
                    "10.77.10.54:53".parse().unwrap(),
                    tcp,
                    scope.clone(),
                    capture.capability()
                )
                .is_err()
        );
        platform.lockdown.store(false, Ordering::Release);
        assert!(!query.current());
    }
    assert!(platform.checks.load(Ordering::Acquire) >= 6);
    assert_eq!(platform.prepares.load(Ordering::Acquire), 0);
}
#[test]
fn split_dns_partial_network_incarnation_and_capture_mode_fence_queries() {
    let (system, platform, capture, scope) = fixture();
    let query = system
        .authorize(
            "10.77.10.54:53".parse().unwrap(),
            false,
            scope.clone(),
            capture.capability(),
        )
        .unwrap();
    platform.token.store(8, Ordering::Release);
    assert!(!query.current());
    platform.token.store(7, Ordering::Release);
    assert!(!query.current());
    let query = system
        .authorize(
            "10.77.10.54:53".parse().unwrap(),
            true,
            scope.clone(),
            capture.capability(),
        )
        .unwrap();
    system.partial.store(false, Ordering::Release);
    assert!(!query.current());
    system.partial.store(true, Ordering::Release);
    assert!(!query.current());
    assert!(
        system
            .authorize(
                "10.77.10.53:53".parse().unwrap(),
                false,
                scope,
                capture.capability()
            )
            .is_err()
    );
}

#[test]
fn split_dns_partial_link_local_resolver_keeps_underlying_interface_scope() {
    let (system, _, capture, _) = fixture();
    let buffers = BufferBudget::new(4096);
    let scope = ReceiveScope::new(
        "fdf0:ce4a:801d::172:27:1:1".parse().unwrap(),
        "fe80::54".parse().unwrap(),
        &buffers,
    )
    .unwrap();
    let query = system
        .authorize(
            "[fe80::54]:53".parse().unwrap(),
            false,
            scope,
            capture.capability(),
        )
        .unwrap();
    let SocketAddr::V6(destination) = query.destination else {
        panic!("IPv6 resolver")
    };
    assert_eq!(destination.scope_id(), 17);
    assert_eq!(
        destination.ip(),
        &"fe80::54".parse::<std::net::Ipv6Addr>().unwrap()
    );
}
