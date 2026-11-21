use super::*;
use crate::local_delivery::tests::{observation, policy};
use hickory_proto::{
    op::{Message, Query},
    rr::{Name, RecordType},
};
use mullvad_types::settings::local_network_access::{
    LocalNetworkAccess, split_dns::SplitDnsPolicy,
};
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use talpid_netstack::buffer_budget::BufferBudget;

fn configured() -> LocalNetworkAccess {
    let mut on = policy();
    on.split_dns = SplitDnsPolicy {
        enabled: true,
        suffixes: vec!["home.".into()],
        home_resolver: Some("10.0.2.2".parse().unwrap()),
        local_rule_id: Some(on.rules[0].id),
    };
    on
}

fn client() -> SocketAddr {
    "172.27.1.1:49152".parse().unwrap()
}

fn message() -> Message {
    let mut message = Message::query();
    message.add_query(Query::query(
        Name::from_ascii("nonce.home.").unwrap(),
        RecordType::A,
    ));
    message
}

fn authority(on: &LocalNetworkAccess) -> Arc<DeliveryAuthority> {
    let authority = Arc::new(DeliveryAuthority::new(on, Arc::new(|_, _| Ok(()))));
    authority.update(on, Some(observation()));
    authority
}

#[tokio::test]
async fn split_dns_home_path_local_leases_hide_resolver_and_keep_transport_independent() {
    let on = configured();
    let authority = authority(&on);
    let budget = Arc::new(BufferBudget::new(256 * 1024));
    let path: Box<dyn HomeDnsPath> =
        Box::new(LocalHomeDnsPath::new(authority.clone(), budget.clone()));
    let udp = path.authorize(client(), Protocol::Udp).unwrap();
    let tcp = path.authorize(client(), Protocol::Tcp).unwrap();
    let used = budget.used();
    assert!(
        used > 8192,
        "query grants and capability backing must stay charged"
    );
    assert!(udp.current() && tcp.current());
    drop(udp);
    assert!(
        tcp.current(),
        "dropping a UDP query revoked a sibling TCP query"
    );
    assert!(budget.used() < used);
    drop(tcp);
    path.close().await.unwrap();
    authority.update(&on, Some(observation()));
    assert_eq!(budget.used(), 0);
}

#[tokio::test]
async fn split_dns_home_path_local_policy_and_network_revocation_never_revive_a_query() {
    let on = configured();
    let authority = authority(&on);
    let path = LocalHomeDnsPath::new(authority.clone(), Arc::new(BufferBudget::new(256 * 1024)));
    for network_loss in [false, true] {
        let query = path.authorize(client(), Protocol::Udp).unwrap();
        let waiting = query.retired();
        tokio::pin!(waiting);
        assert!(futures::poll!(waiting.as_mut()).is_pending());
        if network_loss {
            authority.update(&on, None);
            authority.update(&on, Some(observation()));
        } else {
            let mut off = on.clone();
            off.split_dns.enabled = false;
            authority.update_policy(&off);
            authority.update_policy(&on);
        }
        tokio::time::timeout(Duration::from_secs(1), waiting)
            .await
            .unwrap();
        assert!(!query.current());
        assert!(
            query
                .exchange(Duration::from_secs(1), message())
                .await
                .is_err()
        );
        assert!(path.authorize(client(), Protocol::Tcp).unwrap().current());
    }
    path.close().await.unwrap();
}

#[tokio::test]
async fn split_dns_home_path_local_close_retires_existing_leases_and_refuses_new_work() {
    let on = configured();
    let authority = authority(&on);
    let path = LocalHomeDnsPath::new(authority, Arc::new(BufferBudget::new(256 * 1024)));
    let query = path.authorize(client(), Protocol::Udp).unwrap();
    let waiting = query.retired();
    tokio::pin!(waiting);
    assert!(futures::poll!(waiting.as_mut()).is_pending());
    path.close().await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), waiting)
        .await
        .unwrap();
    assert!(!query.current());
    assert!(path.authorize(client(), Protocol::Udp).is_err());
    assert!(path.authorize(client(), Protocol::Tcp).is_err());
    assert!(
        query
            .exchange(Duration::from_secs(1), message())
            .await
            .is_err()
    );
    path.close().await.unwrap();
}

#[tokio::test]
async fn split_dns_home_path_local_denial_or_resource_failure_never_prepares_a_socket() {
    let on = configured();
    let prepared = Arc::new(AtomicUsize::new(0));
    let count = prepared.clone();
    let authority = Arc::new(DeliveryAuthority::new(
        &on,
        Arc::new(move |_, _| {
            count.fetch_add(1, SeqCst);
            Ok(())
        }),
    ));
    authority.update(&on, Some(observation()));
    let empty = LocalHomeDnsPath::new(authority.clone(), Arc::new(BufferBudget::new(0)));
    assert!(empty.authorize(client(), Protocol::Udp).is_err());
    empty.close().await.unwrap();
    let path = LocalHomeDnsPath::new(authority.clone(), Arc::new(BufferBudget::new(256 * 1024)));
    assert!(
        path.authorize("172.27.1.2:49152".parse().unwrap(), Protocol::Udp)
            .is_err()
    );
    let mut off = on.clone();
    off.split_dns.enabled = false;
    authority.update_policy(&off);
    assert!(path.authorize(client(), Protocol::Udp).is_err());
    authority.update_policy(&on);
    authority.revoke();
    assert!(path.authorize(client(), Protocol::Tcp).is_err());
    assert_eq!(prepared.load(SeqCst), 0);
    path.close().await.unwrap();
}

// A path without any Local authority or physical network proves that the message
// consumer depends only on the injected Home interface. This is not a second
// production path or a claim of home WireGuard support.
struct MemoryPath;
struct MemoryQuery;

impl HomeDnsPath for MemoryPath {
    fn authorize(
        &self,
        _: SocketAddr,
        _: Protocol,
    ) -> Result<Box<dyn HomeDnsQuery>, ExchangeError> {
        Ok(Box::new(MemoryQuery))
    }
    fn close(&self) -> PathFuture<'_, io::Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

impl HomeDnsQuery for MemoryQuery {
    fn current(&self) -> bool {
        true
    }
    fn retired(&self) -> PathFuture<'_, ()> {
        Box::pin(std::future::pending())
    }
    fn exchange(
        &self,
        _: Duration,
        message: Message,
    ) -> PathFuture<'_, Result<DnsResponse, ExchangeError>> {
        Box::pin(async move {
            let bytes = message
                .into_response()
                .to_vec()
                .map_err(|_| ExchangeError::Malformed)?;
            DnsResponse::from_buffer(bytes).map_err(|_| ExchangeError::Malformed)
        })
    }
}

#[tokio::test]
async fn split_dns_home_path_udp_message_consumer_accepts_a_nonlocal_injected_path() {
    use super::super::udp::{UdpDecision, inspect};
    use mullvad_types::settings::local_network_access::split_dns::SuffixMatcher;
    let path: Box<dyn HomeDnsPath> = Box::new(MemoryPath);
    let matcher = SuffixMatcher::compile(["home"]).unwrap();
    let request = message();
    let original = request.to_vec().unwrap();
    let resolver = "10.64.0.1:53".parse::<SocketAddr>().unwrap();
    let UdpDecision::Intercept(query) = inspect(
        Some(&matcher),
        &[resolver.ip()],
        client(),
        resolver,
        &original,
    ) else {
        panic!("listed query was not intercepted");
    };
    let path = path.as_ref();
    let reply = query
        .answer(
            |protocol, request| async move {
                let query = path.authorize(client(), protocol)?;
                query.exchange(Duration::from_secs(1), request).await
            },
            false,
            65507,
        )
        .await
        .unwrap();
    assert_eq!(reply.source, resolver);
    assert_eq!(reply.destination, client());
    assert_eq!(
        Message::from_vec(&reply.bytes).unwrap(),
        request.into_response()
    );
    path.close().await.unwrap();
}

struct UnavailablePath;

impl HomeDnsPath for UnavailablePath {
    fn authorize(
        &self,
        _: SocketAddr,
        _: Protocol,
    ) -> Result<Box<dyn HomeDnsQuery>, ExchangeError> {
        Err(io::Error::new(io::ErrorKind::PermissionDenied, "No Home path").into())
    }
    fn close(&self) -> PathFuture<'_, io::Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

#[tokio::test]
async fn split_dns_home_path_unavailable_path_is_servfail_without_an_ordinary_capability() {
    use super::super::udp::{UdpDecision, inspect};
    use mullvad_types::settings::local_network_access::split_dns::SuffixMatcher;
    let path: Box<dyn HomeDnsPath> = Box::new(UnavailablePath);
    let matcher = SuffixMatcher::compile(["home"]).unwrap();
    let request = message();
    let original = request.to_vec().unwrap();
    let resolver = "10.64.0.1:53".parse::<SocketAddr>().unwrap();
    let UdpDecision::Intercept(query) = inspect(
        Some(&matcher),
        &[resolver.ip()],
        client(),
        resolver,
        &original,
    ) else {
        panic!("listed query was not intercepted");
    };
    let path = path.as_ref();
    let reply = query
        .answer(
            |protocol, request| async move {
                let query = path.authorize(client(), protocol)?;
                query.exchange(Duration::from_secs(1), request).await
            },
            false,
            65507,
        )
        .await
        .unwrap();
    let response = Message::from_vec(&reply.bytes).unwrap();
    assert_eq!(
        response.metadata.response_code,
        hickory_proto::op::ResponseCode::ServFail
    );
    assert_eq!(response.metadata.id, request.metadata.id);
    assert_eq!(response.queries, request.queries);
    assert_eq!(reply.source, resolver);
    assert_eq!(reply.destination, client());
    path.close().await.unwrap();
}
