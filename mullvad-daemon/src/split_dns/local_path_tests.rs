use super::*;
use crate::local_delivery::tests::{observation, policy};
use hickory_proto::{
    op::{Message, Query},
    rr::{Name, RecordType},
};
use mullvad_types::settings::local_network_access::{
    LocalNetworkAccess,
    split_dns::{SplitDnsPolicy, SuffixMatcher},
};
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use talpid_lan_forwarder::ReceiveScope;
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

fn resolver() -> SocketAddr {
    "10.64.0.1:53".parse().unwrap()
}

fn input(authority: &DeliveryAuthority) -> DnsInput {
    authority
        .dns_input(client().ip(), resolver().ip(), &BufferBudget::new(1024))
        .unwrap()
}

fn fixture_input() -> DnsInput {
    DnsInput::for_test(
        SuffixMatcher::compile(["home"]).unwrap(),
        ReceiveScope::new(client().ip(), resolver().ip(), &BufferBudget::new(1024)).unwrap(),
    )
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
    let input = input(&authority);
    let udp = path.authorize(&input, client(), Protocol::Udp).unwrap();
    let tcp = path.authorize(&input, client(), Protocol::Tcp).unwrap();
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
        let query = path
            .authorize(&input(&authority), client(), Protocol::Udp)
            .unwrap();
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
        assert!(
            path.authorize(&input(&authority), client(), Protocol::Tcp)
                .unwrap()
                .current()
        );
    }
    path.close().await.unwrap();
}

#[tokio::test]
async fn split_dns_home_path_local_close_retires_existing_leases_and_refuses_new_work() {
    let on = configured();
    let authority = authority(&on);
    let input = input(&authority);
    let path = LocalHomeDnsPath::new(authority, Arc::new(BufferBudget::new(256 * 1024)));
    let query = path.authorize(&input, client(), Protocol::Udp).unwrap();
    let waiting = query.retired();
    tokio::pin!(waiting);
    assert!(futures::poll!(waiting.as_mut()).is_pending());
    path.close().await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), waiting)
        .await
        .unwrap();
    assert!(!query.current());
    assert!(path.authorize(&input, client(), Protocol::Udp).is_err());
    assert!(path.authorize(&input, client(), Protocol::Tcp).is_err());
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
    let original = input(&authority);
    let empty = LocalHomeDnsPath::new(authority.clone(), Arc::new(BufferBudget::new(0)));
    assert!(empty.authorize(&original, client(), Protocol::Udp).is_err());
    empty.close().await.unwrap();
    let path = LocalHomeDnsPath::new(authority.clone(), Arc::new(BufferBudget::new(256 * 1024)));
    assert!(
        path.authorize(
            &original,
            "172.27.1.2:49152".parse().unwrap(),
            Protocol::Udp
        )
        .is_err()
    );
    let mut off = on.clone();
    off.split_dns.enabled = false;
    authority.update_policy(&off);
    assert!(path.authorize(&original, client(), Protocol::Udp).is_err());
    authority.update_policy(&on);
    let successor = input(&authority);
    authority.revoke();
    assert!(path.authorize(&successor, client(), Protocol::Tcp).is_err());
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
        _: &DnsInput,
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
    let path: Box<dyn HomeDnsPath> = Box::new(MemoryPath);
    let input = fixture_input();
    let request = message();
    let original = request.to_vec().unwrap();
    let resolver = resolver();
    let UdpDecision::Intercept(query) = inspect(
        Some(&input),
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
            Some(path),
            Duration::from_secs(1),
            false,
            65507,
            &BufferBudget::new(256 * 1024),
        )
        .await
        .unwrap();
    reply
        .with_current(|source, destination, bytes| {
            assert_eq!(source, resolver);
            assert_eq!(destination, client());
            assert_eq!(Message::from_vec(bytes).unwrap(), request.into_response());
        })
        .unwrap();
    path.close().await.unwrap();
}

struct UnavailablePath;

impl HomeDnsPath for UnavailablePath {
    fn authorize(
        &self,
        _: &DnsInput,
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
    let path: Box<dyn HomeDnsPath> = Box::new(UnavailablePath);
    let input = fixture_input();
    let request = message();
    let original = request.to_vec().unwrap();
    let resolver = resolver();
    let UdpDecision::Intercept(query) = inspect(
        Some(&input),
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
            Some(path),
            Duration::from_secs(1),
            false,
            65507,
            &BufferBudget::new(256 * 1024),
        )
        .await
        .unwrap();
    let response = reply
        .with_current(|source, destination, bytes| {
            assert_eq!(source, resolver);
            assert_eq!(destination, client());
            Message::from_vec(bytes).unwrap()
        })
        .unwrap();
    assert_eq!(
        response.metadata.response_code,
        hickory_proto::op::ResponseCode::ServFail
    );
    assert_eq!(response.metadata.id, request.metadata.id);
    assert_eq!(response.queries, request.queries);
    path.close().await.unwrap();
}
