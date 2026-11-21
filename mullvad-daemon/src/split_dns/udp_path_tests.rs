use super::super::home_path::PathFuture;
use super::*;
use hickory_proto::{
    op::Query,
    rr::{Name, RecordType},
};
use std::{
    io,
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering::SeqCst},
    },
};
use talpid_netstack::buffer_budget::BufferBudget;

struct State {
    live: tokio::sync::watch::Sender<bool>,
    active: AtomicUsize,
    protocols: Mutex<Vec<Protocol>>,
    truncate: bool,
    pending: bool,
    deny: bool,
}

struct Path(Arc<State>);
struct Lease {
    state: Arc<State>,
    protocol: Protocol,
}

impl Path {
    fn new(truncate: bool, pending: bool, deny: bool) -> Self {
        Self(Arc::new(State {
            live: tokio::sync::watch::channel(true).0,
            active: AtomicUsize::new(0),
            protocols: Mutex::new(Vec::new()),
            truncate,
            pending,
            deny,
        }))
    }
}

impl HomeDnsPath for Path {
    fn authorize(
        &self,
        _: SocketAddr,
        protocol: Protocol,
    ) -> Result<Box<dyn HomeDnsQuery>, ExchangeError> {
        self.0.protocols.lock().unwrap().push(protocol);
        if self.0.deny || !*self.0.live.borrow() {
            return Err(ExchangeError::Closed);
        }
        self.0.active.fetch_add(1, SeqCst);
        Ok(Box::new(Lease {
            state: self.0.clone(),
            protocol,
        }))
    }
    fn close(&self) -> PathFuture<'_, io::Result<()>> {
        self.0.live.send_replace(false);
        Box::pin(async { Ok(()) })
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        self.state.active.fetch_sub(1, SeqCst);
    }
}

impl HomeDnsQuery for Lease {
    fn current(&self) -> bool {
        *self.state.live.borrow()
    }
    fn retired(&self) -> PathFuture<'_, ()> {
        Box::pin(async move {
            let mut live = self.state.live.subscribe();
            while *live.borrow_and_update() {
                if live.changed().await.is_err() {
                    break;
                }
            }
        })
    }
    fn exchange(
        &self,
        _: Duration,
        message: Message,
    ) -> PathFuture<'_, Result<DnsResponse, ExchangeError>> {
        Box::pin(async move {
            if self.state.pending && (!self.state.truncate || self.protocol == Protocol::Tcp) {
                return std::future::pending().await;
            }
            let mut response = message.into_response();
            response.metadata.truncation = self.state.truncate && self.protocol == Protocol::Udp;
            DnsResponse::from_buffer(response.to_vec().unwrap())
                .map_err(|_| ExchangeError::Malformed)
        })
    }
}

fn query() -> UdpQuery {
    let mut request = Message::query();
    request.add_query(Query::query(
        Name::from_ascii("nonce.home.").unwrap(),
        RecordType::A,
    ));
    UdpQuery {
        client: "172.27.1.1:49152".parse().unwrap(),
        resolver: "10.64.0.1:53".parse().unwrap(),
        request,
        error: None,
    }
}

#[tokio::test]
async fn split_dns_udp_path_retains_both_transport_leases_through_reply_retries() {
    for truncate in [false, true] {
        let path = Path::new(truncate, false, false);
        let budget = BufferBudget::new(256 * 1024);
        let reply = query()
            .answer(Some(&path), Duration::from_secs(1), true, 65507, &budget)
            .await
            .unwrap();
        assert_eq!(path.0.active.load(SeqCst), if truncate { 2 } else { 1 });
        assert!(budget.used() > usize::from(u16::MAX));
        for _ in 0..2 {
            let result = reply
                .with_current(|source, destination, bytes| {
                    assert_eq!(source, "10.64.0.1:53".parse().unwrap());
                    assert_eq!(destination, "172.27.1.1:49152".parse().unwrap());
                    assert_eq!(
                        Message::from_vec(bytes).unwrap().metadata.response_code,
                        ResponseCode::NoError
                    );
                    Err::<(), _>(io::ErrorKind::WouldBlock)
                })
                .unwrap();
            assert_eq!(result, Err(io::ErrorKind::WouldBlock));
            assert_eq!(path.0.active.load(SeqCst), if truncate { 2 } else { 1 });
        }
        drop(reply);
        assert_eq!(path.0.active.load(SeqCst), 0);
        assert_eq!(budget.used(), 0);
    }
}

#[tokio::test]
async fn split_dns_udp_path_revoked_reply_never_calls_an_emitter() {
    let path = Path::new(true, false, false);
    let budget = BufferBudget::new(256 * 1024);
    let reply = query()
        .answer(Some(&path), Duration::from_secs(1), true, 65507, &budget)
        .await
        .unwrap();
    path.close().await.unwrap();
    assert!(
        reply
            .with_current(|_, _, _| panic!("stale reply emitted"))
            .is_err()
    );
    assert_eq!(path.0.active.load(SeqCst), 2);
    drop(reply);
    assert_eq!(budget.used(), 0);
    assert_eq!(path.0.active.load(SeqCst), 0);
}

#[tokio::test]
async fn split_dns_udp_path_unavailable_or_denied_produces_only_servfail() {
    let path = Path::new(false, false, true);
    let budget = BufferBudget::new(256 * 1024);
    for selected in [None, Some(&path as &dyn HomeDnsPath)] {
        let reply = query()
            .answer(selected, Duration::from_secs(1), true, 65507, &budget)
            .await
            .unwrap();
        reply
            .with_current(|_, _, bytes| {
                assert_eq!(
                    Message::from_vec(bytes).unwrap().metadata.response_code,
                    ResponseCode::ServFail
                );
            })
            .unwrap();
        assert_eq!(path.0.active.load(SeqCst), 0);
        drop(reply);
        assert_eq!(budget.used(), 0);
    }
    assert_eq!(*path.0.protocols.lock().unwrap(), [Protocol::Udp]);
}

#[tokio::test]
async fn split_dns_udp_path_unfunded_reply_cannot_authorize_or_exchange() {
    let path = Path::new(false, false, false);
    assert!(
        query()
            .answer(
                Some(&path),
                Duration::from_secs(1),
                true,
                65507,
                &BufferBudget::new(0)
            )
            .await
            .is_err()
    );
    assert!(path.0.protocols.lock().unwrap().is_empty());
    assert_eq!(path.0.active.load(SeqCst), 0);
}

#[tokio::test]
async fn split_dns_udp_path_cancelled_exchange_refunds_and_retires_every_lease() {
    for truncate in [false, true] {
        let path = Path::new(truncate, true, false);
        let budget = BufferBudget::new(256 * 1024);
        {
            let waiting = query().answer(Some(&path), Duration::from_secs(1), true, 65507, &budget);
            tokio::pin!(waiting);
            assert!(futures::poll!(waiting.as_mut()).is_pending());
            assert_eq!(path.0.active.load(SeqCst), if truncate { 2 } else { 1 });
        }
        assert_eq!(path.0.active.load(SeqCst), 0);
        assert_eq!(budget.used(), 0);
    }
}

#[tokio::test]
async fn split_dns_udp_path_retirement_wakes_a_silent_exchange_without_an_emission() {
    for truncate in [false, true] {
        let path = Path::new(truncate, true, false);
        let budget = BufferBudget::new(256 * 1024);
        {
            let waiting =
                query().answer(Some(&path), Duration::from_secs(60), true, 65507, &budget);
            tokio::pin!(waiting);
            assert!(futures::poll!(waiting.as_mut()).is_pending());
            path.close().await.unwrap();
            assert!(
                tokio::time::timeout(Duration::from_secs(1), waiting)
                    .await
                    .unwrap()
                    .is_err()
            );
        }
        assert_eq!(path.0.active.load(SeqCst), 0);
        assert_eq!(budget.used(), 0);
    }
}

struct RacingPath {
    original: Path,
    tcp_started: Arc<AtomicUsize>,
}
struct FreshTcp(Arc<AtomicUsize>);

impl HomeDnsPath for RacingPath {
    fn authorize(
        &self,
        client: SocketAddr,
        protocol: Protocol,
    ) -> Result<Box<dyn HomeDnsQuery>, ExchangeError> {
        if protocol == Protocol::Udp {
            return self.original.authorize(client, protocol);
        }
        // A policy replacement races between the consumer's currentness check
        // and obtaining TCP authority. The successor must never perform I/O.
        self.original.0.live.send_replace(false);
        Ok(Box::new(FreshTcp(self.tcp_started.clone())))
    }
    fn close(&self) -> PathFuture<'_, io::Result<()>> {
        self.original.close()
    }
}

impl HomeDnsQuery for FreshTcp {
    fn current(&self) -> bool {
        true
    }
    fn retired(&self) -> PathFuture<'_, ()> {
        Box::pin(std::future::pending())
    }
    fn exchange(
        &self,
        _: Duration,
        _: Message,
    ) -> PathFuture<'_, Result<DnsResponse, ExchangeError>> {
        Box::pin(async {
            self.0.fetch_add(1, SeqCst);
            Err(ExchangeError::Closed)
        })
    }
}

#[tokio::test]
async fn split_dns_udp_path_tc_cannot_cross_into_successor_authority() {
    let path = RacingPath {
        original: Path::new(true, false, false),
        tcp_started: Arc::new(AtomicUsize::new(0)),
    };
    let budget = BufferBudget::new(256 * 1024);
    assert!(
        query()
            .answer(Some(&path), Duration::from_secs(1), true, 65507, &budget)
            .await
            .is_err()
    );
    assert_eq!(path.tcp_started.load(SeqCst), 0);
    assert_eq!(path.original.0.active.load(SeqCst), 0);
    assert_eq!(budget.used(), 0);
}
