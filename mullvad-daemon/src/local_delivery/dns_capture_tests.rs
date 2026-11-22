//! Real sole-fd reactor and managed carrier consumer, not a direct work-owner call.
use super::*;
use crate::split_dns::{
    ExchangeError, Protocol,
    capture::CaptureDns,
    home_path::{HomeDnsPath, HomeDnsQuery, PathFuture},
};
use hickory_proto::{
    op::{DnsResponse, Message, Query, ResponseCode},
    rr::{Name, RData, Record, RecordType, rdata::A},
};
use talpid_tunnel::android_frontend::LocalReceiver;

struct Home(Arc<AtomicUsize>);
impl HomeDnsPath for Home {
    fn authorize(
        &self,
        _: SocketAddr,
        _: Protocol,
    ) -> Result<Box<dyn HomeDnsQuery>, ExchangeError> {
        self.0.fetch_add(1, SeqCst);
        Ok(Box::new(Home(self.0.clone())))
    }
    fn close(&self) -> PathFuture<'_, io::Result<()>> {
        Box::pin(async { Ok(()) })
    }
}
impl HomeDnsQuery for Home {
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
            if message.queries[0].name() == &Name::from_ascii("silent.home.").unwrap() {
                return std::future::pending().await;
            }
            let mut reply = message.into_response();
            reply.add_answer(Record::from_rdata(
                reply.queries[0].name().clone(),
                741,
                RData::A(A("10.77.10.1".parse().unwrap())),
            ));
            DnsResponse::from_buffer(reply.to_vec().unwrap()).map_err(|_| ExchangeError::Malformed)
        })
    }
}

fn platform() -> Arc<PacketPlatform> {
    Arc::new(PacketPlatform {
        feed: CaptureNetworkFeed::new(41),
        expected: Mutex::new(None),
        opened: Mutex::new(Vec::new()),
        application_coverage: Mutex::new(Vec::new()),
        peer: Mutex::new(None),
        descriptors: Mutex::new(Vec::new()),
        starts: AtomicUsize::new(0),
        releases: AtomicUsize::new(0),
        completed_releases: Mutex::new(Vec::new()),
        released: tokio::sync::Notify::new(),
        fail_release: AtomicBool::new(false),
        retain_handover: AtomicBool::new(false),
        delayed_completion: Mutex::new(None),
        authority: Mutex::new(None),
        generation: 0.into(),
        physical: (
            "127.0.0.1:1".parse().unwrap(),
            "127.0.0.1:1".parse().unwrap(),
        ),
    })
}

fn request(name: &str, id: u16, resolver: SocketAddr) -> Vec<u8> {
    let mut message = Message::query();
    message.metadata.id = id;
    message.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
    let source = if resolver.is_ipv4() {
        "172.27.1.1:49900"
    } else {
        "[fdf0:ce4a:801d::172:27:1:1]:49900"
    }
    .parse()
    .unwrap();
    udp_packet(
        Flow {
            source,
            destination: resolver,
            transport: Transport::Udp,
        },
        &message.to_vec().unwrap(),
    )
}

async fn full_capture(home: bool, ipv6: bool, malformed: bool) {
    let platform = platform();
    let buffers = DeliveryBuffers::new();
    let mut policy = policy();
    policy.split_dns.enabled = true;
    policy.split_dns.suffixes = vec!["home".into()];
    policy.split_dns.home_resolver = Some("10.77.10.53".parse().unwrap());
    policy.split_dns.local_rule_id = Some(policy.rules[0].id);
    policy.rules[0]
        .cidrs
        .push("10.77.10.53/32".parse().unwrap());
    assert!(policy.validate().is_ok());
    let authority = Arc::new(DeliveryAuthority::new(
        &policy,
        Arc::new(|_, _| panic!("unavailable Local must not prepare")),
    ));
    let broker = AttachmentBroker::new(
        buffers._application.clone(),
        buffers._capture.clone(),
        buffers._control.clone(),
    )
    .unwrap();
    broker.set_mode(AttachmentMode::ManagedRequired).unwrap();
    let target = assigned_config();
    let projection = talpid_tunnel::tun_provider::transport::router_config(&target, vec![]);
    let resolver = SocketAddr::new(projection.gateways()[usize::from(ipv6)], 53);
    let client: SocketAddr = if ipv6 {
        "[fdf0:ce4a:801d::172:27:1:1]:49900"
    } else {
        "172.27.1.1:49900"
    }
    .parse()
    .unwrap();
    let mut requested = broker.request_target_capture(target, projection).unwrap();
    let delivery = DeliveryConfig::Secured {
        broker: broker.clone(),
        request: broker.pending_request().unwrap(),
    };
    authority.install(delivery.authority(&broker));
    let config = delivery.into_frontend(authority.clone());
    let calls = Arc::new(AtomicUsize::new(0));
    let path: Arc<dyn HomeDnsPath> = if home {
        Arc::new(Home(calls.clone()))
    } else {
        crate::split_dns::local_home_path(authority.clone(), buffers.local.clone())
    };
    let dns = CaptureDns::new(authority.clone(), buffers.local.clone(), path);
    let engine_authority = authority.clone();
    let local_buffers = buffers.local.clone();
    let forwarder = LocalReceiver::new(move |mtu| {
        Forwarder::with_mtu(engine_authority.clone(), local_buffers.clone(), mtu)
    })
    .with_dns(dns);
    let mut owner = FrontendOwner::start(
        platform.clone(),
        config,
        forwarder,
        authority.subscribe(),
        broker.clone(),
    )
    .unwrap();
    bounded(owner.ready()).await.unwrap();
    let receipt = bounded(requested.configured()).await.unwrap();
    let mut pair = broker.acquire(&receipt).unwrap();
    pair.control.activate().unwrap();
    let peer = UnixDatagram::from_std(platform.peer.lock().unwrap().take().unwrap()).unwrap();
    peer.send(&request("NAS.HOME.", 701, resolver))
        .await
        .unwrap();
    let answer = capture_reply(&peer).await;
    let parsed = talpid_lan_forwarder::packet::parse(&answer).unwrap();
    assert_eq!(parsed.flow.source, resolver);
    assert_eq!(parsed.flow.destination, client);
    let response = crate::split_dns::decode_message(parsed.payload).unwrap();
    assert_eq!(response.metadata.id, 701);
    if home {
        assert_eq!(response.answers[0].ttl, 741);
        assert_eq!(
            response.answers[0].data,
            RData::A(A("10.77.10.1".parse().unwrap()))
        );
    } else {
        assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
    }
    assert!(
        futures::poll!(Box::pin(pair.receive.recv())).is_pending(),
        "listed query reached Ordinary"
    );
    let mut refused_input = None;
    if malformed {
        let mut invalid = request("NAS.HOME.", 704, resolver);
        if ipv6 {
            invalid.push(0);
        } else {
            invalid[10] ^= 1;
        }
        assert!(talpid_netstack::raw_packet::inspect(&invalid).is_ok());
        assert!(talpid_lan_forwarder::packet_receiver::udp_endpoints(&invalid).is_err());
        peer.send(&invalid).await.unwrap();
        // The following ordinary datagram is an ordered ingress barrier. A
        // refused candidate must neither escape to the carrier nor reach Home.
        let ordinary = request("barrier.example.", 705, resolver);
        peer.send(&ordinary).await.unwrap();
        let mut exact_barrier = false;
        bounded(pair.receive.recv())
            .await
            .unwrap()
            .handoff(|bytes| {
                exact_barrier = bytes == ordinary;
            })
            .unwrap();
        refused_input = Some((exact_barrier, calls.load(SeqCst)));
        if !exact_barrier {
            // Join the real owner before reporting the regression. Otherwise
            // its destructor aborts the red case and hides the test outcome.
            requested.transport_joined();
            pair.control.detach();
            owner.stop().await.unwrap();
            assert!(exact_barrier, "malformed DNS input reached Ordinary");
            return;
        }
    }
    if home {
        peer.send(&request("silent.home.", 703, resolver))
            .await
            .unwrap();
    }
    let other = if ipv6 {
        "[2606:4700:4700::1111]:53"
    } else {
        "1.1.1.1:53"
    }
    .parse()
    .unwrap();
    for (name, destination) in [
        ("not-home.example.", resolver),
        ("NAS.HOME.", other),
        ("NAS.HOME.", SocketAddr::new(resolver.ip(), 54)),
    ] {
        let original = request(name, 702, destination);
        peer.send(&original).await.unwrap();
        bounded(pair.receive.recv())
            .await
            .unwrap()
            .handoff(|bytes| assert_eq!(bytes, original))
            .unwrap();
    }
    if home {
        bounded(async {
            while calls.load(SeqCst) != 2 {
                tokio::task::yield_now().await;
            }
        })
        .await;
    }
    assert_eq!(calls.load(SeqCst), 2 * usize::from(home));
    // OFF/ON before notification consumption must never revive old input scopes.
    let (_, scope) = authority
        .dns_input(client.ip(), resolver.ip(), &*buffers.local)
        .unwrap();
    policy.split_dns.enabled = false;
    authority.update_policy(&policy);
    policy.split_dns.enabled = true;
    authority.update_policy(&policy);
    assert!(!scope.current());
    requested.transport_joined();
    pair.control.detach();
    owner.stop().await.unwrap();
    if let Some((exact_barrier, calls)) = refused_input {
        assert!(exact_barrier, "malformed DNS input reached Ordinary");
        assert_eq!(
            calls,
            usize::from(home),
            "malformed DNS input authorized Home"
        );
    }
    assert_eq!(platform.starts.load(SeqCst), 1);
    assert_eq!(platform.releases.load(SeqCst), 1);
}

#[tokio::test]
async fn split_dns_live_full_home_reply_and_unlisted_original_reach_consumers() {
    for ipv6 in [false, true] {
        full_capture(true, ipv6, false).await;
    }
}

#[tokio::test]
async fn split_dns_live_full_unavailable_home_is_servfail_never_ordinary() {
    for ipv6 in [false, true] {
        full_capture(false, ipv6, false).await;
    }
}

#[tokio::test]
async fn split_dns_live_full_malformed_ipv4_neither_reaches_carrier_nor_authorizes_home() {
    full_capture(true, false, true).await;
}

#[tokio::test]
async fn split_dns_live_full_malformed_ipv6_neither_reaches_carrier_nor_authorizes_home() {
    full_capture(true, true, true).await;
}
