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

async fn full_capture(home: bool, ipv6: bool, malformed: bool, tcp: bool) {
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
    if tcp {
        use futures::FutureExt;
        let result = std::panic::AssertUnwindSafe(async {
            tcp_consumer(&peer, client, resolver).await;
            assert!(
                futures::poll!(Box::pin(pair.receive.recv())).is_pending(),
                "listed TCP reached Ordinary"
            );
        })
        .catch_unwind()
        .await;
        requested.transport_joined();
        pair.control.detach();
        owner.stop().await.unwrap();
        if let Err(error) = result {
            std::panic::resume_unwind(error);
        }
        assert_eq!(calls.load(SeqCst), 2);
        return;
    }
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
        full_capture(true, ipv6, false, false).await;
    }
}

#[tokio::test]
async fn split_dns_live_full_unavailable_home_is_servfail_never_ordinary() {
    for ipv6 in [false, true] {
        full_capture(false, ipv6, false, false).await;
    }
}

#[tokio::test]
async fn split_dns_live_full_malformed_ipv4_neither_reaches_carrier_nor_authorizes_home() {
    full_capture(true, false, true, false).await;
}

#[tokio::test]
async fn split_dns_live_full_malformed_ipv6_neither_reaches_carrier_nor_authorizes_home() {
    full_capture(true, true, true, false).await;
}

fn tcp_wire(flow: Flow, sequence: u32, ack: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    if flow.source.is_ipv4() {
        return tcp_packet(flow, sequence, ack, flags, payload);
    }
    let mut bytes = vec![0; 60 + payload.len()];
    bytes[0] = 0x60;
    bytes[4..6].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
    bytes[6] = 6;
    bytes[7] = 64;
    let (IpAddr::V6(source), IpAddr::V6(destination)) = (flow.source.ip(), flow.destination.ip())
    else {
        unreachable!()
    };
    bytes[8..24].copy_from_slice(&source.octets());
    bytes[24..40].copy_from_slice(&destination.octets());
    bytes[40..42].copy_from_slice(&flow.source.port().to_be_bytes());
    bytes[42..44].copy_from_slice(&flow.destination.port().to_be_bytes());
    bytes[44..48].copy_from_slice(&sequence.to_be_bytes());
    bytes[48..52].copy_from_slice(&ack.to_be_bytes());
    bytes[52] = 0x50;
    bytes[53] = flags;
    bytes[54..56].copy_from_slice(&32768u16.to_be_bytes());
    bytes[60..].copy_from_slice(payload);
    let mut pseudo = bytes[8..40].to_vec();
    pseudo.extend(((20 + payload.len()) as u32).to_be_bytes());
    pseudo.extend([0, 0, 0, 6]);
    pseudo.extend(&bytes[40..]);
    bytes[56..58].copy_from_slice(&checksum(&pseudo).to_be_bytes());
    assert!(packet::parse(&bytes).is_ok());
    bytes
}

async fn tcp_consumer(peer: &UnixDatagram, client: SocketAddr, resolver: SocketAddr) {
    let flow = Flow {
        source: client,
        destination: resolver,
        transport: Transport::Tcp,
    };
    peer.send(&tcp_wire(flow, 100, 0, 2, &[])).await.unwrap();
    let syn = capture_reply(peer).await;
    let offset = if client.is_ipv4() { 20 } else { 40 };
    assert_eq!(syn[offset + 13] & 0x12, 0x12);
    let mut ack =
        u32::from_be_bytes(syn[offset + 4..offset + 8].try_into().unwrap()).wrapping_add(1);
    let mut frames = Vec::new();
    for (name, id) in [("first.home.", 811), ("last.home.", 812)] {
        let udp = request(name, id, resolver);
        let bytes = packet::parse(&udp).unwrap().payload;
        frames.extend((bytes.len() as u16).to_be_bytes());
        frames.extend(bytes);
    }
    peer.send(&tcp_wire(flow, 101, ack, 0x18, &frames[..1]))
        .await
        .unwrap();
    peer.send(&tcp_wire(flow, 102, ack, 0x18, &frames[1..]))
        .await
        .unwrap();
    let mut received = Vec::new();
    let mut decoded = 0;
    while decoded != 2 {
        let bytes = capture_reply(peer).await;
        let packet = packet::parse(&bytes).unwrap();
        assert_eq!(packet.flow.source, resolver);
        assert_eq!(packet.flow.destination, client);
        let sequence = u32::from_be_bytes(bytes[offset + 4..offset + 8].try_into().unwrap());
        if !packet.payload.is_empty() && sequence == ack {
            received.extend_from_slice(packet.payload);
            ack = ack.wrapping_add(packet.payload.len() as u32);
        }
        while received.len() >= 2 {
            let size = usize::from(u16::from_be_bytes(received[..2].try_into().unwrap()));
            if received.len() < size + 2 {
                break;
            }
            let reply = crate::split_dns::decode_message(&received[2..size + 2]).unwrap();
            assert_eq!(reply.metadata.id, 811 + decoded);
            assert_eq!(reply.answers[0].ttl, 741);
            assert_eq!(
                reply.answers[0].data,
                RData::A(A("10.77.10.1".parse().unwrap()))
            );
            received.drain(..size + 2);
            decoded += 1;
        }
        peer.send(&tcp_wire(flow, 101 + frames.len() as u32, ack, 0x10, &[]))
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn split_dns_live_full_tcp_segmented_and_coalesced_home_frames_reach_consumers() {
    for ipv6 in [false, true] {
        full_capture(true, ipv6, false, true).await;
    }
}
