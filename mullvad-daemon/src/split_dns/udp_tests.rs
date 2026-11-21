use super::*;
use crate::split_dns::transport::exchange;
use hickory_net::runtime::TokioRuntimeProvider;
use hickory_proto::{
    op::{Edns, OpCode, Query},
    rr::{Name, RData, Record, RecordType, rdata::NULL},
};
use std::{
    io,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
};

fn request(name: &str, kind: RecordType, allowance: Option<u16>) -> Message {
    let mut request = Message::query();
    request.metadata.id = 7231;
    request.metadata.recursion_desired = true;
    request.metadata.checking_disabled = true;
    request.add_query(Query::query(Name::from_ascii(name).unwrap(), kind));
    if let Some(allowance) = allowance {
        let mut edns = Edns::new();
        edns.set_max_payload(allowance).set_dnssec_ok(true);
        request.set_edns(edns);
    }
    request
}

fn answer(request: Message, length: usize) -> DnsResponse {
    let name = request.queries[0].name().clone();
    let mut response = request.into_response();
    if length != 0 {
        response.add_answer(Record::from_rdata(
            name,
            741,
            RData::Unknown {
                code: RecordType::Unknown(65400),
                rdata: NULL::with(vec![42; length]),
            },
        ));
    }
    DnsResponse::from_buffer(response.to_vec().unwrap()).unwrap()
}

fn intercepted(request: &Message, ipv6: bool) -> UdpQuery {
    let client = if ipv6 {
        "[fdf0:ce4a:801d::172:27:1:1]:49152"
    } else {
        "172.27.1.1:49152"
    }
    .parse()
    .unwrap();
    let resolver: SocketAddr = if ipv6 {
        "[fd00::53]:53"
    } else {
        "100.64.0.3:53"
    }
    .parse()
    .unwrap();
    let matcher = SuffixMatcher::compile(["home", "my-matrix-server.com"]).unwrap();
    match inspect(
        Some(&matcher),
        &[resolver.ip()],
        client,
        resolver,
        &request.to_vec().unwrap(),
    ) {
        UdpDecision::Intercept(query) => *query,
        _ => panic!("listed question was not intercepted"),
    }
}

fn check_reply(reply: &UdpReply, original: &Message, ipv6: bool) -> Message {
    assert_eq!(
        reply.source,
        if ipv6 {
            "[fd00::53]:53"
        } else {
            "100.64.0.3:53"
        }
        .parse::<SocketAddr>()
        .unwrap()
    );
    assert_eq!(
        reply.destination,
        if ipv6 {
            "[fdf0:ce4a:801d::172:27:1:1]:49152"
        } else {
            "172.27.1.1:49152"
        }
        .parse::<SocketAddr>()
        .unwrap()
    );
    let decoded = decode_message(&reply.bytes).unwrap();
    assert_eq!(decoded.metadata.id, original.metadata.id);
    assert_eq!(decoded.queries, original.queries);
    decoded
}

#[test]
fn split_dns_udp_unlisted_and_out_of_scope_keep_original_bytes() {
    let matcher = SuffixMatcher::compile(["home"]).unwrap();
    let client = "172.27.1.1:49152".parse().unwrap();
    let resolver: SocketAddr = "100.64.0.3:53".parse().unwrap();
    for (name, enabled, destination, advertised) in [
        ("outside.example.", true, resolver, true),
        ("myhome.", true, resolver, true),
        ("nas.", true, resolver, true),
        ("nas.home.", false, resolver, true),
        ("nas.home.", true, resolver, false),
        ("nas.home.", true, "100.64.0.3:5353".parse().unwrap(), true),
    ] {
        let bytes = request(name, RecordType::A, Some(4096)).to_vec().unwrap();
        let servers = if advertised {
            vec![resolver.ip()]
        } else {
            vec![]
        };
        let UdpDecision::PassThrough(original) = inspect(
            enabled.then_some(&matcher),
            &servers,
            client,
            destination,
            &bytes,
        ) else {
            panic!("ordinary bytes were consumed");
        };
        assert_eq!(original.as_ptr(), bytes.as_ptr());
        assert_eq!(original, bytes);
    }
}

#[tokio::test]
async fn split_dns_udp_all_types_retain_original_resolver_tuple_and_full_home_bytes() {
    for ipv6 in [false, true] {
        for kind in [
            RecordType::A,
            RecordType::AAAA,
            RecordType::SRV,
            RecordType::HTTPS,
            RecordType::SVCB,
            RecordType::TXT,
            RecordType::MX,
            RecordType::DS,
            RecordType::Unknown(65400),
        ] {
            let original = request("_service._tcp.NAS.HOME.", kind, Some(4096));
            let expected = answer(original.clone(), 100);
            let wire = expected.as_buffer().to_vec();
            let reply = intercepted(&original, ipv6)
                .answer(
                    |protocol, question| {
                        assert_eq!(protocol, Protocol::Udp);
                        assert_eq!(question, original);
                        std::future::ready(Ok(answer(question, 100)))
                    },
                    false,
                    65487,
                )
                .await
                .unwrap();
            assert_eq!(reply.bytes, wire);
            assert_eq!(check_reply(&reply, &original, ipv6).answers[0].ttl, 741);
        }
    }
}

#[tokio::test]
async fn split_dns_udp_home_failure_or_ineligibility_is_servfail_not_passthrough() {
    for kind in [
        io::ErrorKind::TimedOut,
        io::ErrorKind::ConnectionRefused,
        io::ErrorKind::PermissionDenied,
    ] {
        let original = request("nas.home.", RecordType::A, None);
        let calls = Arc::new(Mutex::new(Vec::new()));
        let observed = calls.clone();
        let reply = intercepted(&original, false)
            .answer(
                move |protocol, _| {
                    observed.lock().unwrap().push(protocol);
                    std::future::ready(Err(io::Error::from(kind).into()))
                },
                false,
                65507,
            )
            .await
            .unwrap();
        let decoded = check_reply(&reply, &original, false);
        assert_eq!(decoded.metadata.response_code, ResponseCode::ServFail);
        assert!(!decoded.metadata.authentic_data);
        assert!(!decoded.metadata.authoritative);
        assert!(!decoded.metadata.truncation);
        assert!(decoded.metadata.recursion_desired);
        assert!(decoded.metadata.checking_disabled);
        assert!(decoded.answers.is_empty());
        assert_eq!(*calls.lock().unwrap(), [Protocol::Udp]);
    }
}

#[tokio::test]
async fn split_dns_udp_home_negative_and_protocol_errors_do_not_try_tcp_or_fallback() {
    for code in [
        ResponseCode::NXDomain,
        ResponseCode::NoError,
        ResponseCode::ServFail,
        ResponseCode::Refused,
    ] {
        let original = request("negative.home.", RecordType::A, None);
        let mut expected = original.clone().into_response();
        expected.metadata.response_code = code;
        let wire = expected.to_vec().unwrap();
        let reply = intercepted(&original, false)
            .answer(
                |protocol, _| {
                    assert_eq!(protocol, Protocol::Udp);
                    std::future::ready(Ok(DnsResponse::from_buffer(wire.clone()).unwrap()))
                },
                false,
                65507,
            )
            .await
            .unwrap();
        assert_eq!(reply.bytes, wire);
        assert_eq!(
            check_reply(&reply, &original, false).metadata.response_code,
            code
        );
    }
}

#[tokio::test]
async fn split_dns_udp_ambiguous_and_unsupported_listed_messages_never_dispatch() {
    let original = request("nas.home.", RecordType::A, None);
    let mut mixed = original.clone();
    mixed.add_query(Query::query(
        Name::from_ascii("outside.example.").unwrap(),
        RecordType::A,
    ));
    let mut same_lane = original.clone();
    same_lane.add_query(Query::query(
        Name::from_ascii("other.home.").unwrap(),
        RecordType::AAAA,
    ));
    let mut update = original.clone();
    update.metadata.op_code = OpCode::Update;
    let transfer = request("home.", RecordType::AXFR, None);
    for (request, code) in [
        (mixed, ResponseCode::FormErr),
        (same_lane, ResponseCode::FormErr),
        (update, ResponseCode::NotImp),
        (transfer, ResponseCode::NotImp),
    ] {
        let mut calls = 0;
        let reply = intercepted(&request, false)
            .answer(
                |_, _| {
                    calls += 1;
                    std::future::ready(Err(ExchangeError::Malformed))
                },
                false,
                65507,
            )
            .await
            .unwrap();
        assert_eq!(calls, 0);
        assert_eq!(
            check_reply(&reply, &request, false).metadata.response_code,
            code
        );
    }
}

#[test]
fn split_dns_udp_malformed_or_response_payload_cannot_authorize_forwarding() {
    let matcher = SuffixMatcher::compile(["home"]).unwrap();
    let source = "172.27.1.1:49152".parse().unwrap();
    let resolver: SocketAddr = "100.64.0.3:53".parse().unwrap();
    let good = request("nas.home.", RecordType::A, None).to_vec().unwrap();
    let mut trailing = good.clone();
    trailing.push(42);
    let response = request("nas.home.", RecordType::A, None)
        .into_response()
        .to_vec()
        .unwrap();
    for bytes in [
        vec![],
        vec![255; 13],
        good[..good.len() - 1].to_vec(),
        trailing,
        response,
    ] {
        assert!(matches!(
            inspect(Some(&matcher), &[resolver.ip()], source, resolver, &bytes),
            UdpDecision::Drop
        ));
    }
}

#[tokio::test]
async fn split_dns_udp_edns_and_actual_emission_limit_require_tcp_before_tc() {
    for allowance in [None, Some(1), Some(512), Some(1232), Some(4096)] {
        for tcp_retry in [false, true] {
            for injection in [1280, 65487] {
                let original = request("large.home.", RecordType::TXT, allowance);
                let reply = intercepted(&original, false)
                    .answer(
                        |_, q| std::future::ready(Ok(answer(q, 8192))),
                        tcp_retry,
                        injection,
                    )
                    .await
                    .unwrap();
                let decoded = check_reply(&reply, &original, false);
                assert!(reply.bytes.len() <= usize::from(original.max_payload().min(injection)));
                if tcp_retry {
                    assert!(decoded.metadata.truncation);
                    assert_eq!(decoded.metadata.response_code, ResponseCode::NoError);
                } else {
                    assert!(!decoded.metadata.truncation);
                    assert_eq!(decoded.metadata.response_code, ResponseCode::ServFail);
                }
            }
        }
    }
}

#[tokio::test]
async fn split_dns_udp_home_tc_fetches_complete_tcp_answer_before_client_sizing() {
    for length in [100, 8192] {
        for tcp_retry in [false, true] {
            let original = request("large.home.", RecordType::TXT, Some(4096));
            let mut calls = Vec::new();
            let reply = intercepted(&original, true)
                .answer(
                    |protocol, q| {
                        calls.push(protocol);
                        let mut response =
                            answer(q, if protocol == Protocol::Udp { 0 } else { length })
                                .into_message();
                        response.metadata.truncation = protocol == Protocol::Udp;
                        std::future::ready(Ok(
                            DnsResponse::from_buffer(response.to_vec().unwrap()).unwrap()
                        ))
                    },
                    tcp_retry,
                    65487,
                )
                .await
                .unwrap();
            assert_eq!(calls, [Protocol::Udp, Protocol::Tcp]);
            let decoded = check_reply(&reply, &original, true);
            if length == 100 {
                assert_eq!(reply.bytes, answer(original, length).as_buffer());
            } else if tcp_retry {
                assert!(decoded.metadata.truncation);
            } else {
                assert_eq!(decoded.metadata.response_code, ResponseCode::ServFail);
            }
        }
    }
}

#[tokio::test]
async fn split_dns_udp_wrong_home_identity_and_failed_tcp_recovery_fail_closed() {
    for case in 0..4 {
        let original = request("nas.home.", RecordType::A, Some(4096));
        let reply = intercepted(&original, false)
            .answer(
                |protocol, q| {
                    if case == 3 && protocol == Protocol::Tcp {
                        return std::future::ready(Err(ExchangeError::Closed));
                    }
                    let mut response = answer(q, 100).into_message();
                    match case {
                        0 => response.metadata.id += 1,
                        1 => {
                            response.queries[0] = Query::query(
                                Name::from_ascii("wrong.home.").unwrap(),
                                RecordType::A,
                            )
                        }
                        _ => response.metadata.truncation = true,
                    }
                    std::future::ready(Ok(
                        DnsResponse::from_buffer(response.to_vec().unwrap()).unwrap()
                    ))
                },
                true,
                65507,
            )
            .await
            .unwrap();
        let decoded = check_reply(&reply, &original, false);
        assert_eq!(decoded.metadata.response_code, ResponseCode::ServFail);
        assert!(!decoded.metadata.truncation);
    }
}

#[tokio::test]
async fn split_dns_udp_real_home_transport_both_families_and_tcp_recovery() {
    for host in ["127.0.0.1:0", "[::1]:0"] {
        let udp = UdpSocket::bind(host).await.unwrap();
        let peer = udp.local_addr().unwrap();
        let tcp = TcpListener::bind(peer).await.unwrap();
        let server = tokio::spawn(async move {
            let mut bytes = vec![0; 65535];
            let (length, from) = udp.recv_from(&mut bytes).await.unwrap();
            let mut response = answer(decode_message(&bytes[..length]).unwrap(), 0).into_message();
            response.metadata.truncation = true;
            udp.send_to(&response.to_vec().unwrap(), from)
                .await
                .unwrap();
            let (mut stream, _) = tcp.accept().await.unwrap();
            let length = stream.read_u16().await.unwrap();
            stream
                .read_exact(&mut bytes[..usize::from(length)])
                .await
                .unwrap();
            let response = answer(decode_message(&bytes[..usize::from(length)]).unwrap(), 4096);
            stream
                .write_u16(response.as_buffer().len() as u16)
                .await
                .unwrap();
            stream.write_all(response.as_buffer()).await.unwrap();
        });
        let original = request("nonce.home.", RecordType::TXT, Some(8192));
        let reply = intercepted(&original, peer.is_ipv6())
            .answer(
                |protocol, q| {
                    exchange(
                        TokioRuntimeProvider::default(),
                        peer,
                        protocol,
                        Duration::from_secs(2),
                        q,
                    )
                },
                false,
                65487,
            )
            .await
            .unwrap();
        assert_eq!(reply.bytes, answer(original.clone(), 4096).as_buffer());
        check_reply(&reply, &original, peer.is_ipv6());
        tokio::time::timeout(Duration::from_secs(3), server)
            .await
            .unwrap()
            .unwrap();
    }
}
