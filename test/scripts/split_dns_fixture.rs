//! Non-recursive synthetic authoritative response engine for the run-11 guest.
//! No product classifier, resolver, answer cache or Internet forwarding is used.

use std::net::{Ipv4Addr, Ipv6Addr};

use hickory_proto::{
    op::{Message, MessageType, OpCode, ResponseCode},
    rr::{
        Name, RData, Record, RecordType,
        rdata::{A, AAAA, CNAME, HTTPS, MX, NULL, PTR, SOA, SRV, SVCB, TXT},
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    Home,
    Ordinary,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Protocol {
    Udp,
    Tcp,
}

pub const TTL: u32 = 137;

fn name(text: &str) -> Name {
    Name::from_ascii(text).expect("constant fixture name")
}

fn addresses(role: Role) -> (Ipv4Addr, Ipv6Addr) {
    match role {
        Role::Home => (
            Ipv4Addr::new(10, 77, 10, 1),
            "fd71:7274:656b:10::1".parse().unwrap(),
        ),
        Role::Ordinary => (
            Ipv4Addr::new(10, 77, 10, 54),
            "fd71:7274:656b:10::54".parse().unwrap(),
        ),
    }
}

fn authority(role: Role, owner: &Name) -> Option<Name> {
    let zones: &[&str] = match role {
        Role::Home => &["home.", "my-matrix-server.com.", "xn--bcher-kva.example."],
        Role::Ordinary => &["ordinary.test."],
    };
    zones
        .iter()
        .map(|zone| name(zone))
        .find(|zone| zone.zone_of(owner))
        .or_else(|| {
            let (v4, v6) = addresses(role);
            [Name::from(v4), Name::from(v6)]
                .into_iter()
                .find(|reverse| reverse == owner)
        })
}

/// Returns None only for the explicit synthetic `silent` failure case. All
/// other names get a complete authoritative answer or an explicit DNS error.
pub fn answer(request: &Message, role: Role, protocol: Protocol) -> Option<Message> {
    let mut reply = request.clone().into_response();
    reply.answers.clear();
    reply.authorities.clear();
    reply.additionals.clear();
    reply.signature = None;
    reply.metadata.recursion_available = false;
    reply.metadata.authentic_data = false;
    reply.metadata.authoritative = true;
    if request.metadata.message_type != MessageType::Query || request.queries.len() != 1 {
        reply.metadata.response_code = ResponseCode::FormErr;
        return Some(reply);
    }
    let query = &request.queries[0];
    if request.metadata.op_code != OpCode::Query
        || matches!(query.query_type(), RecordType::AXFR | RecordType::IXFR)
    {
        reply.metadata.response_code = ResponseCode::NotImp;
        return Some(reply);
    }
    let owner = query.name().clone();
    let Some(zone) = authority(role, &owner) else {
        reply.metadata.response_code = ResponseCode::NXDomain;
        return Some(reply);
    };
    let first = owner.iter().next().unwrap_or_default();
    let force_tc = first.eq_ignore_ascii_case(b"tc");
    if first.eq_ignore_ascii_case(b"silent") {
        return None;
    }
    let soa = Record::from_rdata(
        zone,
        TTL,
        RData::SOA(SOA::new(
            name("ns.home."),
            name("hostmaster.home."),
            1,
            60,
            60,
            600,
            30,
        )),
    );
    if first.eq_ignore_ascii_case(b"nxdomain") || first.eq_ignore_ascii_case(b"nodata") {
        if first.eq_ignore_ascii_case(b"nxdomain") {
            reply.metadata.response_code = ResponseCode::NXDomain;
        }
        reply.add_authority(soa);
        return Some(reply);
    }
    if first.eq_ignore_ascii_case(b"servfail") {
        reply.metadata.response_code = ResponseCode::ServFail;
        return Some(reply);
    }
    let (mut v4, mut v6) = addresses(role);
    if first.eq_ignore_ascii_case(b"public") {
        v4 = Ipv4Addr::new(1, 1, 1, 1);
        v6 = "2606:4700:4700::1111".parse().unwrap();
    }
    let delegated = name("delegated.ordinary.test.");
    let data = match query.query_type() {
        RecordType::A => RData::A(A(v4)),
        RecordType::AAAA => RData::AAAA(AAAA(v6)),
        RecordType::CNAME => RData::CNAME(CNAME(delegated.clone())),
        RecordType::SRV => RData::SRV(SRV::new(0, 5, 18443, delegated.clone())),
        RecordType::HTTPS => RData::HTTPS(HTTPS(SVCB::new(0, delegated.clone(), vec![]))),
        RecordType::SVCB => RData::SVCB(SVCB::new(0, delegated, vec![])),
        RecordType::MX => RData::MX(MX::new(10, name("mail.home."))),
        RecordType::PTR => RData::PTR(PTR(name("peer.home."))),
        RecordType::TXT => {
            let text = if first.eq_ignore_ascii_case(b"large") || first.eq_ignore_ascii_case(b"tc")
            {
                // Per-string DNS limits are respected; the aggregate is larger
                // than the capped convenience client's 4096-byte receive buffer.
                vec!["x".repeat(200); 64]
            } else {
                vec![format!("role={role:?};owner={}", owner.to_ascii())]
            };
            RData::TXT(TXT::new(text))
        }
        RecordType::Unknown(code) => RData::Unknown {
            code: RecordType::Unknown(code),
            rdata: NULL::with(format!("{role:?}:{}", owner.to_ascii()).into_bytes()),
        },
        _ => {
            reply.add_authority(soa);
            return Some(reply);
        }
    };
    let mut record = Record::from_rdata(owner, TTL, data);
    record.dns_class = query.query_class();
    reply.add_answer(record);
    let bytes = reply.to_vec().expect("library-generated fixture response");
    if protocol == Protocol::Udp && (force_tc || bytes.len() > request.max_payload() as usize) {
        reply = reply.truncate();
    }
    Some(reply)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{Edns, Query};

    fn query(owner: &str, kind: RecordType) -> Message {
        let mut message = Message::query();
        message.add_query(Query::query(name(owner), kind));
        let mut edns = Edns::new();
        edns.set_max_payload(16384).set_dnssec_ok(true);
        message.set_edns(edns);
        message
    }

    #[test]
    fn fixture_normal_types_and_nonce_identity_are_complete_library_messages() {
        for kind in [
            RecordType::A,
            RecordType::AAAA,
            RecordType::SRV,
            RecordType::HTTPS,
            RecordType::SVCB,
            RecordType::TXT,
            RecordType::MX,
            RecordType::CNAME,
            RecordType::Unknown(65400),
        ] {
            let request = query("nonce.my-matrix-server.com.", kind);
            let response = answer(&request, Role::Home, Protocol::Udp).unwrap();
            assert_eq!(response.queries, request.queries);
            assert_eq!(response.metadata.id, request.metadata.id);
            assert_eq!(response.answers.len(), 1);
            assert_eq!(response.answers[0].record_type(), kind);
            assert_eq!(response.answers[0].ttl, TTL);
            assert_eq!(&response.answers[0].name, request.queries[0].name());
            assert!(!response.metadata.authentic_data);
            assert_eq!(
                Message::from_vec(&response.to_vec().unwrap()).unwrap(),
                response
            );
        }
    }

    #[test]
    fn fixture_is_not_recursive_and_keeps_home_and_ordinary_answers_distinct() {
        let request = query("nonce.home.", RecordType::A);
        let home = answer(&request, Role::Home, Protocol::Udp).unwrap();
        assert_eq!(home.answers[0].data, RData::A(A::new(10, 77, 10, 1)));
        let ordinary = answer(&request, Role::Ordinary, Protocol::Udp).unwrap();
        assert_eq!(ordinary.metadata.response_code, ResponseCode::NXDomain);
        assert!(ordinary.answers.is_empty());
        let request = query("nonce.ordinary.test.", RecordType::A);
        let ordinary = answer(&request, Role::Ordinary, Protocol::Udp).unwrap();
        assert_eq!(ordinary.answers[0].data, RData::A(A::new(10, 77, 10, 54)));
        for owner in ["nothome.", "home.example.", "my-matrix-server.com.evil."] {
            assert_eq!(
                answer(&query(owner, RecordType::A), Role::Home, Protocol::Udp)
                    .unwrap()
                    .metadata
                    .response_code,
                ResponseCode::NXDomain
            );
        }
    }

    #[test]
    fn fixture_negative_silence_tc_and_large_answers_are_distinct() {
        assert!(
            answer(
                &query("silent.home.", RecordType::A),
                Role::Home,
                Protocol::Udp
            )
            .is_none()
        );
        for (owner, rcode) in [
            ("nxdomain.home.", ResponseCode::NXDomain),
            ("nodata.home.", ResponseCode::NoError),
            ("servfail.home.", ResponseCode::ServFail),
        ] {
            let response = answer(&query(owner, RecordType::A), Role::Home, Protocol::Udp).unwrap();
            assert_eq!(response.metadata.response_code, rcode);
            assert!(response.answers.is_empty());
        }
        for protocol in [Protocol::Udp, Protocol::Tcp] {
            let response =
                answer(&query("large.home.", RecordType::TXT), Role::Home, protocol).unwrap();
            assert!(response.to_vec().unwrap().len() > 12800);
            assert!(!response.metadata.truncation);
        }
        let request = query("tc.home.", RecordType::TXT);
        assert!(
            answer(&request, Role::Home, Protocol::Udp)
                .unwrap()
                .metadata
                .truncation
        );
        assert!(
            !answer(&request, Role::Home, Protocol::Tcp)
                .unwrap()
                .metadata
                .truncation
        );
    }
}
