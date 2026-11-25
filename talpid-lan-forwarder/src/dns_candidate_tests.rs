use crate::{
    Flow, Transport, packet,
    packet_receiver::{IpError, udp_endpoints},
};
use smoltcp::wire::{IpProtocol, Ipv4Packet, Ipv6Packet};

#[test]
fn dns_udp_candidate_refuses_unsupported_forms_instead_of_bypassing_dns() {
    let flow = Flow {
        source: "10.64.0.1:53".parse().unwrap(),
        destination: "172.27.1.1:49000".parse().unwrap(),
        transport: Transport::Udp,
    };
    let ordinary = packet::udp_reply(flow, b"dns").unwrap();
    assert!(udp_endpoints(&ordinary).unwrap().is_some());
    let mut options = ordinary[..20].to_vec();
    options.extend_from_slice(&[1, 1, 1, 1]);
    options.extend_from_slice(&ordinary[20..]);
    let length = options.len();
    let mut ip = Ipv4Packet::new_unchecked(&mut options);
    ip.set_header_len(24);
    ip.set_total_len(length as u16);
    ip.set_more_frags(true);
    ip.fill_checksum();
    assert!(
        udp_endpoints(&options).unwrap().is_some(),
        "unsupported fragment options still select the DNS receiver's refusal"
    );
    let v6 = Flow {
        source: "[fd42::1]:53".parse().unwrap(),
        destination: "[fd42::2]:49000".parse().unwrap(),
        transport: Transport::Udp,
    };
    let original = packet::udp_reply(v6, b"dns").unwrap();
    let mut extension = original[..40].to_vec();
    extension.extend_from_slice(&[17, 0, 0, 0, 0, 0, 0, 1]);
    extension.extend_from_slice(&original[40..]);
    let length = extension.len() - 40;
    let mut ip = Ipv6Packet::new_unchecked(&mut extension);
    ip.set_next_header(IpProtocol::Ipv6Frag);
    ip.set_payload_len(length as u16);
    assert!(
        udp_endpoints(&extension).unwrap().is_some(),
        "atomic UDP must not bypass DNS interception"
    );
    for protocol in [0, 43, 51, 60] {
        Ipv6Packet::new_unchecked(&mut extension).set_next_header(IpProtocol::from(protocol));
        assert_eq!(udp_endpoints(&extension), Err(IpError::Unsupported));
    }
    let mut tcp = ordinary;
    let mut ip = Ipv4Packet::new_unchecked(&mut tcp);
    ip.set_next_header(IpProtocol::Tcp);
    ip.fill_checksum();
    assert_eq!(udp_endpoints(&tcp), Ok(None));
}
