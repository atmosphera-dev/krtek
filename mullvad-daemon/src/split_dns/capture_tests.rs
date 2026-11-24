use super::*;
use crate::{
    local_delivery::{home_dns::DnsInput, tests::partial_dns_authority},
    split_dns::{
        platform::home_path::{HomeDnsQuery, PathFuture},
        transport::{ExchangeError, Protocol},
    },
};
use std::net::SocketAddr;
use talpid_lan_forwarder::{Flow, packet};
use talpid_netstack::buffer_budget::BufferBudget;

struct FailingHome;

impl HomeDnsPath for FailingHome {
    fn authorize(
        &self,
        _: &DnsInput,
        _: SocketAddr,
        _: Protocol,
    ) -> Result<Box<dyn HomeDnsQuery>, ExchangeError> {
        panic!("non-DNS traffic must not acquire Home authority")
    }

    fn close(&self) -> PathFuture<'_, io::Result<()>> {
        Box::pin(async { Err(io::Error::other("Home close failed")) })
    }
}

#[tokio::test]
async fn split_dns_capture_review_non_dns_fragments_keep_originals() {
    let (system, _, capture, _) = super::super::system::tests::fixture();
    let buffers = Arc::new(BufferBudget::new(32 * 1024 * 1024));
    let mut dns = CaptureDns::new(
        partial_dns_authority(),
        buffers.clone(),
        Arc::new(FailingHome),
    );
    dns.system = Some(Arc::new(system));
    let flow = Flow {
        source: "[fdf0:ce4a:801d::172:27:1:1]:49900".parse().unwrap(),
        destination: "[fd00::53]:5353".parse().unwrap(),
        transport: Transport::Udp,
    };
    let packet = packet::udp_reply(
        Flow {
            source: flow.destination,
            destination: flow.source,
            ..flow
        },
        &[0x5a; 32],
    )
    .unwrap();
    let fragments = [(&packet[40..56], 1u16), (&packet[56..], 16u16)].map(|(body, flags)| {
        let mut fragment = packet[..40].to_vec();
        fragment[4..6].copy_from_slice(&u16::try_from(8 + body.len()).unwrap().to_be_bytes());
        fragment[6] = 44;
        fragment.extend_from_slice(&[17, 0]);
        fragment.extend_from_slice(&flags.to_be_bytes());
        fragment.extend_from_slice(&1u32.to_be_bytes());
        fragment.extend_from_slice(body);
        fragment
    });
    let advertised = [flow.destination.ip()];
    assert!(!dns.candidate(&packet, &advertised));
    for fragment in &fragments {
        assert!(dns.candidate(fragment, &advertised));
        assert!(dns.ingest(
            fragment,
            &advertised,
            &capture.capability(),
            buffers.clone(),
            1280
        ));
    }
    for fragment in &fragments {
        let original = dns
            .original()
            .expect("non-DNS fragment must reach ordinary IP policy");
        assert_eq!(original.bytes(), fragment);
    }
    assert!(dns.original().is_none());
}

#[tokio::test]
async fn split_dns_capture_review_close_releases_all_owners_on_home_error() {
    let (system, _, capture, _) = super::super::system::tests::fixture();
    let buffers = Arc::new(BufferBudget::new(32 * 1024 * 1024));
    let mut dns = CaptureDns::new(
        partial_dns_authority(),
        buffers.clone(),
        Arc::new(FailingHome),
    );
    let system = Arc::new(system);
    dns.system = Some(system.clone());
    dns.receiver = Some(PacketReceiver::new(buffers.clone(), 1280).unwrap());
    dns.work = Some(HomeUdpWork::new(
        Some(dns.path.clone()),
        capture.capability(),
        buffers.clone(),
        buffers,
    ));

    assert_eq!(
        dns.close().await.unwrap_err().to_string(),
        "Home close failed"
    );
    assert!(
        dns.receiver.is_none(),
        "packet receiver retained after Home close error"
    );
    assert!(futures::poll!(Box::pin(system.io.closed())).is_ready());
}
