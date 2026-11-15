//! Privileged kernel consumer proof, run only in an isolated network namespace.
use super::*;
use std::{
    net::{IpAddr, UdpSocket},
    os::fd::AsRawFd,
    time::Duration,
};
use talpid_netstack::{
    address_translation::{Direction, TargetConfig, TargetPacketPath},
    buffer_budget::BufferBudget,
};
use talpid_types::relay_flow::{RelayPacket, RelaySources};
use tun::AbstractDevice;

fn add_ipv6_address(index: u32, address: std::net::Ipv6Addr) {
    use netlink_packet_core::{
        NLM_F_ACK, NLM_F_CREATE, NLM_F_REQUEST, NetlinkMessage, NetlinkPayload,
    };
    use netlink_packet_route::{
        RouteNetlinkMessage,
        address::AddressHeaderFlags,
        route::{RouteAddress, RouteAttribute, RouteType},
    };
    use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_ROUTE};
    use nix::libc;
    use rtnetlink::AddressMessageBuilder;
    const RTNLGRP_IPV6_ROUTE: u32 = 11;
    const RT_TABLE_LOCAL: u32 = 255;

    // Use the same direct kernel API as tun_provider::netlink, but a /64
    // gives this isolated peer fixture its connected IPv6 route as well.
    let mut message = AddressMessageBuilder::<std::net::Ipv6Addr>::new()
        .index(index)
        .address(address, 64)
        .build();
    message.header.flags |= AddressHeaderFlags::Nodad;
    let mut request = NetlinkMessage::from(RouteNetlinkMessage::NewAddress(message));
    request.header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE;
    request.finalize();
    let mut bytes = vec![0; request.buffer_len()];
    request.serialize(&mut bytes);
    let socket = Socket::new(NETLINK_ROUTE).unwrap();
    // The acknowledgement only means the address exists. Even without DAD,
    // the kernel installs the address's local route later, from addrconf's
    // DAD work; until then inbound packets to it are address errors. So
    // subscribe before the request and wait for that route's announcement.
    socket.add_membership(RTNLGRP_IPV6_ROUTE).unwrap();
    let bound = libc::timeval {
        tv_sec: 10,
        tv_usec: 0,
    };
    // SAFETY: the socket is live, and the option value has its declared size.
    assert_eq!(
        unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                (&bound as *const libc::timeval).cast(),
                std::mem::size_of_val(&bound) as libc::socklen_t,
            )
        },
        0
    );
    socket.send_to(&bytes, &SocketAddr::new(0, 0), 0).unwrap();
    let (mut acknowledged, mut routed) = (false, false);
    while !(acknowledged && routed) {
        let (datagram, _) = socket
            .recv_from_full()
            .expect("address acknowledgement and its local route announcement");
        let mut offset = 0;
        while offset < datagram.len() {
            let message =
                NetlinkMessage::<RouteNetlinkMessage>::deserialize(&datagram[offset..]).unwrap();
            offset += (message.header.length as usize + 3) & !3;
            match message.payload {
                NetlinkPayload::Error(error) => {
                    assert_eq!(error.code, None, "{error:?}");
                    acknowledged = true;
                }
                NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewRoute(route)) => {
                    let table = route
                        .attributes
                        .iter()
                        .find_map(|attribute| match attribute {
                            RouteAttribute::Table(table) => Some(*table),
                            _ => None,
                        })
                        .unwrap_or(u32::from(route.header.table));
                    routed |= route.header.kind == RouteType::Local
                        && table == RT_TABLE_LOCAL
                        && route.header.destination_prefix_length == 128
                        && route.attributes.contains(&RouteAttribute::Oif(index))
                        && route
                            .attributes
                            .contains(&RouteAttribute::Destination(RouteAddress::Inet6(address)));
                }
                // Other IPv6 route announcements are unrelated to readiness.
                NetlinkPayload::InnerMessage(_) => {}
                other => panic!("unexpected address-setup message {other:?}"),
            }
        }
    }
}
fn socket_option(socket: &UdpSocket, level: i32, option: i32) -> i32 {
    use nix::libc;
    let mut value = 0i32;
    let mut length = std::mem::size_of_val(&value) as libc::socklen_t;
    // SAFETY: the socket is live, and both output pointers have their declared sizes.
    assert_eq!(
        unsafe {
            libc::getsockopt(
                socket.as_raw_fd(),
                level,
                option,
                (&mut value as *mut i32).cast(),
                &mut length,
            )
        },
        0,
        "{}",
        io::Error::last_os_error()
    );
    value
}
fn discover(socket: &UdpSocket, v6: bool) {
    use nix::libc;
    let value = if v6 {
        libc::IPV6_PMTUDISC_DO
    } else {
        libc::IP_PMTUDISC_DO
    };
    // SAFETY: the live socket reads one initialized integer of the declared size.
    assert_eq!(
        unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                if v6 {
                    libc::IPPROTO_IPV6
                } else {
                    libc::IPPROTO_IP
                },
                if v6 {
                    libc::IPV6_MTU_DISCOVER
                } else {
                    libc::IP_MTU_DISCOVER
                },
                (&value as *const i32).cast(),
                std::mem::size_of_val(&value) as libc::socklen_t,
            )
        },
        0
    );
}
fn sum(bytes: &[u8]) -> u16 {
    let mut total = 0u32;
    for pair in bytes.chunks(2) {
        total += u32::from(pair[0]) << 8 | u32::from(*pair.get(1).unwrap_or(&0));
    }
    while total >> 16 != 0 {
        total = (total & 65535) + (total >> 16);
    }
    !(total as u16)
}
fn checksums(bytes: &mut [u8], protocol: u8) {
    let v6 = bytes[0] >> 4 == 6;
    let ip = if v6 { 40 } else { 20 };
    let field = ip + if protocol == 17 { 6 } else { 2 };
    bytes[field..field + 2].fill(0);
    let mut domain = Vec::new();
    if v6 {
        domain.extend_from_slice(&bytes[8..40]);
        domain.extend_from_slice(&((bytes.len() - ip) as u32).to_be_bytes());
        domain.extend_from_slice(&[0, 0, 0, protocol]);
    } else if protocol == 17 {
        domain.extend_from_slice(&bytes[12..20]);
        domain.extend_from_slice(&[0, protocol]);
        domain.extend_from_slice(&((bytes.len() - ip) as u16).to_be_bytes());
    }
    domain.extend_from_slice(&bytes[ip..]);
    let mut value = sum(&domain);
    if protocol == 17 && value == 0 {
        value = u16::MAX;
    }
    bytes[field..field + 2].copy_from_slice(&value.to_be_bytes());
    if !v6 {
        bytes[10..12].fill(0);
        let value = sum(&bytes[..20]);
        bytes[10..12].copy_from_slice(&value.to_be_bytes());
    }
}
fn owned_bytes(mut packet: RelayPacket) -> Vec<u8> {
    let mut output = Vec::new();
    assert!(matches!(
        packet.write(|bytes| {
            output.extend_from_slice(bytes);
            Ok(bytes.len())
        }),
        talpid_types::relay_flow::RelayWriteOutcome::Written
    ));
    output
}
fn peer_reply(invoking: &[u8], payload: &[u8]) -> Vec<u8> {
    let v6 = invoking[0] >> 4 == 6;
    let ip = if v6 { 40 } else { 20 };
    let (start, width) = if v6 { (8, 16) } else { (12, 4) };
    let mut output = invoking[..ip + 8].to_vec();
    output[start..start + width].copy_from_slice(&invoking[start + width..start + 2 * width]);
    output[start + width..start + 2 * width].copy_from_slice(&invoking[start..start + width]);
    output[ip..ip + 2].copy_from_slice(&invoking[ip + 2..ip + 4]);
    output[ip + 2..ip + 4].copy_from_slice(&invoking[ip..ip + 2]);
    output.extend_from_slice(payload);
    let length = output.len();
    if v6 {
        output[4..6].copy_from_slice(&((length - 40) as u16).to_be_bytes());
    } else {
        output[2..4].copy_from_slice(&(length as u16).to_be_bytes());
        output[6..8].fill(0);
    }
    output[ip + 4..ip + 6].copy_from_slice(&((length - ip) as u16).to_be_bytes());
    checksums(&mut output, 17);
    output
}
fn fragments(bytes: &[u8], identification: u32) -> Vec<Vec<u8>> {
    let v6 = bytes[0] >> 4 == 6;
    let ip = if v6 { 40 } else { 20 };
    bytes[ip..]
        .chunks(1328)
        .enumerate()
        .map(|(index, part)| {
            let offset = index * 1328;
            let more = offset + part.len() < bytes.len() - ip;
            let mut output = bytes[..ip].to_vec();
            if v6 {
                output[6] = 44;
                output[4..6].copy_from_slice(&((part.len() + 8) as u16).to_be_bytes());
                output.extend_from_slice(&[17, 0]);
                output.extend_from_slice(&((offset as u16) | u16::from(more)).to_be_bytes());
                output.extend_from_slice(&identification.to_be_bytes());
            } else {
                output[2..4].copy_from_slice(&((part.len() + 20) as u16).to_be_bytes());
                output[4..6].copy_from_slice(&(identification as u16).to_be_bytes());
                output[6..8].copy_from_slice(
                    &((offset as u16 / 8) | if more { 0x2000 } else { 0 }).to_be_bytes(),
                );
                output[10..12].fill(0);
                let value = sum(&output);
                output[10..12].copy_from_slice(&value.to_be_bytes());
            }
            output.extend_from_slice(part);
            output
        })
        .collect()
}
fn peer_error(invoking: &[u8]) -> Vec<u8> {
    let v6 = invoking[0] >> 4 == 6;
    let ip = if v6 { 40 } else { 20 };
    let protocol = if v6 { 58 } else { 1 };
    let mut output = peer_reply(invoking, &[]);
    output.truncate(ip + 8);
    output[if v6 { 6 } else { 9 }] = protocol;
    output[ip..ip + 8].fill(0);
    output[ip] = if v6 { 2 } else { 3 };
    output[ip + 1] = if v6 { 0 } else { 4 };
    output[ip + 4..ip + 8].copy_from_slice(&1280u32.to_be_bytes());
    output.extend_from_slice(&invoking[..ip + 8]);
    let length = output.len();
    if v6 {
        output[4..6].copy_from_slice(&((length - 40) as u16).to_be_bytes());
    } else {
        output[2..4].copy_from_slice(&(length as u16).to_be_bytes());
    }
    checksums(&mut output, protocol);
    output
}
async fn invocation<F: AsRawFd>(descriptor: &AsyncFd<F>, v6: bool) -> Vec<u8> {
    tokio::time::timeout(Duration::from_secs(2), async {
        let mut bytes = vec![0; 9000];
        loop {
            let mut ready = descriptor.readable().await.unwrap();
            if let Ok(result) = ready.try_io(|fd| {
                // SAFETY: the descriptor remains borrowed and live for this read.
                let borrowed = unsafe { BorrowedFd::borrow_raw(fd.get_ref().as_raw_fd()) };
                nix::unistd::read(borrowed, &mut bytes).map_err(io::Error::from)
            }) {
                let length = result.unwrap();
                if length >= (if v6 { 48 } else { 28 })
                    && bytes[0] >> 4 == (if v6 { 6 } else { 4 })
                    && bytes[if v6 { 6 } else { 9 }] == 17
                {
                    bytes.truncate(length);
                    return bytes;
                }
            }
        }
    })
    .await
    .unwrap()
}

#[tokio::test]
#[ignore = "requires isolated network namespace, /dev/net/tun and CAP_NET_ADMIN"]
async fn endpoint_injection_preserves_large_replies_and_real_network_pmtu() {
    use nix::libc;
    let fixed: RelaySources = RelaySources {
        ipv4: Some("172.27.1.1".parse().unwrap()),
        ipv6: Some("fdf0:ce4a:801d::172:27:1:1".parse().unwrap()),
    };
    let mut configuration = tun::Configuration::default();
    configuration
        .tun_name("krtek-pmtu")
        .address(fixed.ipv4.unwrap())
        .destination("203.0.113.9")
        .netmask("255.255.255.255")
        .mtu(1280)
        .up();
    let mut device = tun::create(&configuration).expect("isolated kernel TUN");
    device.set_nonblock().unwrap();
    let index = device.tun_index().unwrap() as u32;
    add_ipv6_address(index, fixed.ipv6.unwrap());
    // Reassembly queues belong to the namespace and outlive this process, so
    // a fixed fragment identification could join a queue left by an earlier
    // run. The kernel never reuses an ifindex within a namespace until it
    // wraps, which makes this TUN's index a unique identification per run.
    let identification = index;
    for interface in ["all", "krtek-pmtu"] {
        assert_eq!(
            std::fs::read_to_string(format!("/proc/sys/net/ipv4/conf/{interface}/accept_local"))
                .unwrap()
                .trim(),
            "0"
        );
    }
    // SAFETY: device retains ownership until after the reactor is dropped.
    let descriptor = AsyncFd::new(unsafe { BorrowedFd::borrow_raw(device.as_raw_fd()) }).unwrap();
    let root = BufferBudget::new(64 * 1024 * 1024);
    let buffers = || Arc::new(root.reserve(16 * 1024 * 1024).unwrap().region().unwrap());
    let broker = AttachmentBroker::new(buffers(), buffers(), buffers()).unwrap();
    broker
        .set_mode(crate::packet_attachment::AttachmentMode::ManagedRequired)
        .unwrap();
    let mut config = crate::tun_provider::blocking_config();
    config.addresses = vec![fixed.ipv4.unwrap().into(), fixed.ipv6.unwrap().into()];
    config.mtu = 1280;
    let mut request = broker.request_capture(config).unwrap();
    let pending = broker.pending_request().unwrap();
    let capture = broker.open_capture(Some(&pending)).unwrap();
    let receipt = capture
        .bind_observed_identity("krtek-pmtu", 71_u64 << 32, fixed, 1280)
        .unwrap();
    broker.acknowledge(&pending, &receipt).unwrap();
    request.configured().await.unwrap();
    let pair = broker.acquire(&receipt).unwrap();
    pair.control.activate().unwrap();
    let mut path = TargetPacketPath::new(
        TargetConfig {
            target_id: 1,
            fixed,
            assigned: RelaySources {
                ipv4: Some("10.64.0.7".parse().unwrap()),
                ipv6: Some("fd00::7".parse().unwrap()),
            },
            mtu: 1380,
        },
        pair.control.capability(),
        broker.application_buffers(),
    )
    .unwrap();
    let sink = pair.control.capability().sink().unwrap();
    for v6 in [false, true] {
        device.set_mtu(1280).unwrap();
        let local: IpAddr = if v6 {
            fixed.ipv6.unwrap().into()
        } else {
            fixed.ipv4.unwrap().into()
        };
        let remote: IpAddr = if v6 {
            "fdf0:ce4a:801d::9".parse().unwrap()
        } else {
            "203.0.113.9".parse().unwrap()
        };
        let socket = UdpSocket::bind((local, 0)).unwrap();
        socket.connect((remote, 42042)).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let level = if v6 {
            libc::IPPROTO_IPV6
        } else {
            libc::IPPROTO_IP
        };
        let option = if v6 { libc::IPV6_MTU } else { libc::IP_MTU };
        assert_eq!(socket_option(&socket, level, option), 1280);
        socket.send(b"invoking-socket").unwrap();
        let input = invocation(&descriptor, v6).await;
        let wire = owned_bytes(path.process(&input, Direction::Outbound).unwrap());
        let payload: Vec<u8> = (0..3072).map(|n| (n % 251) as u8).collect();
        let reply = peer_reply(&wire, &payload);
        let pieces = fragments(&reply, identification);
        assert_eq!(pieces.len(), 3);
        assert!(pieces[0].len() > 1280);
        for piece in pieces.iter().rev() {
            let packet = path.process(piece, Direction::Inbound).unwrap();
            assert_eq!(packet.view().bytes().len(), piece.len());
            pair.send.try_send_packet(packet).unwrap();
            let mut pending = Some(capture.reply().await.unwrap());
            let _writable = descriptor.writable().await.unwrap();
            assert!(drain_reply(&descriptor, &sink, &mut pending).unwrap());
            assert!(pending.is_none());
        }
        let mut received = vec![0; 4096];
        let length = socket
            .recv(&mut received)
            .expect("kernel must rejoin oversized return fragments");
        assert_eq!(&received[..length], payload);

        // A new real invocation on a larger native path receives peer ICMP.
        // The translator only maps the error and its quotation back to the
        // invoking socket; no product error generation participates.
        device.set_mtu(9000).unwrap();
        let socket = UdpSocket::bind((local, 0)).unwrap();
        socket.connect((remote, 42042)).unwrap();
        discover(&socket, v6);
        assert_eq!(socket_option(&socket, level, option), 9000);
        socket.send(&vec![0x5a; 3000]).unwrap();
        let input = invocation(&descriptor, v6).await;
        let wire = owned_bytes(path.process(&input, Direction::Outbound).unwrap());
        let error = peer_error(&wire);
        pair.send
            .try_send_packet(path.process(&error, Direction::Inbound).unwrap())
            .unwrap();
        let mut pending = Some(capture.reply().await.unwrap());
        let _writable = descriptor.writable().await.unwrap();
        assert!(drain_reply(&descriptor, &sink, &mut pending).unwrap());
        assert!(pending.is_none());
        tokio::time::timeout(Duration::from_secs(2), async {
            while socket_option(&socket, level, option) != 1280 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("kernel socket did not learn real peer PMTU");
        assert_eq!(
            socket.send(&vec![0x5a; 3000]).unwrap_err().raw_os_error(),
            Some(libc::EMSGSIZE)
        );
    }
    assert_eq!(
        std::fs::read_to_string("/proc/sys/net/ipv4/conf/krtek-pmtu/accept_local")
            .unwrap()
            .trim(),
        "0"
    );
}
