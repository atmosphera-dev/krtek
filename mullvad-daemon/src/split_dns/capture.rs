//! Capture-owned DNS attachment. Profile projection belongs to its capture owner.
use super::home_path::HomeDnsPath;
use super::{
    udp::{self, UdpDecision},
    udp_work::HomeUdpWork,
};
use crate::local_delivery::DeliveryAuthority;
use std::{io, net::IpAddr, sync::Arc, time::Duration};
use talpid_lan_forwarder::{
    Transport,
    packet_receiver::{CompletedDatagram, PacketReceiver, dns_endpoints},
};
use talpid_tunnel::android_frontend::{DnsFuture, DnsReceiver};
use talpid_types::relay_flow::{RelayBuffer, RelayBufferAllocator, RelayCapture, RelaySink};

pub(crate) struct CaptureDns {
    authority: Arc<DeliveryAuthority>,
    buffers: Arc<dyn RelayBufferAllocator>,
    receiver: Option<PacketReceiver>,
    work: Option<HomeUdpWork>,
    original: Option<CompletedDatagram>,
    path: Arc<dyn HomeDnsPath>,
    tcp: Option<super::tcp::TcpWork>,
    tcp_next: bool,
    system: Option<Arc<super::system::SystemIo>>,
}

impl CaptureDns {
    pub(crate) fn new(
        authority: Arc<DeliveryAuthority>,
        buffers: Arc<dyn RelayBufferAllocator>,
        path: Arc<dyn HomeDnsPath>,
    ) -> Self {
        Self {
            authority,
            buffers,
            receiver: None,
            work: None,
            original: None,
            path,
            tcp: None,
            tcp_next: false,
            system: None,
        }
    }
    pub(crate) fn with_system(
        mut self,
        platform: Arc<dyn talpid_tunnel::android_frontend::FrontendPlatform>,
    ) -> Self {
        self.system = Some(Arc::new(super::system::SystemIo::new(
            platform,
            self.buffers.clone(),
        )));
        self
    }
}

impl DnsReceiver for CaptureDns {
    fn set_partial(&mut self, partial: bool) {
        if let Some(system) = &self.system {
            system
                .partial
                .store(partial, std::sync::atomic::Ordering::Release);
        }
        self.revalidate();
    }
    fn candidate(&self, bytes: &[u8], advertised: &[IpAddr]) -> bool {
        if let Ok(packet) = talpid_lan_forwarder::packet::parse(bytes)
            && let Some(current) = self.tcp.as_ref().and_then(|tcp| tcp.egress(packet.flow))
        {
            return !current;
        }
        if !self.authority.dns_enabled()
            || !talpid_netstack::raw_packet::inspect(bytes).is_ok_and(|ip| {
                ip.destination()
                    .is_some_and(|destination| advertised.contains(&destination))
            })
        {
            return false;
        }
        match dns_endpoints(bytes) {
            Ok(Some(_)) => !talpid_lan_forwarder::packet::parse(bytes).is_ok_and(|packet| {
                packet.flow.destination.port() != 53
                    || self.tcp.as_ref().is_some_and(|tcp| tcp.owns(packet.flow))
            }),
            // A validation refusal is not evidence of ordinary traffic. Once
            // selected by resolver destination, ambiguous input stays here and
            // ingest refuses it before any Home authority or carrier release.
            Err(_) => true,
            Ok(None) => false,
        }
    }

    fn ingest(
        &mut self,
        bytes: &[u8],
        advertised: &[IpAddr],
        capture: &RelayCapture,
        replies: Arc<dyn RelayBufferAllocator>,
        mtu: u16,
    ) -> bool {
        if let Ok(packet) = talpid_lan_forwarder::packet::parse(bytes)
            && let Some(current) = self.tcp.as_ref().and_then(|tcp| tcp.egress(packet.flow))
        {
            return !current;
        }
        let Ok(Some((source, destination))) = dns_endpoints(bytes) else {
            return true;
        };
        let Ok((matcher, scope)) = self
            .authority
            .dns_input(source, destination, &*self.buffers)
        else {
            return true;
        };
        if self.receiver.is_none() {
            let Ok(receiver) = PacketReceiver::new(self.buffers.clone(), mtu) else {
                return true;
            };
            self.receiver = Some(receiver);
            if self.work.is_none() {
                self.work = Some(HomeUdpWork::new(
                    Some(self.path.clone()),
                    capture.clone(),
                    self.buffers.clone(),
                    replies.clone(),
                ));
            }
        }
        let receiver = self.receiver.as_mut().expect("DNS input owner");
        if let Ok(Some(input)) = receiver.ingest(&scope, bytes)
            && let Ok(packet) = input.packet()
        {
            if packet.flow.transport == Transport::Tcp {
                let egress = self.tcp.as_ref().and_then(|tcp| tcp.egress(packet.flow));
                if egress == Some(false) {
                    return true;
                }
                if packet.flow.destination.port() != 53 || egress == Some(true) {
                    self.original = Some(input);
                } else {
                    if self.tcp.is_none() {
                        self.tcp = super::tcp::TcpWork::new(
                            self.authority.clone(),
                            self.buffers.clone(),
                            self.path.clone(),
                            capture.clone(),
                            mtu,
                            self.system.clone(),
                        )
                        .ok();
                    }
                    if let (Some(tcp), Ok(normalized)) =
                        (&mut self.tcp, input.tcp_packet(&*self.buffers))
                    {
                        tcp.ingest(&normalized);
                    }
                }
                return true;
            }
            match udp::inspect(
                Some(&matcher),
                advertised,
                packet.flow.source,
                packet.flow.destination,
                packet.payload,
            ) {
                UdpDecision::PassThrough(original) => {
                    debug_assert_eq!(original, packet.payload);
                    if let Some(system) = &self.system
                        && system.is_partial()
                    {
                        let _ = self.work.as_mut().expect("DNS work owner").submit_system(
                            system.clone(),
                            input,
                            scope.clone(),
                        );
                    } else {
                        self.original = Some(input);
                    }
                }
                UdpDecision::Drop => {}
                UdpDecision::Intercept(query) => {
                    let limit = if source.is_ipv4() { 65507 } else { 65487 };
                    let _ = self.work.as_mut().expect("DNS work owner").submit(
                        *query,
                        input,
                        Duration::from_secs(5),
                        true,
                        limit,
                    );
                }
            }
        }
        true
    }

    fn original(&mut self) -> Option<RelayBuffer> {
        let input = self.original.as_mut()?;
        match input.pop_original() {
            Ok(Some(bytes)) => Some(bytes),
            _ => {
                self.original.take();
                None
            }
        }
    }
    fn has_original(&self) -> bool {
        self.original.is_some()
    }
    fn has_output(&self) -> bool {
        self.work.as_ref().is_some_and(HomeUdpWork::has_output)
            || self
                .tcp
                .as_ref()
                .is_some_and(super::tcp::TcpWork::has_output)
    }
    fn set_mtu(&mut self, mtu: u16) -> Result<(), talpid_lan_forwarder::Refused> {
        if let Some(tcp) = &mut self.tcp {
            tcp.set_mtu(mtu)?;
        }
        if let Some(receiver) = &mut self.receiver {
            receiver
                .set_mtu(mtu)
                .map_err(|_| talpid_lan_forwarder::Refused::PreparationFailed)?;
        }
        Ok(())
    }
    fn reset_inputs(&mut self) {
        if let Some(tcp) = &mut self.tcp {
            tcp.revalidate();
        }
        self.original.take();
        self.receiver.take();
        if let Some(work) = &mut self.work {
            work.revalidate();
        }
    }
    fn revalidate(&mut self) {
        if let Some(tcp) = &mut self.tcp {
            tcp.revalidate();
        }
        if let Some(receiver) = &mut self.receiver {
            receiver.revalidate();
        }
        if let Some(work) = &mut self.work {
            work.revalidate();
        }
        if self.original.as_ref().is_some_and(|input| !input.current()) {
            self.original.take();
        }
    }
    fn process(&mut self) {
        self.revalidate();
        if let Some(tcp) = &mut self.tcp {
            tcp.process();
        }
        if let (Some(work), Some(receiver)) = (&mut self.work, &mut self.receiver) {
            work.process(receiver);
        }
    }
    fn wait(&mut self) -> DnsFuture<'_, ()> {
        Box::pin(async move {
            tokio::select! {
                _ = async { match &mut self.tcp { Some(tcp) => tcp.wait().await, None => std::future::pending().await } } => {},
                _ = async { match &mut self.work { Some(work) => work.wait().await, None => std::future::pending().await } } => {},
                _ = async { match &mut self.receiver { Some(receiver) => receiver.wait().await, None => std::future::pending().await } } => {},
            }
        })
    }
    fn write_output(
        &mut self,
        sink: &RelaySink,
        write: &mut dyn FnMut(&[u8]) -> io::Result<usize>,
    ) -> io::Result<bool> {
        if let Some(tcp) = &mut self.tcp
            && tcp.has_output()
            && (self.tcp_next || !self.work.as_ref().is_some_and(HomeUdpWork::has_output))
        {
            let result = tcp.write_output(sink, write);
            if matches!(result, Ok(true)) {
                self.tcp_next = false;
            }
            return result;
        }
        match &mut self.work {
            Some(work) => {
                let result = work.write_output(sink, write);
                if matches!(result, Ok(true)) {
                    self.tcp_next = true;
                }
                result
            }
            None => Ok(false),
        }
    }
    fn close(&mut self) -> DnsFuture<'_, io::Result<()>> {
        Box::pin(async move {
            self.original.take();
            if let Some(tcp) = &mut self.tcp {
                tcp.close().await;
            }
            if let Some(work) = &mut self.work {
                work.close().await?;
            }
            self.receiver.take();
            if let Some(system) = &self.system {
                system.io.close().await?;
            }
            Ok(())
        })
    }
}
