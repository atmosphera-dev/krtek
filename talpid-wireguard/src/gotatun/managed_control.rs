//! Per-attempt application target and a separate prepaid connectivity pinger.
//! Address translation is after capture selection and before SourceFilter;
//! authenticated private replies are demultiplexed before inverse translation.
use crate::{
    config::Config,
    connectivity::{CancelReceiver, CancelToken, SmoltcpPinger},
};
use gotatun::{
    packet::{Ip, Packet, PacketBufPool},
    tun::{IpRecv, IpSend, MtuWatcher},
};
use std::{
    collections::VecDeque,
    io,
    net::Ipv4Addr,
    sync::atomic::{AtomicBool, Ordering},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use talpid_netstack::{
    address_translation::{Direction, TargetConfig, TargetPacketPath, TranslationError},
    smoltcp_network::{
        SmoltcpIcmpSocket, SmoltcpIpRecv, SmoltcpIpSend, SmoltcpNetworkConfig, SmoltcpNetworkGuard,
        smoltcp_network_retained,
    },
};
use talpid_tunnel::{
    packet_attachment::{
        AttachmentBroker, AttemptControl, CaptureReceipt, ConfigurationRequest, TransportPair,
        TransportReceive, TransportSend,
    },
    tun_provider::TunConfig,
};
use talpid_types::relay_flow::{
    RelayBufferAllocator, RelayBufferReservation, RelayFlowError, RelaySources,
};

const REQUESTS: usize = 32;
const REQUEST_LIFETIME: Duration = Duration::from_secs(15);
// Private MTU never sizes ordinary IP. At most one ICMP socket, 16 queued
// 50-byte requests, 2 x 256 packet channels, 512 device packets, socket rings,
// channel/stack/ledger metadata and transient processing fit conservatively.
const CONTROL_STORAGE: usize = 4 * 1024 * 1024;
const CONTROL_MTU: u16 = 1280;

pub(super) fn unavailable() -> io::Error {
    // GotaTun retries nonfatal receive errors synchronously. Retirement is
    // terminal, including setup failure: never turn it into a hot retry loop.
    io::ErrorKind::BrokenPipe.into()
}

/// Configuration request ownership exists before any async platform wait.
pub(super) struct SetupRequests {
    current: Mutex<SetupRequest>,
}

struct SetupRequest {
    cancelled: bool,
    cleanup: talpid_tunnel::packet_attachment::TransportCleanup,
}

impl SetupRequests {
    pub(super) fn cancel(&self) {
        let mut current = self.current.lock().expect("setup request");
        current.cancelled = true;
        current.cleanup.cancel();
    }
}

pub(super) struct PendingManaged {
    broker: AttachmentBroker,
    config: TunConfig,
    capture_config: TunConfig,
    request: Option<ConfigurationRequest>,
    setup: Arc<SetupRequests>,
    pub(super) cancellation: CancelToken,
    pub(super) cancelled: CancelReceiver,
    #[cfg(test)]
    pub(super) after_receipt: Option<tokio::sync::oneshot::Receiver<()>>,
    #[cfg(test)]
    pub(super) after_receipt_entered: Option<tokio::sync::oneshot::Sender<()>>,
    #[cfg(test)]
    pub(super) after_stack: Option<(
        tokio::sync::oneshot::Sender<()>,
        tokio::sync::oneshot::Receiver<()>,
    )>,
    #[cfg(test)]
    pub(super) cleanup_complete: Option<tokio::sync::oneshot::Sender<()>>,
}

impl PendingManaged {
    pub(super) fn cleanup(&self) -> Arc<SetupRequests> {
        self.setup.clone()
    }
    pub(super) fn new(source: talpid_tunnel::tun_provider::transport::ManagedTun) -> Self {
        let (cancellation, cancelled) = CancelToken::new();
        let setup = Arc::new(SetupRequests {
            current: Mutex::new(SetupRequest {
                cancelled: false,
                cleanup: source.request.cleanup(),
            }),
        });
        Self {
            broker: source.broker,
            config: source.config,
            capture_config: source.capture_config,
            request: Some(source.request),
            setup,
            cancellation,
            cancelled,
            #[cfg(test)]
            after_receipt: None,
            #[cfg(test)]
            after_receipt_entered: None,
            #[cfg(test)]
            after_stack: None,
            #[cfg(test)]
            cleanup_complete: None,
        }
    }

    #[cfg(test)]
    pub(super) fn request(broker: AttachmentBroker, config: TunConfig) -> io::Result<Self> {
        talpid_tunnel::tun_provider::transport::ManagedTun::request(broker, config)
            .map(Self::new)
            .map_err(io::Error::other)
    }

    /// Retry uses a fresh configuration request, receipt and sole receiver.
    /// The caller must finish joined cleanup of the previous pair first.
    pub(super) async fn create(&mut self, config: &Config) -> io::Result<ManagedPair> {
        let result = self.create_inner(config).await;
        if result.is_err()
            && let Some(request) = &self.request
        {
            // No installed device escaped. The fallible control construction
            // below joins its guard before returning an error.
            request.transport_joined();
        }
        result
    }

    async fn create_inner(&mut self, config: &Config) -> io::Result<ManagedPair> {
        if self.cancellation.is_closed() {
            return Err(io::ErrorKind::Interrupted.into());
        }
        if self.request.is_none() {
            // Publication of a fresh request and caller-drop cancellation share
            // this lock. Drop can never retain only the previous retry identity.
            let mut current = self.setup.current.lock().expect("setup request");
            if current.cancelled || self.cancellation.is_closed() {
                return Err(io::ErrorKind::Interrupted.into());
            }
            let request = self
                .broker
                .request_target_capture(self.config.clone(), self.capture_config.clone())
                .map_err(io::Error::other)?;
            current.cleanup = request.cleanup();
            self.request = Some(request);
        }
        // Platform acquisition is owned/joined, not an independent admission
        // deadline. The fd owner's new-route wait has upstream's2s boundary.
        let receipt = tokio::select! { biased;
            _ = self.cancelled.cancelled() => {
                self.request.as_ref().expect("request owner").cancel();
                return Err(io::ErrorKind::Interrupted.into());
            }
            receipt = self.request.as_mut().expect("request owner").configured() => receipt.map_err(io::Error::other)?,
        };
        #[cfg(test)]
        if let Some(resume) = self.after_receipt.take() {
            if let Some(entered) = self.after_receipt_entered.take() {
                let _ = entered.send(());
            }
            tokio::select! { biased;
                _ = self.cancelled.cancelled() => { self.request.as_ref().expect("request owner").cancel(); return Err(io::ErrorKind::Interrupted.into()); },
                result = resume => result.map_err(|_| unavailable())?,
            }
        }
        let pair = self.broker.acquire(&receipt).map_err(io::Error::other)?;
        let source = config.tunnel_ipv4();
        let identity = pair.control.capability();
        if identity.sources().ipv4 != source
            || identity.sources().ipv6 != config.tunnel_ipv6()
            || identity.mtu() != config.mtu
        {
            return Err(unavailable());
        }
        let path = TargetPacketPath::new(
            TargetConfig {
                target_id: identity.target().get(),
                fixed: identity.identity().sources,
                assigned: RelaySources {
                    ipv4: config.tunnel_ipv4(),
                    ipv6: config.tunnel_ipv6(),
                },
                mtu: config.mtu,
            },
            identity,
            self.broker.application_buffers(),
        )
        .map_err(|_| unavailable())?;
        let id = rand::random();
        let private = if let Some(source) = source {
            let storage = self
                .broker
                .control_buffers()
                .try_reserve(CONTROL_STORAGE)
                .map_err(|_| io::ErrorKind::OutOfMemory)?;
            let (network, receive, send, mut guard) = smoltcp_network_retained(
                SmoltcpNetworkConfig {
                    ipv4_addr: source,
                    ipv6_addr: None,
                    mtu: CONTROL_MTU.min(config.mtu),
                },
                storage.clone(),
            );
            #[cfg(test)]
            if let Some((entered, resume)) = self.after_stack.take() {
                let _ = entered.send(());
                tokio::select! { biased;
                    _ = self.cancelled.cancelled() => {
                        self.request.as_ref().expect("request owner").cancel();
                        guard.stop().await;
                        return Err(io::ErrorKind::Interrupted.into());
                    },
                    _ = resume => {},
                }
            }
            let socket = tokio::select! { biased;
                _ = self.cancelled.cancelled() => {
                    self.request.as_ref().expect("request owner").cancel();
                    Err(io::ErrorKind::Interrupted.into())
                },
                socket = network.icmp_socket(id) => socket,
            };
            let socket = match socket {
                Ok(socket) => socket,
                Err(error) => {
                    guard.stop().await;
                    return Err(error);
                }
            };
            // The handle with TCP methods does not escape this construction.
            drop(network);
            Some((receive, send, guard, socket, storage))
        } else {
            None
        };
        let (receive, send, guard, socket, storage) = match private {
            Some((receive, send, guard, socket, storage)) => (
                Some(receive),
                Some(send),
                Some(guard),
                Some(socket),
                Some(storage),
            ),
            None => (None, None, None, None, None),
        };
        let TransportPair {
            control,
            receive: ordinary_receive,
            send: ordinary_send,
        } = pair;
        let (send_dropped, send_joined) = tokio::sync::oneshot::channel();
        let (receive_dropped, receive_joined) = tokio::sync::oneshot::channel();
        let owner = Arc::new(ManagedControl {
            control,
            receipt,
            request: self.request.take().expect("request owner"),
            guard: tokio::sync::Mutex::new(guard),
            device_halves: tokio::sync::Mutex::new([Some(send_joined), Some(receive_joined)]),
            socket: Mutex::new(socket),
            source,
            gateway: config.ipv4_gateway,
            id,
            secret: rand::random(),
            ledger: Mutex::new(Ledger {
                highest: 0,
                live: VecDeque::with_capacity(REQUESTS),
            }),
            application: self.broker.application_buffers(),
            ordinary_send,
            path: Mutex::new(path),
            _storage: storage,
            installed: AtomicBool::new(false),
            #[cfg(test)]
            return_pending: Mutex::new(None),
        });
        Ok(ManagedPair {
            send: ManagedSend {
                send,
                owner: owner.clone(),
                _dropped: send_dropped,
            },
            receive: ManagedReceive {
                receive,
                ordinary_receive,
                owner: owner.clone(),
                turn: 0,
                _dropped: receive_dropped,
            },
            owner,
        })
    }
}

pub(super) struct ManagedPair {
    pub(super) send: ManagedSend,
    pub(super) receive: ManagedReceive,
    pub(super) owner: Arc<ManagedControl>,
}

struct Ledger {
    highest: u64,
    live: VecDeque<(u64, Instant)>,
}

pub(crate) struct ManagedControl {
    control: AttemptControl,
    receipt: CaptureReceipt,
    request: ConfigurationRequest,
    guard: tokio::sync::Mutex<Option<SmoltcpNetworkGuard>>,
    device_halves: tokio::sync::Mutex<[Option<tokio::sync::oneshot::Receiver<()>>; 2]>,
    socket: Mutex<Option<SmoltcpIcmpSocket>>,
    source: Option<Ipv4Addr>,
    gateway: Ipv4Addr,
    id: u16,
    secret: [u8; 32],
    ledger: Mutex<Ledger>,
    application: Arc<dyn RelayBufferAllocator>,
    ordinary_send: TransportSend,
    path: Mutex<TargetPacketPath>,
    _storage: Option<Arc<dyn RelayBufferReservation>>,
    installed: AtomicBool,
    #[cfg(test)]
    return_pending: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
}

impl ManagedControl {
    pub(super) fn live(&self) -> bool {
        // The receipt admits this adapter's initial fd epoch. Ongoing transport
        // and private-control lifetime belongs to the exact tunnel attempt;
        // a coordinated sink handover must not terminate that live target.
        self.control.live()
    }
    pub(super) fn interface(&self) -> String {
        self.control
            .capability()
            .sink()
            .map(|sink| sink.identity().interface.clone())
            .unwrap_or_default()
    }
    pub(crate) fn pinger(&self) -> io::Result<SmoltcpPinger> {
        let socket = self.socket.lock().expect("private pinger").take();
        if self.source.is_some() && socket.is_none() {
            return Err(unavailable());
        }
        Ok(SmoltcpPinger::new(
            socket,
            self.gateway,
            self.id,
            self.secret,
        ))
    }
    pub(crate) fn activate(&self) -> io::Result<()> {
        if !self.live() || !self.installed.load(Ordering::Acquire) {
            return Err(unavailable());
        }
        self.control
            .activate_with_receipt(&self.receipt)
            .map_err(|_| unavailable())
    }
    pub(crate) fn publish<T>(&self, operation: impl FnOnce() -> T) -> io::Result<T> {
        self.control
            .capability()
            .with_current(operation)
            .map_err(|_| unavailable())
    }
    pub(super) fn installed(&self) {
        self.installed.store(true, Ordering::Release);
    }
    pub(crate) fn revoke(&self) {
        self.control.detach();
        self.request.cancel();
    }
    pub(crate) async fn cancelled(&self) {
        self.control.cancelled().await;
    }
    pub(super) async fn stop(&self) {
        self.revoke();
        if let Some(guard) = self.guard.lock().await.as_mut() {
            guard.stop().await;
        }
        // Every production caller has already joined create_devices failure or
        // devices.stop(). The control guard is the final transport task owner.
        self.request.transport_joined();
    }

    pub(super) async fn stop_after_device(&self) {
        self.revoke();
        // Device::stop joins I/O, but Device::drop spawns a final cleanup task
        // that still owns its plaintext halves. Join their actual destruction
        // before acknowledging transport cleanup or refunding private storage.
        for receiver in self.device_halves.lock().await.iter_mut() {
            if let Some(joined) = receiver.as_mut() {
                let _ = joined.await;
                *receiver = None;
            }
        }
        self.stop().await;
    }

    // This deliberately recognizes only a plain IPv4 private echo. Fragments,
    // errors/quotations, options and all IPv6 chains remain raw application IP.
    fn echo(&self, bytes: &[u8], outbound: bool) -> Option<u64> {
        let assigned = self.source?;
        if bytes.len() != 70
            || bytes[0] != 0x45
            || bytes[9] != 1
            || u16::from_be_bytes([bytes[2], bytes[3]]) != 70
            || u16::from_be_bytes([bytes[6], bytes[7]]) & 0x3fff != 0
            || internet_checksum::checksum(&bytes[..20]) != [0, 0]
            || internet_checksum::checksum(&bytes[20..]) != [0, 0]
        {
            return None;
        }
        let (source, destination) = if outbound {
            (assigned, self.gateway)
        } else {
            (self.gateway, assigned)
        };
        if bytes[12..16] != source.octets()
            || bytes[16..20] != destination.octets()
            || bytes[20..22] != [if outbound { 8 } else { 0 }, 0]
            || bytes[24..26] != self.id.to_be_bytes()
            || bytes[28..60] != self.secret
            || bytes[68..70] != [0, 0]
        {
            return None;
        }
        let counter = u64::from_be_bytes(bytes[60..68].try_into().ok()?);
        (counter != 0 && bytes[26..28] == (counter as u16).to_be_bytes()).then_some(counter)
    }
    fn record(&self, bytes: &[u8]) -> bool {
        let Some(counter) = self.echo(bytes, true) else {
            return false;
        };
        let mut ledger = self.ledger.lock().expect("private ledger");
        ledger
            .live
            .retain(|(_, sent)| sent.elapsed() < REQUEST_LIFETIME);
        if !self.live() || counter <= ledger.highest || ledger.live.len() == REQUESTS {
            return false;
        }
        ledger.highest = counter;
        ledger.live.push_back((counter, Instant::now()));
        true
    }
    fn reply(&self, bytes: &[u8]) -> Reply {
        let Some(counter) = self.echo(bytes, false) else {
            return Reply::Application;
        };
        let mut ledger = self.ledger.lock().expect("private ledger");
        ledger
            .live
            .retain(|(_, sent)| sent.elapsed() < REQUEST_LIFETIME);
        if let Some(index) = ledger.live.iter().position(|(value, _)| *value == counter) {
            ledger.live.remove(index);
            Reply::Private
        } else if counter <= ledger.highest {
            // An exact issued probe remains recognizable after bounded ledger
            // expiry/consumption, without retaining an unbounded replay history.
            Reply::Discard
        } else {
            Reply::Application
        }
    }
}

enum Reply {
    Private,
    Discard,
    Application,
}

#[cfg(test)]
#[path = "tcp_fixture.rs"]
mod tcp_fixture;

pub(super) struct ManagedReceive {
    receive: Option<SmoltcpIpRecv>,
    ordinary_receive: TransportReceive,
    owner: Arc<ManagedControl>,
    turn: u8,
    // Fields drop in order: completion follows the owned handles and owner Arc.
    _dropped: tokio::sync::oneshot::Sender<()>,
}

impl ManagedControl {
    fn translate(
        &self,
        bytes: &[u8],
        direction: Direction,
    ) -> Result<talpid_types::relay_flow::RelayPacket, TranslationError> {
        self.path
            .lock()
            .expect("target path")
            .process(bytes, direction)
    }
    fn refused(&self, reason: TranslationError) {
        self.path.lock().expect("target path").refused(reason);
    }
    fn handoff_refused(&self, error: RelayFlowError) {
        self.refused(match error {
            RelayFlowError::Full => TranslationError::Full,
            RelayFlowError::Stale | RelayFlowError::Closed => TranslationError::Stale,
            RelayFlowError::Invalid => TranslationError::Malformed,
        });
    }
}

impl ManagedReceive {
    async fn private(
        receive: &mut Option<SmoltcpIpRecv>,
        pool: &mut PacketBufPool,
    ) -> io::Result<Option<Packet<Ip>>> {
        match receive {
            Some(receive) => Ok(receive.recv(pool).await?.next()),
            None => std::future::pending().await,
        }
    }
    async fn ordinary_parts(
        receive: &mut TransportReceive,
        owner: &ManagedControl,
    ) -> io::Result<talpid_types::relay_flow::RelayPacket> {
        loop {
            let packet = receive.recv().await.map_err(|_| unavailable())?;
            if let Ok(packet) = owner
                .path
                .lock()
                .expect("target path")
                .process_owned(packet, Direction::Outbound)
            {
                return Ok(packet);
            }
            tokio::task::yield_now().await;
        }
    }
}

enum Selected {
    Private(Option<Packet<Ip>>),
    Application(talpid_types::relay_flow::RelayPacket),
}
impl IpRecv for ManagedReceive {
    async fn recv<'a>(
        &'a mut self,
        pool: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + Send + 'a> {
        loop {
            if !self.owner.live() {
                return Err(unavailable());
            }
            // Rotate priority: neither an application flood nor private probes
            // can starve the other. Each handoff yields at most one packet.
            let turn = self.turn;
            self.turn = (turn + 1) % 2;
            let owner = self.owner.clone();
            let packet = if turn == 0 {
                tokio::select! { biased;
                    _ = owner.cancelled() => return Err(unavailable()),
                    packet = Self::private(&mut self.receive, pool) => Selected::Private(packet?),
                    packet = Self::ordinary_parts(&mut self.ordinary_receive, &owner) => Selected::Application(packet?),
                }
            } else {
                tokio::select! { biased;
                    _ = owner.cancelled() => return Err(unavailable()),
                    packet = Self::ordinary_parts(&mut self.ordinary_receive, &owner) => Selected::Application(packet?),
                    packet = Self::private(&mut self.receive, pool) => Selected::Private(packet?),
                }
            };
            let packet = match packet {
                Selected::Private(Some(packet)) => {
                    let bytes = packet.into_bytes();
                    if !self.owner.record(&bytes) {
                        continue;
                    }
                    bytes.try_into_ip().map_err(|_| unavailable())?
                }
                Selected::Private(_) => continue,
                Selected::Application(packet) => match talpid_netstack::raw_packet::handoff(
                    packet,
                    self.owner.application.as_ref(),
                    |packet| packet,
                ) {
                    Ok(packet) => packet,
                    Err(error) => {
                        self.owner.handoff_refused(error);
                        continue;
                    }
                },
            };
            if !self.owner.live() {
                return Err(unavailable());
            }
            return Ok(std::iter::once(packet));
        }
    }
    fn mtu(&self) -> MtuWatcher {
        MtuWatcher::new(self.owner.control.capability().mtu())
    }
}

pub(super) struct ManagedSend {
    send: Option<SmoltcpIpSend>,
    owner: Arc<ManagedControl>,
    _dropped: tokio::sync::oneshot::Sender<()>,
}
impl IpSend for ManagedSend {
    async fn send(&mut self, packet: Packet<Ip>) -> io::Result<()> {
        if !self.owner.live() {
            return Err(unavailable());
        }
        let bytes = packet.into_bytes();
        match self.owner.reply(&bytes) {
            Reply::Private => {
                // Only exact 70-byte private replies enter this fixed stack.
                let packet = bytes.try_into_ip().map_err(|_| unavailable())?;
                tokio::select! { biased;
                    _ = self.owner.cancelled() => Err(unavailable()),
                    result = self.send.as_mut().expect("private reply has assigned source").send(packet) => result,
                }
            }
            Reply::Discard => Ok(()),
            Reply::Application => {
                self.owner
                    .control
                    .ready()
                    .await
                    .map_err(|_| unavailable())?;
                match self.owner.translate(&bytes, Direction::Inbound) {
                    Ok(packet) => {
                        drop(bytes);
                        let send = self.owner.ordinary_send.send_packet(packet);
                        tokio::pin!(send);
                        #[cfg(test)]
                        let send = std::future::poll_fn(|cx| {
                            let result = std::future::Future::poll(send.as_mut(), cx);
                            if result.is_pending()
                                && let Some(observer) = self
                                    .owner
                                    .return_pending
                                    .lock()
                                    .expect("owned return observer")
                                    .take()
                            {
                                let _ = observer.send(());
                            }
                            result
                        });
                        send.await.map_err(|_| unavailable())?;
                    }
                    Err(TranslationError::Stale) => return Err(unavailable()),
                    // Pre-ownership validation/budget refusals are counted by
                    // the mapper; they never masquerade as an owned queue send.
                    Err(_) => {}
                }
                Ok(())
            }
        }
    }
}
