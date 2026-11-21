//! Single-owner, readiness-driven forwarding with count/size ceilings.

mod stack;

use crate::{
    Disposition, Flow, LocalAuthority, Refused, Transport,
    ip_endpoint::{
        capture::{self, BATCH_RESERVATION, PacketBatch},
        contract::{IpError, LocalIpEngine, ReceiveScopeId, ReplyTuple},
        native::Engine,
    },
    packet::{self, MAX_PACKET_SIZE, PacketRefusal},
};
use smoltcp::{
    iface::SocketHandle, socket::tcp, time::Instant as StackInstant, wire::TcpSeqNumber,
};
use socket2::{Domain, Protocol, Socket, Type};
use stack::Stack;
use std::{
    collections::{HashMap, VecDeque},
    future::{Future, poll_fn},
    io,
    net::Shutdown,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, Waker},
    time::Duration,
};
use talpid_types::relay_flow::{
    BUFFER_OVERHEAD, RelayBuffer, RelayBufferAllocator, RelayBufferReservation,
};
use tokio::{
    net::{TcpSocket, TcpStream, UdpSocket},
    sync::Notify,
    task::JoinHandle,
    time::Instant,
};

const TCP_FLOWS: usize = 64;
const TCP_TOMBSTONES: usize = 256;
const _: () = assert!(TCP_TOMBSTONES >= TCP_FLOWS);
const UDP_FLOWS: usize = 256;
const OUTPUT_PACKETS: usize = 256;
/// TUN's IPv4 interface minimum and the upstream u16 MTU parameter range.
pub const MIN_SUPPORTED_MTU: usize = 68;
pub const MAX_SUPPORTED_MTU: usize = u16::MAX as usize;
const DEFAULT_LOCAL_MTU: usize = 1280;
// Byte-credited queues are ceilings, not an arena per maximum-sized packet.
// Keep the existing startup footprint, with enough prepaid credit for both
// maximum-sized producer peaks even when the root is otherwise exhausted.
const REPLY_STORAGE_BYTES: usize = (2 * OUTPUT_PACKETS + 2) * (DEFAULT_LOCAL_MTU + BUFFER_OVERHEAD);
const _: () = assert!(REPLY_STORAGE_BYTES >= 2 * (MAX_SUPPORTED_MTU + BUFFER_OVERHEAD));
// UDP cannot consume the existing two maximum TCP producer peaks. TCP can still
// use the whole shared arena when UDP is idle; the startup/root size is unchanged.
const UDP_REPLY_HEADROOM: usize = 2 * (MAX_SUPPORTED_MTU + BUFFER_OVERHEAD);
const _: () = assert!(REPLY_STORAGE_BYTES >= BATCH_RESERVATION + UDP_REPLY_HEADROOM);

pub fn validate_mtu(mtu: usize) -> Result<(), Refused> {
    if (MIN_SUPPORTED_MTU..=MAX_SUPPORTED_MTU).contains(&mtu) {
        Ok(())
    } else {
        Err(Refused::UnsupportedMtu)
    }
}
const HELD_DATAGRAMS: usize = 4;
const STREAM_BUFFER: usize = 4096;
const CONNECT_LIMIT: Duration = Duration::from_secs(2);
const IDLE_LIMIT: Duration = Duration::from_secs(60);
const RETIRED_TCP_LIMIT: Duration = Duration::from_secs(60);
// Withheld region metadata plus fixed ring/task storage. Count limits remain
// ceilings; the injected byte budget may refuse admission before a count fills.
const REGION_METADATA: usize = 512;
const TASK_METADATA: usize = 16 * 1024;

struct FlowStorage {
    held: Arc<dyn RelayBufferAllocator>,
    fixed: Arc<dyn RelayBufferReservation>,
}

fn region(
    buffers: &dyn RelayBufferAllocator,
    bytes: usize,
) -> Result<Arc<dyn RelayBufferAllocator>, Refused> {
    buffers
        .try_reserve(bytes.checked_add(REGION_METADATA).ok_or(Refused::Full)?)
        .and_then(|charge| charge.allocator())
        .map_err(|_| Refused::Full)
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Stats {
    pub unsupported_mtu: u64,
    pub tcp_flows: usize,
    pub udp_flows: usize,
    pub dropped_disposition: u64,
    pub malformed: u64,
    pub fragments: u64,
    pub unsupported_protocol: u64,
    pub bad_checksum: u64,
    pub denied: u64,
    pub stale: u64,
    pub full: u64,
    pub preparation_failed: u64,
    pub oversized_reply: u64,
    pub revoked: u64,
    pub expired: u64,
    pub stale_reply: u64,
}

struct Task<T> {
    handle: JoinHandle<Result<T, Refused>>,
    result: Option<Result<T, Refused>>,
}
impl<T> Task<T> {
    fn new(handle: JoinHandle<Result<T, Refused>>) -> Self {
        Self {
            handle,
            result: None,
        }
    }
    fn poll(&mut self, cx: &mut Context<'_>) -> bool {
        if self.result.is_none()
            && let Poll::Ready(result) = Pin::new(&mut self.handle).poll(cx)
        {
            self.result = Some(result.unwrap_or(Err(Refused::PreparationFailed)));
        }
        self.result.is_some()
    }
}
enum Work {
    Preparing(Task<Socket>),
    Connecting(Task<TcpStream>),
    Waiting,
}
impl Work {
    fn poll(&mut self, cx: &mut Context<'_>) -> bool {
        match self {
            Self::Preparing(task) => task.poll(cx),
            Self::Connecting(task) => task.poll(cx),
            Self::Waiting => false,
        }
    }
}
struct Pending<G> {
    tcp: Option<Incarnation>,
    scope: crate::ReceiveScope,
    grant: G,
    work: Work,
    held: VecDeque<RelayBuffer>,
    storage: FlowStorage,
    deadline: Instant,
    attempt_revision: u64,
    retried: bool,
    expired: bool,
}
struct Tcp<G> {
    scope: crate::ReceiveScope,
    _storage: FlowStorage,
    incarnation: Incarnation,
    finished_at: Option<Instant>,
    grant: G,
    physical: TcpStream,
    handle: SocketHandle,
    last_activity: Instant,
    physical_eof: bool,
    application_eof: bool,
    application_fin: bool,
    application_reset: bool,
    fin_delivered: bool,
}
struct Udp<G> {
    scope: crate::ReceiveScope,
    grant: G,
    physical: UdpSocket,
    held: VecDeque<RelayBuffer>,
    storage: FlowStorage,
    last_activity: Instant,
}
struct Output<G> {
    bytes: OutputBytes,
    // Only protocol resets can outlive a grant. Application data always retains it.
    grant: Option<G>,
    tcp: Option<TcpOutput>,
    udp: Option<UdpOutput>,
}

struct UdpOutput {
    flow: Flow,
    scope: crate::ReceiveScope,
}

enum OutputBytes {
    Packet(RelayBuffer),
    Batch(crate::ip_endpoint::capture::PacketBatch),
}

impl From<RelayBuffer> for OutputBytes {
    fn from(bytes: RelayBuffer) -> Self {
        Self::Packet(bytes)
    }
}

impl std::ops::Deref for OutputBytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match self {
            Self::Packet(bytes) => bytes,
            Self::Batch(batch) => batch.packet(),
        }
    }
}

impl OutputBytes {
    #[cfg(test)]
    fn as_slice(&self) -> &[u8] {
        self
    }

    fn fits(&self, mtu: usize) -> bool {
        match self {
            Self::Packet(bytes) => bytes.len() <= mtu,
            Self::Batch(batch) => batch.fits(mtu),
        }
    }

    fn advance(&mut self) -> bool {
        match self {
            Self::Packet(_) => false,
            Self::Batch(batch) => batch.advance(),
        }
    }
}

#[derive(Clone, Copy)]
struct TcpOutput {
    flow: Flow,
    id: u64,
    fin: bool,
    reset: bool,
}

// TCP tuple reuse must not transfer either input or queued-output ownership.
// Keep the original SYN separately from the sliding terminal sequence windows:
// a long stream may wrap its sequence space more than once.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Incarnation {
    id: u64,
    application_isn: TcpSeqNumber,
    application_next: TcpSeqNumber,
    peer_isn: Option<TcpSeqNumber>,
    peer_next: Option<TcpSeqNumber>,
}
impl Incarnation {
    fn new(id: u64, syn: stack::Segment) -> Self {
        Self {
            id,
            application_isn: syn.seq,
            application_next: syn.seq + 1,
            peer_isn: None,
            peer_next: None,
        }
    }
    fn observe_output(&mut self, segment: stack::Segment) {
        // A protocol reset reflects rejected input, not this stream's progress.
        if segment.rst {
            return;
        }
        if segment.syn {
            self.peer_isn = Some(segment.seq);
        }
        // Only SYN/data/FIN consumes send sequence space. A cumulative ACK can
        // independently prove newly accepted application SYN/data/FIN progress.
        if segment.end != segment.seq {
            self.peer_next = Some(
                self.peer_next
                    .map_or(segment.end, |old| old.max(segment.end)),
            );
        }
        if let Some(ack) = segment.ack {
            self.application_next = self.application_next.max(ack);
        }
    }
    fn accepts_syn(&self, segment: stack::Segment, valid_syn: bool) -> bool {
        // RFC 1122 4.2.2.13 / RFC 6191: the previous FIN consumed next-1.
        // A distinct ISN alone cannot distinguish overlapping incarnations.
        valid_syn && segment.seq > self.application_next - 1
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RetiredTcp {
    flow: Flow,
    incarnation: Incarnation,
    deadline: Instant,
}

#[cfg_attr(feature = "r06-diagnostics", derive(Debug))]
enum TcpInput {
    Ignore,
    Current,
    New,
    Reuse,
    Replace,
}

/// Call `ingest`, `process` and `write_output` from the owning task. Select
/// `wait` for internal progress and sink writability when `has_output` is true.
/// The consumer updates authority inputs before signalling
/// `revalidation_signal`. `close_all` joins even blocking preparations.
pub struct Forwarder<A: LocalAuthority> {
    authority: Arc<A>,
    stack: Stack,
    pending: HashMap<Flow, Pending<Arc<A::Grant>>>,
    tcp: HashMap<Flow, Tcp<Arc<A::Grant>>>,
    retired_tcp: Vec<RetiredTcp>,
    next_tcp_id: u64,
    udp: HashMap<Flow, Udp<Arc<A::Grant>>>,
    udp_receive_after: Option<Flow>,
    output: VecDeque<Output<Arc<A::Grant>>>,
    stats: Stats,
    started: Instant,
    revision: u64,
    notify: Arc<Notify>,
    mtu: usize,
    buffers: Arc<dyn RelayBufferAllocator>,
    input: Arc<dyn RelayBufferAllocator>,
    complete: Arc<dyn RelayBufferAllocator>,
    native: Option<Engine>,
    #[cfg(test)]
    ip_engine: Option<crate::ip_endpoint::contract::scripted::ScriptedEngine>,
    replies: Arc<dyn RelayBufferAllocator>,
    scratch: RelayBuffer,
    _metadata: Arc<dyn RelayBufferReservation>,
}

impl<A: LocalAuthority> Forwarder<A> {
    pub fn new(authority: Arc<A>, buffers: Arc<dyn RelayBufferAllocator>) -> Result<Self, Refused> {
        Self::with_mtu(authority, buffers, DEFAULT_LOCAL_MTU)
    }

    pub fn with_mtu(
        authority: Arc<A>,
        buffers: Arc<dyn RelayBufferAllocator>,
        mtu: usize,
    ) -> Result<Self, Refused> {
        validate_mtu(mtu)?;
        // Both queues, one token/encoder peak and a receive scratch are funded
        // before startup. They cannot compete with newly admitted input bytes.
        let replies = region(&*buffers, REPLY_STORAGE_BYTES)?;
        let input = region(&*buffers, MAX_PACKET_SIZE + BUFFER_OVERHEAD)?;
        // Native transport capture and minimal TCP normalization overlap, while
        // smoltcp simultaneously needs its separately prepaid ingress copy.
        let complete = region(&*buffers, 2 * (MAX_PACKET_SIZE + BUFFER_OVERHEAD))?;
        let scratch_charge = buffers
            .try_reserve(MAX_PACKET_SIZE + BUFFER_OVERHEAD)
            .map_err(|_| Refused::Full)?;
        let scratch = RelayBuffer::from_reservation(vec![0; MAX_PACKET_SIZE], scratch_charge)
            .map_err(|_| Refused::Full)?;
        // Maps, queue slots, tombstones and bounded process worklists are fixed
        // arenas. Include generic grants and both simultaneously live maps.
        let metadata_bytes = 64 * 1024
            // Bounded authority payloads (up to 64 rule UUIDs in a local lease)
            // and worklists. Queues/tasks share grants, never clone their backing.
            + 4096 * (TCP_FLOWS + UDP_FLOWS + 2 * OUTPUT_PACKETS)
            + 4 * TCP_FLOWS * (size_of::<(Flow, Pending<A::Grant>)>() + size_of::<(Flow, Tcp<A::Grant>)>() + size_of::<smoltcp::iface::SocketStorage<'static>>())
            + 4 * UDP_FLOWS * (size_of::<(Flow, Pending<A::Grant>)>() + size_of::<(Flow, Udp<A::Grant>)>())
            + TCP_TOMBSTONES * size_of::<RetiredTcp>()
            + 4 * OUTPUT_PACKETS * size_of::<Output<A::Grant>>();
        let metadata = buffers
            .try_reserve(metadata_bytes)
            .map_err(|_| Refused::Full)?;
        Ok(Self {
            authority,
            stack: Stack::new(mtu, input.clone(), replies.clone()),
            pending: HashMap::with_capacity(TCP_FLOWS + UDP_FLOWS),
            tcp: HashMap::with_capacity(TCP_FLOWS),
            retired_tcp: Vec::with_capacity(TCP_TOMBSTONES),
            next_tcp_id: 0,
            udp: HashMap::with_capacity(UDP_FLOWS),
            udp_receive_after: None,
            output: VecDeque::with_capacity(OUTPUT_PACKETS),
            stats: Stats::default(),
            started: Instant::now(),
            revision: 0,
            notify: Arc::new(Notify::new()),
            mtu,
            buffers,
            input,
            complete,
            native: None,
            #[cfg(test)]
            ip_engine: None,
            replies,
            scratch,
            _metadata: metadata,
        })
    }

    /// Update packetization metadata, never sockets, grants or funded queues.
    pub fn set_mtu(&mut self, mtu: usize) -> Result<(), Refused> {
        validate_mtu(mtu)?;
        if mtu != self.mtu {
            if let Some(engine) = &mut self.native {
                engine
                    .set_mtu(mtu as u16)
                    .map_err(|_| Refused::UnsupportedMtu)?;
            }
            log::debug!("local-receiver-mtu previous={} current={mtu}", self.mtu);
            self.stack.set_mtu(mtu);
            self.mtu = mtu;
        }
        Ok(())
    }

    fn flow_storage(&self, transport: Transport) -> Result<FlowStorage, Refused> {
        let fixed_bytes = TASK_METADATA
            + if transport == Transport::Tcp {
                2 * STREAM_BUFFER
            } else {
                0
            };
        let slots = if transport == Transport::Tcp {
            1
        } else {
            HELD_DATAGRAMS
        };
        // Fixed bounded ingress rings are owned from admission through retirement,
        // including blocked preparation. Existing flows do not need fresh root
        // credit merely to accept their next datagram or retransmitted segment.
        let held = region(
            &*self.buffers,
            fixed_bytes + slots * (MAX_PACKET_SIZE + BUFFER_OVERHEAD),
        )?;
        let fixed = held.try_reserve(fixed_bytes).map_err(|_| Refused::Full)?;
        Ok(FlowStorage { held, fixed })
    }

    pub fn revalidation_signal(&self) -> Arc<Notify> {
        self.notify.clone()
    }

    pub fn stats(&self) -> Stats {
        Stats {
            tcp_flows: self.flow_count(Transport::Tcp),
            udp_flows: self.flow_count(Transport::Udp),
            ..self.stats
        }
    }

    fn flow_count(&self, transport: Transport) -> usize {
        let active = match transport {
            Transport::Tcp => self.tcp.len(),
            Transport::Udp => self.udp.len(),
        };
        active
            + self
                .pending
                .keys()
                .filter(|flow| flow.transport == transport)
                .count()
    }

    fn stack_now(&self) -> StackInstant {
        StackInstant::from_millis(self.started.elapsed().as_millis() as i64)
    }

    fn refused(&mut self, refusal: Refused) {
        match refusal {
            Refused::UnsupportedMtu => self.stats.unsupported_mtu += 1,
            Refused::Denied => self.stats.denied += 1,
            Refused::Stale => self.stats.stale += 1,
            Refused::Full => self.stats.full += 1,
            Refused::PreparationFailed => self.stats.preparation_failed += 1,
        }
    }

    fn enqueue(
        &mut self,
        bytes: RelayBuffer,
        grant: Option<Arc<A::Grant>>,
        tcp: Option<TcpOutput>,
    ) {
        if self.output.len() < OUTPUT_PACKETS {
            self.output.push_back(Output {
                bytes: bytes.into(),
                grant,
                tcp,
                udp: None,
            });
        } else {
            self.refused(Refused::Full);
        }
    }

    fn reset(&mut self, bytes: &[u8]) {
        let owner = packet::parse(bytes).ok().and_then(|packet| {
            self.tcp
                .get(&packet.flow)
                .map(|entry| (packet.flow, entry.incarnation.id))
                .or_else(|| {
                    self.pending
                        .get(&packet.flow)
                        .and_then(|entry| entry.tcp.map(|tcp| (packet.flow, tcp.id)))
                })
        });
        self.reset_for(bytes, owner);
    }

    fn reset_for(&mut self, bytes: &[u8], owner: Option<(Flow, u64)>) {
        let Ok(peak) = self.replies.try_reserve(self.mtu + BUFFER_OVERHEAD) else {
            self.refused(Refused::Full);
            return;
        };
        if let Some(reply) = stack::reset(bytes) {
            let Ok(reply) = RelayBuffer::from_reservation(reply, peak) else {
                self.refused(Refused::Full);
                return;
            };
            self.enqueue(
                reply,
                None,
                owner.map(|(flow, id)| TcpOutput {
                    flow,
                    id,
                    fin: false,
                    reset: true,
                }),
            );
        }
    }

    fn prepare(&self, flow: Flow, grant: &Arc<A::Grant>, storage: &FlowStorage) -> Work {
        let authority = self.authority.clone();
        let grant = grant.clone();
        let charge = storage.fixed.clone();
        Work::Preparing(Task::new(tokio::task::spawn_blocking(move || {
            let _charge = charge;
            if !authority.current(&grant) {
                return Err(Refused::Stale);
            }
            let (kind, protocol) = match flow.transport {
                Transport::Tcp => (Type::STREAM, Protocol::TCP),
                Transport::Udp => (Type::DGRAM, Protocol::UDP),
            };
            let socket = Socket::new(Domain::for_address(flow.destination), kind, Some(protocol))
                .map_err(|error| {
                #[cfg(feature = "r06-diagnostics")]
                crate::diagnostics::observe(
                    "physical-socket-create-failed",
                    format_args!("flow={flow:?} errno={:?}", error.raw_os_error()),
                );
                let _ = error;
                Refused::PreparationFailed
            })?;
            #[cfg(all(feature = "r06-diagnostics", unix))]
            {
                use std::os::fd::AsRawFd;
                crate::diagnostics::observe(
                    "physical-prepare-begin",
                    format_args!("flow={flow:?} fd={}", socket.as_raw_fd()),
                );
            }
            authority.prepare(&socket, &grant).inspect_err(|error| {
                #[cfg(feature = "r06-diagnostics")]
                crate::diagnostics::observe(
                    "physical-prepare-failed",
                    format_args!("flow={flow:?} refusal={error:?}"),
                );
                let _ = error;
            })?;
            socket.set_nonblocking(true).map_err(|error| {
                #[cfg(feature = "r06-diagnostics")]
                crate::diagnostics::observe(
                    "physical-nonblocking-failed",
                    format_args!("flow={flow:?} errno={:?}", error.raw_os_error()),
                );
                let _ = error;
                Refused::PreparationFailed
            })?;
            #[cfg(feature = "r06-diagnostics")]
            crate::diagnostics::observe(
                "physical-prepare-ok",
                format_args!("flow={flow:?} local={:?}", socket.local_addr()),
            );
            Ok(socket)
        })))
    }

    // TIME-WAIT is exclusive ownership, not an overlapping packet filter. Reuse
    // discards its record before admission, so it cannot outrank the new owner.
    fn classify_tcp(&self, flow: Flow, segment: stack::Segment, valid_syn: bool) -> TcpInput {
        if let Some(entry) = self.tcp.get(&flow) {
            if self.graceful_tcp_finished(entry) {
                return if entry.incarnation.accepts_syn(segment, valid_syn) {
                    TcpInput::Replace
                } else {
                    TcpInput::Ignore
                };
            }
            return if segment.syn && segment.seq != entry.incarnation.application_isn {
                TcpInput::Ignore
            } else {
                TcpInput::Current
            };
        }
        if let Some(entry) = self.pending.get(&flow) {
            let incarnation = entry.tcp.expect("TCP pending identity");
            return if segment.syn && segment.seq != incarnation.application_isn
                || segment.rst && segment.seq != incarnation.application_next
            {
                TcpInput::Ignore
            } else {
                TcpInput::Current
            };
        }
        if let Some(old) = self.retired_tcp.iter().find(|old| old.flow == flow) {
            return if old.incarnation.accepts_syn(segment, valid_syn) {
                TcpInput::Reuse
            } else {
                TcpInput::Ignore
            };
        }
        TcpInput::New
    }

    pub fn ingest(&mut self, bytes: &[u8]) {
        #[cfg(feature = "r06-diagnostics")]
        crate::diagnostics::tcp_packet("local-ingress", bytes);
        let (source, destination) = match packet::ip_endpoints(bytes) {
            Ok(endpoints) => endpoints,
            Err(reason) => {
                match reason {
                    PacketRefusal::Malformed => self.stats.malformed += 1,
                    PacketRefusal::Fragment => self.stats.fragments += 1,
                    PacketRefusal::UnsupportedProtocol => self.stats.unsupported_protocol += 1,
                    PacketRefusal::Checksum => self.stats.bad_checksum += 1,
                }
                return;
            }
        };
        if self.authority.disposition(destination) == Disposition::Drop {
            self.stats.dropped_disposition += 1;
            return;
        }
        if source.is_ipv6() && self.mtu < 1280 {
            self.refused(Refused::UnsupportedMtu);
            return;
        }
        let scope = match self.authority.receive(source, destination, &*self.buffers) {
            Ok(scope) => scope,
            Err(error) => {
                self.refused(error);
                return;
            }
        };
        if self.native.is_none() {
            match Engine::open(self.buffers.clone(), self.mtu as u16) {
                Ok(engine) => self.native = Some(engine),
                Err(error) => {
                    self.ip_refused(error);
                    return;
                }
            }
        }
        let engine = self.native.as_mut().expect("opened real Local engine");
        #[cfg(feature = "r06-diagnostics")]
        crate::diagnostics::observe(
            "native-ingest",
            format_args!(
                "scope={} source={source} destination={destination} bytes={}",
                scope.id(),
                bytes.len()
            ),
        );
        let result = engine.register(&scope).and_then(|()| {
            capture::ingest(engine, ReceiveScopeId(scope.id()), bytes, &*self.complete)
        });
        match result {
            Ok(Some(complete)) => {
                #[cfg(feature = "r06-diagnostics")]
                crate::diagnostics::observe(
                    "native-complete",
                    format_args!(
                        "scope={} source={source} destination={destination}",
                        scope.id()
                    ),
                );
                if let Err(error) = self.admit_complete(complete, &scope) {
                    self.ip_refused(error);
                }
            }
            Ok(None) => {}
            Err(error) => {
                #[cfg(feature = "r06-diagnostics")]
                crate::diagnostics::observe(
                    "native-ingest-refused",
                    format_args!("scope={} reason={error:?}", scope.id()),
                );
                self.ip_refused(error)
            }
        }
    }

    fn ip_refused(&mut self, error: IpError) {
        match error {
            IpError::Full => self.stats.full += 1,
            IpError::Stale => self.stats.stale += 1,
            IpError::Unsupported => self.stats.unsupported_protocol += 1,
            IpError::Checksum => self.stats.bad_checksum += 1,
            IpError::Malformed | IpError::Oversized | IpError::Internal => {
                self.stats.malformed += 1
            }
        }
    }

    // Deterministic scheduler/capture fixture only, never production fallback.
    #[cfg(test)]
    fn ingest_ip(
        &mut self,
        engine: &mut impl crate::ip_endpoint::contract::LocalIpEngine,
        scope: &crate::ReceiveScope,
        bytes: &[u8],
    ) -> Result<(), crate::ip_endpoint::contract::IpError> {
        use crate::ip_endpoint::{capture, contract::ReceiveScopeId};
        let complete = capture::ingest(engine, ReceiveScopeId(scope.id()), bytes, &*self.complete)?;
        let Some(complete) = complete else {
            return Ok(());
        };
        self.admit_complete(complete, scope)
    }

    fn admit_complete(
        &mut self,
        complete: capture::OwnedTransport,
        scope: &crate::ReceiveScope,
    ) -> Result<(), IpError> {
        let packet = complete.validated()?;
        #[cfg(feature = "r06-diagnostics")]
        crate::diagnostics::observe(
            "validated-transport",
            format_args!(
                "scope={} native_scope={} flow={:?}",
                scope.id(),
                complete.scope.0,
                packet.flow
            ),
        );
        if complete.scope.0 != scope.id()
            || !scope.current()
            || packet.flow.source.ip() != scope.source()
            || packet.flow.destination.ip() != scope.destination()
        {
            return Err(IpError::Stale);
        }
        if packet.flow.transport == Transport::Tcp {
            let normalized = complete.tcp_packet(&*self.complete)?;
            self.admit(packet, &normalized, scope);
        } else {
            self.admit(packet, &[], scope);
        }
        Ok(())
    }

    fn admit(&mut self, packet: packet::Packet<'_>, bytes: &[u8], scope: &crate::ReceiveScope) {
        let flow = packet.flow;
        if flow.source.is_ipv6() && self.mtu < 1280 {
            self.refused(Refused::UnsupportedMtu);
            return;
        }
        if self.authority.disposition(flow.destination.ip()) == Disposition::Drop {
            self.stats.dropped_disposition += 1;
            return;
        }
        self.sweep();
        let tcp_segment = stack::segment(bytes);
        if let Some(segment) = tcp_segment {
            let disposition = self.classify_tcp(flow, segment, stack::valid_syn(bytes));
            #[cfg(feature = "r06-diagnostics")]
            crate::diagnostics::observe(
                "tcp-classify",
                format_args!(
                    "scope={} flow={flow:?} seq={:?} syn={} input={disposition:?}",
                    scope.id(),
                    segment.seq,
                    segment.syn
                ),
            );
            match disposition {
                TcpInput::Ignore => return,
                TcpInput::Replace => self.remove_tcp(flow, false),
                TcpInput::Reuse => self.retired_tcp.retain(|old| old.flow != flow),
                TcpInput::Current | TcpInput::New => {}
            }
        }
        if let Some(pending) = self.pending.get_mut(&flow) {
            if flow.transport == Transport::Tcp && packet.tcp_flags.is_some_and(|flags| flags.rst) {
                pending.expired = true;
                pending.held.clear();
                if let Work::Connecting(task) = &pending.work {
                    task.handle.abort();
                }
            }
            if flow.transport == Transport::Udp && !pending.expired {
                if pending.held.len() < HELD_DATAGRAMS {
                    match RelayBuffer::copy_from(packet.payload, &*pending.storage.held) {
                        Ok(bytes) => pending.held.push_back(bytes),
                        Err(_) => self.refused(Refused::Full),
                    }
                } else {
                    self.refused(Refused::Full);
                }
            }
            return;
        }
        if let Some(entry) = self.udp.get_mut(&flow) {
            if entry.held.len() < HELD_DATAGRAMS {
                match RelayBuffer::copy_from(packet.payload, &*entry.storage.held) {
                    Ok(bytes) => entry.held.push_back(bytes),
                    Err(_) => self.refused(Refused::Full),
                }
            } else {
                self.refused(Refused::Full);
            }
            self.process();
            return;
        }
        if self.tcp.contains_key(&flow) {
            let now = self.stack_now();
            let previous_state = self
                .stack
                .sockets
                .get::<tcp::Socket<'_>>(self.tcp[&flow].handle)
                .state();
            if !self.stack.receive(bytes, now) {
                self.refused(Refused::Full);
            }
            if let Some(entry) = self.tcp.get_mut(&flow) {
                entry.last_activity = Instant::now();
                // smoltcp validates the sequence before accepting a reset. A
                // reset during SynReceived returns a passive socket to Listen;
                // it must never remain available to claim another owner's tuple.
                let state = self
                    .stack
                    .sockets
                    .get::<tcp::Socket<'_>>(entry.handle)
                    .state();
                entry.application_reset |= packet.tcp_flags.is_some_and(|f| f.rst)
                    && state != previous_state
                    && matches!(state, tcp::State::Closed | tcp::State::Listen);
            }
            self.drain_stack();
            self.process();
            return;
        }
        if flow.transport == Transport::Tcp
            && !packet
                .tcp_flags
                .is_some_and(|flags| flags.syn && !flags.ack)
        {
            self.reset(bytes);
            return;
        }
        if flow.transport == Transport::Tcp && !stack::valid_syn(bytes) {
            self.stats.malformed += 1;
            return;
        }
        let limit = match flow.transport {
            Transport::Tcp => TCP_FLOWS,
            Transport::Udp => UDP_FLOWS,
        };
        let count = self.flow_count(flow.transport);
        // A pending/live owner reserves its eventual TIME-WAIT record. Reuse
        // removed the previous record before arriving here; no tuple has both.
        if count >= limit
            || (flow.transport == Transport::Tcp
                && (count + self.retired_tcp.len() >= TCP_TOMBSTONES
                    || self.next_tcp_id == u64::MAX))
        {
            self.refused(Refused::Full);
            if flow.transport == Transport::Tcp {
                self.reset(bytes);
            }
            return;
        }
        let authorization = self.authority.authorize_received(flow, scope);
        #[cfg(feature = "r06-diagnostics")]
        crate::diagnostics::observe(
            "forwarder-grant-result",
            format_args!(
                "flow={flow:?} scope={} result={:?}",
                scope.id(),
                authorization.as_ref().map(|_| ())
            ),
        );
        let grant = match authorization {
            Ok(grant) => Arc::new(grant),
            Err(reason) => {
                self.refused(reason);
                if flow.transport == Transport::Tcp && reason != Refused::Stale {
                    self.reset(bytes);
                }
                return;
            }
        };
        let storage = match self.flow_storage(flow.transport) {
            Ok(storage) => storage,
            Err(reason) => {
                self.refused(reason);
                return;
            }
        };
        let held_bytes = if flow.transport == Transport::Tcp {
            bytes
        } else {
            packet.payload
        };
        let held_bytes = match RelayBuffer::copy_from(held_bytes, &*storage.held) {
            Ok(bytes) => bytes,
            Err(_) => {
                self.refused(Refused::Full);
                return;
            }
        };
        let work = self.prepare(flow, &grant, &storage);
        let tcp = tcp_segment.map(|syn| {
            let incarnation = Incarnation::new(self.next_tcp_id, syn);
            self.next_tcp_id += 1;
            incarnation
        });
        #[cfg(feature = "r06-diagnostics")]
        crate::diagnostics::observe(
            "tcp-pending-created",
            format_args!(
                "flow={flow:?} scope={} incarnation={:?}",
                scope.id(),
                tcp.map(|value| value.id)
            ),
        );
        let mut held = VecDeque::with_capacity(HELD_DATAGRAMS);
        held.push_back(held_bytes);
        self.pending.insert(
            flow,
            Pending {
                tcp,
                scope: scope.clone(),
                grant,
                work,
                held,
                storage,
                deadline: Instant::now() + CONNECT_LIMIT,
                attempt_revision: self.revision,
                retried: false,
                expired: false,
            },
        );
    }

    fn drain_stack(&mut self) {
        if let Some(refused) = self.stack.device.refused.take() {
            self.refused(refused);
        }
        while let Some(bytes) = self.stack.device.outgoing.pop_front() {
            #[cfg(feature = "r06-diagnostics")]
            crate::diagnostics::tcp_packet("smoltcp-output", &bytes);
            let Ok(packet) = packet::parse(&bytes) else {
                self.stats.malformed += 1;
                continue;
            };
            let flow = Flow {
                source: packet.flow.destination,
                destination: packet.flow.source,
                transport: packet.flow.transport,
            };
            let reset = packet.tcp_flags.is_some_and(|flags| flags.rst);
            let fin = packet.tcp_flags.is_some_and(|flags| flags.fin);
            if let Some(entry) = self.tcp.get_mut(&flow) {
                entry
                    .incarnation
                    .observe_output(stack::segment(&bytes).expect("parsed TCP output"));
                let owner = Some(TcpOutput {
                    flow,
                    id: entry.incarnation.id,
                    fin,
                    reset,
                });
                if reset {
                    self.enqueue(bytes, None, owner);
                } else if self.authority.current(&entry.grant) {
                    let grant = entry.grant.clone();
                    self.enqueue(bytes, Some(grant), owner);
                } else {
                    self.stats.stale_reply += 1;
                }
            }
        }
    }

    /// Expiry never detaches a blocking prepare or frees its slot prematurely.
    fn sweep(&mut self) {
        let now = Instant::now();
        self.retired_tcp.retain(|entry| now < entry.deadline);
        let dead: Vec<_> = self
            .tcp
            .iter()
            .filter_map(|(flow, entry)| {
                let revoked = !self.authority.current(&entry.grant) || !entry.scope.current();
                (revoked || now >= entry.last_activity + IDLE_LIMIT).then_some((*flow, revoked))
            })
            .collect();
        for (flow, revoked) in dead {
            if revoked {
                self.stats.revoked += 1;
            } else {
                self.stats.expired += 1;
            }
            self.remove_tcp(flow, true);
        }
        self.udp.retain(|_, entry| {
            if !self.authority.current(&entry.grant) || !entry.scope.current() {
                self.stats.revoked += 1;
                false
            } else if now >= entry.last_activity + IDLE_LIMIT {
                self.stats.expired += 1;
                false
            } else {
                true
            }
        });
        let expired: Vec<_> = self
            .pending
            .iter()
            .filter_map(|(flow, entry)| {
                let revoked = (flow.transport == Transport::Tcp
                    && !self.authority.current(&entry.grant))
                    || !entry.scope.current();
                (!entry.expired && (now >= entry.deadline || revoked)).then_some((*flow, revoked))
            })
            .collect();
        for (flow, revoked) in expired {
            let entry = self.pending.get_mut(&flow).expect("pending expiry");
            entry.expired = true;
            let syn = if flow.transport == Transport::Tcp {
                entry.held.pop_front()
            } else {
                None
            };
            entry.held.clear();
            if let Work::Connecting(task) = &entry.work {
                task.handle.abort();
            }
            if revoked {
                self.stats.revoked += 1;
            } else {
                self.stats.expired += 1;
            }
            if let Some(syn) = syn {
                self.reset(&syn);
            }
        }
        self.pending
            .retain(|_, entry| !(entry.expired && matches!(entry.work, Work::Waiting)));
    }

    fn remove_tcp(&mut self, flow: Flow, reset: bool) {
        let handle = self.tcp[&flow].handle;
        let id = self.tcp[&flow].incarnation.id;
        // Purge before generating the abort, so the new, identity-tagged reset
        // can outlive this socket while its queued payload cannot.
        let before = self.output.len();
        self.output
            .retain(|output| output.tcp.is_none_or(|tcp| tcp.id != id));
        self.stats.stale_reply += (before - self.output.len()) as u64;
        if reset {
            self.stack
                .sockets
                .get_mut::<tcp::Socket<'_>>(handle)
                .abort();
            self.stack.poll(self.stack_now());
            self.drain_stack();
        }
        self.stack.sockets.remove(handle);
        self.tcp.remove(&flow);
    }

    fn graceful_tcp_finished(&self, entry: &Tcp<Arc<A::Grant>>) -> bool {
        let endpoint = self.stack.sockets.get::<tcp::Socket<'_>>(entry.handle);
        entry.application_eof
            && entry.physical_eof
            && matches!(endpoint.state(), tcp::State::Closed | tcp::State::TimeWait)
            && !endpoint.can_recv()
            && endpoint.send_queue() == 0
    }

    fn retire_finished_tcp(&mut self) {
        debug_assert!(self.flow_count(Transport::Tcp) + self.retired_tcp.len() <= TCP_TOMBSTONES);
        let available = TCP_TOMBSTONES - self.retired_tcp.len();
        let finished: Vec<_> =
            self.tcp
                .iter()
                .filter_map(|(flow, entry)| {
                    (self.graceful_tcp_finished(entry)
                        && entry.fin_delivered
                        && !self.output.iter().any(|output| {
                            output.tcp.is_some_and(|tcp| tcp.id == entry.incarnation.id)
                        }))
                    .then_some(*flow)
                })
                .take(available)
                .collect();
        for flow in finished {
            self.retire_tcp(flow);
        }
    }

    fn retire_tcp(&mut self, flow: Flow) {
        debug_assert!(!self.retired_tcp.iter().any(|old| old.flow == flow));
        let entry = &self.tcp[&flow];
        let retired = RetiredTcp {
            flow,
            incarnation: entry.incarnation,
            deadline: entry.finished_at.unwrap_or_else(Instant::now) + RETIRED_TCP_LIMIT,
        };
        self.remove_tcp(flow, false);
        self.retired_tcp.push(retired);
    }

    fn retry(&mut self, flow: Flow, mut pending: Pending<Arc<A::Grant>>) {
        let authorization = self.authority.authorize_received(flow, &pending.scope);
        match authorization {
            Ok(grant) => {
                let grant = Arc::new(grant);
                pending.work = self.prepare(flow, &grant, &pending.storage);
                pending.grant = grant;
                pending.attempt_revision = self.revision;
                pending.retried = true;
                self.pending.insert(flow, pending);
            }
            Err(reason) => self.refused(reason),
        }
    }

    fn failed_pending(&mut self, flow: Flow, mut pending: Pending<Arc<A::Grant>>, reason: Refused) {
        #[cfg(feature = "r06-diagnostics")]
        crate::diagnostics::observe(
            "pending-failed",
            format_args!(
                "flow={flow:?} scope={} incarnation={:?} expired={} reason={reason:?}",
                pending.scope.id(),
                pending.tcp.map(|value| value.id),
                pending.expired
            ),
        );
        self.refused(reason);
        if flow.transport == Transport::Tcp {
            if reason != Refused::Stale
                && let Some(syn) = pending.held.front()
            {
                self.reset_for(syn, pending.tcp.map(|tcp| (flow, tcp.id)));
            }
        } else if reason == Refused::Stale && !pending.retried {
            pending.work = Work::Waiting;
            if pending.attempt_revision != self.revision {
                self.retry(flow, pending);
            } else {
                self.pending.insert(flow, pending);
            }
        }
    }

    fn completions(&mut self) {
        let mut cx = Context::from_waker(Waker::noop());
        let done: Vec<_> = self
            .pending
            .iter_mut()
            .filter_map(|(flow, entry)| entry.work.poll(&mut cx).then_some(*flow))
            .collect();
        for flow in done {
            let mut pending = self.pending.remove(&flow).expect("completed pending");
            let work = std::mem::replace(&mut pending.work, Work::Waiting);
            if pending.expired {
                continue;
            }
            match work {
                Work::Preparing(mut task) => {
                    let result = task.result.take().expect("polled prepare");
                    let socket = match result {
                        Ok(socket) if self.authority.current(&pending.grant) => socket,
                        Ok(_) => {
                            self.failed_pending(flow, pending, Refused::Stale);
                            continue;
                        }
                        Err(reason) => {
                            self.failed_pending(flow, pending, reason);
                            continue;
                        }
                    };
                    let destination = self.authority.physical_destination(&pending.grant, flow);
                    if flow.transport == Transport::Tcp {
                        let deadline = pending.deadline;
                        pending.work = Work::Connecting(Task::new(tokio::spawn(async move {
                            #[cfg(feature = "r06-diagnostics")]
                            crate::diagnostics::observe(
                                "physical-connect-begin",
                                format_args!(
                                    "flow={flow:?} destination={destination} deadline={deadline:?}"
                                ),
                            );
                            tokio::time::timeout_at(
                                deadline,
                                TcpSocket::from_std_stream(socket.into()).connect(destination),
                            )
                            .await
                            .map_err(|error| {
                                #[cfg(feature = "r06-diagnostics")]
                                crate::diagnostics::observe("physical-connect-deadline", format_args!("flow={flow:?} destination={destination} os_errno=unobserved deadline={deadline:?}"));
                                let _ = error;
                                Refused::PreparationFailed
                            })?
                            .inspect(|stream| {
                                #[cfg(feature = "r06-diagnostics")]
                                crate::diagnostics::observe("physical-connect-ok", format_args!("flow={flow:?} local={:?} peer={:?}", stream.local_addr(), stream.peer_addr()));
                                let _ = stream;
                            })
                            .map_err(|error| {
                                #[cfg(feature = "r06-diagnostics")]
                                crate::diagnostics::observe("physical-connect-failed", format_args!("flow={flow:?} destination={destination} errno={:?}", error.raw_os_error()));
                                let _ = error;
                                Refused::PreparationFailed
                            })
                        })));
                        self.pending.insert(flow, pending);
                    } else {
                        let result = socket
                            .connect(&destination.into())
                            .and_then(|()| UdpSocket::from_std(socket.into()));
                        match result {
                            Ok(physical) => {
                                self.udp.insert(
                                    flow,
                                    Udp {
                                        scope: pending.scope,
                                        grant: pending.grant,
                                        physical,
                                        held: pending.held,
                                        storage: pending.storage,
                                        last_activity: Instant::now(),
                                    },
                                );
                            }
                            Err(_) => {
                                self.failed_pending(flow, pending, Refused::PreparationFailed)
                            }
                        }
                    }
                }
                Work::Connecting(mut task) => {
                    let physical = match task.result.take().expect("polled connect") {
                        Ok(physical) if self.authority.current(&pending.grant) => physical,
                        Ok(_) => {
                            self.failed_pending(flow, pending, Refused::Stale);
                            continue;
                        }
                        Err(reason) => {
                            self.failed_pending(flow, pending, reason);
                            continue;
                        }
                    };
                    let syn = pending.held.front().expect("held SYN");
                    // Attribute every older stack packet before a tuple can be
                    // installed with a different incarnation identity.
                    self.drain_stack();
                    let Some(handle) = self.stack.accept_syn(flow, syn, self.stack_now()) else {
                        #[cfg(feature = "r06-diagnostics")]
                        crate::diagnostics::observe(
                            "smoltcp-accept-syn-failed",
                            format_args!("flow={flow:?} scope={}", pending.scope.id()),
                        );
                        self.failed_pending(flow, pending, Refused::PreparationFailed);
                        continue;
                    };
                    #[cfg(feature = "r06-diagnostics")]
                    crate::diagnostics::observe(
                        "smoltcp-accept-syn-ok",
                        format_args!(
                            "flow={flow:?} scope={} incarnation={}",
                            pending.scope.id(),
                            pending.tcp.expect("connected TCP identity").id
                        ),
                    );
                    self.tcp.insert(
                        flow,
                        Tcp {
                            scope: pending.scope,
                            _storage: pending.storage,
                            incarnation: pending.tcp.expect("connected TCP identity"),
                            finished_at: None,
                            grant: pending.grant,
                            physical,
                            handle,
                            last_activity: Instant::now(),
                            physical_eof: false,
                            application_eof: false,
                            application_fin: false,
                            application_reset: false,
                            fin_delivered: false,
                        },
                    );
                    self.drain_stack();
                }
                Work::Waiting => unreachable!("waiting has no completion"),
            }
        }
    }

    fn pump_tcp(&mut self) {
        let mut removed = Vec::new();
        for (flow, entry) in &mut self.tcp {
            let endpoint = self.stack.sockets.get_mut::<tcp::Socket<'_>>(entry.handle);
            entry.application_fin |= matches!(
                endpoint.state(),
                tcp::State::CloseWait
                    | tcp::State::LastAck
                    | tcp::State::Closing
                    | tcp::State::TimeWait
            );
            if entry.application_reset
                || endpoint.state() == tcp::State::Listen
                || (endpoint.state() == tcp::State::Closed && !entry.application_fin)
            {
                // A validated reset/stack abort discards data immediately. A
                // graceful terminal state, in contrast, can still own rx bytes.
                let _ = socket2::SockRef::from(&entry.physical).set_linger(Some(Duration::ZERO));
                removed.push((*flow, false));
                continue;
            }
            let mut failed = false;
            // Use the endpoint's rings directly: no extra unbounded stream buffers.
            while endpoint.can_recv() && self.authority.current(&entry.grant) {
                let count = endpoint
                    .recv(|data| match entry.physical.try_write(data) {
                        Ok(0) => {
                            failed = true;
                            (0, 0)
                        }
                        Ok(n) => (n, n),
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => (0, 0),
                        Err(_) => {
                            failed = true;
                            (0, 0)
                        }
                    })
                    .unwrap_or(0);
                if count == 0 {
                    break;
                }
                entry.last_activity = Instant::now();
            }
            if entry.application_fin && !endpoint.may_recv() && !entry.application_eof {
                failed |= socket2::SockRef::from(&entry.physical)
                    .shutdown(Shutdown::Write)
                    .is_err();
                entry.application_eof = true;
            }
            while !entry.physical_eof && endpoint.can_send() && self.authority.current(&entry.grant)
            {
                let count = endpoint
                    .send(|data| match entry.physical.try_read(data) {
                        Ok(0) => {
                            entry.physical_eof = true;
                            (0, 0)
                        }
                        Ok(n) => (n, n),
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => (0, 0),
                        Err(_) => {
                            failed = true;
                            (0, 0)
                        }
                    })
                    .unwrap_or(0);
                if count == 0 {
                    break;
                }
                entry.last_activity = Instant::now();
            }
            if entry.physical_eof {
                endpoint.close();
            }
            if failed {
                removed.push((*flow, true));
            }
        }
        self.stack.poll(self.stack_now());
        self.drain_stack();
        let finished: Vec<_> = self
            .tcp
            .iter()
            .filter_map(|(flow, entry)| {
                (entry.finished_at.is_none() && self.graceful_tcp_finished(entry)).then_some(*flow)
            })
            .collect();
        for flow in finished {
            self.tcp.get_mut(&flow).expect("finished TCP").finished_at = Some(Instant::now());
        }
        for (flow, reset) in removed {
            self.remove_tcp(flow, reset);
        }
        self.retire_finished_tcp();
    }

    fn pump_udp(&mut self) {
        let mut received = Vec::new();
        let mut removed = Vec::new();
        // Global per-process receive allowance also bounds transient reply storage.
        let mut slots = OUTPUT_PACKETS - self.output.len();
        let mut flows: Vec<_> = self.udp.keys().copied().collect();
        if let Some(index) = flows
            .iter()
            .position(|flow| Some(*flow) == self.udp_receive_after)
        {
            let count = flows.len();
            flows.rotate_left((index + 1) % count);
        }
        for flow in &flows {
            let entry = self
                .udp
                .get_mut(flow)
                .expect("current UDP admission candidate");
            while let Some(payload) = entry.held.front() {
                if !self.authority.current(&entry.grant) {
                    break;
                }
                match entry.physical.try_send(payload) {
                    Ok(n) if n == payload.len() => {
                        entry.held.pop_front();
                        entry.last_activity = Instant::now();
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    _ => {
                        removed.push(*flow);
                        break;
                    }
                }
            }
            if slots > 0 && self.authority.current(&entry.grant) {
                if !entry.scope.current()
                    || self
                        .output
                        .iter()
                        .any(|job| job.udp.as_ref().is_some_and(|owner| owner.flow == *flow))
                {
                    continue;
                }
                if entry
                    .physical
                    .poll_recv_ready(&mut Context::from_waker(Waker::noop()))
                    .is_pending()
                {
                    continue;
                }
                let Ok(batch) =
                    PacketBatch::reserve_preserving(&*self.replies, self.mtu, UDP_REPLY_HEADROOM)
                else {
                    continue;
                };
                match entry.physical.try_recv(&mut self.scratch) {
                    Ok(n) => {
                        self.udp_receive_after = Some(*flow);
                        slots -= 1;
                        entry.last_activity = Instant::now();
                        let scope = &entry.scope;
                        let tuple = ReplyTuple::from_flow(ReceiveScopeId(scope.id()), *flow)
                            .expect("same-family UDP");
                        #[cfg(test)]
                        let result = if let Some(engine) = self.ip_engine.as_mut() {
                            batch.generate(engine, tuple, &self.scratch[..n])
                        } else {
                            batch.generate(
                                self.native.as_mut().expect("real Local engine"),
                                tuple,
                                &self.scratch[..n],
                            )
                        };
                        #[cfg(not(test))]
                        let result = batch.generate(
                            self.native.as_mut().expect("real Local engine"),
                            tuple,
                            &self.scratch[..n],
                        );
                        match result {
                            Ok(batch) => received.push(Output {
                                bytes: OutputBytes::Batch(batch),
                                grant: Some(entry.grant.clone()),
                                tcp: None,
                                udp: Some(UdpOutput {
                                    flow: *flow,
                                    scope: scope.clone(),
                                }),
                            }),
                            Err(IpError::Oversized) => self.stats.oversized_reply += 1,
                            Err(IpError::Full) => self.stats.full += 1,
                            Err(_) => self.stats.malformed += 1,
                        }
                        // Exactly one active batch per physical flow.
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                    Err(_) => {
                        removed.push(*flow);
                    }
                }
            }
        }
        for flow in removed {
            self.udp.remove(&flow);
        }
        self.output.extend(received);
    }

    pub fn process(&mut self) {
        self.sweep();
        self.completions();
        self.pump_tcp();
        self.pump_udp();
    }

    /// Whether the owner should select sink writability. This is deliberately
    /// independent of `wait`: a blocked sink cannot make internal work ready.
    pub fn has_output(&self) -> bool {
        !self.output.is_empty()
    }

    /// Attempt one whole-packet nonblocking sink write, checking authority at
    /// the syscall boundary on EVERY retry. The callback must perform the write
    /// synchronously, never retain/queue the borrowed bytes. `Ok(false)` means
    /// drained (including discarded revoked packets); `Ok(true)` wrote a packet.
    /// `WouldBlock` retains the head AND its grant. Select sink writability and
    /// retry here; never cache a raw pending packet outside this owner. Other
    /// errors, including a partial packet write, are fatal to the sink owner.
    pub fn write_output(
        &mut self,
        write: impl FnOnce(&[u8]) -> io::Result<usize>,
    ) -> io::Result<bool> {
        while let Some(output) = self.output.front() {
            let owns_output = output.tcp.is_none_or(|owner| {
                if self
                    .tcp
                    .get(&owner.flow)
                    .is_some_and(|entry| !entry.scope.current())
                    || self
                        .pending
                        .get(&owner.flow)
                        .is_some_and(|entry| !entry.scope.current())
                {
                    return false;
                }
                let current = self
                    .tcp
                    .get(&owner.flow)
                    .map(|entry| entry.incarnation.id)
                    .or_else(|| {
                        self.pending
                            .get(&owner.flow)
                            .and_then(|entry| entry.tcp.map(|tcp| tcp.id))
                    });
                current.map_or(owner.reset, |id| id == owner.id)
            });
            let owns_udp = output.udp.as_ref().is_none_or(|owner| {
                owner.scope.current()
                    && self.udp.get(&owner.flow).is_some_and(|entry| {
                        entry.scope.id() == owner.scope.id()
                            && output
                                .grant
                                .as_ref()
                                .is_some_and(|grant| Arc::ptr_eq(grant, &entry.grant))
                    })
            });
            if owns_output
                && owns_udp
                && output.bytes.fits(self.mtu)
                && output
                    .grant
                    .as_ref()
                    .is_none_or(|grant| self.authority.current(grant))
            {
                let n = write(&output.bytes)?;
                if n != output.bytes.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "partial IP packet write",
                    ));
                }
                let delivered = output.tcp;
                let mut output = self.output.pop_front().expect("written head");
                if output.bytes.advance() {
                    // Give other ready jobs a turn after EACH packet, retaining
                    // the same funded batch and exact unsent cursor.
                    self.output.push_back(output);
                }
                if let Some(TcpOutput {
                    flow,
                    id,
                    fin: true,
                    ..
                }) = delivered
                    && let Some(entry) = self.tcp.get_mut(&flow)
                    && entry.incarnation.id == id
                {
                    entry.fin_delivered = true;
                }
                self.retire_finished_tcp();
                return Ok(true);
            }
            self.output.pop_front();
            self.stats.stale_reply += 1;
        }
        Ok(false)
    }

    pub fn revalidate(&mut self) {
        self.revision = self.revision.wrapping_add(1);
        self.sweep();
        let waiting: Vec<_> = self
            .pending
            .iter()
            .filter_map(|(flow, pending)| matches!(pending.work, Work::Waiting).then_some(*flow))
            .collect();
        for flow in waiting {
            let pending = self.pending.remove(&flow).expect("waiting retry");
            self.retry(flow, pending);
        }
    }

    fn deadline(&mut self) -> Option<Instant> {
        let mut nearest = self
            .pending
            .values()
            .filter(|p| !p.expired)
            .map(|p| p.deadline)
            .chain(self.tcp.values().map(|e| e.last_activity + IDLE_LIMIT))
            .chain(self.udp.values().map(|e| e.last_activity + IDLE_LIMIT))
            .chain(self.retired_tcp.iter().map(|entry| entry.deadline))
            .min();
        if let Some(delay) = self
            .stack
            .interface
            .poll_delay(self.stack_now(), &self.stack.sockets)
        {
            let deadline = Instant::now() + Duration::from_millis(delay.total_millis());
            nearest = Some(nearest.map_or(deadline, |old| old.min(deadline)));
        }
        nearest
    }

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        let mut ready = false;
        for pending in self.pending.values_mut() {
            ready |= pending.work.poll(cx);
        }
        for entry in self.tcp.values() {
            let endpoint = self.stack.sockets.get::<tcp::Socket<'_>>(entry.handle);
            if !entry.physical_eof && endpoint.can_send() {
                ready |= entry.physical.poll_read_ready(cx).is_ready();
            }
            if endpoint.can_recv() {
                ready |= entry.physical.poll_write_ready(cx).is_ready();
            }
        }
        // Readability is actionable only when pump_udp can reserve its producer
        // peak. Retained replies can exhaust bytes long before the slot ceiling;
        // a blocked sink must not turn that readable socket into a busy wake.
        let udp_receive_capacity = self.output.len() < OUTPUT_PACKETS
            && self
                .replies
                .try_reserve(BATCH_RESERVATION + UDP_REPLY_HEADROOM)
                .is_ok();
        for (flow, entry) in &self.udp {
            if udp_receive_capacity
                && !self
                    .output
                    .iter()
                    .any(|job| job.udp.as_ref().is_some_and(|owner| owner.flow == *flow))
            {
                ready |= entry.physical.poll_recv_ready(cx).is_ready();
            }
            if !entry.held.is_empty() {
                ready |= entry.physical.poll_send_ready(cx).is_ready();
            }
        }
        if ready {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }

    /// Cancellation-safe: completed tasks remain owned; socket readiness is not consumed.
    pub async fn wait(&mut self) {
        // Do not consume a completion before installing the wait: even a
        // completion producing no app output is work the caller must observe.
        let deadline = self.deadline();
        let notify = self.notify.clone();
        tokio::select! {
            _ = poll_fn(|cx| self.poll_ready(cx)) => {},
            _ = notify.notified() => self.revalidate(),
            _ = async {
                if let Some(deadline) = deadline { tokio::time::sleep_until(deadline).await; }
                else { std::future::pending::<()>().await; }
            } => {},
        }
        self.process();
    }

    pub async fn close_all(&mut self) {
        // Started blocking work cannot be aborted. Keep every handle across the
        // awaits, so cancelling and resuming close_all still joins all of it.
        for pending in self.pending.values_mut() {
            pending.expired = true;
            pending.held.clear();
            if let Work::Connecting(task) = &pending.work {
                task.handle.abort();
            }
        }
        for pending in self.pending.values_mut() {
            match &mut pending.work {
                Work::Preparing(task) if task.result.is_none() => {
                    task.result = Some(
                        (&mut task.handle)
                            .await
                            .unwrap_or(Err(Refused::PreparationFailed)),
                    );
                }
                Work::Connecting(task) if task.result.is_none() => {
                    task.result = Some(
                        (&mut task.handle)
                            .await
                            .unwrap_or(Err(Refused::PreparationFailed)),
                    );
                }
                _ => {}
            }
        }
        self.pending.clear();
        // Destroy actual ring allocations before returning their flow credit.
        self.stack = Stack::new(self.mtu, self.input.clone(), self.replies.clone());
        self.tcp.clear();
        self.retired_tcp.clear();
        self.udp.clear();
        self.output.clear();
        // A cancelled close still owns its pending blocking preparations and
        // engine. Retire the native handle only after the owner's joined close.
        if let Some(mut engine) = self.native.take() {
            engine.close();
        }
    }
}

#[cfg(test)]
pub(crate) mod tests;
