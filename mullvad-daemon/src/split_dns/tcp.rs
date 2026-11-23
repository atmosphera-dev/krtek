//! Per-message TCP DNS service. The capture reactor polls all sessions; there
//! is no listener, extra packet reader or independent route classifier.
use super::{
    home_path::{HomeDnsPath, HomeDnsQuery},
    tcp_egress::{OwnedTcp, Registry, Upstream},
    tcp_io::CodecIo,
    transport::{ExchangeError, Protocol, decode_message},
};
use crate::local_delivery::DeliveryAuthority;
use futures::StreamExt;
use hickory_net::{tcp::TcpStream, xfer::DnsStreamHandle};
use hickory_proto::op::{Message, MessageType, Metadata, ResponseCode, SerialMessage};
use mullvad_types::settings::local_network_access::split_dns::{DnsLane, SuffixMatcher};
use std::{
    collections::{HashMap, LinkedList},
    future::Future,
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use talpid_lan_forwarder::{
    Disposition, Flow, Forwarder, LocalAuthority, ReceiveScope, Refused,
    tcp_service::{ServiceStream, TcpChannel, TcpService},
};
use talpid_types::relay_flow::{
    RelayBufferAllocator, RelayBufferReservation, RelayCapture, RelaySink,
};

const DEADLINE: Duration = Duration::from_secs(5);
type Work = Pin<Box<dyn Future<Output = Result<(), ExchangeError>> + Send>>;

enum Guard {
    Home(Arc<dyn HomeDnsQuery>),
    Ordinary(Arc<OwnedTcp>),
    System(Arc<super::system::SystemQuery>),
}
impl Guard {
    fn current(&self) -> bool {
        match self {
            Self::Home(home) => home.current(),
            Self::Ordinary(socket) => socket.current(),
            Self::System(query) => query.current(),
        }
    }
}
struct Reply {
    end: u64,
    guard: Option<Guard>,
    _charge: Arc<dyn RelayBufferReservation>,
}
struct Replies {
    end: u64,
    pending: LinkedList<Reply>,
}
struct Session {
    live: AtomicBool,
    flow: Flow,
    scope: ReceiveScope,
    capture: RelayCapture,
    sink: RelaySink,
    matcher: Arc<SuffixMatcher>,
    system: Option<Arc<super::system::SystemIo>>,
    partial: bool,
    replies: Mutex<Replies>,
    _storage: Arc<dyn RelayBufferReservation>,
}
impl Session {
    fn current(&self) -> bool {
        let current = self.live.load(Ordering::Acquire)
            && self
                .system
                .as_ref()
                .is_none_or(|system| system.is_partial() == self.partial)
            && self.scope.current()
            && self.capture.current()
            && self
                .capture
                .sink()
                .is_some_and(|sink| sink.same_sink(&self.sink))
            && self
                .replies
                .lock()
                .unwrap()
                .pending
                .iter()
                .all(|reply| reply.guard.as_ref().is_none_or(Guard::current));
        if !current {
            self.live.store(false, Ordering::Release);
        }
        current
    }
    fn retain(
        &self,
        len: usize,
        guard: Option<Guard>,
        buffers: &dyn RelayBufferAllocator,
    ) -> Result<(), ExchangeError> {
        if !self.current() {
            return Err(ExchangeError::Closed);
        }
        let charge = buffers
            .try_reserve(size_of::<Reply>() + 512)
            .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
        let mut replies = self.replies.lock().unwrap();
        replies.end = replies
            .end
            .checked_add(u64::try_from(len + 2).map_err(|_| ExchangeError::Closed)?)
            .ok_or(ExchangeError::Closed)?;
        let end = replies.end;
        replies.pending.push_back(Reply {
            end,
            guard,
            _charge: charge,
        });
        Ok(())
    }
}

struct Application {
    stream: ServiceStream,
    session: Arc<Session>,
    read: u64,
}
impl Drop for Application {
    fn drop(&mut self) {
        self.session.live.store(false, Ordering::Release);
    }
}
impl TcpChannel for Application {
    fn current(&self) -> bool {
        self.session.current()
    }
    fn queued_output(&mut self, queued: usize) {
        if !self.session.current() {
            return;
        }
        let acked = self.read.saturating_sub(queued as u64);
        let mut replies = self.session.replies.lock().unwrap();
        while replies
            .pending
            .front()
            .is_some_and(|reply| reply.end <= acked)
        {
            replies.pending.pop_front();
        }
    }
    fn try_read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if !self.current() {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let n = self.stream.try_read(bytes)?;
        self.read = self
            .read
            .checked_add(n as u64)
            .ok_or(io::ErrorKind::OutOfMemory)?;
        Ok(n)
    }
    fn try_write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.stream.try_write(bytes)
    }
    fn shutdown(&mut self) -> io::Result<()> {
        self.stream.shutdown()
    }
    fn abort(&mut self) {
        self.stream.abort();
    }
    fn poll_read_ready(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.stream.poll_read_ready(cx)
    }
    fn poll_write_ready(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.stream.poll_write_ready(cx)
    }
}

struct Pending {
    session: Arc<Session>,
    work: Work,
    done: bool,
}
struct Owner {
    delivery: Arc<DeliveryAuthority>,
    capture: RelayCapture,
    path: Arc<dyn HomeDnsPath>,
    registry: Arc<Registry>,
    system: Option<Arc<super::system::SystemIo>>,
    buffers: Arc<dyn RelayBufferAllocator>,
    sessions: Mutex<HashMap<Flow, Weak<Session>>>,
    pending: Mutex<LinkedList<Pending>>,
}
impl LocalAuthority for Owner {
    type Grant = Arc<Session>;
    fn disposition(&self, _: IpAddr) -> Disposition {
        Disposition::Local
    }
    fn receive(
        &self,
        source: IpAddr,
        destination: IpAddr,
        buffers: &dyn RelayBufferAllocator,
    ) -> Result<ReceiveScope, Refused> {
        self.delivery
            .dns_input(source, destination, buffers)
            .map(|(_, scope)| scope)
    }
    fn authorize(&self, _: Flow) -> Result<Self::Grant, Refused> {
        Err(Refused::Denied)
    }
    fn authorize_received(&self, flow: Flow, scope: &ReceiveScope) -> Result<Self::Grant, Refused> {
        if flow.transport != talpid_lan_forwarder::Transport::Tcp
            || flow.destination.port() != 53
            || !scope.current()
        {
            return Err(Refused::Denied);
        }
        let (matcher, current) =
            self.delivery
                .dns_input(flow.source.ip(), flow.destination.ip(), &*self.buffers)?;
        if current.id() != scope.id() {
            return Err(Refused::Stale);
        }
        let sink = self.capture.sink().ok_or(Refused::Stale)?;
        // One framing/message/exchange peak per serial session, not per packet
        // and not an unbounded future/response queue. Ring credit is separate.
        let storage = self
            .buffers
            .try_reserve(6 * (usize::from(u16::MAX) + 1) + 16 * 1024)
            .map_err(|_| Refused::Full)?;
        let session = Arc::new(Session {
            live: AtomicBool::new(true),
            flow,
            scope: scope.clone(),
            capture: self.capture.clone(),
            sink,
            matcher,
            system: self.system.clone(),
            partial: self
                .system
                .as_ref()
                .is_some_and(|system| system.is_partial()),
            replies: Mutex::new(Replies {
                end: 0,
                pending: LinkedList::new(),
            }),
            _storage: storage,
        });
        let mut sessions = self.sessions.lock().unwrap();
        sessions.retain(|_, session| session.strong_count() != 0);
        sessions.insert(flow, Arc::downgrade(&session));
        Ok(session)
    }
    fn prepare(&self, _: &socket2::Socket, _: &Self::Grant) -> Result<(), Refused> {
        Err(Refused::Denied)
    }
    fn current(&self, grant: &Self::Grant) -> bool {
        grant.current()
    }
    fn physical_destination(&self, _: &Self::Grant, flow: Flow) -> SocketAddr {
        flow.destination
    }
}
impl TcpService for Owner {
    fn open(
        &self,
        flow: Flow,
        scope: &ReceiveScope,
        buffers: &dyn RelayBufferAllocator,
    ) -> Result<Box<dyn TcpChannel>, Refused> {
        let session = self
            .sessions
            .lock()
            .unwrap()
            .get(&flow)
            .and_then(Weak::upgrade)
            .ok_or(Refused::Stale)?;
        if !session.current() || session.scope.id() != scope.id() {
            return Err(Refused::Stale);
        }
        // Same ring size as the shared endpoint. This is backpressure, not a
        // message-length limit; Hickory accumulates complete protocol frames.
        let (application, codec) = ServiceStream::pair(buffers, 4096)?;
        let work = serve(
            session.clone(),
            codec,
            self.path.clone(),
            self.registry.clone(),
            self.buffers.clone(),
        );
        self.pending.lock().unwrap().push_back(Pending {
            session: session.clone(),
            work: Box::pin(work),
            done: false,
        });
        Ok(Box::new(Application {
            stream: application,
            session,
            read: 0,
        }))
    }
}

async fn serve(
    session: Arc<Session>,
    codec: ServiceStream,
    path: Arc<dyn HomeDnsPath>,
    registry: Arc<Registry>,
    buffers: Arc<dyn RelayBufferAllocator>,
) -> Result<(), ExchangeError> {
    let (mut stream, mut sender) = TcpStream::from_stream(CodecIo(codec), session.flow.source);
    loop {
        let Some(input) = stream.next().await else {
            return Ok(());
        };
        let (bytes, _) = input?.into_parts();
        if !session.current() {
            return Err(ExchangeError::Closed);
        }
        let request = decode_message(&bytes)?;
        if request.metadata.message_type != MessageType::Query {
            return Err(ExchangeError::Malformed);
        }
        let result = match session.matcher.classify(&request) {
            Err(mullvad_types::settings::local_network_access::split_dns::QuestionError::Unsupported) => (failure(&request, ResponseCode::NotImp)?, None),
            Err(_) => (failure(&request, ResponseCode::FormErr)?, None),
            Ok(DnsLane::Home) => {
                match path.authorize(session.flow.source, Protocol::Tcp) {
                    Err(_) => (failure(&request, ResponseCode::ServFail)?, None),
                    Ok(lease) => {
                        let lease: Arc<dyn HomeDnsQuery> = lease.into();
                        let result = tokio::select! { biased; _ = lease.retired() => Err(ExchangeError::Closed), result = lease.exchange(DEADLINE, request.clone()) => result };
                        if !lease.current() { return Err(ExchangeError::Closed); }
                        let reply = match result { Ok(reply) => { check(&reply, &request)?; reply.as_buffer().to_vec() }, Err(_) => failure(&request, ResponseCode::ServFail)? };
                        (reply, Some(Guard::Home(lease)))
                    }
                }
            }
            Ok(DnsLane::Ordinary) => {
                if session.partial {
                    let system = session.system.as_ref().ok_or(ExchangeError::Closed)?;
                    // Lockdown denies this message, not Home on the same stream.
                    let Ok(query) = system.authorize(session.flow.destination, true, session.scope.clone(), session.capture.clone()) else { continue; };
                    let Ok(reply) = query.exchange(&system.io, bytes).await else { continue; };
                    (reply, Some(Guard::System(query)))
                } else {
                // This branch receives original bytes, not request.to_vec().
                // It never uses Home preparation or a protected retry.
                match tokio::time::timeout(DEADLINE, ordinary(&session, &registry, bytes, &request, &*buffers)).await {
                    Ok(Ok((reply, socket))) => (reply, Some(Guard::Ordinary(socket))),
                    _ => (failure(&request, ResponseCode::ServFail)?, None),
                }
                }
            }
        };
        session.retain(result.0.len(), result.1, &*buffers)?;
        sender.send(SerialMessage::new(result.0, session.flow.source))?;
        // TcpStream flushes the queued reply before reading the next frame,
        // including a half-close. No hand-written DNS framing or ID rewriting.
    }
}
async fn ordinary(
    session: &Session,
    registry: &Registry,
    bytes: Vec<u8>,
    request: &Message,
    buffers: &dyn RelayBufferAllocator,
) -> Result<(Vec<u8>, Arc<OwnedTcp>), ExchangeError> {
    let socket = registry
        .connect(
            session.flow.source,
            session.flow.destination,
            session.scope.clone(),
            session.capture.clone(),
            buffers,
        )
        .await?;
    let (mut stream, mut sender) =
        TcpStream::from_stream(CodecIo(Upstream(socket.clone())), session.flow.destination);
    sender.send(SerialMessage::new(bytes, session.flow.destination))?;
    let (bytes, _) = stream
        .next()
        .await
        .ok_or(ExchangeError::Closed)??
        .into_parts();
    let reply = decode_message(&bytes)?;
    check(&reply, request)?;
    Ok((bytes, socket))
}
fn check(reply: &Message, request: &Message) -> Result<(), ExchangeError> {
    if reply.metadata.message_type != MessageType::Response
        || reply.metadata.id != request.metadata.id
        || reply.metadata.op_code != request.metadata.op_code
        || reply.queries != request.queries
    {
        return Err(ExchangeError::Identity);
    }
    Ok(())
}
fn failure(request: &Message, code: ResponseCode) -> Result<Vec<u8>, ExchangeError> {
    let mut reply = Message::response(request.metadata.id, request.metadata.op_code);
    reply.metadata = Metadata::response_from_request(&request.metadata);
    reply.metadata.response_code = code;
    reply.queries = request.queries.clone();
    reply.to_vec().map_err(|_| ExchangeError::Malformed)
}

pub(super) struct TcpWork {
    forwarder: Forwarder<Owner>,
    owner: Arc<Owner>,
}
impl TcpWork {
    pub(super) fn new(
        delivery: Arc<DeliveryAuthority>,
        buffers: Arc<dyn RelayBufferAllocator>,
        path: Arc<dyn HomeDnsPath>,
        capture: RelayCapture,
        mtu: u16,
        system: Option<Arc<super::system::SystemIo>>,
    ) -> Result<Self, Refused> {
        let owner = Arc::new(Owner {
            delivery,
            capture,
            path,
            registry: Arc::default(),
            system,
            buffers: buffers.clone(),
            sessions: Mutex::default(),
            pending: Mutex::default(),
        });
        let forwarder = Forwarder::with_mtu(owner.clone(), buffers, mtu.into())?
            .with_tcp_service(owner.clone());
        Ok(Self { forwarder, owner })
    }
    pub(super) fn owns(&self, flow: Flow) -> bool {
        self.owner.registry.owns(flow)
    }
    pub(super) fn egress(&self, flow: Flow) -> Option<bool> {
        self.owner.registry.route(flow)
    }
    pub(super) fn ingest(&mut self, bytes: &[u8]) {
        self.forwarder.ingest(bytes);
    }
    pub(super) fn has_output(&self) -> bool {
        self.forwarder.has_output()
    }
    pub(super) fn set_mtu(&mut self, mtu: u16) -> Result<(), Refused> {
        self.forwarder.set_mtu(mtu.into())
    }
    pub(super) fn revalidate(&mut self) {
        self.forwarder.revalidate();
        self.owner.registry.prune();
        let mut pending = self.owner.pending.lock().unwrap();
        for _ in 0..pending.len() {
            let work = pending.pop_front().unwrap();
            if !work.done && work.session.current() {
                pending.push_back(work);
            }
        }
    }
    pub(super) fn process(&mut self) {
        self.revalidate();
        self.forwarder.process();
    }
    pub(super) async fn wait(&mut self) {
        // Split borrows: the service futures and transport endpoint are separate
        // poll owners, but both run in the same sole capture reactor.
        let owner = self.owner.clone();
        tokio::select! {
            _ = self.forwarder.wait() => {},
            _ = std::future::poll_fn(|cx| {
                let mut ready = false;
                for work in owner.pending.lock().unwrap().iter_mut() {
                    if !work.session.current() || work.work.as_mut().poll(cx).is_ready() { work.done = true; ready = true; }
                }
                if ready { Poll::Ready(()) } else { Poll::Pending }
            }) => {},
        }
        self.process();
    }
    pub(super) fn write_output(
        &mut self,
        sink: &RelaySink,
        write: &mut dyn FnMut(&[u8]) -> io::Result<usize>,
    ) -> io::Result<bool> {
        self.forwarder.write_output(|bytes| {
            self.owner
                .capture
                .with_sink(sink, || write(bytes))
                .map_err(|_| io::Error::other("DNS TCP capture retired"))?
        })
    }
    pub(super) async fn close(&mut self) {
        self.owner.pending.lock().unwrap().clear();
        self.forwarder.close_all().await;
        // A service-open task may have been inside its synchronous admission
        // when close began. The joined transport owner now proves every such
        // task has stopped, so retire any session it published after the first
        // clear as well. Cancellation retains both owners for the next close.
        self.owner.pending.lock().unwrap().clear();
    }
}

#[cfg(test)]
#[path = "tcp_tests.rs"]
mod tests;
