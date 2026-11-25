//! One serialized, funded native core. Logical handles never own native globals.
//!
//! The narrow unsafe API is implemented by the pinned C ABI. Tests
//! exercise the same lock, callback boundary and retirement with a scripted port.

use super::{contract::*, ffi};
use crate::{ReceiveScope, authority::MAX_RECEIVE_SCOPES};
use std::{
    ffi::c_void,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{Arc, Condvar, Mutex},
    time::Duration,
};
use talpid_types::relay_flow::{RelayBufferAllocator, RelayBufferReservation};

pub(crate) const NATIVE_RESERVATION: usize = 12 * 1024 * 1024;
// R1's refreshed four-ABI all-LOAD ceiling is 9,905,405 bytes (arm64).
// Include code/rodata as well as all fixed C pools, plus Rust bookkeeping and
// the explicitly sized worker stack. The guard allowance covers a 64 KiB page;
// allocator/OS thread runtime memory is not a process-RSS guarantee.
const NATIVE_LINKED_BYTES: usize = 9_905_405;
const TIMER_STACK_BYTES: usize = 2 * 1024 * 1024;
const TIMER_GUARD_BYTES: usize = 64 * 1024;
const TIMER_METADATA_BYTES: usize = 64 * 1024;
const _: () = assert!(
    NATIVE_LINKED_BYTES
        + TIMER_STACK_BYTES
        + TIMER_GUARD_BYTES
        + TIMER_METADATA_BYTES
        + MAX_RECEIVE_SCOPES * size_of::<TaggedScope>()
        + size_of::<NativeCore<LwipApi>>()
        <= NATIVE_RESERVATION
);

#[cfg(test)]
pub(crate) fn backing_receipt() -> [usize; 5] {
    [
        NATIVE_LINKED_BYTES,
        TIMER_STACK_BYTES,
        TIMER_GUARD_BYTES,
        TIMER_METADATA_BYTES,
        MAX_RECEIVE_SCOPES * size_of::<TaggedScope>() + size_of::<NativeCore<LwipApi>>(),
    ]
}

/// # Safety
/// Implementations obey the C0 pointer, synchronous-callback and ownership
/// contract. They neither retain callback pointers nor invoke them after return.
pub(crate) unsafe trait NativeApi: Send + 'static {
    fn abi_version(&mut self) -> u32;
    fn open(&mut self, handle: &mut ffi::Handle) -> i32;
    unsafe fn ingest(
        &mut self,
        handle: ffi::Handle,
        scope: u64,
        ip: &[u8],
        callbacks: &ffi::Callbacks,
        context: *mut c_void,
    ) -> i32;
    unsafe fn reply(
        &mut self,
        handle: ffi::Handle,
        tuple: &ffi::Transport,
        ports: (u16, u16),
        payload: &[u8],
        callbacks: &ffi::Callbacks,
        context: *mut c_void,
    ) -> i32;
    fn set_mtu(&mut self, handle: ffi::Handle, mtu: u16) -> i32;
    fn tick(&mut self, now: u32) -> i32;
    fn next_timeout_ms(&mut self) -> u32;
    fn scope_refs(&mut self, handle: ffi::Handle, scope: u64) -> u32;
    fn close(&mut self, handle: ffi::Handle) -> i32;
}

struct TaggedScope {
    handle: ffi::Handle,
    scope: ReceiveScope,
}

struct Funding {
    _charge: Arc<dyn RelayBufferReservation>,
}

struct State<A> {
    api: A,
    funding: Option<Funding>,
    handles: usize,
    scopes: Vec<TaggedScope>,
    maintaining: bool,
    worker: Option<std::thread::JoinHandle<()>>,
    failed: bool,
}

impl<A: NativeApi> State<A> {
    fn reap(&mut self) {
        self.scopes
            .retain(|tag| self.api.scope_refs(tag.handle, tag.scope.id()) != 0);
    }

    fn quiescent(&self) -> bool {
        !self.failed && self.handles == 0 && self.scopes.is_empty()
    }
}

pub(crate) struct NativeCore<A> {
    state: Mutex<State<A>>,
    origin: Clock,
    changed: Condvar,
}

enum Clock {
    Process(std::time::Instant),
    #[cfg(test)]
    Scripted(std::sync::atomic::AtomicU32),
}

impl Clock {
    fn elapsed(&self) -> Duration {
        match self {
            Self::Process(origin) => origin.elapsed(),
            #[cfg(test)]
            Self::Scripted(ms) => {
                Duration::from_millis(ms.load(std::sync::atomic::Ordering::Relaxed).into())
            }
        }
    }
}

impl<A: NativeApi> NativeCore<A> {
    pub(crate) fn new(api: A) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State {
                api,
                funding: None,
                handles: 0,
                scopes: Vec::new(),
                maintaining: false,
                worker: None,
                failed: false,
            }),
            origin: Clock::Process(std::time::Instant::now()),
            changed: Condvar::new(),
        })
    }

    #[cfg(test)]
    pub(crate) fn scripted(api: A) -> Arc<Self> {
        let mut core = Self::new(api);
        Arc::get_mut(&mut core).unwrap().origin =
            Clock::Scripted(std::sync::atomic::AtomicU32::new(0));
        core
    }

    #[cfg(test)]
    pub(crate) fn advance_scripted(&self, ms: u32) {
        let _state = self.state.lock().unwrap();
        let Clock::Scripted(now) = &self.origin else {
            panic!("not a scripted core")
        };
        now.fetch_add(ms, std::sync::atomic::Ordering::Relaxed);
        self.changed.notify_all();
    }

    pub(crate) fn now(&self) -> MonotonicMillis {
        MonotonicMillis(self.origin.elapsed().as_millis() as u32)
    }

    pub(crate) fn open(
        self: &Arc<Self>,
        buffers: Arc<dyn RelayBufferAllocator>,
        mtu: u16,
    ) -> Result<NativeEngine<A>, IpError> {
        let mut state = self.state.lock().unwrap();
        let result = (|| {
            if state.failed {
                return Err(IpError::Internal);
            }
            if state.funding.is_some() {
                status(state.api.tick(self.now().0))?;
            }
            state.reap();
            if state.failed {
                return Err(IpError::Internal);
            }
            if state.funding.is_none() {
                // A retiring worker has already relinquished the lock forever.
                // Join it before allocating another stack, even on another root.
                if let Some(worker) = state.worker.take() {
                    worker.join().map_err(|_| IpError::Internal)?;
                }
                let charge = buffers
                    .try_reserve(NATIVE_RESERVATION)
                    .map_err(|_| IpError::Full)?;
                let mut scopes = Vec::new();
                scopes
                    .try_reserve_exact(MAX_RECEIVE_SCOPES)
                    .map_err(|_| IpError::Full)?;
                state.scopes = scopes;
                state.funding = Some(Funding { _charge: charge });
                let core = self.clone();
                match std::thread::Builder::new()
                    .name("krtek-local-ip".into())
                    .stack_size(TIMER_STACK_BYTES)
                    .spawn(move || core.maintain())
                {
                    Ok(worker) => {
                        state.worker = Some(worker);
                        state.maintaining = true;
                    }
                    Err(_) => {
                        state.scopes = Vec::new();
                        state.funding = None;
                        return Err(IpError::Full);
                    }
                }
            }
            if state.api.abi_version() != ffi::ABI_VERSION {
                state.reap();
                return Err(IpError::Internal);
            }
            // Synchronize even a newly refunded/reopened core before creating
            // the first live handle. The native port rebases only at quiescence.
            status(state.api.tick(self.now().0))?;
            let mut handle = 0;
            let opened = status(state.api.open(&mut handle));
            if let Err(error) = opened {
                state.reap();
                return Err(error);
            }
            if handle == 0 {
                state.reap();
                return Err(IpError::Internal);
            }
            state.handles += 1;
            if let Err(error) = status(state.api.set_mtu(handle, mtu)) {
                if status(state.api.close(handle)).is_ok() {
                    state.handles -= 1;
                } else {
                    state.failed = true;
                }
                state.reap();
                return Err(error);
            }
            Ok(handle)
        })();
        self.changed.notify_all();
        drop(state);
        if result.is_err() {
            self.join_if_idle();
        }
        result.map(|handle| NativeEngine {
            core: self.clone(),
            handle,
            closed: false,
            registered: None,
            require_retained: false,
        })
    }

    fn maintain(self: Arc<Self>) {
        let mut state = self.state.lock().unwrap();
        loop {
            if !state.failed {
                if status(state.api.tick(self.now().0)).is_err() {
                    state.failed = true;
                }
                state.reap();
            }
            if state.quiescent() || state.failed {
                // No later lock acquisition by this worker. Its final charge
                // outlives its last native call; a successor joins before spawn.
                let funding = if state.quiescent() {
                    state.scopes = Vec::new();
                    state.funding.take()
                } else {
                    None // Unknown native state remains funded and fail-closed.
                };
                state.maintaining = false;
                self.changed.notify_all();
                drop(state);
                drop(funding);
                return;
            }
            // Predicate and wait use the one native mutex, so ingress/close
            // cannot lose a wake. Waiting never holds the native mutex.
            state = if let Some(ms) = timeout(state.api.next_timeout_ms()) {
                self.changed
                    .wait_timeout(state, Duration::from_millis(ms.into()))
                    .unwrap()
                    .0
            } else {
                self.changed.wait(state).unwrap()
            };
        }
    }

    fn join_if_idle(&self) {
        let mut state = self.state.lock().unwrap();
        while state.quiescent() && state.maintaining {
            state = self.changed.wait(state).unwrap();
        }
        if !state.maintaining
            && let Some(worker) = state.worker.take()
        {
            worker.join().expect("native timer worker panicked");
        }
    }
}

pub(crate) struct NativeEngine<A: NativeApi> {
    core: Arc<NativeCore<A>>,
    handle: ffi::Handle,
    closed: bool,
    registered: Option<ReceiveScope>,
    require_retained: bool,
}

impl<A: NativeApi> NativeEngine<A> {
    /// Register before injection; only native-referenced guards survive the call.
    pub(crate) fn register(&mut self, scope: &ReceiveScope) -> Result<(), IpError> {
        if self.closed || !scope.current() {
            return Err(IpError::Stale);
        }
        if self.core.state.lock().unwrap().failed {
            return Err(IpError::Internal);
        }
        self.registered = Some(scope.clone());
        self.require_retained = false;
        Ok(())
    }

    /// A packet-custody continuation cannot start a new native datagram after
    /// expiry/eviction. Check this after the ingress timer tick under the same
    /// native lock, not with a racy caller-side scope_refs observation.
    pub(crate) fn register_retained(&mut self, scope: &ReceiveScope) -> Result<(), IpError> {
        self.register(scope)?;
        self.require_retained = true;
        Ok(())
    }
}

fn status(value: i32) -> Result<(), IpError> {
    match IpError::from_status(value)? {
        Ingress::Consumed => Ok(()),
        Ingress::Pending => Err(IpError::Internal),
    }
}

fn timeout(ms: u32) -> Option<u32> {
    (ms != u32::MAX).then_some(ms)
}

type OutputFn<'a> = dyn FnMut(&[u8]) + 'a;

struct Call<'a> {
    scope: ReceiveScopeId,
    completed: Option<&'a mut dyn FnMut(CompleteTransport<'_>)>,
    output: Option<&'a mut OutputFn<'a>>,
    failure: Option<IpError>,
}

impl Call<'_> {
    fn contain(&mut self, f: impl FnOnce(&mut Self) -> Result<(), IpError>) {
        if self.failure.is_some() {
            return;
        }
        self.failure = match catch_unwind(AssertUnwindSafe(|| f(self))) {
            Ok(result) => result.err(),
            // Drop a panic payload inside a second catcher: a user payload's
            // destructor may itself panic. Nothing can unwind through C.
            Err(payload) => {
                if let Err(payload) = catch_unwind(AssertUnwindSafe(|| drop(payload))) {
                    std::mem::forget(payload);
                }
                Some(IpError::Internal)
            }
        };
    }
}

unsafe extern "C" fn complete(
    context: *mut c_void,
    metadata: *const ffi::Transport,
    bytes: *const u8,
    len: usize,
) {
    if context.is_null() {
        return;
    }
    // SAFETY: NativeApi borrows this non-null stack Call for this call only.
    let call = unsafe { &mut *context.cast::<Call<'_>>() };
    call.contain(|call| {
        if metadata.is_null() || !metadata.is_aligned() || bytes.is_null() {
            return Err(IpError::Malformed);
        }
        // SAFETY: the native contract provides a readable metadata object and
        // contiguous segment for the synchronous callback; bounds checked above.
        let metadata = unsafe { *metadata };
        if metadata.scope != call.scope.0 || metadata.scope == 0 {
            return Err(IpError::Stale);
        }
        let (source, destination) = addresses(&metadata)?;
        let protocol = match metadata.protocol {
            6 => crate::Transport::Tcp,
            17 => crate::Transport::Udp,
            _ => return Err(IpError::Unsupported),
        };
        if len
            < if protocol == crate::Transport::Tcp {
                20
            } else {
                8
            }
        {
            return Err(IpError::Malformed);
        }
        if len > 65535 - if source.is_ipv4() { 20 } else { 40 } {
            return Err(IpError::Oversized);
        }
        let callback = call.completed.as_mut().ok_or(IpError::Internal)?;
        // SAFETY: NativeApi promises contiguous borrowed bytes; checked length
        // and non-null pointer above, and callback cannot retain the borrow.
        let segment = unsafe { std::slice::from_raw_parts(bytes, len) };
        callback(CompleteTransport {
            scope: call.scope,
            source,
            destination,
            protocol,
            segment,
        });
        Ok(())
    });
}

unsafe extern "C" fn output(context: *mut c_void, bytes: *const u8, len: usize) {
    if context.is_null() {
        return;
    }
    // SAFETY: see complete. No output callback may outlive its native call.
    let call = unsafe { &mut *context.cast::<Call<'_>>() };
    call.contain(|call| {
        if bytes.is_null() || !(20..=65535).contains(&len) {
            return Err(IpError::Malformed);
        }
        let callback = call.output.as_mut().ok_or(IpError::Internal)?;
        // SAFETY: NativeApi supplies this checked, non-null synchronous borrow.
        let packet = unsafe { std::slice::from_raw_parts(bytes, len) };
        callback(packet);
        Ok(())
    });
}

fn addresses(metadata: &ffi::Transport) -> Result<(IpAddr, IpAddr), IpError> {
    match metadata.family {
        4 if metadata.source[4..] == [0; 12] && metadata.destination[4..] == [0; 12] => Ok((
            Ipv4Addr::from(<[u8; 4]>::try_from(&metadata.source[..4]).unwrap()).into(),
            Ipv4Addr::from(<[u8; 4]>::try_from(&metadata.destination[..4]).unwrap()).into(),
        )),
        6 => Ok((
            Ipv6Addr::from(metadata.source).into(),
            Ipv6Addr::from(metadata.destination).into(),
        )),
        _ => Err(IpError::Malformed),
    }
}

fn wire_address(address: IpAddr) -> [u8; 16] {
    match address {
        IpAddr::V4(ip) => {
            let mut bytes = [0; 16];
            bytes[..4].copy_from_slice(&ip.octets());
            bytes
        }
        IpAddr::V6(ip) => ip.octets(),
    }
}

impl<A: NativeApi> LocalIpEngine for NativeEngine<A> {
    fn ingest(
        &mut self,
        scope: ReceiveScopeId,
        ip: &[u8],
        completed: &mut dyn FnMut(CompleteTransport<'_>),
    ) -> Result<Ingress, IpError> {
        if self.closed {
            return Err(IpError::Stale);
        }
        if ip.is_empty() {
            return Err(IpError::Malformed);
        }
        if ip.len() > 65535 {
            return Err(IpError::Oversized);
        }
        let mut state = self.core.state.lock().unwrap();
        let registered = self.registered.take().ok_or(IpError::Stale)?;
        if state.failed {
            return Err(IpError::Internal);
        }
        // Expire older work before admitting a newly arrived fragment. Otherwise
        // a delayed worker's catch-up would also age this new input retroactively.
        if status(state.api.tick(self.core.now().0)).is_err() {
            state.failed = true;
            self.core.changed.notify_all();
            return Err(IpError::Internal);
        }
        state.reap();
        if registered.id() != scope.0 || !registered.current() {
            return Err(IpError::Stale);
        }
        if std::mem::take(&mut self.require_retained)
            && state.api.scope_refs(self.handle, scope.0) == 0
        {
            return Err(IpError::Stale);
        }
        if !state
            .scopes
            .iter()
            .any(|tag| tag.handle == self.handle && tag.scope.id() == scope.0)
        {
            if state.scopes.len() == MAX_RECEIVE_SCOPES {
                return Err(IpError::Full);
            }
            state.scopes.push(TaggedScope {
                handle: self.handle,
                scope: registered,
            });
        }
        if !state.scopes.iter().any(|tag| {
            tag.handle == self.handle && tag.scope.id() == scope.0 && tag.scope.current()
        }) {
            return Err(IpError::Stale);
        }
        let mut call = Call {
            scope,
            completed: Some(completed),
            output: None,
            failure: None,
        };
        let callbacks = ffi::Callbacks {
            complete: Some(complete),
            output: None,
        };
        // SAFETY: buffers and callback context live until synchronous return.
        let result = unsafe {
            state
                .api
                .ingest(self.handle, scope.0, ip, &callbacks, (&raw mut call).cast())
        };
        state.reap();
        drop(state);
        self.core.changed.notify_all();
        if let Some(error) = call.failure {
            return Err(error);
        }
        IpError::from_status(result)
    }

    fn reply(
        &mut self,
        tuple: ReplyTuple,
        payload: &[u8],
        output_fn: &mut dyn FnMut(&[u8]),
    ) -> Result<(), IpError> {
        if self.closed {
            return Err(IpError::Stale);
        }
        if tuple.scope.0 == 0 {
            return Err(IpError::Stale);
        }
        tuple.check_payload_len(payload.len())?;
        let metadata = ffi::Transport {
            scope: tuple.scope.0,
            family: if tuple.source.is_ipv4() { 4 } else { 6 },
            protocol: 17,
            source: wire_address(tuple.source.ip()),
            destination: wire_address(tuple.destination.ip()),
        };
        let mut call = Call {
            scope: tuple.scope,
            completed: None,
            output: Some(output_fn),
            failure: None,
        };
        let callbacks = ffi::Callbacks {
            complete: None,
            output: Some(output),
        };
        let mut state = self.core.state.lock().unwrap();
        if state.failed {
            return Err(IpError::Internal);
        }
        // SAFETY: explicit reversed tuple and borrowed payload/context.
        let result = unsafe {
            state.api.reply(
                self.handle,
                &metadata,
                (tuple.source.port(), tuple.destination.port()),
                payload,
                &callbacks,
                (&raw mut call).cast(),
            )
        };
        state.reap();
        drop(state);
        self.core.changed.notify_all();
        call.failure.map_or_else(|| status(result), Err)
    }

    fn set_mtu(&mut self, mtu: u16) -> Result<(), IpError> {
        if self.closed {
            return Err(IpError::Stale);
        }
        let mut state = self.core.state.lock().unwrap();
        if state.failed {
            return Err(IpError::Internal);
        }
        status(state.api.set_mtu(self.handle, mtu))
    }
    fn poll_time(&mut self, now: MonotonicMillis) -> Result<(), IpError> {
        if self.closed {
            return Err(IpError::Stale);
        }
        let mut state = self.core.state.lock().unwrap();
        if state.failed {
            return Err(IpError::Internal);
        }
        if state.funding.is_none() {
            return Ok(());
        }
        let result = status(state.api.tick(now.0));
        state.reap();
        result
    }
    fn next_timeout_ms(&self) -> Option<u32> {
        let mut state = self.core.state.lock().unwrap();
        if state.failed {
            return None;
        }
        state.funding.as_ref()?;
        timeout(state.api.next_timeout_ms())
    }
    fn scope_refs(&self, scope: ReceiveScopeId) -> usize {
        let mut state = self.core.state.lock().unwrap();
        if state.funding.is_none() {
            return 0;
        }
        state.api.scope_refs(self.handle, scope.0) as usize
    }
    fn close(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;
        self.registered = None;
        let mut state = self.core.state.lock().unwrap();
        if status(state.api.close(self.handle)).is_ok() {
            state.handles -= 1;
        } else {
            state.failed = true;
        }
        state.reap();
        drop(state);
        self.core.changed.notify_all();
        self.core.join_if_idle();
    }
}

impl<A: NativeApi> Drop for NativeEngine<A> {
    fn drop(&mut self) {
        self.close();
    }
}

struct LwipApi;

// SAFETY: the vendored device port implements the synchronous C0 ABI. Only
// NativeCore invokes this private implementation, under its process-global lock.
unsafe impl NativeApi for LwipApi {
    fn abi_version(&mut self) -> u32 {
        // SAFETY: no pointers; caller holds the sole native lock.
        unsafe { ffi::krtek_lwip_abi_version() }
    }
    fn open(&mut self, handle: &mut ffi::Handle) -> i32 {
        // SAFETY: writable borrowed handle, funding acquired before this call.
        unsafe { ffi::krtek_lwip_open(handle) }
    }
    unsafe fn ingest(
        &mut self,
        handle: ffi::Handle,
        scope: u64,
        ip: &[u8],
        callbacks: &ffi::Callbacks,
        context: *mut c_void,
    ) -> i32 {
        // SAFETY: NativeCore supplies live call-only buffers/callback context.
        unsafe { ffi::krtek_lwip_ingest(handle, scope, ip.as_ptr(), ip.len(), callbacks, context) }
    }
    unsafe fn reply(
        &mut self,
        handle: ffi::Handle,
        tuple: &ffi::Transport,
        ports: (u16, u16),
        payload: &[u8],
        callbacks: &ffi::Callbacks,
        context: *mut c_void,
    ) -> i32 {
        // SAFETY: lengths and tuple checked by NativeEngine; all borrows span
        // the synchronous native call and no foreign allocation is transferred.
        unsafe {
            ffi::krtek_lwip_reply(
                handle,
                tuple,
                ports.0,
                ports.1,
                payload.as_ptr(),
                payload.len(),
                callbacks,
                context,
            )
        }
    }
    fn set_mtu(&mut self, handle: ffi::Handle, mtu: u16) -> i32 {
        // SAFETY: logical handle and scalar MTU, serialized by NativeCore.
        unsafe { ffi::krtek_lwip_set_mtu(handle, mtu) }
    }
    fn tick(&mut self, now: u32) -> i32 {
        // SAFETY: one process-relative clock, serialized with every native call.
        unsafe { ffi::krtek_lwip_tick(now) }
    }
    fn next_timeout_ms(&mut self) -> u32 {
        // SAFETY: scalar query under the same native lock.
        unsafe { ffi::krtek_lwip_next_timeout_ms() }
    }
    fn scope_refs(&mut self, handle: ffi::Handle, scope: u64) -> u32 {
        // SAFETY: numeric provenance query, including retired handles.
        unsafe { ffi::krtek_lwip_scope_refs(handle, scope) }
    }
    fn close(&mut self, handle: ffi::Handle) -> i32 {
        // SAFETY: once-only logical retirement, serialized with all frees.
        unsafe { ffi::krtek_lwip_close(handle) }
    }
}

/// Private real API construction guarantees there is exactly one native lock,
/// clock and retained reservation, including across Tokio/runtime replacement.
pub(crate) struct Engine(NativeEngine<LwipApi>);

impl Engine {
    pub(crate) fn open(buffers: Arc<dyn RelayBufferAllocator>, mtu: u16) -> Result<Self, IpError> {
        static CORE: std::sync::OnceLock<Arc<NativeCore<LwipApi>>> = std::sync::OnceLock::new();
        CORE.get_or_init(|| NativeCore::new(LwipApi))
            .open(buffers, mtu)
            .map(Self)
    }
    pub(crate) fn register(&mut self, scope: &ReceiveScope) -> Result<(), IpError> {
        self.0.register(scope)
    }
    pub(crate) fn register_retained(&mut self, scope: &ReceiveScope) -> Result<(), IpError> {
        self.0.register_retained(scope)
    }
}

impl LocalIpEngine for Engine {
    fn ingest(
        &mut self,
        scope: ReceiveScopeId,
        ip: &[u8],
        completed: &mut dyn FnMut(CompleteTransport<'_>),
    ) -> Result<Ingress, IpError> {
        self.0.ingest(scope, ip, completed)
    }
    fn reply(
        &mut self,
        tuple: ReplyTuple,
        payload: &[u8],
        output: &mut dyn FnMut(&[u8]),
    ) -> Result<(), IpError> {
        self.0.reply(tuple, payload, output)
    }
    fn set_mtu(&mut self, mtu: u16) -> Result<(), IpError> {
        self.0.set_mtu(mtu)
    }
    fn poll_time(&mut self, now: MonotonicMillis) -> Result<(), IpError> {
        self.0.poll_time(now)
    }
    fn next_timeout_ms(&self) -> Option<u32> {
        self.0.next_timeout_ms()
    }
    fn scope_refs(&self, scope: ReceiveScopeId) -> usize {
        self.0.scope_refs(scope)
    }
    fn close(&mut self) {
        self.0.close();
    }
}
