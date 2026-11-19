use super::{contract::*, ffi, native::*};
use crate::{ReceiveScope, Transport, packet::tests::flow};
use std::{
    ffi::c_void,
    sync::{Arc, Mutex},
    time::Duration,
};
use talpid_netstack::buffer_budget::BufferBudget;

#[derive(Default)]
struct Port {
    calls: usize,
    next: u64,
    retained: Vec<(u64, u64)>,
    ticks: Vec<u32>,
    expires: u32,
    completion: Option<(ffi::Transport, Vec<u8>)>,
    output: Option<Vec<u8>>,
    close_status: i32,
    open_status: i32,
}
#[derive(Clone, Default)]
struct Api(Arc<Mutex<Port>>);

// SAFETY: fake port only calls borrowed callbacks synchronously, just as C0.
unsafe impl NativeApi for Api {
    fn abi_version(&mut self) -> u32 {
        self.0.lock().unwrap().calls += 1;
        ffi::ABI_VERSION
    }
    fn open(&mut self, handle: &mut u64) -> i32 {
        let mut port = self.0.lock().unwrap();
        if port.open_status != ffi::OK {
            return port.open_status;
        }
        port.next += 1;
        *handle = port.next;
        ffi::OK
    }
    unsafe fn ingest(
        &mut self,
        handle: u64,
        scope: u64,
        _: &[u8],
        callbacks: &ffi::Callbacks,
        context: *mut c_void,
    ) -> i32 {
        let completion = {
            let mut port = self.0.lock().unwrap();
            if port.completion.is_none() {
                port.retained.push((handle, scope));
            }
            port.completion.take()
        };
        if let Some((metadata, segment)) = completion {
            // SAFETY: synchronous callback with live aligned metadata/segment.
            unsafe {
                callbacks.complete.unwrap()(
                    context,
                    &raw const metadata,
                    segment.as_ptr(),
                    segment.len(),
                );
            }
            ffi::OK
        } else {
            ffi::PENDING
        }
    }
    unsafe fn reply(
        &mut self,
        _: u64,
        _: &ffi::Transport,
        _: (u16, u16),
        _: &[u8],
        callbacks: &ffi::Callbacks,
        context: *mut c_void,
    ) -> i32 {
        let bytes = self.0.lock().unwrap().output.clone().unwrap();
        // SAFETY: borrowed packet lives across this synchronous callback.
        unsafe {
            callbacks.output.unwrap()(context, bytes.as_ptr(), bytes.len());
        }
        ffi::OK
    }
    fn set_mtu(&mut self, _: u64, _: u16) -> i32 {
        ffi::OK
    }
    fn tick(&mut self, now: u32) -> i32 {
        let mut port = self.0.lock().unwrap();
        port.ticks.push(now);
        if now >= port.expires {
            port.retained.clear();
        }
        ffi::OK
    }
    fn next_timeout_ms(&mut self) -> u32 {
        10
    }
    fn scope_refs(&mut self, handle: u64, scope: u64) -> u32 {
        self.0
            .lock()
            .unwrap()
            .retained
            .iter()
            .filter(|tag| **tag == (handle, scope))
            .count() as u32
    }
    fn close(&mut self, _: u64) -> i32 {
        self.0.lock().unwrap().close_status
    }
}

fn wait_for_refund(budget: &BufferBudget) {
    let deadline = std::time::Instant::now() + Duration::from_secs(1);
    while budget.used() != 0 && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(budget.used(), 0, "independent timer retirement");
}

#[test]
fn stock_lwip_wrapper_funds_before_init_and_retires_on_idle_timer_after_close() {
    let api = Api::default();
    api.0.lock().unwrap().expires = 30;
    let core = NativeCore::scripted(api.clone());
    let small = Arc::new(BufferBudget::new(NATIVE_RESERVATION - 1));
    assert!(matches!(core.open(small.clone(), 1280), Err(IpError::Full)));
    assert_eq!(
        api.0.lock().unwrap().calls,
        0,
        "no native initialization without credit"
    );
    let budget = Arc::new(BufferBudget::new(NATIVE_RESERVATION + 4096));
    let mut engine = core.open(budget.clone(), 1280).unwrap();
    let flow = flow(false, Transport::Udp);
    let scope = ReceiveScope::new(flow.source.ip(), flow.destination.ip(), &*budget).unwrap();
    let weak = scope.downgrade();
    engine.register(&scope).unwrap();
    assert_eq!(
        engine.ingest(ReceiveScopeId(scope.id()), &[0; 20], &mut |_| panic!(
            "pending"
        )),
        Ok(Ingress::Pending)
    );
    let id = ReceiveScopeId(scope.id());
    engine.close();
    assert_eq!(engine.scope_refs(id), 1);
    assert_eq!(engine.poll_time(core.now()), Err(IpError::Stale));
    drop(scope);
    assert!(weak.upgrade().is_some());
    assert!(budget.used() >= NATIVE_RESERVATION);
    // Another logical client shares the still-retained original reservation.
    // It does not transfer/refund that charge or allocate another native core.
    let other = Arc::new(BufferBudget::new(NATIVE_RESERVATION));
    let mut overlapping = core.open(other.clone(), 1280).unwrap();
    assert_eq!(other.used(), 0);
    assert!(budget.used() >= NATIVE_RESERVATION);
    overlapping.close();
    core.advance_scripted(29);
    assert!(
        budget.used() >= NATIVE_RESERVATION,
        "not expired before deadline"
    );
    core.advance_scripted(2);
    wait_for_refund(&budget);
    assert!(weak.upgrade().is_none());
    assert_eq!(budget.used(), 0);
    assert_eq!(engine.scope_refs(id), 0);
    let mut successor = core.open(budget.clone(), 1280).unwrap();
    assert!(core.now().0 >= 31, "opening never resets process clock");
    successor.close();
    assert_eq!(budget.used(), 0);
}

#[tokio::test]
async fn stock_lwip_wrapper_contains_callback_panics_and_rejects_invalid_metadata() {
    let api = Api::default();
    let core = NativeCore::new(api.clone());
    let budget = Arc::new(BufferBudget::new(NATIVE_RESERVATION + 4096));
    let mut engine = core.open(budget.clone(), 1280).unwrap();
    let flow = flow(false, Transport::Udp);
    let scope = ReceiveScope::new(flow.source.ip(), flow.destination.ip(), &*budget).unwrap();
    let id = ReceiveScopeId(scope.id());
    let mut metadata = ffi::Transport {
        scope: id.0,
        family: 4,
        protocol: 17,
        source: [0; 16],
        destination: [0; 16],
    };
    for malformed in [false, true] {
        if malformed {
            metadata.source[15] = 1;
        }
        api.0.lock().unwrap().completion = Some((metadata, vec![0; 8]));
        engine.register(&scope).unwrap();
        assert_eq!(
            engine.ingest(id, &[0; 20], &mut |_| panic!("contained callback")),
            Err(if malformed {
                IpError::Malformed
            } else {
                IpError::Internal
            })
        );
    }
    api.0.lock().unwrap().output = Some(vec![0; 20]);
    let tuple = ReplyTuple::from_flow(id, flow).unwrap();
    assert_eq!(
        engine.reply(tuple, &[], &mut |_| panic!("contained output")),
        Err(IpError::Internal)
    );
    // A callback panic never poisons the global mutex or leaves borrowed pointers.
    engine.set_mtu(1400).unwrap();
    engine.close();
    drop(scope);
    assert_eq!(budget.used(), 0);
}

#[test]
fn stock_lwip_wrapper_resumes_retirement_after_the_owning_runtime_is_replaced() {
    let api = Api::default();
    api.0.lock().unwrap().expires = u32::MAX;
    let core = NativeCore::new(api.clone());
    let budget = Arc::new(BufferBudget::new(NATIVE_RESERVATION + 4096));
    let runtime = || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    };
    let first = runtime();
    first.block_on(async {
        let mut engine = core.open(budget.clone(), 1280).unwrap();
        let flow = flow(false, Transport::Udp);
        let scope = ReceiveScope::new(flow.source.ip(), flow.destination.ip(), &*budget).unwrap();
        engine.register(&scope).unwrap();
        engine
            .ingest(ReceiveScopeId(scope.id()), &[0; 20], &mut |_| {
                panic!("pending")
            })
            .unwrap();
        engine.close();
        tokio::task::yield_now().await;
    });
    drop(first);
    assert!(budget.used() >= NATIVE_RESERVATION);
    let second_budget = Arc::new(BufferBudget::new(NATIVE_RESERVATION + 4096));
    runtime().block_on(async {
        api.0.lock().unwrap().open_status = ffi::FULL;
        assert!(matches!(
            core.open(second_budget.clone(), 1280),
            Err(IpError::Full)
        ));
        api.0.lock().unwrap().expires = core.now().0 + 5;
        wait_for_refund(&budget);
        assert_eq!(
            budget.used(),
            0,
            "a refused successor still resumes idle expiry"
        );
        api.0.lock().unwrap().open_status = ffi::OK;
        let mut next = core.open(second_budget.clone(), 1280).unwrap();
        next.close();
        assert_eq!(second_budget.used(), 0);
    });
}

#[test]
fn stock_lwip_wrapper_retirement_does_not_depend_on_a_successor_runtime() {
    let api = Api::default();
    api.0.lock().unwrap().expires = u32::MAX;
    let core = NativeCore::new(api.clone());
    let budget = Arc::new(BufferBudget::new(NATIVE_RESERVATION + 4096));
    {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let mut engine = core.open(budget.clone(), 1280).unwrap();
            let flow = flow(false, Transport::Udp);
            let scope =
                ReceiveScope::new(flow.source.ip(), flow.destination.ip(), &*budget).unwrap();
            engine.register(&scope).unwrap();
            engine
                .ingest(ReceiveScopeId(scope.id()), &[0; 20], &mut |_| {
                    panic!("pending")
                })
                .unwrap();
            engine.close();
            tokio::task::yield_now().await;
        });
    } // There is deliberately no successor runtime or native operation.
    api.0.lock().unwrap().expires = core.now().0 + 1;
    let deadline = std::time::Instant::now() + Duration::from_secs(1);
    while budget.used() != 0 && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(
        budget.used(),
        0,
        "global retirement must continue after the last caller runtime is destroyed"
    );
}

#[test]
fn stock_lwip_wrapper_simultaneous_handles_keep_one_reservation_and_per_handle_refs() {
    let api = Api::default();
    api.0.lock().unwrap().expires = 30;
    let core = NativeCore::scripted(api);
    let budget = Arc::new(BufferBudget::new(NATIVE_RESERVATION + 4096));
    let mut first = core.open(budget.clone(), 1280).unwrap();
    let mut second = core.open(budget.clone(), 1400).unwrap();
    assert_eq!(budget.used(), NATIVE_RESERVATION);
    let flow = flow(false, Transport::Udp);
    let scope = ReceiveScope::new(flow.source.ip(), flow.destination.ip(), &*budget).unwrap();
    let id = ReceiveScopeId(scope.id());
    for engine in [&mut first, &mut second] {
        engine.register(&scope).unwrap();
        engine
            .ingest(id, &[0; 20], &mut |_| panic!("pending"))
            .unwrap();
        assert_eq!(engine.scope_refs(id), 1);
    }
    first.close();
    assert_eq!(second.scope_refs(id), 1);
    second.close();
    drop(scope);
    core.advance_scripted(31);
    wait_for_refund(&budget);
    assert_eq!(budget.used(), 0);
}

#[tokio::test]
async fn stock_lwip_wrapper_failed_close_never_refunds_unknown_native_state() {
    let api = Api::default();
    let core = NativeCore::new(api.clone());
    let budget = Arc::new(BufferBudget::new(NATIVE_RESERVATION));
    let mut engine = core.open(budget.clone(), 1280).unwrap();
    api.0.lock().unwrap().close_status = ffi::INTERNAL;
    engine.close();
    assert_eq!(budget.used(), NATIVE_RESERVATION);
    assert!(matches!(
        core.open(budget.clone(), 1280),
        Err(IpError::Internal)
    ));
    // This deliberately faulted fake core stays funded until the core is
    // destroyed; production never pretends failed free is safe.
}

#[test]
fn stock_lwip_wrapper_timer_survives_runtime_loss_with_another_handle_alive() {
    let api = Api::default();
    api.0.lock().unwrap().expires = u32::MAX;
    let core = NativeCore::new(api.clone());
    let budget = Arc::new(BufferBudget::new(NATIVE_RESERVATION + 4096));
    let first = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut survivor = first.block_on(async { core.open(budget.clone(), 1280).unwrap() });
    let flow = flow(false, Transport::Udp);
    let scope = ReceiveScope::new(flow.source.ip(), flow.destination.ip(), &*budget).unwrap();
    let weak = scope.downgrade();
    survivor.register(&scope).unwrap();
    survivor
        .ingest(ReceiveScopeId(scope.id()), &[0; 20], &mut |_| {
            panic!("pending")
        })
        .unwrap();
    drop(scope);
    drop(first);
    api.0.lock().unwrap().expires = core.now().0 + 1;
    let deadline = std::time::Instant::now() + Duration::from_secs(1);
    while weak.upgrade().is_some() && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(
        weak.upgrade().is_none(),
        "live handles do not depend on their creator runtime"
    );
    assert_eq!(
        budget.used(),
        NATIVE_RESERVATION,
        "live handle retains backing"
    );
    survivor.close();
    assert_eq!(budget.used(), 0);
    // A fresh epoch can also open, expire and close with no Tokio runtime at all.
    let mut next = core.open(budget.clone(), 1280).unwrap();
    next.close();
    assert_eq!(budget.used(), 0);
}

#[test]
fn stock_lwip_wrapper_combined_backing_fits_existing_reservation() {
    // These constants and the scope/core layouts are also asserted at compile
    // time on each Android ABI. C1's all-LOAD maximum includes every C pool.
    let receipt = backing_receipt();
    let total: usize = receipt.iter().sum();
    eprintln!(
        "native combined backing: [C all-LOAD ceiling, stack, guard, worker allowance, Rust tables/core]={receipt:?}, total={total}, reservation={NATIVE_RESERVATION}"
    );
    assert!(total <= NATIVE_RESERVATION);
}

#[test]
fn stock_lwip_failed_core_refuses_work_on_surviving_handles_before_native_calls() {
    let api = Api::default();
    let core = NativeCore::scripted(api.clone());
    let budget = Arc::new(BufferBudget::new(NATIVE_RESERVATION + 4096));
    let mut first = core.open(budget.clone(), 1280).unwrap();
    let mut survivor = core.open(budget.clone(), 1280).unwrap();
    let flow = flow(false, Transport::Udp);
    let scope = ReceiveScope::new(flow.source.ip(), flow.destination.ip(), &*budget).unwrap();
    let id = ReceiveScopeId(scope.id());
    survivor.register(&scope).unwrap();
    api.0.lock().unwrap().close_status = ffi::INTERNAL;
    first.close();
    let ticks = api.0.lock().unwrap().ticks.len();
    assert!(matches!(
        core.open(budget.clone(), 1280),
        Err(IpError::Internal)
    ));
    let observed_ticks = api.0.lock().unwrap().ticks.len();
    assert_eq!(observed_ticks, ticks, "failed open never ticks");
    assert_eq!(
        survivor.ingest(id, &[0; 20], &mut |_| panic!("failed core")),
        Err(IpError::Internal)
    );
    assert_eq!(survivor.register(&scope), Err(IpError::Internal));
    assert_eq!(
        survivor.reply(
            ReplyTuple::from_flow(id, flow).unwrap(),
            &[],
            &mut |_| panic!("failed core")
        ),
        Err(IpError::Internal)
    );
    assert!(api.0.lock().unwrap().retained.is_empty());
    assert_eq!(survivor.scope_refs(id), 0);
    let observed_ticks = api.0.lock().unwrap().ticks.len();
    assert_eq!(observed_ticks, ticks, "failed surviving handle never ticks");
    api.0.lock().unwrap().close_status = ffi::OK;
    survivor.close();
    assert!(
        budget.used() >= NATIVE_RESERVATION,
        "unknown native state stays funded"
    );
}
