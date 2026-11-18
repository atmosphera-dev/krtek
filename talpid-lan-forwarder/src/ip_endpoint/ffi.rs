//! Handwritten ABI v1 bindings. The C header is canonical; contract tests check
//! the mirrored constants and layout. No lwIP internals belong in these types.

use std::ffi::c_void;

pub const ABI_VERSION: u32 = 1;
pub const OK: i32 = 0;
pub const PENDING: i32 = 1;
pub const FULL: i32 = -1;
pub const MALFORMED: i32 = -2;
pub const UNSUPPORTED: i32 = -3;
pub const OVERSIZED: i32 = -4;
pub const STALE: i32 = -5;
pub const INTERNAL: i32 = -6;

pub type Handle = u64;

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Transport {
    pub scope: u64,
    pub family: u8,
    pub protocol: u8,
    pub source: [u8; 16],
    pub destination: [u8; 16],
}

pub type CompleteCallback = unsafe extern "C" fn(*mut c_void, *const Transport, *const u8, usize);
pub type OutputCallback = unsafe extern "C" fn(*mut c_void, *const u8, usize);

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Callbacks {
    pub complete: Option<CompleteCallback>,
    pub output: Option<OutputCallback>,
}

// These assertions also run in compile-only Android ABI checks; they do not
// depend on executing an Android test binary or linking the absent C0 engine.
const _: () = {
    use std::mem::{align_of, offset_of, size_of};
    let (size, alignment) = if cfg!(target_arch = "x86") {
        (44, 4)
    } else {
        (48, 8)
    };
    assert!(size_of::<Handle>() == 8);
    assert!(size_of::<Transport>() == size);
    assert!(align_of::<Transport>() == alignment);
    assert!(offset_of!(Transport, scope) == 0);
    assert!(offset_of!(Transport, family) == 8);
    assert!(offset_of!(Transport, protocol) == 9);
    assert!(offset_of!(Transport, source) == 10);
    assert!(offset_of!(Transport, destination) == 26);
    assert!(size_of::<Callbacks>() == 2 * size_of::<usize>());
    assert!(align_of::<Callbacks>() == align_of::<usize>());
    assert!(offset_of!(Callbacks, complete) == 0);
    assert!(offset_of!(Callbacks, output) == size_of::<usize>());
};

// Declarations only: C0 does not link or call an engine. The real wrapper must
// serialize calls, validate borrowed buffers and contain callback panics.
#[cfg_attr(
    test,
    expect(
        dead_code,
        reason = "contract-only ABI declarations; no native engine in C0"
    )
)]
unsafe extern "C" {
    pub fn krtek_lwip_abi_version() -> u32;
    pub fn krtek_lwip_open(handle: *mut Handle) -> i32;
    pub fn krtek_lwip_ingest(
        handle: Handle,
        scope: u64,
        ip: *const u8,
        len: usize,
        callbacks: *const Callbacks,
        context: *mut c_void,
    ) -> i32;
    pub fn krtek_lwip_reply(
        handle: Handle,
        transport: *const Transport,
        source_port: u16,
        destination_port: u16,
        payload: *const u8,
        len: usize,
        callbacks: *const Callbacks,
        context: *mut c_void,
    ) -> i32;
    pub fn krtek_lwip_set_mtu(handle: Handle, mtu: u16) -> i32;
    pub fn krtek_lwip_tick(monotonic_ms: u32) -> i32;
    pub fn krtek_lwip_next_timeout_ms() -> u32;
    pub fn krtek_lwip_scope_refs(handle: Handle, scope: u64) -> u32;
    pub fn krtek_lwip_close(handle: Handle) -> i32;
}
