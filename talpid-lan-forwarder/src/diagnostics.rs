//! Explicit test-build observations. Never included in normal APKs.
//!
//! Records can contain private endpoint/socket metadata. They belong only in
//! the private diagnostic campaign, with its separate source/feature receipt.
//! Calls do not change grants, retries, deadlines, ownership or refusal results.
//! Logging itself changes timing; a passing traced call is not a causal fix.

use std::fmt;

/// Sample Android/Linux CLOCK_BOOTTIME, matching elapsedRealtimeNanos.
/// A failed clock read is missing evidence, never a fabricated timestamp.
#[cfg(any(target_os = "android", target_os = "linux"))]
pub fn boottime_ns() -> Option<u64> {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: the initialized output has the required timespec layout and is
    // writable for the duration of the syscall. No pointer is retained.
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &raw mut value) } != 0 {
        return None;
    }
    u64::try_from(value.tv_sec)
        .ok()?
        .checked_mul(1_000_000_000)?
        .checked_add(u64::try_from(value.tv_nsec).ok()?)
}

/// Emit one private trace boundary without taking ownership of its arguments.
pub fn observe(boundary: &str, fields: fmt::Arguments<'_>) {
    #[cfg(any(target_os = "android", target_os = "linux"))]
    {
        // SAFETY: gettid has no pointers, inputs or side effects on the socket.
        let tid = unsafe { libc::gettid() };
        log::info!(target: "krtek_r06", "KRTEK_R06 boundary={boundary} boot_ns={:?} pid={} tid={tid} {fields}",
            boottime_ns(), std::process::id());
    }
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    log::info!(target: "krtek_r06", "KRTEK_R06 boundary={boundary} boot_ns=unavailable pid={} {fields}", std::process::id());
}

/// Describe only validated complete TCP packets. Raw TUN capture remains the
/// independent evidence for malformed/fragmented packets and wire checksums.
pub fn tcp_packet(boundary: &str, bytes: &[u8]) {
    let Ok(packet) = crate::packet::parse(bytes) else {
        return;
    };
    if packet.flow.transport != crate::Transport::Tcp {
        return;
    }
    let offset = if bytes[0] >> 4 == 4 {
        usize::from(bytes[0] & 15) * 4
    } else {
        40
    };
    let Some(tcp) = bytes.get(offset..offset + 20) else {
        return;
    };
    let sequence = u32::from_be_bytes(tcp[4..8].try_into().expect("four bytes"));
    let acknowledgement = u32::from_be_bytes(tcp[8..12].try_into().expect("four bytes"));
    observe(
        boundary,
        format_args!(
            "flow={:?} seq={sequence} ack={acknowledgement} flags={} bytes={}",
            packet.flow,
            tcp[13],
            bytes.len()
        ),
    );
}

#[cfg(all(test, any(target_os = "android", target_os = "linux")))]
mod tests {
    #[test]
    fn r06_diagnostic_boottime_is_monotone_and_kernel_tid_exists() {
        let first = super::boottime_ns().expect("BOOTTIME supported");
        let second = super::boottime_ns().expect("BOOTTIME supported");
        assert!(first > 0 && second >= first);
        // SAFETY: gettid has no pointer arguments or socket side effects.
        assert!(unsafe { libc::gettid() } > 0);
        super::observe(
            "clock-preflight",
            format_args!("first={first} second={second}"),
        );
    }
}
