//! Standalone linked ABI exercise; production serialization belongs to lane B.
#[allow(dead_code)]
#[path = "../../src/ip_endpoint/ffi.rs"]
mod ffi;

use std::{ffi::c_void, panic::AssertUnwindSafe};

#[derive(Default)]
struct Capture {
    packets: Vec<Vec<u8>>,
    completed: Vec<(ffi::Transport, Vec<u8>)>,
    panic: bool,
}

unsafe extern "C" fn complete(
    context: *mut c_void,
    transport: *const ffi::Transport,
    bytes: *const u8,
    length: usize,
) {
    // SAFETY: main lends one exclusive Capture; metadata and bytes are native
    // synchronous borrows. Copies complete before this callback returns.
    let capture = unsafe { &mut *context.cast::<Capture>() };
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
        capture.completed.push(unsafe {
            (
                *transport,
                std::slice::from_raw_parts(bytes, length).to_vec(),
            )
        });
    }));
    capture.panic |= result.is_err();
}

unsafe extern "C" fn output(context: *mut c_void, bytes: *const u8, length: usize) {
    // SAFETY: main lends one exclusive Capture for this synchronous native call.
    let capture = unsafe { &mut *context.cast::<Capture>() };
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: native owns and lends this complete packet only during callback.
        capture
            .packets
            .push(unsafe { std::slice::from_raw_parts(bytes, length) }.to_vec());
    }));
    capture.panic |= result.is_err();
}

fn main() {
    let callbacks = ffi::Callbacks {
        complete: Some(complete),
        output: Some(output),
    };
    let mut handle = 0;
    // SAFETY: one thread owns the process-global core; all pointers remain live
    // through each synchronous call and callbacks contain unwinding.
    unsafe {
        assert_eq!(ffi::krtek_lwip_abi_version(), ffi::ABI_VERSION);
        assert_eq!(ffi::krtek_lwip_open(&mut handle), ffi::OK);
        for (family, maximum) in [(4, 65507), (6, 65487)] {
            let mut tuple = ffi::Transport {
                scope: 1,
                family,
                protocol: 17,
                source: [0; 16],
                destination: [0; 16],
            };
            if family == 4 {
                tuple.source[..4].copy_from_slice(&[192, 168, 50, 9]);
                tuple.destination[..4].copy_from_slice(&[172, 27, 1, 1]);
            } else {
                tuple.source[0] = 0xfd;
                tuple.source[15] = 9;
                tuple.destination[0] = 0xfd;
                tuple.destination[15] = 1;
            }
            for length in [0, 4096, maximum] {
                let payload = (0..length).map(|i| (i * 37) as u8).collect::<Vec<_>>();
                let mut capture = Capture::default();
                assert_eq!(
                    ffi::krtek_lwip_reply(
                        handle,
                        &tuple,
                        18081,
                        32001,
                        payload.as_ptr(),
                        payload.len(),
                        &callbacks,
                        std::ptr::from_mut(&mut capture).cast(),
                    ),
                    ffi::OK
                );
                assert!(!capture.panic && !capture.packets.is_empty());
                let mut segment = vec![0; length + 8];
                let mut covered = vec![false; length + 8];
                for packet in &capture.packets {
                    assert!(packet.len() <= 1280);
                    let (header, offset) = if family == 4 {
                        (
                            20,
                            usize::from(u16::from_be_bytes([packet[6], packet[7]]) & 8191) * 8,
                        )
                    } else if packet[6] == 44 {
                        (
                            48,
                            usize::from(u16::from_be_bytes([packet[42], packet[43]]) & 65528),
                        )
                    } else {
                        (40, 0)
                    };
                    let end = offset + packet.len() - header;
                    assert!(end <= segment.len());
                    assert!(covered[offset..end].iter().all(|seen| !seen));
                    covered[offset..end].fill(true);
                    segment[offset..end].copy_from_slice(&packet[header..]);
                }
                assert!(covered.iter().all(|seen| *seen));
                assert_eq!(&segment[8..], &payload);
                assert_eq!(u16::from_be_bytes([segment[0], segment[1]]), 18081);
                assert_eq!(u16::from_be_bytes([segment[2], segment[3]]), 32001);
                assert_eq!(
                    usize::from(u16::from_be_bytes([segment[4], segment[5]])),
                    segment.len()
                );
                let packets = std::mem::take(&mut capture.packets);
                for (index, packet) in packets.iter().enumerate() {
                    assert_eq!(
                        ffi::krtek_lwip_ingest(
                            handle,
                            tuple.scope,
                            packet.as_ptr(),
                            packet.len(),
                            &callbacks,
                            std::ptr::from_mut(&mut capture).cast(),
                        ),
                        if index + 1 == packets.len() {
                            ffi::OK
                        } else {
                            ffi::PENDING
                        }
                    );
                    assert_eq!(
                        capture.completed.len(),
                        usize::from(index + 1 == packets.len())
                    );
                }
                assert!(!capture.panic);
                assert_eq!(capture.completed, vec![(tuple, segment)]);
            }
            assert_eq!(
                ffi::krtek_lwip_reply(
                    handle,
                    &tuple,
                    18081,
                    32001,
                    std::ptr::dangling(),
                    maximum + 1,
                    &callbacks,
                    std::ptr::null_mut(),
                ),
                ffi::OVERSIZED
            );
        }
        assert_eq!(ffi::krtek_lwip_close(handle), ffi::OK);
        assert_eq!(ffi::krtek_lwip_scope_refs(handle, 1), 0);
    }
    println!(
        "stock_lwip_ffi: 6 full payload/tuple output+ingress captures and 2 size refusals passed"
    );
}
