//! Private, feature-gated byte observations, not packet validation or routing.
//! Log I/O changes diagnostic timing. Missing chunks/markers are missing evidence.
use std::{
    fmt::Write as _,
    net::Ipv6Addr,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT_OBSERVER: AtomicU64 = AtomicU64::new(1);
static NEXT_PACKET: AtomicU64 = AtomicU64::new(1);
// Keep each record well below Android log's per-entry limit. Not a packet limit.
const CHUNK_BYTES: usize = 128;

pub(super) struct Observer {
    id: u64,
    session: u64,
    target: u64,
    request: u64,
    packets: AtomicU64,
    chunks: AtomicU64,
    completions: AtomicU64,
}

pub(super) struct Observation(u64);

fn peer_family(bytes: &[u8], outbound: bool) -> Option<u8> {
    match bytes.first().map(|byte| byte >> 4) {
        Some(4) if bytes.len() >= 20 => {
            let address = if outbound {
                &bytes[16..20]
            } else {
                &bytes[12..16]
            };
            (address == [1, 1, 1, 1]).then_some(4)
        }
        Some(6) if bytes.len() >= 40 => {
            let address = if outbound {
                &bytes[24..40]
            } else {
                &bytes[8..24]
            };
            (address == Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111).octets())
                .then_some(6)
        }
        _ => None,
    }
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn boottime_ns() -> Option<u64> {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: this initialized timespec is writable and retained only for this call.
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &raw mut time) } != 0 {
        return None;
    }
    u64::try_from(time.tv_sec)
        .ok()?
        .checked_mul(1_000_000_000)?
        .checked_add(u64::try_from(time.tv_nsec).ok()?)
}

#[cfg(not(any(target_os = "android", target_os = "linux")))]
fn boottime_ns() -> Option<u64> {
    None
}

impl Observer {
    pub(super) fn new(session: u64, target: u64, request: u64) -> Self {
        let observer = Self {
            id: NEXT_OBSERVER.fetch_add(1, Ordering::Relaxed),
            session,
            target,
            request,
            packets: AtomicU64::new(0),
            chunks: AtomicU64::new(0),
            completions: AtomicU64::new(0),
        };
        observer.event("observer-open", None);
        observer
    }

    fn prefix(&self, event: &str, stamp: Option<u64>) -> String {
        let stamp = stamp.map_or_else(|| "unavailable".to_owned(), |value| value.to_string());
        format!(
            "KRTEK_PUBLIC_DNS schema=1 event={event} boot_ns={stamp} pid={} observer={} session={} target={} request={}",
            std::process::id(),
            self.id,
            self.session,
            self.target,
            self.request
        )
    }

    fn packet_to(
        &self,
        boundary: &str,
        outbound: bool,
        bytes: &[u8],
        stamp: Option<u64>,
        mut emit: impl FnMut(String),
    ) -> Option<Observation> {
        let family = peer_family(bytes, outbound)?;
        let id = NEXT_PACKET.fetch_add(1, Ordering::Relaxed);
        let prefix = self.prefix("chunk", stamp);
        let chunks = bytes.len().div_ceil(CHUNK_BYTES);
        self.packets.fetch_add(1, Ordering::Relaxed);
        self.chunks.fetch_add(chunks as u64, Ordering::Relaxed);
        for (index, chunk) in bytes.chunks(CHUNK_BYTES).enumerate() {
            let mut hex = String::with_capacity(chunk.len() * 2);
            for byte in chunk {
                // Formatting into a String cannot fail.
                write!(&mut hex, "{byte:02x}").expect("String formatting");
            }
            emit(format!(
                "{prefix} packet={id} boundary={boundary} outbound={outbound} family={family} bytes={} index={index} chunks={chunks} hex={hex}",
                bytes.len()
            ));
        }
        Some(Observation(id))
    }

    pub(super) fn packet(
        &self,
        boundary: &str,
        outbound: bool,
        bytes: &[u8],
    ) -> Option<Observation> {
        self.packet_to(boundary, outbound, bytes, boottime_ns(), |line| {
            log::info!(target: "krtek_public_dns", "{line}");
        })
    }

    fn event_line(&self, boundary: &str, packet: Option<&Observation>) -> String {
        if packet.is_some() {
            self.completions.fetch_add(1, Ordering::Relaxed);
        }
        format!(
            "{} boundary={boundary} packet={} packets={} chunks={} completions={}",
            self.prefix("marker", boottime_ns()),
            packet.map_or(0, |value| value.0),
            self.packets.load(Ordering::Relaxed),
            self.chunks.load(Ordering::Relaxed),
            self.completions.load(Ordering::Relaxed)
        )
    }

    pub(super) fn event(&self, boundary: &str, packet: Option<&Observation>) {
        let line = self.event_line(boundary, packet);
        log::info!(target: "krtek_public_dns", "{line}");
    }
}

impl Drop for Observer {
    fn drop(&mut self) {
        self.event("observer-close", None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(family: u8, outbound: bool, size: usize) -> Vec<u8> {
        let mut bytes: Vec<u8> = (0..size).map(|index| (index % 251) as u8).collect();
        bytes[0] = family << 4;
        if family == 4 {
            let start = if outbound { 16 } else { 12 };
            bytes[start..start + 4].copy_from_slice(&[1, 1, 1, 1]);
        } else {
            let start = if outbound { 24 } else { 8 };
            bytes[start..start + 16].copy_from_slice(
                &Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111).octets(),
            );
        }
        bytes
    }

    #[test]
    fn public_dns_diagnostics_retains_every_byte_and_fragment_tail_in_both_directions() {
        let observer = Observer::new(1, 2, 3);
        for family in [4, 6] {
            for outbound in [false, true] {
                for size in [76, 1280, 4096, 65535] {
                    let original = packet(family, outbound, size);
                    let mut lines = Vec::new();
                    observer
                        .packet_to("fixture", outbound, &original, Some(123), |line| {
                            lines.push(line)
                        })
                        .unwrap();
                    assert_eq!(lines.len(), size.div_ceil(CHUNK_BYTES));
                    let joined: String = lines
                        .iter()
                        .map(|line| line.split(" hex=").nth(1).unwrap())
                        .collect();
                    let decoded: Vec<u8> = (0..joined.len())
                        .step_by(2)
                        .map(|index| u8::from_str_radix(&joined[index..index + 2], 16).unwrap())
                        .collect();
                    assert_eq!(decoded, original);
                    assert_eq!(
                        original,
                        packet(family, outbound, size),
                        "observer mutated bytes"
                    );
                    assert!(
                        lines
                            .iter()
                            .all(|line| line.len() < 1024 && line.contains("boot_ns=123"))
                    );
                }
            }
        }
    }

    #[test]
    fn public_dns_diagnostics_ignores_other_peers_short_headers_and_unknown_versions() {
        let observer = Observer::new(1, 2, 3);
        for bytes in [
            vec![],
            vec![0x45; 19],
            vec![0x60; 39],
            vec![0x70; 40],
            vec![0x45; 40],
            vec![0x60; 40],
        ] {
            for outbound in [false, true] {
                assert!(
                    observer
                        .packet_to("fixture", outbound, &bytes, None, |_| panic!(
                            "unselected packet logged"
                        ))
                        .is_none()
                );
            }
        }
    }

    #[test]
    fn public_dns_diagnostics_missing_clock_is_explicit_and_packet_ids_are_unique() {
        let observer = Observer::new(1, 2, 3);
        let bytes = packet(4, true, 76);
        let mut lines = Vec::new();
        let first = observer
            .packet_to("fixture", true, &bytes, None, |line| lines.push(line))
            .unwrap();
        let second = observer
            .packet_to("fixture", true, &bytes, None, |_| {})
            .unwrap();
        assert_ne!(first.0, second.0);
        assert!(lines[0].contains("boot_ns=unavailable"));
        assert_eq!(observer.packets.load(Ordering::Relaxed), 2);
        assert_eq!(observer.chunks.load(Ordering::Relaxed), 2);
        assert_eq!(observer.completions.load(Ordering::Relaxed), 0);
        observer.event("handoff-return", Some(&first));
        assert_eq!(observer.completions.load(Ordering::Relaxed), 1);
        let other = Observer::new(1, 2, 3);
        assert_ne!(observer.id, other.id);
    }

    #[test]
    #[cfg(any(target_os = "android", target_os = "linux"))]
    fn public_dns_diagnostics_boottime_is_monotone() {
        let first = boottime_ns().expect("BOOTTIME");
        let second = boottime_ns().expect("BOOTTIME");
        assert!(first > 0 && second >= first);
    }

    #[test]
    fn public_dns_diagnostics_emits_reconstructable_private_fixture() {
        // --nocapture exposes the very same line format as the production logger,
        // for an independent saved-output decoder; no network I/O or test logger.
        let observer = Observer::new(11, 12, 13);
        println!("{}", observer.event_line("observer-open", None));
        for (boundary, marker, outbound) in [
            ("handoff-input", "handoff-return", true),
            ("decrypted-return", "decrypted-return-queued", false),
            ("translated-return", "return-queued", false),
        ] {
            let bytes = packet(4, outbound, 4096);
            let observed = observer.packet_to(boundary, outbound, &bytes, boottime_ns(), |line| {
                println!("{line}")
            });
            assert!(observed.is_some());
            println!("{}", observer.event_line(marker, observed.as_ref()));
        }
        println!("{}", observer.event_line("observer-close", None));
    }
}
