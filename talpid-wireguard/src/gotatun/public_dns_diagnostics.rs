//! Private, feature-gated byte observations, not packet validation or routing.
//! Journal I/O changes diagnostic timing. Missing chunks/markers are missing evidence.
use std::{
    fmt::Write as _,
    fs::{File, OpenOptions},
    io::{self, Write as _},
    net::Ipv6Addr,
    ops::Deref,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicU64, Ordering},
    },
};

static NEXT_OBSERVER: AtomicU64 = AtomicU64::new(1);
static NEXT_PACKET: AtomicU64 = AtomicU64::new(1);
// Keep private journal records compact. This is not a packet limit.
const CHUNK_BYTES: usize = 128;
// Reserved at admission, so exhaustion can always retain a gap and close record.
const SEAL_BYTES: u64 = 2048;

static REGISTRY: Mutex<Registry> = Mutex::new(Registry {
    directory: None,
    owners: Vec::new(),
    latest: 0,
    setup_error: None,
    storage: None,
    journal_limit: 0,
    clock: boottime_ns,
});

struct Registry {
    directory: Option<PathBuf>,
    owners: Vec<Weak<Owner>>,
    latest: u64,
    setup_error: Option<String>,
    storage: Option<Arc<Mutex<Storage>>>,
    journal_limit: u64,
    clock: fn() -> Option<u64>,
}

struct Storage {
    used: u64,
    limit: u64,
}

impl Storage {
    fn reserve(&mut self, bytes: u64) -> bool {
        if bytes > self.limit.saturating_sub(self.used) {
            return false;
        }
        self.used += bytes;
        true
    }
}

/// Select an application-private, non-rotating directory and explicit byte budgets.
/// Existing owners are never rebound to a replacement process or directory.
/// Setup errors gate observations, never daemon startup.
pub fn configure(directory: &Path, journal_bytes: u64, retained_bytes: u64) {
    let mut registry = REGISTRY.lock().expect("diagnostic registry");
    registry.configure(directory, journal_bytes, retained_bytes);
}

/// Start (empty expected identity) or seal an exact live owner's observation.
/// A changed/retired owner is a gap, never an empty successor observation.
pub fn barrier(expected: &str) -> io::Result<String> {
    let registry = REGISTRY.lock().expect("diagnostic registry");
    registry.barrier(expected)
}

impl Registry {
    fn configure(&mut self, directory: &Path, journal_bytes: u64, retained_bytes: u64) {
        let mut setup = || -> io::Result<()> {
            if self
                .directory
                .as_deref()
                .is_some_and(|current| current != directory)
            {
                return Err(io::Error::other("Observation directory changed"));
            }
            std::fs::create_dir_all(directory)?;
            if journal_bytes < SEAL_BYTES || retained_bytes < journal_bytes {
                return Err(io::Error::other("Invalid observation storage budgets"));
            }
            if let Some(storage) = &self.storage {
                if self.journal_limit != journal_bytes
                    || storage.lock().expect("diagnostic storage").limit != retained_bytes
                {
                    return Err(io::Error::other("Observation storage budgets changed"));
                }
            } else {
                let mut used = 0u64;
                for entry in std::fs::read_dir(directory)? {
                    let entry = entry?;
                    if !entry.file_type()?.is_file() {
                        return Err(io::Error::other("Unexpected observation directory entry"));
                    }
                    used = used
                        .checked_add(entry.metadata()?.len())
                        .ok_or_else(|| io::Error::other("Observation storage size overflow"))?;
                }
                self.storage = Some(Arc::new(Mutex::new(Storage {
                    used,
                    limit: retained_bytes,
                })));
                self.journal_limit = journal_bytes;
            }
            File::open(directory)?.sync_all()?;
            if let Some(parent) = directory.parent() {
                File::open(parent)?.sync_all()?;
            }
            Ok(())
        };
        // Observation failure must not change daemon startup or routing.
        match setup() {
            Ok(()) => {
                self.directory = Some(directory.to_owned());
                self.setup_error = None;
            }
            Err(error) => self.setup_error = Some(format!("Observation setup failed: {error}")),
        }
    }

    fn barrier(&self, expected: &str) -> io::Result<String> {
        if let Some(error) = &self.setup_error {
            return Err(io::Error::other(error.clone()));
        }
        let owners: Vec<_> = self
            .owners
            .iter()
            .filter_map(Weak::upgrade)
            .filter(|owner| {
                let journal = owner.journal.lock().expect("diagnostic journal");
                !journal.sealed || journal.gap.is_some()
            })
            .collect();
        let [owner] = owners.as_slice() else {
            return Err(io::Error::other("Observation gap: expected one live owner"));
        };
        let identity = owner.identity();
        if self.latest != owner.id || (!expected.is_empty() && expected != identity) {
            return Err(io::Error::other(
                "Observation gap: owner changed during call",
            ));
        }
        if expected.is_empty() {
            let mut journal = owner.journal.lock().expect("diagnostic journal");
            journal.check()?;
            if journal.sealed || journal.retired || owner.epoch == 0 {
                return Err(io::Error::other(
                    "Observation gap: owner retired or clock unavailable",
                ));
            }
            journal.check()?;
            if let Err(error) = journal.file.as_ref().expect("checked journal").sync_all() {
                journal.error = Some(error.to_string());
            }
            journal.check()?;
        } else {
            owner.seal_result(true)?;
        }
        Ok(identity)
    }
}

pub(crate) struct Observer(Arc<Owner>);

pub(crate) struct Owner {
    id: u64,
    epoch: u64,
    session: u64,
    target: u64,
    request: u64,
    packets: AtomicU64,
    chunks: AtomicU64,
    completions: AtomicU64,
    journal: Mutex<Journal>,
    clock: fn() -> Option<u64>,
}

struct Journal {
    file: Option<File>,
    path: Option<PathBuf>,
    error: Option<String>,
    sealed: bool,
    persisted: bool,
    retired: bool,
    written: u64,
    limit: u64,
    storage: Option<Arc<Mutex<Storage>>>,
    seal_reserved: u64,
    gap: Option<String>,
    sends: usize,
}

impl Journal {
    fn check(&self) -> io::Result<()> {
        if let Some(gap) = &self.gap {
            return Err(io::Error::other(gap.clone()));
        }
        if let Some(error) = &self.error {
            return Err(io::Error::other(error.clone()));
        }
        if self.file.is_none() {
            return Err(io::Error::other("Observation journal unavailable"));
        }
        Ok(())
    }
    fn write(&mut self, line: &str) -> Option<&'static str> {
        let bytes = line.len() as u64 + 1;
        if self.file.is_some() {
            if bytes > self.limit.saturating_sub(self.written + self.seal_reserved) {
                return Some("journal-byte-budget");
            }
            if let Some(storage) = &self.storage
                && !storage.lock().expect("diagnostic storage").reserve(bytes)
            {
                return Some("aggregate-byte-budget");
            }
            self.append(line);
        }
        None
    }
    fn append(&mut self, line: &str) {
        if let Some(file) = &mut self.file
            && let Err(error) = writeln!(file, "{line}")
        {
            self.error = Some(error.to_string());
        }
        self.written += line.len() as u64 + 1;
    }
    fn terminal(&mut self, line: &str) {
        let bytes = line.len() as u64 + 1;
        if bytes > self.seal_reserved {
            self.error = Some("Observation terminal reserve exhausted".to_owned());
            return;
        }
        self.seal_reserved -= bytes;
        self.append(line);
    }
    fn sync(&mut self) -> io::Result<()> {
        // Persist the recorded prefix and explicit gap even though check fails.
        if let Some(error) = &self.error {
            return Err(io::Error::other(error.clone()));
        }
        if self.file.is_none() {
            return self.check();
        }
        let persist = || -> io::Result<()> {
            self.file.as_ref().expect("checked journal").sync_all()?;
            if !self.persisted {
                let path = self.path.as_ref().expect("configured journal");
                std::fs::rename(path, path.with_extension("sealed"))?;
                File::open(path.parent().expect("journal directory"))?.sync_all()?;
            }
            Ok(())
        };
        if let Err(error) = persist() {
            self.error = Some(error.to_string());
        } else {
            if let Some(storage) = &self.storage {
                storage.lock().expect("diagnostic storage").used -= self.seal_reserved;
            }
            self.seal_reserved = 0;
            self.persisted = true;
        }
        self.check()
    }
}

impl Deref for Observer {
    type Target = Owner;
    fn deref(&self) -> &Owner {
        &self.0
    }
}

pub(crate) struct Observation(u64);

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
    pub(crate) fn new(session: u64, target: u64, request: u64) -> Self {
        let mut registry = REGISTRY.lock().expect("diagnostic registry");
        Self::new_in(&mut registry, session, target, request)
    }

    fn new_in(registry: &mut Registry, session: u64, target: u64, request: u64) -> Self {
        let id = NEXT_OBSERVER.fetch_add(1, Ordering::Relaxed);
        let epoch = (registry.clock)().unwrap_or(0);
        let path = registry.directory.as_ref().map(|directory| {
            directory.join(format!("owner-{}-{id}-{epoch}.open", std::process::id()))
        });
        let journal = path.as_ref().map(|path| -> io::Result<File> {
            let storage = registry
                .storage
                .as_ref()
                .ok_or_else(|| io::Error::other("Observation storage not configured"))?;
            if !storage
                .lock()
                .expect("diagnostic storage")
                .reserve(SEAL_BYTES)
            {
                return Err(io::Error::other(
                    "Observation gap: aggregate-byte-budget at owner admission",
                ));
            }
            let file = match OpenOptions::new().write(true).create_new(true).open(path) {
                Ok(file) => file,
                Err(error) => {
                    storage.lock().expect("diagnostic storage").used -= SEAL_BYTES;
                    return Err(error);
                }
            };
            File::open(path.parent().expect("journal directory"))?.sync_all()?;
            Ok(file)
        });
        let (file, error) = match journal {
            Some(Ok(file)) => (Some(file), None),
            Some(Err(error)) => (None, Some(error.to_string())),
            None => (None, Some("Observation journal not configured".to_owned())),
        };
        let seal_reserved = if file.is_some() { SEAL_BYTES } else { 0 };
        let observer = Self(Arc::new(Owner {
            id,
            epoch,
            session,
            target,
            request,
            packets: AtomicU64::new(0),
            chunks: AtomicU64::new(0),
            completions: AtomicU64::new(0),
            journal: Mutex::new(Journal {
                file,
                path,
                error,
                sealed: false,
                persisted: false,
                retired: false,
                written: 0,
                limit: registry.journal_limit,
                storage: registry.storage.clone(),
                seal_reserved,
                gap: None,
                sends: 0,
            }),
            clock: registry.clock,
        }));
        registry.owners.retain(|owner| owner.strong_count() > 0);
        registry.owners.push(Arc::downgrade(&observer.0));
        registry.latest = id;
        observer.event("observer-open", None);
        observer
    }
}

impl Owner {
    fn write(&self, journal: &mut Journal, line: &str) {
        if let Some(reason) = journal.write(line) {
            let field = |key: &str| {
                line.split_whitespace()
                    .find_map(|word| word.strip_prefix(key))
                    .unwrap_or("none")
            };
            let gap = format!(
                "{} boundary=observation-gap packet=0 reason={reason} dropped_event={} dropped_boundary={} dropped_packet={} dropped_index={} dropped_record_bytes={} from_boot_ns={} subsequent=all-selected-owner-records",
                self.prefix("gap", (self.clock)()),
                field("event="),
                field("boundary="),
                field("packet="),
                field("index="),
                line.len() + 1,
                field("boot_ns=")
            );
            journal.gap = Some(format!("Observation gap: {reason}"));
            journal.terminal(&gap);
            journal.terminal(&self.event_line("observer-close", None));
            journal.sealed = true;
            if let Err(error) = journal.sync() {
                log::error!("Public DNS observation gap: {error}");
            }
        }
    }

    fn identity(&self) -> String {
        format!(
            "pid={} observer={} epoch={} session={} target={} request={}",
            std::process::id(),
            self.id,
            self.epoch,
            self.session,
            self.target,
            self.request
        )
    }

    fn prefix(&self, event: &str, stamp: Option<u64>) -> String {
        let stamp = stamp.map_or_else(|| "unavailable".to_owned(), |value| value.to_string());
        format!(
            "KRTEK_PUBLIC_DNS schema=2 event={event} boot_ns={stamp} {}",
            self.identity()
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
        let mut journal = self.journal.lock().expect("diagnostic journal");
        if journal.sealed {
            return None;
        }
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
            let line = format!(
                "{prefix} packet={id} boundary={boundary} outbound={outbound} family={family} bytes={} index={index} chunks={chunks} hex={hex}",
                bytes.len()
            );
            self.write(&mut journal, &line);
            if journal.sealed {
                return None;
            }
            emit(line);
        }
        Some(Observation(id))
    }

    pub(crate) fn packet(
        &self,
        boundary: &str,
        outbound: bool,
        bytes: &[u8],
    ) -> Option<Observation> {
        // Payloads belong only to private custody, never exported daemon logs.
        self.packet_to(boundary, outbound, bytes, (self.clock)(), |_| {})
    }

    fn event_line(&self, boundary: &str, packet: Option<&Observation>) -> String {
        if packet.is_some() {
            self.completions.fetch_add(1, Ordering::Relaxed);
        }
        format!(
            "{} boundary={boundary} packet={} packets={} chunks={} completions={}",
            self.prefix("marker", (self.clock)()),
            packet.map_or(0, |value| value.0),
            self.packets.load(Ordering::Relaxed),
            self.chunks.load(Ordering::Relaxed),
            self.completions.load(Ordering::Relaxed)
        )
    }

    pub(crate) fn event(&self, boundary: &str, packet: Option<&Observation>) {
        self.events(&[(boundary, packet)]);
    }

    pub(crate) fn events(&self, events: &[(&str, Option<&Observation>)]) {
        let mut journal = self.journal.lock().expect("diagnostic journal");
        for (boundary, packet) in events {
            if journal.sealed {
                return;
            }
            let line = self.event_line(boundary, *packet);
            self.write(&mut journal, &line);
            log::info!(target: "krtek_public_dns", "{line}");
        }
    }

    pub(crate) fn send_guard(&self, bytes: &[u8]) -> SendGuard<'_> {
        let mut journal = self.journal.lock().expect("diagnostic journal");
        let active = !journal.sealed && peer_family(bytes, false).is_some();
        if active {
            journal.sends += 1;
        }
        SendGuard {
            owner: self,
            active,
        }
    }

    fn seal_result(&self, require_live: bool) -> io::Result<()> {
        // Serializes final counters with every packet and completion. No Arc
        // retention, task scheduling or logger worker can write after this seal.
        let mut journal = self.journal.lock().expect("diagnostic journal");
        if journal.sends != 0 {
            return Err(io::Error::other("Observation gap: return send in flight"));
        }
        if journal.gap.is_some() {
            return journal.check();
        }
        if require_live && (journal.sealed || journal.retired) {
            return Err(io::Error::other(
                "Observation gap: owner retired before finish",
            ));
        }
        if !journal.sealed {
            let line = self.event_line("observer-close", None);
            journal.terminal(&line);
            journal.sealed = true;
            log::info!(target: "krtek_public_dns", "{line}");
        }
        journal.sync()
    }

    pub(crate) fn seal(&self) {
        if let Err(error) = self.seal_result(false) {
            log::error!("Public DNS observation gap: {error}");
        }
    }

    pub(crate) fn retire(&self) {
        // Same lock as the finish barrier: revocation cannot race a live seal.
        // Producers still drain until joined teardown writes final counters.
        self.journal.lock().expect("diagnostic journal").retired = true;
    }
}

pub(crate) struct SendGuard<'a> {
    owner: &'a Owner,
    active: bool,
}

impl Drop for SendGuard<'_> {
    fn drop(&mut self) {
        if self.active {
            self.owner.journal.lock().expect("diagnostic journal").sends -= 1;
        }
    }
}

impl Drop for Observer {
    fn drop(&mut self) {
        self.seal();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn durable_registry() -> (PathBuf, Registry) {
        let directory = std::env::temp_dir().join(format!(
            "public-dns-owner-{}-{}",
            std::process::id(),
            NEXT_PACKET.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).unwrap();
        let registry = Registry {
            directory: Some(directory.clone()),
            owners: Vec::new(),
            latest: 0,
            setup_error: None,
            storage: Some(Arc::new(Mutex::new(Storage {
                used: 0,
                limit: 64 * 1024 * 1024,
            }))),
            journal_limit: 16 * 1024 * 1024,
            clock: || Some(123),
        };
        (directory, registry)
    }

    fn read_journal(directory: &Path) -> String {
        let file = std::fs::read_dir(directory)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        std::fs::read_to_string(file).unwrap()
    }

    #[test]
    fn public_dns_diagnostics_journal_budget_seals_an_explicit_immutable_gap_before_start() {
        let (directory, mut registry) = durable_registry();
        registry.journal_limit = SEAL_BYTES + 1024;
        let observer = Observer::new_in(&mut registry, 1, 2, 3);
        assert!(
            observer
                .packet("handoff-input", true, &packet(4, true, 4096))
                .is_none()
        );
        let text = read_journal(&directory);
        assert!(text.contains("event=gap "));
        assert!(text.contains("reason=journal-byte-budget"));
        assert!(text.contains("dropped_event=chunk dropped_boundary=handoff-input"));
        assert!(text.contains("from_boot_ns=123 subsequent=all-selected-owner-records"));
        assert!(text.contains("boundary=observer-close"));
        let mut fixture = String::new();
        for byte in text.bytes() {
            write!(&mut fixture, "{byte:02x}").unwrap();
        }
        println!("KRTEK_GAP_FIXTURE_HEX={fixture}");
        assert!(text.len() as u64 <= registry.journal_limit);
        assert!(observer.journal.lock().unwrap().persisted);
        for expected in [String::new(), observer.identity()] {
            assert!(
                registry
                    .barrier(&expected)
                    .unwrap_err()
                    .to_string()
                    .contains("journal-byte-budget")
            );
        }
        observer.packet("handoff-input", true, &packet(4, true, 76));
        observer.event("handoff-return", None);
        drop(observer);
        assert_eq!(text, read_journal(&directory));
        assert!(
            std::fs::read_dir(&directory)
                .unwrap()
                .all(|p| p.unwrap().path().extension().unwrap() == "sealed")
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn public_dns_diagnostics_aggregate_budget_preserves_evidence_and_refuses_new_owners() {
        let (directory, mut registry) = durable_registry();
        registry.storage.as_ref().unwrap().lock().unwrap().limit = SEAL_BYTES + 1024;
        let observer = Observer::new_in(&mut registry, 1, 2, 3);
        observer.packet("handoff-input", true, &packet(4, true, 4096));
        let text = read_journal(&directory);
        assert!(text.contains("reason=aggregate-byte-budget"));
        assert!(observer.journal.lock().unwrap().persisted);
        assert!(registry.barrier(&observer.identity()).is_err());
        let successor = Observer::new_in(&mut registry, 1, 2, 4);
        assert!(successor.journal.lock().unwrap().file.is_none());
        drop(successor);
        drop(observer);
        assert_eq!(text, read_journal(&directory));
        assert_eq!(std::fs::read_dir(&directory).unwrap().count(), 1);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn public_dns_diagnostics_retained_bytes_are_charged_after_registry_restart() {
        let (directory, mut registry) = durable_registry();
        let observer = Observer::new_in(&mut registry, 1, 2, 3);
        observer.packet("handoff-input", true, &packet(4, true, 4096));
        observer.seal_result(false).unwrap();
        let text = read_journal(&directory);
        drop(observer);
        registry.directory = None;
        registry.storage = None;
        registry.configure(&directory, SEAL_BYTES, text.len() as u64 + SEAL_BYTES - 1);
        assert!(registry.setup_error.is_none());
        let successor = Observer::new_in(&mut registry, 1, 2, 3);
        assert!(
            registry
                .barrier("")
                .unwrap_err()
                .to_string()
                .contains("aggregate-byte-budget")
        );
        drop(successor);
        assert_eq!(text, read_journal(&directory));
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn public_dns_diagnostics_fixture_clock_controls_barrier_admission() {
        let (directory, mut registry) = durable_registry();
        registry.clock = || None;
        let observer = Observer::new_in(&mut registry, 1, 2, 3);
        assert_eq!(observer.epoch, 0);
        assert!(
            registry
                .barrier("")
                .unwrap_err()
                .to_string()
                .contains("clock unavailable")
        );
        drop(observer);
        registry.clock = || Some(456);
        let observer = Observer::new_in(&mut registry, 1, 2, 3);
        assert_eq!(observer.epoch, 456);
        let identity = registry.barrier("").unwrap();
        registry.barrier(&identity).unwrap();
        drop(observer);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn public_dns_diagnostics_finish_excludes_inflight_send_and_keeps_queue_markers_together() {
        let (directory, mut registry) = durable_registry();
        let observer = Observer::new_in(&mut registry, 1, 2, 3);
        let identity = registry.barrier("").unwrap();
        let send = observer.send_guard(&packet(4, false, 76));
        let decrypted = observer.packet("decrypted-return", false, &packet(4, false, 76));
        let translated = observer.packet("translated-return", false, &packet(4, false, 76));
        for live in [false, true] {
            assert!(
                observer
                    .seal_result(live)
                    .unwrap_err()
                    .to_string()
                    .contains("send in flight")
            );
        }
        assert!(!observer.journal.lock().unwrap().sealed);
        observer.events(&[
            ("return-queued", translated.as_ref()),
            ("decrypted-return-queued", decrypted.as_ref()),
        ]);
        drop(send);
        registry.barrier(&identity).unwrap();
        let text = read_journal(&directory);
        assert_eq!(text.matches("boundary=return-queued ").count(), 1);
        assert_eq!(text.matches("boundary=decrypted-return-queued ").count(), 1);
        assert!(text.contains("packets=2 chunks=2 completions=2"));
        drop(observer);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn public_dns_diagnostics_setup_failure_does_not_abort_and_barrier_reports_it() {
        let (directory, mut registry) = durable_registry();
        let blocker = directory.join("not-a-directory");
        std::fs::write(&blocker, b"block").unwrap();
        registry.directory = None;
        registry.configure(&blocker, 16 * 1024 * 1024, 64 * 1024 * 1024);
        let observer = Observer::new_in(&mut registry, 1, 2, 3);
        for expected in [String::new(), observer.identity()] {
            assert!(
                registry
                    .barrier(&expected)
                    .unwrap_err()
                    .to_string()
                    .contains("setup failed")
            );
        }
        drop(observer);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn public_dns_diagnostics_revoked_owner_cannot_finish_but_teardown_still_flushes() {
        let (directory, mut registry) = durable_registry();
        let observer = Observer::new_in(&mut registry, 1, 2, 3);
        let identity = registry.barrier("").unwrap();
        observer.retire();
        assert!(registry.barrier("").is_err());
        assert!(
            registry
                .barrier(&identity)
                .unwrap_err()
                .to_string()
                .contains("retired")
        );
        assert!(!read_journal(&directory).contains("observer-close"));
        let packet = observer.packet("handoff-input", true, &packet(4, true, 76));
        observer.event("handoff-return", packet.as_ref());
        observer.seal_result(false).unwrap();
        assert!(read_journal(&directory).contains("packets=1 chunks=1 completions=1"));
        drop(observer);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn public_dns_diagnostics_payloads_stay_private_even_when_info_logging_enabled() {
        struct PayloadLogger(AtomicU64);
        impl log::Log for PayloadLogger {
            fn enabled(&self, _: &log::Metadata<'_>) -> bool {
                true
            }
            fn log(&self, record: &log::Record<'_>) {
                if record.args().to_string().contains(" hex=") {
                    self.0.fetch_add(1, Ordering::Relaxed);
                }
            }
            fn flush(&self) {}
        }
        static LOGGER: PayloadLogger = PayloadLogger(AtomicU64::new(0));
        log::set_logger(&LOGGER).unwrap();
        log::set_max_level(log::LevelFilter::Info);
        assert!(log::log_enabled!(target: "krtek_public_dns", log::Level::Info));
        let (directory, mut registry) = durable_registry();
        let observer = Observer::new_in(&mut registry, 1, 2, 3);
        observer.packet("handoff-input", true, &packet(4, true, 4096));
        observer.seal_result(false).unwrap();
        assert!(read_journal(&directory).contains(" hex="));
        assert_eq!(LOGGER.0.load(Ordering::Relaxed), 0);
        drop(observer);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn public_dns_diagnostics_barrier_persists_final_counters_before_owner_drop() {
        let (directory, mut registry) = durable_registry();
        let observer = Observer::new_in(&mut registry, 1, 2, 3);
        let identity = registry.barrier("").unwrap();
        let observed = observer.packet("handoff-input", true, &packet(4, true, 4096));
        observer.event("handoff-return", observed.as_ref());
        assert_eq!(identity, registry.barrier(&identity).unwrap());
        let sealed = read_journal(&directory);
        assert!(
            std::fs::read_dir(&directory).unwrap().all(|entry| entry
                .unwrap()
                .path()
                .extension()
                .unwrap()
                == "sealed")
        );
        assert!(sealed.contains(&identity));
        assert_eq!(sealed.matches("boundary=observer-close ").count(), 1);
        assert!(sealed.contains("packets=1 chunks=32 completions=1"));
        assert!(
            observer
                .packet("handoff-input", true, &packet(4, true, 76))
                .is_none()
        );
        observer.event("handoff-return", observed.as_ref());
        observer.seal();
        drop(observer);
        assert_eq!(
            sealed,
            read_journal(&directory),
            "sealed owner must be immutable"
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn public_dns_diagnostics_barrier_rejects_replaced_retired_or_ambiguous_owners() {
        let (directory, mut registry) = durable_registry();
        let observer = Observer::new_in(&mut registry, 1, 2, 3);
        let identity = registry.barrier("").unwrap();
        let successor = Observer::new_in(&mut registry, 1, 2, 3);
        assert!(
            registry
                .barrier(&identity)
                .unwrap_err()
                .to_string()
                .contains("Observation gap")
        );
        drop(successor);
        assert!(
            registry
                .barrier(&identity)
                .unwrap_err()
                .to_string()
                .contains("owner changed"),
            "a transient replacement cannot revive the retained original owner"
        );
        let successor = Observer::new_in(&mut registry, 1, 2, 3);
        observer.seal();
        assert!(
            registry
                .barrier(&identity)
                .unwrap_err()
                .to_string()
                .contains("owner changed")
        );
        drop(successor);
        assert!(registry.barrier(&identity).is_err());
        drop(observer);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn public_dns_diagnostics_drop_seals_without_logger_or_async_runtime() {
        let (directory, mut registry) = durable_registry();
        {
            let observer = Observer::new_in(&mut registry, 4, 5, 6);
            observer.packet("decrypted-return", false, &packet(6, false, 76));
        }
        let sealed = read_journal(&directory);
        assert_eq!(sealed.matches("boundary=observer-close ").count(), 1);
        assert!(sealed.contains("packets=1 chunks=1 completions=0"));
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn public_dns_diagnostics_io_failure_is_an_observation_gap_not_a_seal() {
        let mut registry = Registry {
            directory: None,
            owners: Vec::new(),
            latest: 0,
            setup_error: None,
            storage: None,
            journal_limit: 0,
            clock: || Some(123),
        };
        let observer = Observer::new_in(&mut registry, 1, 2, 3);
        assert!(registry.barrier("").is_err());
        assert!(registry.barrier(&observer.identity()).is_err());
        assert!(observer.seal_result(false).is_err());
        let (directory, mut registry) = durable_registry();
        let observer = Observer::new_in(&mut registry, 1, 2, 3);
        let identity = registry.barrier("").unwrap();
        {
            let mut journal = observer.journal.lock().unwrap();
            // A real failing write, not a fabricated final-counter verdict.
            journal.file = Some(File::open(journal.path.as_ref().unwrap()).unwrap());
        }
        observer.packet("handoff-input", true, &packet(4, true, 76));
        assert!(registry.barrier(&identity).is_err());
        assert!(
            std::fs::read_dir(&directory).unwrap().all(|entry| entry
                .unwrap()
                .path()
                .extension()
                .unwrap()
                == "open")
        );
        drop(observer);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn public_dns_diagnostics_abrupt_exit_retains_an_unsealed_gap() {
        const CHILD_DIRECTORY: &str = "KRTEK_PUBLIC_DNS_CHILD_DIRECTORY";
        if let Some(directory) = std::env::var_os(CHILD_DIRECTORY) {
            let mut registry = Registry {
                directory: Some(directory.into()),
                owners: Vec::new(),
                latest: 0,
                setup_error: None,
                storage: Some(Arc::new(Mutex::new(Storage {
                    used: 0,
                    limit: 64 * 1024 * 1024,
                }))),
                journal_limit: 16 * 1024 * 1024,
                clock: || Some(123),
            };
            let observer = Observer::new_in(&mut registry, 1, 2, 3);
            observer.packet("handoff-input", true, &packet(4, true, 76));
            // Models Android terminating the instrumentation process without
            // Rust destructors. It cannot honestly produce final counters.
            std::process::exit(0);
        }
        let (directory, _) = durable_registry();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg(format!(
                "{}::public_dns_diagnostics_abrupt_exit_retains_an_unsealed_gap",
                module_path!().split_once("::").unwrap().1
            ))
            .env(CHILD_DIRECTORY, &directory)
            .status()
            .unwrap();
        assert!(status.success());
        let journal = read_journal(&directory);
        assert!(journal.contains("boundary=observer-open"));
        assert!(!journal.contains("boundary=observer-close"));
        assert!(
            std::fs::read_dir(&directory).unwrap().all(|entry| entry
                .unwrap()
                .path()
                .extension()
                .unwrap()
                == "open")
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

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
        // Expose read-back bytes from the actual sealed journal for an
        // independent decoder; no network I/O or asynchronous test logger.
        let (directory, mut registry) = durable_registry();
        let observer = Observer::new_in(&mut registry, 11, 12, 13);
        let identity = registry.barrier("").unwrap();
        for (boundary, marker, outbound) in [
            ("handoff-input", "handoff-return", true),
            ("decrypted-return", "decrypted-return-queued", false),
            ("translated-return", "return-queued", false),
        ] {
            let bytes = packet(4, outbound, 4096);
            let observed = observer.packet(boundary, outbound, &bytes);
            assert!(observed.is_some());
            observer.event(marker, observed.as_ref());
        }
        registry.barrier(&identity).unwrap();
        let sealed = read_journal(&directory);
        assert!(sealed.contains("packets=3 chunks=96 completions=3"));
        print!("{sealed}");
        drop(observer);
        assert_eq!(sealed, read_journal(&directory));
        std::fs::remove_dir_all(directory).unwrap();
    }
}
