//! Scripted reporter bridge only; no process, live Root or completion witness.
//! Deadline comparisons here do not bound arbitrary blocking I/O. A real
//! admitted nonblocking exchange and source/lifetime proofs remain separate.

use super::process::Tools;
use super::reporter_frame::{DataSession, parse_frame};
use super::requests::{
    Capability, ClientStatus, Clock, CollectionProof, NativeCollectionIntent, Negotiated,
    PublishedNativeCollection, RequestJournal,
};
use serde::Deserialize;
use serde_json::json;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

const ERROR: &str = "Reporter OBS publication unavailable";
const SAFE: u64 = 9_007_199_254_740_991;
type Result<T> = std::result::Result<T, String>;

fn require(condition: bool) -> Result<()> {
    if condition { Ok(()) } else { Err(ERROR.into()) }
}

// Deliberately module-private: only the deterministic scripted implementation
// below exists. A future real bounded transport requires independent review.
// None of these methods may call ANY Journal API, spawn, or wait for Root.
trait Exchange {
    fn sample(&mut self) -> Result<Clock>;
    fn read(&mut self) -> Result<Vec<u8>>;
    fn write(&mut self, raw: &[u8]) -> Result<()>;
    fn close(&mut self) -> Result<()>;
    fn host_metadata(&mut self, kind: HostMetadata) -> Result<String>;
    fn root_status(&mut self, receipt: bool) -> Result<serde_json::Value>;
}
#[derive(Clone, Copy)]
enum HostMetadata {
    Hostname,
    MachineArchitecture,
}

struct ExpectedPin {
    cache_generation: String,
    policy_generation: String,
    successful_checked_at: String,
    boot_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Pin {
    cache_generation: String,
    policy_generation: String,
    successful_checked_at: String,
    boot_id: String,
    pinned_boottime_ms: u64,
}

pub(super) fn checked_at(value: &str) -> bool {
    let bytes = value.as_bytes();
    if !(bytes.len() == 20 || (22..=27).contains(&bytes.len())) || bytes.last() != Some(&b'Z') {
        return false;
    }
    if !bytes.iter().enumerate().all(|(index, byte)| match index {
        4 | 7 => *byte == b'-',
        10 => *byte == b'T',
        13 | 16 => *byte == b':',
        i if i == bytes.len() - 1 => *byte == b'Z',
        19 if bytes.len() > 20 => *byte == b'.',
        _ => byte.is_ascii_digit(),
    }) {
        return false;
    }
    let number = |from, to| value[from..to].parse::<u32>().ok();
    let (Some(year), Some(month), Some(day), Some(hour), Some(minute), Some(second)) = (
        number(0, 4),
        number(5, 7),
        number(8, 10),
        number(11, 13),
        number(14, 16),
        number(17, 19),
    ) else {
        return false;
    };
    if year == 0 || !(1..=12).contains(&month) || hour > 23 || minute > 59 || second > 59 {
        return false;
    }
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let days = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    day > 0 && day <= days[(month - 1) as usize]
}
fn hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(PartialEq)]
enum Phase {
    Admitting,
    Pinned,
    Publishing,
    Published,
    AwaitingOffer,
    Acknowledging,
    Scanning,
    Querying,
    Closed,
}
struct PinnedSession<E: Exchange> {
    exchange: Option<E>,
    context: Pin,
    deadline: u64,
    last: u64,
    phase: Phase,
}
struct PublishedSession<E: Exchange> {
    session: PinnedSession<E>,
    published: PublishedNativeCollection,
}

// Structural scripted metadata, never proof of a live Root lock/source origin.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RootOffer {
    nonce: String,
    boot_id: String,
    cache_generation: String,
    policy_generation: String,
    lock_open_boottime_ms: u64,
    expires_boottime_ms: u64,
}
struct ScanningSession<E: Exchange> {
    session: PinnedSession<E>,
    proof: CollectionProof,
    offer: RootOffer,
    data: DataSession,
    next_id: u64,
    request_id: String,
}
struct NormalizedSession<E: Exchange> {
    scanning: ScanningSession<E>,
    scan: serde_json::Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FrozenScan {
    scan_started_boottime_ms: u64,
    scan_finished_boottime_ms: u64,
    installed_before_sha256: String,
    installed_after_sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RootReceipt {
    nonce: String,
    boot_id: String,
    cache_generation: String,
    policy_generation: String,
    lock_open_boottime_ms: u64,
    expires_boottime_ms: u64,
    lock_held_until_boottime_ms: u64,
    released_boottime_ms: u64,
    outcome: String,
    installed_before_sha256: String,
    installed_after_sha256: String,
}
struct PreparedSession<E: Exchange> {
    scanning: ScanningSession<E>,
    frozen: FrozenScan,
    scan: serde_json::Value,
}

fn phase_frame(
    raw: &[u8],
    id: u64,
    operation: &str,
    phase: &str,
    count: usize,
) -> Result<serde_json::Value> {
    let value = parse_frame(raw).map_err(|_| ERROR.to_owned())?;
    require(
        value
            .as_object()
            .is_some_and(|object| object.len() == count)
            && value["schema_version"].as_u64() == Some(1)
            && value["id"].as_u64() == Some(id)
            && value["operation"] == operation
            && value["phase"] == phase,
    )?;
    Ok(value)
}
fn send_command<E: Exchange>(
    session: &mut PinnedSession<E>,
    value: serde_json::Value,
) -> Result<()> {
    session.check()?;
    let mut raw = serde_json::to_vec(&value).map_err(|_| ERROR.to_owned())?;
    raw.push(b'\n');
    session.port()?.write(&raw).map_err(|_| ERROR.to_owned())?;
    session.check()?;
    Ok(())
}
fn read_phase<E: Exchange>(
    session: &mut PinnedSession<E>,
    id: u64,
    operation: &str,
    phase: &str,
    count: usize,
) -> Result<serde_json::Value> {
    session.check()?;
    let raw = session.port()?.read().map_err(|_| ERROR.to_owned())?;
    session.check()?;
    let result = phase_frame(&raw, id, operation, phase, count)?;
    session.check()?;
    Ok(result)
}
impl<E: Exchange> NormalizedSession<E> {
    fn prepare(self, journal: &mut RequestJournal<'_>) -> Result<PreparedSession<E>> {
        let Self { mut scanning, scan } = self;
        let id = scanning.next_id;
        require(id <= SAFE - 2 && scanning.session.phase == Phase::Scanning)?;
        send_command(
            &mut scanning.session,
            json!({"schema_version":1,"id":id,"operation":"freeze_scan"}),
        )?;
        let frame = read_phase(&mut scanning.session, id, "freeze_scan", "scan_frozen", 5)?;
        let frozen: FrozenScan =
            serde_json::from_value(frame["scan"].clone()).map_err(|_| ERROR.to_owned())?;
        let start = scanning
            .proof
            .scan
            .as_ref()
            .ok_or(ERROR)?
            .started_boottime_ms;
        let now = scanning.session.check()?;
        require(
            frozen.scan_started_boottime_ms == start
                && frozen.scan_finished_boottime_ms >= start
                && frozen.scan_finished_boottime_ms <= now.boottime_ms
                && frozen.scan_finished_boottime_ms < scanning.session.deadline
                && hex(&frozen.installed_before_sha256, 64)
                && frozen.installed_before_sha256 == frozen.installed_after_sha256,
        )?;
        let release = journal
            .prepare_native_release(&scanning.request_id, &now)
            .map_err(|_| ERROR.to_owned())?;
        require(release.observation_nonce() == scanning.offer.nonce)?;
        let current = scanning.session.check()?;
        journal.publish_native_release(release,&current,|nonce| {
            send_command(&mut scanning.session,json!({"schema_version":1,"id":id+1,"operation":"publish_release","nonce":nonce}))?;
            read_phase(&mut scanning.session,id+1,"publish_release","published",4)?;
            Ok(())
        }).map_err(|_| ERROR.to_owned())?;
        scanning.session.check()?;
        send_command(
            &mut scanning.session,
            json!({"schema_version":1,"id":id+2,"operation":"await_receipt"}),
        )?;
        let prepared = read_phase(
            &mut scanning.session,
            id + 2,
            "await_receipt",
            "prepared",
            5,
        )?;
        let evidence = prepared["evidence"].as_object().ok_or(ERROR)?;
        require(
            evidence.len() == 5
                && evidence
                    .get("schema_version")
                    .and_then(serde_json::Value::as_u64)
                    == Some(1)
                && evidence
                    .get("scan_started_boottime_ms")
                    .and_then(serde_json::Value::as_u64)
                    == Some(start)
                && evidence
                    .get("scan_finished_boottime_ms")
                    .and_then(serde_json::Value::as_u64)
                    == Some(frozen.scan_finished_boottime_ms)
                && evidence
                    .get("successful_checked_at")
                    .and_then(serde_json::Value::as_str)
                    == Some(scanning.session.context.successful_checked_at.as_str()),
        )?;
        let receipt_value = evidence.get("observation_receipt").ok_or(ERROR)?;
        let receipt: RootReceipt =
            serde_json::from_value(receipt_value.clone()).map_err(|_| ERROR.to_owned())?;
        scanning.session.check()?;
        let root = scanning
            .session
            .port()?
            .root_status(true)
            .map_err(|_| ERROR.to_owned())?;
        let now = scanning.session.check()?;
        super::reporter_status::validate_status(&root).map_err(|_| ERROR.to_owned())?;
        let offer = &scanning.offer;
        require(
            &root["observation_receipt"] == receipt_value
                && root["cache_generation"] == scanning.session.context.cache_generation
                && root["policy_generation"] == scanning.session.context.policy_generation
                && root["successful_checked_at"] == scanning.session.context.successful_checked_at
                && receipt.nonce == offer.nonce
                && receipt.boot_id == offer.boot_id
                && receipt.cache_generation == offer.cache_generation
                && receipt.policy_generation == offer.policy_generation
                && receipt.lock_open_boottime_ms == offer.lock_open_boottime_ms
                && receipt.expires_boottime_ms == offer.expires_boottime_ms
                && receipt.outcome == "released"
                && receipt.installed_before_sha256 == frozen.installed_before_sha256
                && receipt.installed_after_sha256 == frozen.installed_after_sha256
                && offer.lock_open_boottime_ms <= start
                && frozen.scan_finished_boottime_ms <= receipt.lock_held_until_boottime_ms
                && receipt.lock_held_until_boottime_ms <= receipt.released_boottime_ms
                && receipt.released_boottime_ms <= offer.expires_boottime_ms
                && receipt.released_boottime_ms <= now.boottime_ms,
        )?;
        scanning.session.check()?;
        Ok(PreparedSession {
            scanning,
            frozen,
            scan,
        })
    }
}

// Sync is required by the existing normalizer. Contention/reentry must fail
// immediately and poison BOTH callers, never wait beyond the native deadline.
struct FixedTools<E: Exchange + Send> {
    scanning: Mutex<ScanningSession<E>>,
    failed: Arc<AtomicBool>,
}
impl<E: Exchange + Send> FixedTools<E> {
    fn new(scanning: ScanningSession<E>) -> Self {
        Self {
            scanning: Mutex::new(scanning),
            failed: Arc::new(AtomicBool::new(false)),
        }
    }
    fn into_scanning(self) -> Result<ScanningSession<E>> {
        let mut scanning = self.scanning.into_inner().map_err(|_| ERROR.to_owned())?;
        require(!self.failed.load(Ordering::SeqCst) && scanning.session.phase == Phase::Scanning)?;
        guarded(&mut scanning.session, &self.failed)?;
        Ok(scanning)
    }
}
impl<E: Exchange + Send> Tools for FixedTools<E> {
    fn text(&self, program: &str, args: &[&str], limit: usize) -> Result<String> {
        if self.failed.load(Ordering::SeqCst) {
            return Err(ERROR.into());
        }
        let mut scanning = match self.scanning.try_lock() {
            Ok(value) => value,
            Err(_) => {
                self.failed.store(true, Ordering::SeqCst);
                return Err(ERROR.into());
            }
        };
        let result = scanning.fixed_text(program, args, limit, &self.failed);
        if result.is_err() {
            self.failed.store(true, Ordering::SeqCst);
        }
        require(!self.failed.load(Ordering::SeqCst))?;
        result
    }
    fn sha256(&self, _bytes: &[u8]) -> Result<String> {
        self.failed.store(true, Ordering::SeqCst);
        Err(ERROR.into())
    }
}
fn guarded<E: Exchange>(session: &mut PinnedSession<E>, failed: &AtomicBool) -> Result<Clock> {
    require(!failed.load(Ordering::SeqCst))?;
    let clock = session.check()?;
    require(!failed.load(Ordering::SeqCst))?;
    Ok(clock)
}

impl<E: Exchange> ScanningSession<E> {
    fn fixed_text(
        &mut self,
        program: &str,
        args: &[&str],
        limit: usize,
        failed: &AtomicBool,
    ) -> Result<String> {
        require(self.session.phase == Phase::Scanning)?;
        self.session.phase = Phase::Querying;
        guarded(&mut self.session, failed)?;
        let host = match (program, args, limit) {
            ("/bin/hostname", [], 4096) => Some(HostMetadata::Hostname),
            ("/usr/bin/uname", ["-m"], 4096) => Some(HostMetadata::MachineArchitecture),
            _ => None,
        };
        if let Some(kind) = host {
            guarded(&mut self.session, failed)?;
            let text = self
                .session
                .port()?
                .host_metadata(kind)
                .map_err(|_| ERROR.to_owned())?;
            guarded(&mut self.session, failed)?;
            require(text.len() <= 4096)?;
            self.session.phase = Phase::Scanning;
            return Ok(text);
        }
        const FORMAT: &str = "--showformat=${db:Status-Status}\\t${binary:Package}\\t${Version}\\t${Architecture}\\n";
        const HOLDS: [&str; 5] = [
            "-o",
            "Dir::Cache::pkgcache=",
            "-o",
            "Dir::Cache::srcpkgcache=",
            "showhold",
        ];
        const POLICY: [&str; 5] = [
            "-o",
            "Dir::Cache::pkgcache=",
            "-o",
            "Dir::Cache::srcpkgcache=",
            "policy",
        ];
        let operation = if program == "/usr/bin/dpkg-query"
            && args == ["--show", FORMAT]
            && limit == 8 * 1024 * 1024
        {
            "installed"
        } else if program == "/usr/bin/dpkg" && args == ["--print-architecture"] && limit == 128 {
            "architecture"
        } else if program == "/usr/bin/apt-mark" && args == HOLDS && limit == 1024 * 1024 {
            "holds"
        } else if program == "/usr/bin/apt-cache"
            && args.len() >= 6
            && args.len() <= 305
            && args[..5] == POLICY
            && limit == 16 * 1024 * 1024
        {
            let packages = &args[5..];
            require(
                packages.iter().all(|value| super::linux::package_id(value))
                    && packages
                        .iter()
                        .copied()
                        .collect::<std::collections::BTreeSet<_>>()
                        .len()
                        == packages.len(),
            )?;
            "policy"
        } else {
            return Err(ERROR.into());
        };
        let id = self.next_id;
        self.next_id = id.checked_add(1).ok_or(ERROR)?;
        let mut command = json!({"schema_version":1,"id":id,"operation":operation});
        if operation == "policy" {
            command["packages"] = json!(&args[5..]);
        }
        let mut raw = serde_json::to_vec(&command).map_err(|_| ERROR.to_owned())?;
        raw.push(b'\n');
        require(raw.len() <= 256 * 1024)?;
        let Self { session, data, .. } = self;
        let mut assembly = data.start(id, operation).map_err(|_| ERROR.to_owned())?;
        guarded(session, failed)?;
        session.port()?.write(&raw).map_err(|_| ERROR.to_owned())?;
        guarded(session, failed)?;
        loop {
            guarded(session, failed)?;
            let raw = session.port()?.read().map_err(|_| ERROR.to_owned())?;
            guarded(session, failed)?;
            assembly.feed(&raw).map_err(|_| ERROR.to_owned())?;
            guarded(session, failed)?;
            if assembly.complete() {
                break;
            }
        }
        let text = assembly.take().map_err(|_| ERROR.to_owned())?;
        guarded(session, failed)?;
        session.phase = Phase::Scanning;
        Ok(text)
    }
}
impl<E: Exchange + Send> ScanningSession<E> {
    fn collect_selected(self, now: &str) -> Result<NormalizedSession<E>> {
        require(checked_at(now))?;
        let report = self.proof.scan.as_ref().ok_or(ERROR)?.report_id.clone();
        let tools = FixedTools::new(self);
        let result = super::linux::collect_selected_generation(&tools, &report, now);
        // linux.rs intentionally converts several Tools failures to partial
        // coverage. A failed managed exchange must never escape that way.
        let mut scanning = tools.into_scanning()?;
        let scan = result.map_err(|_| ERROR.to_owned())?;
        require(
            scan["inventoryComplete"] == true
                && matches!(scan["status"].as_str(), Some("complete" | "partial")),
        )?;
        scanning.session.check()?;
        Ok(NormalizedSession { scanning, scan })
    }
}

impl<E: Exchange> PublishedSession<E> {
    fn admit_scan(
        self,
        journal: &mut RequestJournal<'_>,
        negotiated: &Negotiated,
    ) -> Result<ScanningSession<E>> {
        let Self {
            mut session,
            published,
        } = self;
        require(session.phase == Phase::Published)?;
        session.phase = Phase::AwaitingOffer;
        session.check()?;
        let mut command =
            serde_json::to_vec(&json!({"schema_version":1,"id":2,"operation":"await_open"}))
                .map_err(|_| ERROR.to_owned())?;
        command.push(b'\n');
        // Metadata-only wait outside JOURNAL_ACCESS. Current authority is checked
        // by attach before ANY scan_admitted command can release native reads.
        session
            .port()?
            .write(&command)
            .map_err(|_| ERROR.to_owned())?;
        session.check()?;
        let raw = session.port()?.read().map_err(|_| ERROR.to_owned())?;
        session.check()?;
        let frame = parse_frame(&raw).map_err(|_| ERROR.to_owned())?;
        let object = frame.as_object().ok_or(ERROR)?;
        require(
            object.len() == 6
                && frame["schema_version"].as_u64() == Some(1)
                && frame["id"].as_u64() == Some(2)
                && frame["operation"] == "await_open"
                && frame["phase"] == "scan_proposed",
        )?;
        let offer: RootOffer =
            serde_json::from_value(frame["offer"].clone()).map_err(|_| ERROR.to_owned())?;
        let proposed = frame["scan_started_boottime_ms"]
            .as_u64()
            .filter(|time| *time <= SAFE)
            .ok_or(ERROR)?;
        session.check()?;
        let status = session
            .port()?
            .root_status(false)
            .map_err(|_| ERROR.to_owned())?;
        session.check()?;
        super::reporter_status::validate_status(&status).map_err(|_| ERROR.to_owned())?;
        require(
            status["observation_lease"] == frame["offer"]
                && status["cache_generation"] == session.context.cache_generation
                && status["policy_generation"] == session.context.policy_generation
                && status["successful_checked_at"] == session.context.successful_checked_at,
        )?;
        require(
            offer.nonce == published.observation_nonce()
                && offer.boot_id == session.context.boot_id
                && offer.cache_generation == session.context.cache_generation
                && offer.policy_generation == session.context.policy_generation
                && offer.lock_open_boottime_ms <= SAFE
                && offer.expires_boottime_ms <= SAFE
                && offer
                    .expires_boottime_ms
                    .checked_sub(offer.lock_open_boottime_ms)
                    .is_some_and(|span| span <= 120000)
                && session.context.pinned_boottime_ms <= offer.lock_open_boottime_ms
                && offer.lock_open_boottime_ms <= proposed,
        )?;
        let actual = session.check()?;
        session.deadline = session.deadline.min(offer.expires_boottime_ms);
        require(proposed <= actual.boottime_ms && actual.boottime_ms < session.deadline)?;
        // Preserve the fresh owner last-clock. Only the separate proof Clock is
        // historical, recording the exact child proposal before its first read.
        let attachment_clock = Clock {
            boottime_ms: proposed,
            ..actual
        };
        let proof = journal
            .attach_native_scan(published, &attachment_clock, negotiated)
            .map_err(|_| ERROR.to_owned())?;
        session.check()?; // Fsync may consume the last budget; no ACK on expiry.
        session.phase = Phase::Acknowledging;
        let mut command=serde_json::to_vec(&json!({"schema_version":1,"id":3,"operation":"scan_admitted","scan_started_boottime_ms":proposed})).map_err(|_|ERROR.to_owned())?;
        command.push(b'\n');
        session.check()?;
        session
            .port()?
            .write(&command)
            .map_err(|_| ERROR.to_owned())?;
        session.check()?;
        let raw = session.port()?.read().map_err(|_| ERROR.to_owned())?;
        session.check()?;
        let frame = parse_frame(&raw).map_err(|_| ERROR.to_owned())?;
        let object = frame.as_object().ok_or(ERROR)?;
        require(
            object.len() == 5
                && frame["schema_version"].as_u64() == Some(1)
                && frame["id"].as_u64() == Some(3)
                && frame["operation"] == "scan_admitted"
                && frame["phase"] == "scanning"
                && frame["scan_started_boottime_ms"].as_u64() == Some(proposed),
        )?;
        let pending = journal
            .pending(Capability::Collection)
            .map_err(|_| ERROR.to_owned())?
            .ok_or(ERROR)?;
        require(
            pending.status == ClientStatus::Running
                && pending.operation_nonce.as_deref() == Some(proof.operation_nonce.as_str())
                && pending.report_id.is_none()
                && pending.report_sha256.is_none()
                && pending.attempt
                    == Some(serde_json::to_value(&proof).map_err(|_| ERROR.to_owned())?),
        )?;
        session.check()?; // Includes time spent in the protected pending read.
        session.phase = Phase::Scanning;
        Ok(ScanningSession {
            session,
            proof,
            offer,
            data: DataSession::new(),
            next_id: 4,
            request_id: pending.request_id,
        })
    }
}

impl<E: Exchange> PinnedSession<E> {
    fn admit(exchange: E, expected: ExpectedPin) -> Result<Self> {
        let mut value = Self {
            exchange: Some(exchange),
            context: Pin {
                cache_generation: String::new(),
                policy_generation: String::new(),
                successful_checked_at: String::new(),
                boot_id: expected.boot_id.clone(),
                pinned_boottime_ms: 0,
            },
            deadline: 0,
            last: 0,
            phase: Phase::Admitting,
        };
        require(
            hex(&expected.cache_generation, 32)
                && hex(&expected.policy_generation, 64)
                && checked_at(&expected.successful_checked_at),
        )?;
        let first = value.port()?.sample().map_err(|_| ERROR.to_owned())?;
        first.validate().map_err(|_| ERROR.to_owned())?;
        require(first.boot_id == expected.boot_id)?;
        value.deadline = first
            .boottime_ms
            .checked_add(120000)
            .filter(|limit| *limit <= SAFE)
            .ok_or(ERROR)?;
        value.last = first.boottime_ms;
        let raw = value.port()?.read().map_err(|_| ERROR.to_owned())?;
        value.check()?;
        let frame = parse_frame(&raw).map_err(|_| ERROR.to_owned())?;
        let object = frame.as_object().ok_or(ERROR)?;
        require(
            object.len() == 5
                && frame["schema_version"].as_u64() == Some(1)
                && frame["id"].as_u64() == Some(0)
                && frame["operation"] == "initialize"
                && frame["phase"] == "pinned",
        )?;
        let context: Pin =
            serde_json::from_value(frame["context"].clone()).map_err(|_| ERROR.to_owned())?;
        require(
            context.cache_generation == expected.cache_generation
                && context.policy_generation == expected.policy_generation
                && context.successful_checked_at == expected.successful_checked_at
                && context.boot_id == expected.boot_id
                && context.pinned_boottime_ms <= value.last
                && context.pinned_boottime_ms <= SAFE,
        )?;
        value.context = context;
        value.check()?;
        value.phase = Phase::Pinned;
        Ok(value)
    }
    fn port(&mut self) -> Result<&mut E> {
        self.exchange.as_mut().ok_or(ERROR.into())
    }
    fn check(&mut self) -> Result<Clock> {
        require(self.phase != Phase::Closed)?;
        let clock = self.port()?.sample().map_err(|_| ERROR.to_owned())?;
        clock.validate().map_err(|_| ERROR.to_owned())?;
        require(
            clock.boot_id == self.context.boot_id
                && clock.boottime_ms >= self.last
                && clock.boottime_ms < self.deadline,
        )?;
        self.last = clock.boottime_ms;
        Ok(clock)
    }
    fn publish(
        mut self,
        journal: &mut RequestJournal<'_>,
        intent: NativeCollectionIntent,
        session: &Negotiated,
    ) -> Result<PublishedSession<E>> {
        require(self.phase == Phase::Pinned)?;
        self.phase = Phase::Publishing;
        let clock = self.check()?;
        let published=journal.publish_native_observation(intent,&clock,session,|nonce| {
            // Borrow the session; no Drop/teardown or Journal reentry under the
            // global publication mutex. No Root offer/scan/receipt operation.
            self.check()?;
            let raw=serde_json::to_vec(&json!({"schema_version":1,"id":1,"operation":"publish_observation","nonce":nonce})).map_err(|_|ERROR.to_owned())?;
            let mut command=raw;command.push(b'\n');self.port()?.write(&command).map_err(|_|ERROR.to_owned())?;
            self.check()?;
            let raw=self.port()?.read().map_err(|_|ERROR.to_owned())?;self.check()?;
            let frame=parse_frame(&raw).map_err(|_|ERROR.to_owned())?;let object=frame.as_object().ok_or(ERROR)?;
            require(object.len()==4 && frame["schema_version"].as_u64()==Some(1) && frame["id"].as_u64()==Some(1) &&
                frame["operation"]=="publish_observation" && frame["phase"]=="published")?;
            self.check()?;Ok(())
        }).map_err(|_|ERROR.to_owned())?;
        // The journal's post-callback protected snapshot can itself consume the
        // remaining budget. Late success drops the opaque token, never remints.
        self.check()?;
        self.phase = Phase::Published;
        Ok(PublishedSession {
            session: self,
            published,
        })
    }
}
impl<E: Exchange> Drop for PinnedSession<E> {
    fn drop(&mut self) {
        self.phase = Phase::Closed;
        if let Some(mut exchange) = self.exchange.take() {
            let _ = exchange.close();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::requests::{
        Canonical, CanonicalRequest, CanonicalStatus, Capability, CollectionDelivery, CounterSeeds,
        Delivery,
    };
    use serde_json::{Value, json};
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    const BOOT: &str = "00000000-0000-4000-8000-000000000001";
    const REPORT: &str = "00000000-0000-4000-8000-000000000002";
    const REQUEST: &str = "00000000-0000-4000-8000-000000000003";
    struct InputEvent {
        program: String,
        args: Vec<String>,
        limit: usize,
        output: String,
    }
    #[cfg(target_os = "linux")]
    const INPUT_MAX: usize = 32 * 1024 * 1024;
    #[cfg(target_os = "linux")]
    struct InputCapture<'a, T> {
        inner: &'a T,
        events: Mutex<(usize, Vec<InputEvent>)>,
        failed: AtomicBool,
    }
    #[cfg(target_os = "linux")]
    impl<'a, T> InputCapture<'a, T> {
        fn new(inner: &'a T) -> Self {
            Self {
                inner,
                events: Mutex::new((0, Vec::new())),
                failed: AtomicBool::new(false),
            }
        }
        fn finish(self) -> Result<Vec<InputEvent>> {
            require(!self.failed.load(Ordering::SeqCst))?;
            Ok(self.events.into_inner().map_err(|_| ERROR.to_owned())?.1)
        }
    }
    #[cfg(target_os = "linux")]
    impl<T: Tools> Tools for InputCapture<'_, T> {
        fn text(&self, program: &str, args: &[&str], limit: usize) -> Result<String> {
            let result = (|| {
                let output = self.inner.text(program, args, limit)?;
                let mut events = self.events.lock().map_err(|_| ERROR.to_owned())?;
                let size = args
                    .iter()
                    .try_fold(program.len(), |n, arg| n.checked_add(arg.len()))
                    .and_then(|n| n.checked_add(output.len()))
                    .ok_or(ERROR)?;
                let total = events.0.checked_add(size).ok_or(ERROR)?;
                require(
                    events.1.len() < 512
                        && args.len() <= 305
                        && output.len() <= limit
                        && total <= INPUT_MAX,
                )?;
                events.1.push(InputEvent {
                    program: program.into(),
                    args: args.iter().map(|s| (*s).into()).collect(),
                    limit,
                    output: output.clone(),
                });
                events.0 = total;
                Ok(output)
            })();
            if result.is_err() {
                self.failed.store(true, Ordering::SeqCst);
            }
            result
        }
        fn sha256(&self, _: &[u8]) -> Result<String> {
            self.failed.store(true, Ordering::SeqCst);
            Err(ERROR.into())
        }
    }
    struct InputReplay {
        remaining: Mutex<VecDeque<InputEvent>>,
        failed: AtomicBool,
    }
    impl InputReplay {
        fn new(events: Vec<InputEvent>) -> Self {
            Self {
                remaining: Mutex::new(events.into()),
                failed: AtomicBool::new(false),
            }
        }
        fn finish(&self) -> Result<()> {
            require(
                !self.failed.load(Ordering::SeqCst)
                    && self
                        .remaining
                        .lock()
                        .map_err(|_| ERROR.to_owned())?
                        .is_empty(),
            )
        }
    }
    impl Tools for InputReplay {
        fn text(&self, program: &str, args: &[&str], limit: usize) -> Result<String> {
            let result = (|| {
                let event = self
                    .remaining
                    .lock()
                    .map_err(|_| ERROR.to_owned())?
                    .pop_front()
                    .ok_or(ERROR)?;
                require(
                    event.program == program
                        && event
                            .args
                            .iter()
                            .map(String::as_str)
                            .eq(args.iter().copied())
                        && event.limit == limit,
                )?;
                Ok(event.output)
            })();
            if result.is_err() {
                self.failed.store(true, Ordering::SeqCst);
            }
            result
        }
        fn sha256(&self, _: &[u8]) -> Result<String> {
            self.failed.store(true, Ordering::SeqCst);
            Err(ERROR.into())
        }
    }
    #[cfg(target_os = "linux")]
    fn collect_observed<E: Exchange + Send>(
        scanning: ScanningSession<E>,
        now: &str,
    ) -> Result<(NormalizedSession<E>, Value)> {
        require(checked_at(now))?;
        let report = scanning.proof.scan.as_ref().ok_or(ERROR)?.report_id.clone();
        let tools = FixedTools::new(scanning);
        let capture = InputCapture::new(&tools);
        let mut os_release = None;
        let mut completed = None;
        let scan = super::super::linux::collect_selected_observed(
            &capture,
            &report,
            now,
            || {
                let value = super::super::linux::read_os_release();
                os_release = Some(value.clone());
                value
            },
            || {
                let value = super::super::linux::completion_time();
                completed = Some(value.clone());
                value
            },
        )
        .map_err(|_| ERROR.to_owned())?;
        let events = capture.finish()?;
        let mut scanning = tools.into_scanning()?;
        let os_release = os_release.ok_or(ERROR)?;
        let completed = completed.ok_or(ERROR)?;
        require(os_release.len() <= 16384 && checked_at(&completed))?;
        let replay = InputReplay::new(events);
        let repeated = super::super::linux::collect_selected_observed(
            &replay,
            &report,
            now,
            || os_release,
            || completed,
        )
        .map_err(|_| ERROR.to_owned())?;
        replay.finish()?;
        require(
            scan == repeated
                && scan["inventoryComplete"] == true
                && matches!(scan["status"].as_str(), Some("complete" | "partial")),
        )?;
        scanning.session.check()?;
        Ok((NormalizedSession { scanning, scan }, repeated))
    }
    #[test]
    fn replay_requires_exact_order_and_consumes_every_input() {
        let event = InputEvent {
            program: "/bin/hostname".into(),
            args: vec![],
            limit: 4096,
            output: "host".into(),
        };
        let replay = InputReplay::new(vec![event]);
        assert!(replay.text("/usr/bin/uname", &["-m"], 4096).is_err());
        assert!(replay.finish().is_err());
    }
    #[test]
    fn replay_rejects_missing_extra_and_changed_arguments() {
        let event = || InputEvent {
            program: "/usr/bin/uname".into(),
            args: vec!["-m".into()],
            limit: 4096,
            output: "arm64".into(),
        };
        let missing = InputReplay::new(vec![event()]);
        assert!(missing.finish().is_err());
        let extra = InputReplay::new(vec![event()]);
        assert_eq!(
            extra.text("/usr/bin/uname", &["-m"], 4096).unwrap(),
            "arm64"
        );
        assert!(extra.text("/usr/bin/uname", &["-m"], 4096).is_err());
        assert!(extra.finish().is_err());
        let changed = InputReplay::new(vec![event()]);
        assert!(changed.text("/usr/bin/uname", &["-a"], 4096).is_err());
        assert!(changed.finish().is_err());
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn capture_rejects_excess_input_and_latches_failure() {
        struct Big;
        impl Tools for Big {
            fn text(&self, _: &str, _: &[&str], _: usize) -> Result<String> {
                Ok("x".repeat(INPUT_MAX + 1))
            }
            fn sha256(&self, _: &[u8]) -> Result<String> {
                Err(ERROR.into())
            }
        }
        let capture = InputCapture::new(&Big);
        assert!(capture.text("fixed", &[], INPUT_MAX + 1).is_err());
        assert!(capture.finish().is_err());
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn changed_recorded_input_changes_the_replayed_scan() {
        struct Fixed;
        impl Tools for Fixed {
            fn text(&self, program: &str, _: &[&str], _: usize) -> Result<String> {
                Ok(match program {
                    "/bin/hostname" => "host".into(),
                    "/usr/bin/uname" | "/usr/bin/dpkg" => "arm64".into(),
                    "/usr/bin/dpkg-query" => "installed\tcups\t1\tarm64\n".into(),
                    "/usr/bin/apt-mark" | "/usr/bin/apt-cache" => String::new(),
                    _ => return Err(ERROR.into()),
                })
            }
            fn sha256(&self, _: &[u8]) -> Result<String> {
                Err(ERROR.into())
            }
        }
        let capture = InputCapture::new(&Fixed);
        let scan = super::super::linux::collect_selected_observed(
            &capture,
            REPORT,
            "2026-01-01T00:00:00Z",
            || "ID=debian".into(),
            || "2026-01-01T00:00:01Z".into(),
        )
        .unwrap();
        let mut events = capture.finish().unwrap();
        events[0].output = "changed".into();
        let replay = InputReplay::new(events);
        let repeated = super::super::linux::collect_selected_observed(
            &replay,
            REPORT,
            "2026-01-01T00:00:00Z",
            || "ID=debian".into(),
            || "2026-01-01T00:00:01Z".into(),
        )
        .unwrap();
        replay.finish().unwrap();
        assert_ne!(scan, repeated);
    }
    fn clock(time: u64) -> Clock {
        Clock {
            boot_id: BOOT.into(),
            boottime_ms: time,
            unix_ms: 1_767_225_600_000,
        }
    }
    fn negotiated() -> Negotiated {
        Negotiated::new(&[Capability::Collection], &[Capability::Collection], true).unwrap()
    }
    fn expected() -> ExpectedPin {
        ExpectedPin {
            cache_generation: "a".repeat(32),
            policy_generation: "b".repeat(64),
            successful_checked_at: "2026-01-01T00:00:00.123456Z".into(),
            boot_id: BOOT.into(),
        }
    }
    fn initial() -> Vec<u8> {
        format!("{}\n",json!({"schema_version":1,"id":0,"operation":"initialize","phase":"pinned","context":{
        "cache_generation":"a".repeat(32),"policy_generation":"b".repeat(64),"successful_checked_at":"2026-01-01T00:00:00.123456Z","boot_id":BOOT,"pinned_boottime_ms":1001}})).into_bytes()
    }
    fn ack() -> Vec<u8> {
        b"{\"schema_version\":1,\"id\":1,\"operation\":\"publish_observation\",\"phase\":\"published\"}\n".to_vec()
    }

    struct Fixture {
        dir: std::path::PathBuf,
        lock: crate::inventory::state::Lock,
    }
    impl Fixture {
        fn new() -> Self {
            let dir = std::fs::canonicalize(std::env::temp_dir())
                .unwrap()
                .join(format!(
                    "inventory-obs-{}",
                    crate::inventory::transport::report_id().unwrap()
                ));
            std::fs::create_dir(&dir).unwrap();
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
            let lock = crate::inventory::state::Lock::acquire(&dir).unwrap();
            RequestJournal::initialize(
                &dir,
                BOOT,
                CounterSeeds {
                    helper: 5,
                    observation: 7,
                },
                &lock,
            )
            .unwrap();
            Self { dir, lock }
        }
        fn ready(&self, session: &Negotiated) -> RequestJournal<'_> {
            let mut journal = RequestJournal::open(&self.dir, BOOT, &self.lock).unwrap();
            journal
                .admit(
                    Delivery::Collection(CollectionDelivery {
                        request_id: REQUEST.into(),
                        delivery_sequence: 1,
                        not_before: "2026-01-01T00:00:00.000Z".into(),
                        source_revision: 1,
                    }),
                    1,
                    &clock(1000),
                    "aaaaaaaaaaaaaaaa",
                    session,
                )
                .unwrap();
            let pending = journal.pending(Capability::Collection).unwrap().unwrap();
            journal
                .canonical(
                    Capability::Collection,
                    &Canonical {
                        schema_version: 1,
                        request: CanonicalRequest {
                            request_id: pending.request_id,
                            delivery_sequence: 1,
                            status: CanonicalStatus::Delivered,
                            reason: None,
                            report_id: None,
                            report_sha256: None,
                            operation_nonce: pending.operation_nonce,
                        },
                        receipt: None,
                    },
                )
                .unwrap();
            journal
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    #[derive(Default)]
    struct Recorded {
        writes: Vec<Vec<u8>>,
        closes: usize,
        durable_seen: bool,
        reads: usize,
        samples: usize,
        scan_seen: bool,
        host_calls: usize,
    }
    struct Scripted {
        frames: VecDeque<Vec<u8>>,
        times: VecDeque<Clock>,
        record: Arc<Mutex<Recorded>>,
        path: std::path::PathBuf,
        fail_write: bool,
        change_on_ack: bool,
        fail_scan_ack: bool,
        fail_attach: bool,
        change_after_scanning: bool,
        data_reply: bool,
        data_fault: Option<&'static str>,
        poison_on_data_write: Option<Arc<AtomicBool>>,
        poison_on_data_final: Option<Arc<AtomicBool>>,
        finish_reply: bool,
        finish_fault: Option<&'static str>,
        root_lease_mismatch: bool,
        root_expiry: u64,
    }
    impl Exchange for Scripted {
        fn sample(&mut self) -> Result<Clock> {
            self.record.lock().unwrap().samples += 1;
            self.times
                .pop_front()
                .ok_or("Synthetic clock exhausted".into())
        }
        fn read(&mut self) -> Result<Vec<u8>> {
            let mut record = self.record.lock().unwrap();
            record.reads += 1;
            if record.reads == 2 && self.change_on_ack {
                let mut bytes = std::fs::read(&self.path).unwrap();
                bytes.push(b'\n');
                std::fs::write(&self.path, bytes).unwrap();
            }
            if record.reads == 3 && self.fail_attach {
                std::fs::create_dir(self.path.with_extension("pending")).unwrap();
            }
            if record.reads == 4 && self.change_after_scanning {
                let mut bytes = std::fs::read(&self.path).unwrap();
                bytes.push(b'\n');
                std::fs::write(&self.path, bytes).unwrap();
            }
            let frame = self.frames.pop_front().ok_or("Synthetic EOF")?;
            if self.finish_fault == Some("postrelease")
                && serde_json::from_slice::<Value>(&frame)
                    .is_ok_and(|value| value["operation"] == "publish_release")
            {
                let mut bytes = std::fs::read(&self.path).unwrap();
                bytes.push(b'\n');
                std::fs::write(&self.path, bytes).unwrap();
            }
            if self.finish_fault == Some("after_fsync")
                && serde_json::from_slice::<Value>(&frame)
                    .is_ok_and(|value| value["phase"] == "scan_frozen")
            {
                self.times = VecDeque::from([clock(1012), clock(1012), clock(1012), clock(10000)]);
            }
            if let Some(flag) = &self.poison_on_data_final
                && serde_json::from_slice::<Value>(&frame)
                    .is_ok_and(|value| value["phase"] == "data_complete")
            {
                flag.store(true, Ordering::SeqCst);
            }
            Ok(frame)
        }
        fn write(&mut self, raw: &[u8]) -> Result<()> {
            let saved: Value = serde_json::from_slice(&std::fs::read(&self.path).unwrap()).unwrap();
            let command: Value = serde_json::from_slice(raw).unwrap();
            let retained = if saved["collection"]["active"].is_object() {
                &saved["collection"]["active"]
            } else {
                &saved["collection"]["last_terminal"]
            };
            assert_eq!(retained["submitted"], true);
            let scan = &retained["proof"]["evidence"]["scan"];
            let mut record = self.record.lock().unwrap();
            match command["operation"].as_str().unwrap() {
                "publish_observation" => {
                    assert!(scan.is_null());
                    assert_eq!(
                        retained["native_attempt"]["observation_nonce"],
                        command["nonce"]
                    );
                    record.durable_seen = true;
                }
                "await_open" => assert!(scan.is_null()),
                "scan_admitted" => {
                    assert_eq!(
                        scan["started_boottime_ms"],
                        command["scan_started_boottime_ms"]
                    );
                    assert_eq!(scan["report_id"], REPORT);
                    assert_eq!(scan["sequence"], 1);
                    assert_eq!(scan["source_revision"], 1);
                    assert!(scan["finished_boottime_ms"].is_null());
                    record.scan_seen = true;
                }
                "installed" | "architecture" | "holds" | "policy" => {
                    assert!(self.data_reply);
                    assert_eq!(scan["started_boottime_ms"], 1010);
                    let operation = command["operation"].as_str().unwrap();
                    let id = command["id"].as_u64().unwrap();
                    let text = match operation {
                        "installed" => {
                            "installed\tinventory-proof:arm64\t0.9\tarm64\ninstalled\tnginx:arm64\t1.0\tarm64\n"
                        }
                        "architecture" => "arm64\n",
                        "holds" => "nginx:arm64\n",
                        _ => {
                            "inventory-proof:arm64:\n  Installed: 0.9\n  Candidate: 1.0\n  Version table:\n     1.0 123\n        123 https://repo.invalid stable/main arm64 Packages\nnginx:arm64:\n  Installed: 1.0\n  Candidate: 1.1\n  Version table:\n     1.1 123\n        123 https://repo.invalid stable/main arm64 Packages\n"
                        }
                    };
                    let text = if self.data_fault == Some("installed_malformed")
                        && operation == "installed"
                    {
                        "synthetic malformed installed data\n".to_owned()
                    } else if self.data_fault == Some("architecture_overflow")
                        && operation == "architecture"
                    {
                        "x".repeat(129)
                    } else {
                        text.to_owned()
                    };
                    let eof = self.data_fault == Some(operation);
                    if !eof {
                        let index = usize::from(
                            self.data_fault == Some("bad_chunk") && operation == "installed",
                        );
                        self.frames.push_back(format!("{}\n",json!({"schema_version":1,"id":id,"operation":operation,"phase":"data","chunk_index":index,"text":text})).into_bytes());
                        let bytes = text.len()
                            + usize::from(
                                self.data_fault == Some("bad_policy_final")
                                    && operation == "policy",
                            );
                        self.frames.push_back(format!("{}\n",json!({"schema_version":1,"id":id,"operation":operation,"phase":"data_complete","chunks":1,"utf8_bytes":bytes})).into_bytes());
                    }
                    if let Some(flag) = &self.poison_on_data_write {
                        flag.store(true, Ordering::SeqCst);
                    }
                }
                "freeze_scan" if self.finish_reply => {
                    assert!(scan["finished_boottime_ms"].is_null());
                    let id = command["id"].as_u64().unwrap();
                    let mut frame = json!({"schema_version":1,"id":id,"operation":"freeze_scan","phase":"scan_frozen","scan":{"scan_started_boottime_ms":1010,"scan_finished_boottime_ms":1012,"installed_before_sha256":"c".repeat(64),"installed_after_sha256":"c".repeat(64)}});
                    match self.finish_fault {
                        Some("start") => frame["scan"]["scan_started_boottime_ms"] = json!(1011),
                        Some("finish") => frame["scan"]["scan_finished_boottime_ms"] = json!(1013),
                        Some("hash") => {
                            frame["scan"]["installed_after_sha256"] = json!("d".repeat(64))
                        }
                        _ => {}
                    }
                    self.frames.push_back(format!("{frame}\n").into_bytes());
                }
                "publish_release" if self.finish_reply => {
                    assert!(scan["finished_boottime_ms"].is_null());
                    assert_eq!(
                        retained["native_attempt"]["observation_nonce"],
                        command["nonce"]
                    );
                    assert!(retained["native_attempt"]["release_requested_boottime_ms"].is_u64());
                    let id = command["id"].as_u64().unwrap();
                    let phase = if self.finish_fault == Some("release_ack") {
                        "failed"
                    } else {
                        "published"
                    };
                    self.frames.push_back(format!("{}\n",json!({"schema_version":1,"id":id,"operation":"publish_release","phase":phase})).into_bytes());
                }
                "await_receipt" if self.finish_reply => {
                    let id = command["id"].as_u64().unwrap();
                    let mut frame = json!({"schema_version":1,"id":id,"operation":"await_receipt","phase":"prepared","evidence":{"schema_version":1,"scan_started_boottime_ms":1010,"scan_finished_boottime_ms":1012,"successful_checked_at":"2026-01-01T00:00:00.123456Z","observation_receipt":scripted_receipt()}});
                    match self.finish_fault {
                        Some("checked") => {
                            frame["evidence"]["successful_checked_at"] =
                                json!("2026-01-01T00:00:00Z")
                        }
                        Some("receipt") => {
                            frame["evidence"]["observation_receipt"]["nonce"] =
                                json!("0000000000000009bbbbbbbbbbbbbbbb")
                        }
                        Some("extra") => frame["evidence"]["extra"] = json!(1),
                        _ => {}
                    }
                    let encoded = format!("{frame}\n");
                    let encoded = if self.finish_fault == Some("duplicate") {
                        encoded.replace(
                            "\"outcome\":\"released\"",
                            "\"outcome\":\"released\",\"outcome\":\"released\"",
                        )
                    } else {
                        encoded
                    };
                    self.frames.push_back(encoded.into_bytes());
                }
                _ => panic!("Unexpected scripted operation"),
            }
            record.writes.push(raw.to_vec());
            if self.fail_write || (self.fail_scan_ack && command["operation"] == "scan_admitted") {
                Err("Synthetic possibly visible write failure".into())
            } else {
                Ok(())
            }
        }
        fn close(&mut self) -> Result<()> {
            self.record.lock().unwrap().closes += 1;
            Ok(())
        }
        fn host_metadata(&mut self, kind: HostMetadata) -> Result<String> {
            self.record.lock().unwrap().host_calls += 1;
            if self.data_fault == Some("host_error") {
                return Err("Synthetic confidential backend error".into());
            }
            if self.data_fault == Some("host_overflow") {
                return Ok("x".repeat(4097));
            }
            Ok(match kind {
                HostMetadata::Hostname => "synthetic-host\n",
                HostMetadata::MachineArchitecture => "aarch64\n",
            }
            .into())
        }
        fn root_status(&mut self, receipt: bool) -> Result<Value> {
            let mut value = scripted_status(receipt);
            if self.finish_fault == Some("root") && receipt {
                value["observation_receipt"]["outcome"] = json!("expired");
            }
            if self.root_lease_mismatch && !receipt {
                value["observation_lease"]["nonce"] =
                    json!("0000000000000009".to_owned() + &"b".repeat(16));
            }
            if !receipt {
                value["observation_lease"]["expires_boottime_ms"] = json!(self.root_expiry);
            }
            Ok(value)
        }
    }
    fn scripted_status(receipt: bool) -> Value {
        let mut status = json!({"schema_version":1,"operation_nonce":null,"phase":"deferred","reason":"cache_unavailable","policy_generation":"b".repeat(64),"cache_generation":"a".repeat(32),"successful_checked_at":"2026-01-01T00:00:00.123456Z","started_at":null,"finished_at":null,"attempt":null,"observation_lease":null,"observation_receipt":null});
        if receipt {
            status["observation_receipt"] = scripted_receipt();
        } else {
            status["observation_lease"] =
                serde_json::from_slice::<Value>(&proposal()).unwrap()["offer"].clone();
        }
        status
    }
    fn scripted_receipt() -> Value {
        json!({"nonce":"0000000000000008bbbbbbbbbbbbbbbb","boot_id":BOOT,"cache_generation":"a".repeat(32),"policy_generation":"b".repeat(64),"lock_open_boottime_ms":1005,"expires_boottime_ms":10000,"lock_held_until_boottime_ms":1012,"released_boottime_ms":1012,"outcome":"released","installed_before_sha256":"c".repeat(64),"installed_after_sha256":"c".repeat(64)})
    }
    fn scripted(fixture: &Fixture) -> (Scripted, Arc<Mutex<Recorded>>) {
        let record = Arc::new(Mutex::new(Recorded::default()));
        (
            Scripted {
                frames: VecDeque::from([initial(), ack()]),
                times: (0..20).map(|_| clock(1002)).collect(),
                record: record.clone(),
                path: fixture.dir.join("requests.json"),
                fail_write: false,
                change_on_ack: false,
                fail_scan_ack: false,
                fail_attach: false,
                change_after_scanning: false,
                data_reply: false,
                data_fault: None,
                poison_on_data_write: None,
                poison_on_data_final: None,
                finish_reply: false,
                finish_fault: None,
                root_lease_mismatch: false,
                root_expiry: 10000,
            },
            record,
        )
    }

    fn proposal() -> Vec<u8> {
        format!("{}\n",json!({"schema_version":1,"id":2,"operation":"await_open","phase":"scan_proposed","offer":{
        "nonce":"0000000000000008bbbbbbbbbbbbbbbb","boot_id":BOOT,"cache_generation":"a".repeat(32),"policy_generation":"b".repeat(64),
        "lock_open_boottime_ms":1005,"expires_boottime_ms":10000},"scan_started_boottime_ms":1010})).into_bytes()
    }
    fn scanning_ack() -> Vec<u8> {
        b"{\"schema_version\":1,\"id\":3,\"operation\":\"scan_admitted\",\"phase\":\"scanning\",\"scan_started_boottime_ms\":1010}\n".to_vec()
    }
    fn scan_scripted(fixture: &Fixture) -> (Scripted, Arc<Mutex<Recorded>>) {
        let (mut exchange, record) = scripted(fixture);
        exchange.frames.extend([proposal(), scanning_ack()]);
        exchange.times = (0..40)
            .map(|index| clock(if index < 9 { 1002 } else { 1012 }))
            .collect();
        (exchange, record)
    }
    fn data_scanning(
        _fixture: &Fixture,
        journal: &mut RequestJournal<'_>,
        session: &Negotiated,
        exchange: Scripted,
    ) -> ScanningSession<Scripted> {
        let intent = journal
            .admit_native_collection(REPORT, 1, 1, &clock(1001), "bbbbbbbbbbbbbbbb", session)
            .unwrap();
        PinnedSession::admit(exchange, expected())
            .unwrap()
            .publish(journal, intent, session)
            .unwrap()
            .admit_scan(journal, session)
            .unwrap()
    }
    fn data_scripted(fixture: &Fixture) -> (Scripted, Arc<Mutex<Recorded>>) {
        let (mut exchange, record) = scan_scripted(fixture);
        exchange.data_reply = true;
        exchange.times.extend((0..400).map(|_| clock(1012)));
        (exchange, record)
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    struct RealExchange {
        child: std::process::Child,
        pipes: Option<super::super::reporter_pipe::PipePair>,
        deadline: std::time::Instant,
        path: std::path::PathBuf,
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    impl RealExchange {
        fn spawn(fixture: &Fixture) -> Result<Self> {
            Self::spawn_mode(fixture, "")
        }
        fn spawn_mode(fixture: &Fixture, suffix: &'static str) -> Result<Self> {
            use std::process::{Command, Stdio};
            use std::time::{Duration, Instant};
            const PROGRAM: &str = r#"
import sys,json
def emit(v):
    sys.stdout.buffer.write((json.dumps(v,separators=(',',':'))+'\n').encode());sys.stdout.buffer.flush()
def command(i,op,fields=()):
    raw=sys.stdin.buffer.readline(262145)
    assert raw.endswith(b'\n') and len(raw)<=262144
    v=json.loads(raw);assert set(v)=={'schema_version','id','operation'}|set(fields)
    assert type(v['id']) is int and v['id']==i and v['schema_version']==1 and v['operation']==op
    return v
def response(i,op,phase,**fields):emit(dict(schema_version=1,id=i,operation=op,phase=phase,**fields))
boot='00000000-0000-4000-8000-000000000001';nonce='0000000000000008'+'b'*16
offer=dict(nonce=nonce,boot_id=boot,cache_generation='a'*32,policy_generation='b'*64,lock_open_boottime_ms=1005,expires_boottime_ms=10000)
receipt=dict(offer,lock_held_until_boottime_ms=1012,released_boottime_ms=1012,outcome='released',installed_before_sha256='c'*64,installed_after_sha256='c'*64)
response(0,'initialize','pinned',context=dict(cache_generation='a'*32,policy_generation='b'*64,successful_checked_at='2026-01-01T00:00:00.123456Z',boot_id=boot,pinned_boottime_ms=1001))
assert command(1,'publish_observation',('nonce',))['nonce']==nonce;response(1,'publish_observation','published')
command(2,'await_open');response(2,'await_open','scan_proposed',offer=offer,scan_started_boottime_ms=1010)
assert command(3,'scan_admitted',('scan_started_boottime_ms',))['scan_started_boottime_ms']==1010;response(3,'scan_admitted','scanning',scan_started_boottime_ms=1010)
data={4:('installed','installed\tinventory-proof:arm64\t0.9\tarm64\n'),5:('holds',''),6:('policy','inventory-proof:arm64:\n  Installed: 0.9\n  Candidate: 1.0\n  Version table:\n     1.0 123\n        123 https://repo.invalid stable/main arm64 Packages\n'),7:('architecture','arm64\n')}
for i,(op,text) in data.items():
    v=command(i,op,('packages',) if op=='policy' else ())
    if op=='policy':assert v['packages']==['inventory-proof:arm64']
    if text:response(i,op,'data',chunk_index=0,text=text)
    response(i,op,'data_complete',chunks=int(bool(text)),utf8_bytes=len(text.encode()))
command(8,'freeze_scan');response(8,'freeze_scan','scan_frozen',scan=dict(scan_started_boottime_ms=1010,scan_finished_boottime_ms=1012,installed_before_sha256='c'*64,installed_after_sha256='c'*64))
assert command(9,'publish_release',('nonce',))['nonce']==nonce;response(9,'publish_release','published')
command(10,'await_receipt');response(10,'await_receipt','prepared',evidence=dict(schema_version=1,scan_started_boottime_ms=1010,scan_finished_boottime_ms=1012,successful_checked_at='2026-01-01T00:00:00.123456Z',observation_receipt=receipt))
"#;
            require(matches!(
                suffix,
                "" | "\nsys.exit(3)\n"
                    | "\nsys.stdout.buffer.write(b'noise');sys.stdout.buffer.flush()\n"
            ))?;
            let program = format!("{PROGRAM}{suffix}");
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut child = Command::new("/usr/bin/python3")
                .args(["-I", "-B", "-S", "-c", &program])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|_| ERROR.to_owned())?;
            let pipes = super::super::reporter_pipe::PipePair::new(
                child.stdin.take().ok_or(ERROR)?,
                child.stdout.take().ok_or(ERROR)?,
                deadline,
            )
            .map_err(|_| ERROR.to_owned())?;
            Ok(Self {
                child,
                pipes: Some(pipes),
                deadline,
                path: fixture.dir.join("requests.json"),
            })
        }
        fn finish(mut self) -> Result<()> {
            let mut pipes = self.pipes.take().ok_or(ERROR)?;
            let eof = pipes.require_eof().is_ok();
            let closed = pipes.close().is_ok();
            let after_close_in_time = std::time::Instant::now() < self.deadline;
            let exit = loop {
                match self.child.try_wait() {
                    Ok(Some(status)) => {
                        break status.success() && std::time::Instant::now() < self.deadline;
                    }
                    Err(_) => break false,
                    Ok(None) => {}
                }
                if std::time::Instant::now() >= self.deadline {
                    break false;
                }
                let remaining = self
                    .deadline
                    .saturating_duration_since(std::time::Instant::now());
                std::thread::sleep(remaining.min(std::time::Duration::from_millis(2)));
            };
            require(eof && closed && after_close_in_time && exit)
        }
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    impl Exchange for RealExchange {
        fn sample(&mut self) -> Result<Clock> {
            Ok(clock(1012))
        }
        fn read(&mut self) -> Result<Vec<u8>> {
            self.pipes
                .as_mut()
                .ok_or(ERROR)?
                .read_frame()
                .map_err(|_| ERROR.into())
        }
        fn write(&mut self, raw: &[u8]) -> Result<()> {
            let command: Value = serde_json::from_slice(raw).map_err(|_| ERROR.to_owned())?;
            let saved: Value =
                serde_json::from_slice(&std::fs::read(&self.path).map_err(|_| ERROR.to_owned())?)
                    .map_err(|_| ERROR.to_owned())?;
            let active = &saved["collection"]["active"];
            if command["operation"] == "publish_observation" {
                require(
                    active["submitted"] == true
                        && active["native_attempt"]["observation_nonce"] == command["nonce"]
                        && active["proof"]["evidence"]["scan"].is_null(),
                )?;
            } else if command["operation"] == "scan_admitted" {
                require(
                    active["proof"]["evidence"]["scan"]["started_boottime_ms"]
                        == command["scan_started_boottime_ms"],
                )?;
            } else if command["operation"] == "publish_release" {
                require(
                    active["native_attempt"]["observation_nonce"] == command["nonce"]
                        && active["native_attempt"]["release_requested_boottime_ms"].is_u64()
                        && active["proof"]["evidence"]["scan"]["finished_boottime_ms"].is_null(),
                )?;
            }
            self.pipes
                .as_mut()
                .ok_or(ERROR)?
                .write_frame(raw)
                .map_err(|_| ERROR.into())
        }
        fn close(&mut self) -> Result<()> {
            match self.pipes.take() {
                Some(pipes) => pipes.close().map_err(|_| ERROR.into()),
                None => Ok(()),
            }
        }
        fn host_metadata(&mut self, kind: HostMetadata) -> Result<String> {
            Ok(match kind {
                HostMetadata::Hostname => "synthetic-host\n",
                HostMetadata::MachineArchitecture => "aarch64\n",
            }
            .into())
        }
        fn root_status(&mut self, receipt: bool) -> Result<Value> {
            Ok(scripted_status(receipt))
        }
    }

    // Hosted fixture only. The real CLOCK_BOOTTIME sampler and existing fixed
    // tools can terminate their own unprivileged subprocess on timeout. No
    // Root signal, closed process-set, hard pipe deadline or cleanup witness.
    #[cfg(target_os = "linux")]
    struct NativeExchange {
        child: std::process::Child,
        pipes: Option<super::super::reporter_pipe::PipePair>,
        status: super::super::reporter_status::StatusReader,
        deadline: std::time::Instant,
        hostname: String,
        architecture: String,
    }
    #[cfg(target_os = "linux")]
    impl NativeExchange {
        fn spawn(
            status: super::super::reporter_status::StatusReader,
            deadline: std::time::Instant,
            hostname: String,
            architecture: String,
        ) -> Result<Self> {
            use std::process::{Command, Stdio};
            require(std::time::Instant::now() < deadline)?;
            let mut child = Command::new("/usr/bin/python3")
                .args([
                    "-I",
                    "-B",
                    "-S",
                    "/usr/local/libexec/command-center-inventory-refresh/reporter.py",
                ])
                .env_clear()
                .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
                .env("LC_ALL", "C")
                .env("LANG", "C")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|_| ERROR.to_owned())?;
            let pipes = super::super::reporter_pipe::PipePair::new(
                child.stdin.take().ok_or(ERROR)?,
                child.stdout.take().ok_or(ERROR)?,
                deadline,
            )
            .map_err(|_| ERROR.to_owned())?;
            Ok(Self {
                child,
                pipes: Some(pipes),
                status,
                deadline,
                hostname,
                architecture,
            })
        }
        fn finish(mut self) -> Result<()> {
            let mut pipes = self.pipes.take().ok_or(ERROR)?;
            let eof = pipes.require_eof().is_ok();
            let closed = pipes.close().is_ok();
            let after_close = std::time::Instant::now() < self.deadline;
            let exit = loop {
                match self.child.try_wait() {
                    Ok(Some(status)) => {
                        break status.success() && std::time::Instant::now() < self.deadline;
                    }
                    Err(_) => break false,
                    Ok(None) => {}
                }
                let remaining = self
                    .deadline
                    .saturating_duration_since(std::time::Instant::now());
                if remaining.is_zero() {
                    break false;
                }
                std::thread::sleep(remaining.min(std::time::Duration::from_millis(2)));
            };
            require(eof && closed && after_close && exit)
        }
    }
    #[cfg(target_os = "linux")]
    impl Exchange for NativeExchange {
        fn sample(&mut self) -> Result<Clock> {
            super::super::clock::snapshot().map_err(|_| ERROR.into())
        }
        fn read(&mut self) -> Result<Vec<u8>> {
            self.pipes
                .as_mut()
                .ok_or(ERROR)?
                .read_frame()
                .map_err(|_| ERROR.into())
        }
        fn write(&mut self, raw: &[u8]) -> Result<()> {
            self.pipes
                .as_mut()
                .ok_or(ERROR)?
                .write_frame(raw)
                .map_err(|_| ERROR.into())
        }
        fn close(&mut self) -> Result<()> {
            match self.pipes.take() {
                Some(pipes) => pipes.close().map_err(|_| ERROR.into()),
                None => Ok(()),
            }
        }
        fn host_metadata(&mut self, kind: HostMetadata) -> Result<String> {
            Ok(match kind {
                HostMetadata::Hostname => self.hostname.clone(),
                HostMetadata::MachineArchitecture => self.architecture.clone(),
            })
        }
        fn root_status(&mut self, _receipt: bool) -> Result<Value> {
            self.status.read(self.deadline).map_err(|_| ERROR.into())
        }
    }

    #[cfg(target_os = "linux")]
    fn hosted_native_roundtrip(sample: bool) -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        use std::time::{Duration, Instant};
        require(
            std::env::var("GUARDED_UPDATE_NATIVE_RUST_PROOF")
                .ok()
                .as_deref()
                == Some("1"),
        )?;
        require(
            std::env::var("GUARDED_UPDATE_NATIVE_BARRIER_PROOF")
                .ok()
                .as_deref()
                == if sample { Some("1") } else { None },
        )?;
        let deadline = Instant::now() + Duration::from_secs(18);
        let status =
            super::super::reporter_status::StatusReader::fixed().map_err(|_| ERROR.to_owned())?;
        let current = status.read(deadline).map_err(|_| ERROR.to_owned())?;
        super::super::reporter_status::validate_status(&current).map_err(|_| ERROR.to_owned())?;
        let first = super::super::clock::snapshot().map_err(|_| ERROR.to_owned())?;
        let expected = ExpectedPin {
            cache_generation: current["cache_generation"].as_str().ok_or(ERROR)?.into(),
            policy_generation: current["policy_generation"].as_str().ok_or(ERROR)?.into(),
            successful_checked_at: current["successful_checked_at"]
                .as_str()
                .ok_or(ERROR)?
                .into(),
            boot_id: first.boot_id.clone(),
        };
        let tools = super::super::process::SystemTools;
        let hostname = tools
            .text("/bin/hostname", &[], 4096)
            .map_err(|_| ERROR.to_owned())?;
        let architecture = tools
            .text("/usr/bin/uname", &["-m"], 4096)
            .map_err(|_| ERROR.to_owned())?;
        require(!hostname.is_empty() && !architecture.is_empty() && Instant::now() < deadline)?;
        let dir = std::path::Path::new("/tmp").join(format!(
            "inventory-native-{}",
            super::super::transport::report_id().map_err(|_| ERROR.to_owned())?
        ));
        std::fs::create_dir(&dir).map_err(|_| ERROR.to_owned())?;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| ERROR.to_owned())?;
        let lock = super::super::state::Lock::acquire(&dir).map_err(|_| ERROR.to_owned())?;
        RequestJournal::initialize(
            &dir,
            BOOT,
            CounterSeeds {
                helper: 5,
                observation: 8,
            },
            &lock,
        )
        .map_err(|_| ERROR.to_owned())?;
        let negotiated = negotiated();
        let mut journal = RequestJournal::open(&dir, BOOT, &lock).map_err(|_| ERROR.to_owned())?;
        let accepted = super::super::clock::snapshot().map_err(|_| ERROR.to_owned())?;
        journal
            .admit(
                Delivery::Collection(CollectionDelivery {
                    request_id: REQUEST.into(),
                    delivery_sequence: 1,
                    not_before: "2026-01-01T00:00:00.000Z".into(),
                    source_revision: 1,
                }),
                1,
                &accepted,
                "aaaaaaaaaaaaaaaa",
                &negotiated,
            )
            .map_err(|_| ERROR.to_owned())?;
        let pending = journal
            .pending(Capability::Collection)
            .map_err(|_| ERROR.to_owned())?
            .ok_or(ERROR)?;
        journal
            .canonical(
                Capability::Collection,
                &Canonical {
                    schema_version: 1,
                    request: CanonicalRequest {
                        request_id: pending.request_id,
                        delivery_sequence: 1,
                        status: CanonicalStatus::Delivered,
                        reason: None,
                        report_id: None,
                        report_sha256: None,
                        operation_nonce: pending.operation_nonce,
                    },
                    receipt: None,
                },
            )
            .map_err(|_| ERROR.to_owned())?;
        let admitted = super::super::clock::snapshot().map_err(|_| ERROR.to_owned())?;
        let intent = journal
            .admit_native_collection(REPORT, 1, 1, &admitted, "dddddddddddddddd", &negotiated)
            .map_err(|_| ERROR.to_owned())?;
        require(
            intent.observation_nonce() == "0000000000000009dddddddddddddddd"
                && Instant::now() < deadline,
        )?;
        let exchange = NativeExchange::spawn(status, deadline, hostname, architecture)?;
        let scanning = PinnedSession::admit(exchange, expected)?
            .publish(&mut journal, intent, &negotiated)?
            .admit_scan(&mut journal, &negotiated)?;
        let (normalized, replayed) = collect_observed(
            scanning,
            &crate::timefmt::rfc3339(crate::timefmt::now_secs()),
        )?;
        let mut prepared = normalized.prepare(&mut journal)?;
        require(
            prepared.scan["inventoryComplete"] == true
                && prepared.scan["packages"]
                    .as_array()
                    .is_some_and(|packages| !packages.is_empty())
                && prepared.scanning.request_id == REQUEST
                && prepared
                    .scanning
                    .proof
                    .scan
                    .as_ref()
                    .is_some_and(|scan| scan.finished_boottime_ms.is_none())
                && prepared.scanning.offer.nonce == "0000000000000009dddddddddddddddd",
        )?;
        // Exercise the production body encoder on the actual normalized scan.
        // The Root receipt authenticates its own observation, not these bytes.
        // Neither the body nor its hash is persisted, uploaded, or made ready.
        let proof_scan = prepared.scanning.proof.scan.as_ref().ok_or(ERROR)?;
        require(REQUEST != REPORT && proof_scan.report_id == REPORT)?;
        let body = super::super::lifecycle::encode_collection_report(
            "00000000-0000-4000-8000-000000000004",
            &prepared.scanning.request_id,
            proof_scan,
            prepared.scan.clone(),
        )
        .map_err(|_| ERROR.to_owned())?;
        let replay_body = super::super::lifecycle::encode_collection_report(
            "00000000-0000-4000-8000-000000000004",
            &prepared.scanning.request_id,
            proof_scan,
            replayed,
        )
        .map_err(|_| ERROR.to_owned())?;
        require(body == replay_body)?;
        let decoded: serde_json::Value =
            serde_json::from_slice(&body).map_err(|_| ERROR.to_owned())?;
        require(
            decoded["enrollment_id"] == "00000000-0000-4000-8000-000000000004"
                && decoded["collection_request_id"] == REQUEST
                && decoded["report_id"] == REPORT
                && decoded["sequence"] == proof_scan.sequence
                && decoded["source_revision"] == proof_scan.source_revision
                && decoded["scan"] == prepared.scan,
        )?;
        let digest = tools.sha256(&body).map_err(|_| ERROR.to_owned())?;
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or(ERROR)?;
        let independent = tools.run_with_timeout(
            "/usr/bin/python3",
            &["-I", "-B", "-S", "-c", "import hashlib,sys;sys.stdout.write(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())"],
            &body,
            64,
            remaining,
        ).map_err(|_| ERROR.to_owned())?;
        require(independent.as_slice() == digest.as_bytes() && Instant::now() < deadline)?;
        prepared.scanning.session.check()?;
        let boot = prepared.scanning.session.context.boot_id.clone();
        let last = prepared.scanning.session.last;
        let lease_deadline = prepared.scanning.session.deadline;
        prepared
            .scanning
            .session
            .exchange
            .take()
            .ok_or(ERROR)?
            .finish()?;
        require(
            journal
                .recover_collection(None)
                .map_err(|_| ERROR.to_owned())?
                == super::super::requests::CollectionRecovery::Unfinished,
        )?;
        let final_clock = super::super::clock::snapshot().map_err(|_| ERROR.to_owned())?;
        final_native_clock(&boot, last, lease_deadline, &final_clock)?;
        require(Instant::now() < deadline)?;
        #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
        {
            if !sample {
                return Ok(());
            }
            hosted_barrier(deadline)?;
            let after = super::super::reporter_direct_clock::snapshot(deadline)
                .map_err(|_| ERROR.to_owned())?;
            final_native_clock(&boot, final_clock.boottime_ms, lease_deadline, &after)?;
            Ok(())
        }
        #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
        {
            if sample { Err(ERROR.into()) } else { Ok(()) }
        }
    }

    #[cfg(all(
        target_os = "linux",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    #[allow(clippy::disallowed_methods)]
    fn hosted_barrier(deadline: std::time::Instant) -> Result<()> {
        // Stderr is the fixture's private control pipe, not a logging surface.
        // Both shared descriptions remain exclusively owned through restoration.
        super::super::reporter_barrier::handshake(&std::io::stdin(), &std::io::stderr(), deadline)
            .map_err(|_| ERROR.to_owned())
    }

    fn final_native_clock(boot: &str, last: u64, deadline: u64, now: &Clock) -> Result<()> {
        now.validate().map_err(|_| ERROR.to_owned())?;
        require(now.boot_id == boot && now.boottime_ms >= last && now.boottime_ms < deadline)
    }

    #[test]
    fn prepared_receipt_keeps_journal_scan_unfinished() {
        let fixture = Fixture::new();
        let negotiated = negotiated();
        let mut journal = fixture.ready(&negotiated);
        let (mut exchange, record) = data_scripted(&fixture);
        exchange.finish_reply = true;
        let scanning = data_scanning(&fixture, &mut journal, &negotiated, exchange);
        let normalized = scanning.collect_selected("2026-01-01T00:00:00Z").unwrap();
        let before = saved(&fixture);
        let prepared = normalized.prepare(&mut journal).unwrap();
        assert_eq!(prepared.frozen.scan_finished_boottime_ms, 1012);
        assert_eq!(prepared.scanning.request_id, REQUEST);
        assert_eq!(prepared.scan["scanId"], REPORT);
        assert!(
            prepared
                .scanning
                .proof
                .scan
                .as_ref()
                .unwrap()
                .finished_boottime_ms
                .is_none()
        );
        assert_eq!(
            prepared.scanning.offer.nonce,
            "0000000000000008bbbbbbbbbbbbbbbb"
        );
        drop(prepared);
        let commands: Vec<String> = record
            .lock()
            .unwrap()
            .writes
            .iter()
            .map(|raw| {
                serde_json::from_slice::<Value>(raw).unwrap()["operation"]
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect();
        assert_eq!(
            &commands[commands.len() - 3..],
            ["freeze_scan", "publish_release", "await_receipt"]
        );
        unfinished_at(&fixture, &before, Some(1010));
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn real_pipe_dialogue_keeps_journal_unfinished_after_prepared() {
        let fixture = Fixture::new();
        let negotiated = negotiated();
        let mut journal = fixture.ready(&negotiated);
        let intent = journal
            .admit_native_collection(REPORT, 1, 1, &clock(1001), "bbbbbbbbbbbbbbbb", &negotiated)
            .unwrap();
        let exchange = RealExchange::spawn(&fixture).unwrap();
        let mut prepared = PinnedSession::admit(exchange, expected())
            .unwrap()
            .publish(&mut journal, intent, &negotiated)
            .unwrap()
            .admit_scan(&mut journal, &negotiated)
            .unwrap()
            .collect_selected("2026-01-01T00:00:00Z")
            .unwrap()
            .prepare(&mut journal)
            .unwrap();
        assert_eq!(prepared.scan["inventoryComplete"], true);
        assert!(
            prepared
                .scanning
                .proof
                .scan
                .as_ref()
                .unwrap()
                .finished_boottime_ms
                .is_none()
        );
        assert_eq!(prepared.scanning.request_id, REQUEST);
        let before = saved(&fixture);
        prepared
            .scanning
            .session
            .exchange
            .take()
            .unwrap()
            .finish()
            .unwrap();
        unfinished_at(&fixture, &before, Some(1010));
    }

    /// Disposable hosted fixture only. Success is not a production witness.
    #[test]
    #[ignore = "requires the dedicated restricted native CI service"]
    #[cfg(target_os = "linux")]
    fn hosted_real_reporter_rust_journal_roundtrip() {
        hosted_native_roundtrip(false).unwrap();
    }

    /// Hosted-only sample; strict mount uncertainty prevents completion proof.
    #[test]
    #[ignore = "requires the dedicated restricted physical-sample CI service"]
    #[cfg(target_os = "linux")]
    fn hosted_real_reporter_rust_journal_sample() {
        hosted_native_roundtrip(true).unwrap();
    }

    #[test]
    fn final_native_sample_must_keep_boot_and_original_deadline() {
        assert!(final_native_clock(BOOT, 1012, 10000, &clock(1012)).is_ok());
        assert!(final_native_clock(BOOT, 1012, 10000, &clock(1011)).is_err());
        assert!(final_native_clock(BOOT, 1012, 10000, &clock(10000)).is_err());
        let mut changed = clock(1012);
        changed.boot_id = "00000000-0000-4000-8000-000000000003".into();
        assert!(final_native_clock(BOOT, 1012, 10000, &changed).is_err());
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn real_pipe_completion_rejects_nonzero_exit_and_surplus() {
        for suffix in [
            "\nsys.exit(3)\n",
            "\nsys.stdout.buffer.write(b'noise');sys.stdout.buffer.flush()\n",
        ] {
            let fixture = Fixture::new();
            let negotiated = negotiated();
            let mut journal = fixture.ready(&negotiated);
            let intent = journal
                .admit_native_collection(
                    REPORT,
                    1,
                    1,
                    &clock(1001),
                    "bbbbbbbbbbbbbbbb",
                    &negotiated,
                )
                .unwrap();
            let exchange = RealExchange::spawn_mode(&fixture, suffix).unwrap();
            let mut prepared = PinnedSession::admit(exchange, expected())
                .unwrap()
                .publish(&mut journal, intent, &negotiated)
                .unwrap()
                .admit_scan(&mut journal, &negotiated)
                .unwrap()
                .collect_selected("2026-01-01T00:00:00Z")
                .unwrap()
                .prepare(&mut journal)
                .unwrap();
            let before = saved(&fixture);
            assert!(
                prepared
                    .scanning
                    .session
                    .exchange
                    .take()
                    .unwrap()
                    .finish()
                    .is_err()
            );
            unfinished_at(&fixture, &before, Some(1010));
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn real_pipe_completion_cannot_succeed_after_teardown_deadline() {
        let fixture = Fixture::new();
        let negotiated = negotiated();
        let mut journal = fixture.ready(&negotiated);
        let intent = journal
            .admit_native_collection(REPORT, 1, 1, &clock(1001), "bbbbbbbbbbbbbbbb", &negotiated)
            .unwrap();
        let exchange = RealExchange::spawn(&fixture).unwrap();
        let mut prepared = PinnedSession::admit(exchange, expected())
            .unwrap()
            .publish(&mut journal, intent, &negotiated)
            .unwrap()
            .admit_scan(&mut journal, &negotiated)
            .unwrap()
            .collect_selected("2026-01-01T00:00:00Z")
            .unwrap()
            .prepare(&mut journal)
            .unwrap();
        let mut exchange = prepared.scanning.session.exchange.take().unwrap();
        exchange.deadline = std::time::Instant::now();
        assert!(exchange.finish().is_err());
    }

    #[test]
    fn malformed_frozen_or_receipt_never_produces_prepared_evidence() {
        for fault in [
            "start",
            "finish",
            "hash",
            "release_ack",
            "checked",
            "receipt",
            "extra",
            "root",
            "duplicate",
            "postrelease",
        ] {
            let fixture = Fixture::new();
            let negotiated = negotiated();
            let mut journal = fixture.ready(&negotiated);
            let (mut exchange, record) = data_scripted(&fixture);
            exchange.finish_reply = true;
            exchange.finish_fault = Some(fault);
            let scanning = data_scanning(&fixture, &mut journal, &negotiated, exchange);
            let normalized = scanning.collect_selected("2026-01-01T00:00:00Z").unwrap();
            let before = saved(&fixture);
            assert!(normalized.prepare(&mut journal).is_err(), "{fault}");
            if ["start", "finish", "hash"].contains(&fault) {
                assert!(!record.lock().unwrap().writes.iter().any(|raw| {
                    serde_json::from_slice::<Value>(raw).unwrap()["operation"] == "publish_release"
                }));
            }
            unfinished_at(&fixture, &before, Some(1010));
        }
    }

    #[test]
    fn expired_after_release_intent_never_sends_release() {
        let fixture = Fixture::new();
        let negotiated = negotiated();
        let mut journal = fixture.ready(&negotiated);
        let (mut exchange, record) = data_scripted(&fixture);
        exchange.finish_reply = true;
        exchange.finish_fault = Some("after_fsync");
        let normalized = data_scanning(&fixture, &mut journal, &negotiated, exchange)
            .collect_selected("2026-01-01T00:00:00Z")
            .unwrap();
        let before = saved(&fixture);
        assert!(normalized.prepare(&mut journal).is_err());
        assert!(!record.lock().unwrap().writes.iter().any(|raw| {
            serde_json::from_slice::<Value>(raw).unwrap()["operation"] == "publish_release"
        }));
        assert!(saved(&fixture)["collection"]["active"]["native_attempt"]["release_requested_boottime_ms"].is_u64());
        unfinished_at(&fixture, &before, Some(1010));
    }

    fn unfinished(fixture: &Fixture, before: &Value) {
        unfinished_at(fixture, before, None);
    }
    fn unfinished_at(fixture: &Fixture, before: &Value, start: Option<u64>) {
        let mut reopened = RequestJournal::open(&fixture.dir, BOOT, &fixture.lock).unwrap();
        assert_eq!(
            reopened.recover_collection(None).unwrap(),
            crate::inventory::requests::CollectionRecovery::Unfinished
        );
        let after: Value =
            serde_json::from_slice(&std::fs::read(fixture.dir.join("requests.json")).unwrap())
                .unwrap();
        assert_eq!(after["counters"], before["counters"]);
        let retained = after["collection"]["active"]
            .as_object()
            .or_else(|| after["collection"]["last_terminal"].as_object())
            .unwrap();
        assert_eq!(retained["submitted"], true);
        let scan = &retained["proof"]["evidence"]["scan"];
        if let Some(start) = start {
            assert_eq!(scan["started_boottime_ms"], start);
            assert!(scan["finished_boottime_ms"].is_null());
        } else {
            assert!(scan.is_null());
        }
        assert_eq!(
            retained["native_attempt"]["observation_nonce"],
            "0000000000000008bbbbbbbbbbbbbbbb"
        );
        assert!(
            reopened
                .admit_native_collection(
                    REPORT,
                    1,
                    1,
                    &clock(1010),
                    "cccccccccccccccc",
                    &negotiated()
                )
                .is_err()
        );
    }
    fn saved(fixture: &Fixture) -> Value {
        serde_json::from_slice(&std::fs::read(fixture.dir.join("requests.json")).unwrap()).unwrap()
    }

    #[test]
    fn publication_uses_durable_native_admission_before_one_exact_reporter_write() {
        let fixture = Fixture::new();
        let session = negotiated();
        let mut journal = fixture.ready(&session);
        let intent = journal
            .admit_native_collection(REPORT, 1, 1, &clock(1001), "bbbbbbbbbbbbbbbb", &session)
            .unwrap();
        let (exchange, record) = scripted(&fixture);
        let pinned = PinnedSession::admit(exchange, expected()).unwrap();
        let published = pinned.publish(&mut journal, intent, &session).unwrap();
        assert_eq!(
            published.published.observation_nonce(),
            "0000000000000008bbbbbbbbbbbbbbbb"
        );
        assert_eq!(published.session.context.pinned_boottime_ms, 1001);
        let saved = record.lock().unwrap();
        assert!(saved.durable_seen);
        assert_eq!(saved.writes.len(), 1);
        let command: Value = serde_json::from_slice(&saved.writes[0]).unwrap();
        assert_eq!(
            command,
            json!({"schema_version":1,"id":1,"operation":"publish_observation","nonce":"0000000000000008bbbbbbbbbbbbbbbb"})
        );
        drop(saved);
        drop(published);
        assert_eq!(record.lock().unwrap().closes, 1);
    }

    #[test]
    fn pin_admission_rechecks_original_deadline_after_frame_validation() {
        let fixture = Fixture::new();
        let (mut exchange, record) = scripted(&fixture);
        exchange.times = VecDeque::from([clock(1002), clock(1002), clock(121002)]);
        assert!(PinnedSession::admit(exchange, expected()).is_err());
        let record = record.lock().unwrap();
        assert!(record.writes.is_empty());
        assert_eq!(record.closes, 1);
    }

    #[test]
    fn root_offer_attaches_exact_scan_durably_before_scan_admitted_ack() {
        let fixture = Fixture::new();
        let session = negotiated();
        let mut journal = fixture.ready(&session);
        let intent = journal
            .admit_native_collection(REPORT, 1, 1, &clock(1001), "bbbbbbbbbbbbbbbb", &session)
            .unwrap();
        let (exchange, record) = scan_scripted(&fixture);
        let published = PinnedSession::admit(exchange, expected())
            .unwrap()
            .publish(&mut journal, intent, &session)
            .unwrap();
        let scanning = published.admit_scan(&mut journal, &session).unwrap();
        let scan = scanning.proof.scan.as_ref().unwrap();
        assert_eq!(scan.started_boottime_ms, 1010);
        assert!(scan.finished_boottime_ms.is_none());
        assert_eq!(scanning.session.last, 1012);
        assert_eq!(scanning.session.deadline, 10000);
        assert_eq!(scanning.offer.lock_open_boottime_ms, 1005);
        assert!(!scanning.proof.ready());
        let record = record.lock().unwrap();
        assert!(record.scan_seen);
        assert_eq!(record.writes.len(), 3);
        let command: Value = serde_json::from_slice(&record.writes[2]).unwrap();
        assert_eq!(
            command,
            json!({"schema_version":1,"id":3,"operation":"scan_admitted","scan_started_boottime_ms":1010})
        );
    }

    #[test]
    fn fresh_root_lease_mismatch_never_admits_a_scan() {
        let fixture = Fixture::new();
        let negotiated = negotiated();
        let mut journal = fixture.ready(&negotiated);
        let intent = journal
            .admit_native_collection(REPORT, 1, 1, &clock(1001), "bbbbbbbbbbbbbbbb", &negotiated)
            .unwrap();
        let (mut exchange, record) = scan_scripted(&fixture);
        exchange.root_lease_mismatch = true;
        let published = PinnedSession::admit(exchange, expected())
            .unwrap()
            .publish(&mut journal, intent, &negotiated)
            .unwrap();
        let before = saved(&fixture);
        assert!(published.admit_scan(&mut journal, &negotiated).is_err());
        assert!(!record.lock().unwrap().writes.iter().any(|raw| {
            serde_json::from_slice::<Value>(raw).unwrap()["operation"] == "scan_admitted"
        }));
        unfinished(&fixture, &before);
    }

    #[test]
    fn fixed_reporter_tools_feed_the_existing_selected_normalizer_without_currency_claims() {
        let fixture = Fixture::new();
        let session = negotiated();
        let mut journal = fixture.ready(&session);
        let intent = journal
            .admit_native_collection(REPORT, 1, 1, &clock(1001), "bbbbbbbbbbbbbbbb", &session)
            .unwrap();
        let (mut exchange, record) = scan_scripted(&fixture);
        exchange.data_reply = true;
        exchange.times.extend((0..200).map(|_| clock(1012)));
        let scanning = PinnedSession::admit(exchange, expected())
            .unwrap()
            .publish(&mut journal, intent, &session)
            .unwrap()
            .admit_scan(&mut journal, &session)
            .unwrap();
        let normalized = scanning.collect_selected("2026-01-01T00:00:00Z").unwrap();
        assert_eq!(normalized.scan["scanId"], REPORT);
        assert_eq!(normalized.scan["inventoryComplete"], true);
        assert!(normalized.scan["aptIndexOldestAt"].is_null());
        assert_eq!(normalized.scan["applicationIdentification"], "partial");
        let packages = normalized.scan["packages"].as_array().unwrap();
        assert_eq!(packages.len(), 2);
        assert_eq!(packages[0]["packageId"], "inventory-proof:arm64");
        assert_eq!(packages[0]["latestVersion"], "1.0");
        assert_eq!(packages[1]["held"], true);
        assert_eq!(packages[1]["provider"], "APT");
        for package in packages {
            assert_eq!(package["reliableMatch"], false);
            assert_eq!(package["upgradeAvailable"], false);
        }
        assert!(
            normalized
                .scanning
                .proof
                .scan
                .as_ref()
                .unwrap()
                .finished_boottime_ms
                .is_none()
        );
        let writes = &record.lock().unwrap().writes;
        let data: Vec<Value> = writes[3..]
            .iter()
            .map(|raw| serde_json::from_slice(raw).unwrap())
            .collect();
        assert_eq!(
            data.iter()
                .map(|frame| frame["operation"].as_str().unwrap())
                .collect::<Vec<_>>(),
            ["installed", "holds", "policy", "architecture"]
        );
        assert_eq!(
            data[2]["packages"],
            json!(["inventory-proof:arm64", "nginx:arm64"])
        );
    }

    #[test]
    fn swallowed_tool_failures_and_malformed_inventory_never_escape_as_normalized_drafts() {
        for fault in [
            "holds",
            "policy",
            "architecture",
            "bad_policy_final",
            "bad_chunk",
            "architecture_overflow",
            "installed_malformed",
            "host_error",
            "host_overflow",
        ] {
            let fixture = Fixture::new();
            let session = negotiated();
            let mut journal = fixture.ready(&session);
            let (mut exchange, record) = data_scripted(&fixture);
            exchange.data_fault = Some(fault);
            let scanning = data_scanning(&fixture, &mut journal, &session, exchange);
            let before = saved(&fixture);
            let error = match scanning.collect_selected("2026-01-01T00:00:00Z") {
                Ok(_) => panic!("Invalid draft for {fault}"),
                Err(error) => error,
            };
            assert_eq!(error, ERROR);
            let recorded = record.lock().unwrap();
            assert_eq!(recorded.closes, 1);
            let operations: Vec<String> = recorded.writes[3..]
                .iter()
                .map(|raw| {
                    serde_json::from_slice::<Value>(raw).unwrap()["operation"]
                        .as_str()
                        .unwrap()
                        .to_owned()
                })
                .collect();
            match fault {
                "holds" => assert_eq!(operations, ["installed", "holds"]),
                "policy" | "bad_policy_final" => {
                    assert_eq!(operations, ["installed", "holds", "policy"])
                }
                "host_error" | "host_overflow" => assert!(operations.is_empty()),
                _ => {}
            }
            drop(recorded);
            drop(journal);
            unfinished_at(&fixture, &before, Some(1010));
        }
    }

    #[test]
    fn fixed_tool_whitelist_rejects_options_programs_limits_and_policy_aliases_without_io() {
        let cases = vec![
            ("/bin/sh", vec!["-c", "true"], 4096),
            ("/bin/hostname", vec![], 4095),
            ("/usr/bin/uname", vec!["-a"], 4096),
            (
                "/usr/bin/dpkg-query",
                vec!["--search", "/usr/share/applications/*.desktop"],
                1024 * 1024,
            ),
            (
                "/usr/bin/dpkg",
                vec!["--admindir=/tmp", "--print-architecture"],
                128,
            ),
            ("/usr/bin/apt-mark", vec!["showhold"], 1024 * 1024),
            (
                "/usr/bin/apt-cache",
                vec![
                    "-o",
                    "Dir::Cache::pkgcache=",
                    "-o",
                    "Dir::Cache::srcpkgcache=",
                    "policy",
                    "-oBad=1",
                ],
                16 * 1024 * 1024,
            ),
            (
                "/usr/bin/apt-cache",
                vec![
                    "-o",
                    "Dir::Cache::pkgcache=",
                    "-o",
                    "Dir::Cache::srcpkgcache=",
                    "policy",
                    "pkg",
                    "pkg",
                ],
                16 * 1024 * 1024,
            ),
        ];
        for (program, args, limit) in cases {
            let fixture = Fixture::new();
            let session = negotiated();
            let mut journal = fixture.ready(&session);
            let (exchange, record) = data_scripted(&fixture);
            let tools = FixedTools::new(data_scanning(&fixture, &mut journal, &session, exchange));
            assert_eq!(tools.text(program, &args, limit).unwrap_err(), ERROR);
            assert!(tools.text("/bin/hostname", &[], 4096).is_err());
            assert!(tools.into_scanning().is_err());
            let record = record.lock().unwrap();
            assert_eq!(record.writes.len(), 3);
            assert_eq!(record.host_calls, 0);
            assert_eq!(record.closes, 1);
        }
    }

    #[test]
    fn digest_is_never_a_system_tools_fallback_or_partial_success() {
        let fixture = Fixture::new();
        let session = negotiated();
        let mut journal = fixture.ready(&session);
        let (exchange, record) = data_scripted(&fixture);
        let tools = FixedTools::new(data_scanning(&fixture, &mut journal, &session, exchange));
        assert_eq!(tools.sha256(b"synthetic private body").unwrap_err(), ERROR);
        assert!(tools.text("/bin/hostname", &[], 4096).is_err());
        assert!(tools.into_scanning().is_err());
        let record = record.lock().unwrap();
        assert_eq!(record.writes.len(), 3);
        assert_eq!(record.host_calls, 0);
    }

    #[test]
    fn repeated_fixed_read_poison_cannot_reset_shared_data_session() {
        let fixture = Fixture::new();
        let session = negotiated();
        let mut journal = fixture.ready(&session);
        let (exchange, record) = data_scripted(&fixture);
        let tools = FixedTools::new(data_scanning(&fixture, &mut journal, &session, exchange));
        assert_eq!(
            tools
                .text("/usr/bin/dpkg", &["--print-architecture"], 128)
                .unwrap(),
            "arm64\n"
        );
        assert!(
            tools
                .text("/usr/bin/dpkg", &["--print-architecture"], 128)
                .is_err()
        );
        assert!(tools.text("/bin/hostname", &[], 4096).is_err());
        assert!(tools.into_scanning().is_err());
        let record = record.lock().unwrap();
        assert_eq!(record.writes.len(), 4);
        assert_eq!(record.reads, 6);
    }

    #[test]
    fn in_flight_poison_stops_next_port_effect_and_withholds_completed_text() {
        for on_final in [false, true] {
            let fixture = Fixture::new();
            let session = negotiated();
            let mut journal = fixture.ready(&session);
            let (exchange, record) = data_scripted(&fixture);
            let tools = FixedTools::new(data_scanning(&fixture, &mut journal, &session, exchange));
            {
                let mut scanning = tools.scanning.lock().unwrap();
                let exchange = scanning.session.exchange.as_mut().unwrap();
                if on_final {
                    exchange.poison_on_data_final = Some(tools.failed.clone());
                } else {
                    exchange.poison_on_data_write = Some(tools.failed.clone());
                }
            }
            assert!(
                tools
                    .text("/usr/bin/dpkg", &["--print-architecture"], 128)
                    .is_err()
            );
            assert!(tools.text("/bin/hostname", &[], 4096).is_err());
            assert!(tools.into_scanning().is_err());
            let record = record.lock().unwrap();
            assert_eq!(record.writes.len(), 4);
            assert_eq!(record.reads, if on_final { 6 } else { 4 });
            assert_eq!(record.host_calls, 0);
        }
    }

    #[test]
    fn concurrent_tool_entry_fails_without_waiting_for_the_locked_session() {
        let fixture = Fixture::new();
        let session = negotiated();
        let mut journal = fixture.ready(&session);
        let (exchange, record) = data_scripted(&fixture);
        let tools = Arc::new(FixedTools::new(data_scanning(
            &fixture,
            &mut journal,
            &session,
            exchange,
        )));
        let locked = tools.scanning.lock().unwrap();
        let other = tools.clone();
        let (sent, received) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            sent.send(other.text("/bin/hostname", &[], 4096)).unwrap();
        });
        let result = received.recv_timeout(std::time::Duration::from_secs(1));
        drop(locked);
        thread.join().unwrap();
        assert!(result.unwrap().is_err());
        assert!(tools.text("/bin/hostname", &[], 4096).is_err());
        drop(tools);
        let record = record.lock().unwrap();
        assert_eq!(record.host_calls, 0);
        assert_eq!(record.writes.len(), 3);
        assert_eq!(record.closes, 1);
    }

    #[test]
    fn data_calls_keep_the_earlier_original_or_root_deadline() {
        for original in [false, true] {
            let fixture = Fixture::new();
            let session = negotiated();
            let mut journal = fixture.ready(&session);
            let (mut exchange, record) = data_scripted(&fixture);
            if original {
                let mut frame: Value = serde_json::from_slice(&proposal()).unwrap();
                frame["offer"]["expires_boottime_ms"] = json!(121005);
                exchange.frames[2] = format!("{frame}\n").into_bytes();
                exchange.root_expiry = 121005;
                exchange.times[32] = clock(121002);
            } else {
                exchange.times[32] = clock(10000);
            }
            let scanning = data_scanning(&fixture, &mut journal, &session, exchange);
            let before = saved(&fixture);
            assert!(scanning.collect_selected("2026-01-01T00:00:00Z").is_err());
            let record = record.lock().unwrap();
            assert_eq!(record.writes.len(), 4);
            assert_eq!(record.reads, 5);
            assert_eq!(record.closes, 1);
            drop(record);
            drop(journal);
            unfinished_at(&fixture, &before, Some(1010));
        }
    }

    #[test]
    fn malformed_or_mismatched_offer_never_attaches_or_acknowledges_scan() {
        for change in 0..16 {
            let fixture = Fixture::new();
            let session = negotiated();
            let mut journal = fixture.ready(&session);
            let intent = journal
                .admit_native_collection(REPORT, 1, 1, &clock(1001), "bbbbbbbbbbbbbbbb", &session)
                .unwrap();
            let before = saved(&fixture);
            let (mut exchange, record) = scan_scripted(&fixture);
            let mut frame: Value = serde_json::from_slice(&proposal()).unwrap();
            match change {
                0 => frame["offer"]["nonce"] = json!("0000000000000008cccccccccccccccc"),
                1 => frame["offer"]["boot_id"] = json!("00000000-0000-4000-8000-000000000003"),
                2 => frame["offer"]["cache_generation"] = json!("d".repeat(32)),
                3 => frame["offer"]["policy_generation"] = json!("d".repeat(64)),
                4 => frame["offer"]["lock_open_boottime_ms"] = json!(1000),
                5 => frame["scan_started_boottime_ms"] = json!(1004),
                6 => frame["scan_started_boottime_ms"] = json!(1013),
                7 => frame["offer"]["expires_boottime_ms"] = json!(1004),
                8 => frame["offer"]["expires_boottime_ms"] = json!(121006),
                9 => frame["offer"]["expires_boottime_ms"] = json!(1012),
                10 => frame["scan_started_boottime_ms"] = json!(true),
                11 => frame["offer"]["lock_open_boottime_ms"] = json!(1005.0),
                12 => frame["offer"]["extra"] = json!(0),
                13 => frame["id"] = json!(3),
                14 => frame["extra"] = json!(0),
                _ => frame["offer"]["expires_boottime_ms"] = json!(SAFE + 1),
            }
            exchange.frames[2] = format!("{frame}\n").into_bytes();
            let published = PinnedSession::admit(exchange, expected())
                .unwrap()
                .publish(&mut journal, intent, &session)
                .unwrap();
            assert!(
                published.admit_scan(&mut journal, &session).is_err(),
                "case {change}"
            );
            let record = record.lock().unwrap();
            assert_eq!(record.writes.len(), 2);
            assert!(!record.scan_seen);
            assert_eq!(record.closes, 1);
            drop(record);
            drop(journal);
            unfinished(&fixture, &before);
        }
    }

    #[test]
    fn lost_offer_authority_allows_metadata_exchange_but_never_scan_ack() {
        for change in 0..4 {
            let fixture = Fixture::new();
            let session = negotiated();
            let mut journal = fixture.ready(&session);
            let intent = journal
                .admit_native_collection(REPORT, 1, 1, &clock(1001), "bbbbbbbbbbbbbbbb", &session)
                .unwrap();
            let before = saved(&fixture);
            let (exchange, record) = scan_scripted(&fixture);
            let published = PinnedSession::admit(exchange, expected())
                .unwrap()
                .publish(&mut journal, intent, &session)
                .unwrap();
            let current = if change == 0 {
                negotiated()
            } else {
                session.clone()
            };
            match change {
                1 => {
                    journal.unconfirmed(Capability::Collection).unwrap();
                }
                2 => {
                    let pending = journal.pending(Capability::Collection).unwrap().unwrap();
                    journal
                        .canonical(
                            Capability::Collection,
                            &Canonical {
                                schema_version: 1,
                                request: CanonicalRequest {
                                    request_id: pending.request_id,
                                    delivery_sequence: pending.delivery_sequence,
                                    status: CanonicalStatus::Failed,
                                    reason: Some("inventory_authority_changed".into()),
                                    report_id: None,
                                    report_sha256: None,
                                    operation_nonce: pending.operation_nonce,
                                },
                                receipt: None,
                            },
                        )
                        .unwrap();
                }
                3 => {
                    let path = fixture.dir.join("requests.json");
                    let mut bytes = std::fs::read(&path).unwrap();
                    bytes.push(b'\n');
                    std::fs::write(path, bytes).unwrap();
                }
                _ => {}
            }
            assert!(published.admit_scan(&mut journal, &current).is_err());
            let record = record.lock().unwrap();
            assert_eq!(record.writes.len(), 2);
            assert!(!record.scan_seen);
            drop(record);
            drop(journal);
            unfinished(&fixture, &before);
        }
    }

    #[test]
    fn failed_attachment_persistence_never_sends_scan_admitted_ack() {
        let fixture = Fixture::new();
        let session = negotiated();
        let mut journal = fixture.ready(&session);
        let intent = journal
            .admit_native_collection(REPORT, 1, 1, &clock(1001), "bbbbbbbbbbbbbbbb", &session)
            .unwrap();
        let before = saved(&fixture);
        let (mut exchange, record) = scan_scripted(&fixture);
        exchange.fail_attach = true;
        let published = PinnedSession::admit(exchange, expected())
            .unwrap()
            .publish(&mut journal, intent, &session)
            .unwrap();
        assert!(published.admit_scan(&mut journal, &session).is_err());
        assert!(journal.pending(Capability::Collection).is_err());
        let record = record.lock().unwrap();
        assert_eq!(record.writes.len(), 2);
        assert!(!record.scan_seen);
        drop(record);
        std::fs::remove_dir(fixture.dir.join("requests.pending")).unwrap();
        drop(journal);
        unfinished(&fixture, &before);
    }

    #[test]
    fn expired_after_attach_fsync_retains_proof_but_never_sends_scan_ack() {
        for expiry in [10000, 121002] {
            let fixture = Fixture::new();
            let session = negotiated();
            let mut journal = fixture.ready(&session);
            let intent = journal
                .admit_native_collection(REPORT, 1, 1, &clock(1001), "bbbbbbbbbbbbbbbb", &session)
                .unwrap();
            let before = saved(&fixture);
            let (mut exchange, record) = scan_scripted(&fixture);
            exchange.times[15] = clock(expiry);
            if expiry == 121002 {
                let mut frame: Value = serde_json::from_slice(&proposal()).unwrap();
                frame["offer"]["expires_boottime_ms"] = json!(121005);
                exchange.frames[2] = format!("{frame}\n").into_bytes();
                exchange.root_expiry = 121005;
            }
            let published = PinnedSession::admit(exchange, expected())
                .unwrap()
                .publish(&mut journal, intent, &session)
                .unwrap();
            assert!(published.admit_scan(&mut journal, &session).is_err());
            assert_eq!(
                saved(&fixture)["collection"]["active"]["proof"]["evidence"]["scan"]["started_boottime_ms"],
                1010
            );
            let record = record.lock().unwrap();
            assert_eq!(record.writes.len(), 2);
            assert!(!record.scan_seen);
            drop(record);
            drop(journal);
            unfinished_at(&fixture, &before, Some(1010));
        }
    }

    #[test]
    fn owner_clock_never_rewinds_to_the_historical_proposal() {
        let fixture = Fixture::new();
        let session = negotiated();
        let mut journal = fixture.ready(&session);
        let intent = journal
            .admit_native_collection(REPORT, 1, 1, &clock(1001), "bbbbbbbbbbbbbbbb", &session)
            .unwrap();
        let before = saved(&fixture);
        let (mut exchange, record) = scan_scripted(&fixture);
        exchange.times[15] = clock(1011);
        let published = PinnedSession::admit(exchange, expected())
            .unwrap()
            .publish(&mut journal, intent, &session)
            .unwrap();
        assert!(published.admit_scan(&mut journal, &session).is_err());
        assert_eq!(record.lock().unwrap().writes.len(), 2);
        drop(journal);
        unfinished_at(&fixture, &before, Some(1010));
    }

    #[test]
    fn failed_or_malformed_scanning_ack_never_erases_started_evidence() {
        for change in 0..8 {
            let fixture = Fixture::new();
            let session = negotiated();
            let mut journal = fixture.ready(&session);
            let intent = journal
                .admit_native_collection(REPORT, 1, 1, &clock(1001), "bbbbbbbbbbbbbbbb", &session)
                .unwrap();
            let before = saved(&fixture);
            let (mut exchange, record) = scan_scripted(&fixture);
            let mut frame: Value = serde_json::from_slice(&scanning_ack()).unwrap();
            match change {
                0 => frame["id"] = json!(2),
                1 => frame["scan_started_boottime_ms"] = json!(1011),
                2 => frame["scan_started_boottime_ms"] = json!(true),
                3 => frame["phase"] = json!("prepared"),
                4 => frame["extra"] = json!(0),
                5 => exchange.fail_scan_ack = true,
                6 => exchange.change_after_scanning = true,
                _ => {}
            }
            exchange.frames[3] = if change == 7 {
                b"{\"schema_version\":1".to_vec()
            } else {
                format!("{frame}\n").into_bytes()
            };
            let published = PinnedSession::admit(exchange, expected())
                .unwrap()
                .publish(&mut journal, intent, &session)
                .unwrap();
            assert!(
                published.admit_scan(&mut journal, &session).is_err(),
                "case {change}"
            );
            let record = record.lock().unwrap();
            assert_eq!(record.writes.len(), 3);
            assert!(record.scan_seen);
            assert_eq!(record.closes, 1);
            drop(record);
            drop(journal);
            unfinished_at(&fixture, &before, Some(1010));
        }
    }

    #[test]
    fn final_deadline_check_covers_the_protected_post_ack_journal_read() {
        let fixture = Fixture::new();
        let session = negotiated();
        let mut journal = fixture.ready(&session);
        let intent = journal
            .admit_native_collection(REPORT, 1, 1, &clock(1001), "bbbbbbbbbbbbbbbb", &session)
            .unwrap();
        let before = saved(&fixture);
        let (mut exchange, record) = scan_scripted(&fixture);
        exchange.times[19] = clock(10000);
        let published = PinnedSession::admit(exchange, expected())
            .unwrap()
            .publish(&mut journal, intent, &session)
            .unwrap();
        assert!(published.admit_scan(&mut journal, &session).is_err());
        let record = record.lock().unwrap();
        assert_eq!(record.reads, 4);
        assert_eq!(record.samples, 20);
        assert!(record.scan_seen);
        drop(record);
        drop(journal);
        unfinished_at(&fixture, &before, Some(1010));
    }

    #[test]
    fn invalid_pin_fields_cannot_produce_a_publication_session() {
        for change in 0..10 {
            let fixture = Fixture::new();
            let (mut exchange, record) = scripted(&fixture);
            let mut frame: Value = serde_json::from_slice(&initial()).unwrap();
            match change {
                0 => frame["id"] = json!(false),
                1 => frame["context"]["pinned_boottime_ms"] = json!(true),
                2 => frame["context"]["pinned_boottime_ms"] = json!(1003),
                3 => frame["context"]["cache_generation"] = json!("d".repeat(32)),
                4 => frame["context"]["policy_generation"] = json!("d".repeat(64)),
                5 => frame["context"]["boot_id"] = json!("00000000-0000-4000-8000-000000000003"),
                6 => frame["context"]["successful_checked_at"] = json!("2026-01-01T00:00:00.123Z"),
                7 => frame["context"]["extra"] = json!(false),
                8 => frame["extra"] = json!(false),
                _ => frame["phase"] = json!("published"),
            }
            exchange.frames[0] = format!("{frame}\n").into_bytes();
            assert!(
                PinnedSession::admit(exchange, expected()).is_err(),
                "case {change}"
            );
            let record = record.lock().unwrap();
            assert!(record.writes.is_empty());
            assert_eq!(record.closes, 1);
        }
        for timestamp in [
            "2026-01-01T00:00:00Z",
            "2026-01-01T00:00:00.1Z",
            "2026-01-01T00:00:00.123456Z",
            "2024-02-29T23:59:59.123Z",
        ] {
            assert!(checked_at(timestamp));
        }
        for timestamp in [
            "2026-02-29T00:00:00Z",
            "2026-01-01T24:00:00Z",
            "2026-01-01T00:00:00.1234567Z",
            "2026-01-01T00:00:00+00:00",
            "0000-01-01T00:00:00Z",
        ] {
            assert!(!checked_at(timestamp));
        }
    }

    #[test]
    fn stale_epoch_negotiation_source_or_disk_never_invokes_reporter_io() {
        for change in 0..5 {
            let fixture = Fixture::new();
            let session = negotiated();
            let mut journal = fixture.ready(&session);
            let intent = journal
                .admit_native_collection(REPORT, 1, 1, &clock(1001), "bbbbbbbbbbbbbbbb", &session)
                .unwrap();
            let before = saved(&fixture);
            let (exchange, record) = scripted(&fixture);
            let pinned = PinnedSession::admit(exchange, expected()).unwrap();
            let current = if change == 1 {
                negotiated()
            } else {
                session.clone()
            };
            match change {
                0 => {
                    journal
                        .reserve_nonce(
                            crate::inventory::requests::OperationDomain::Helper,
                            "dddddddddddddddd",
                        )
                        .unwrap();
                }
                2 => {
                    let pending = journal.pending(Capability::Collection).unwrap().unwrap();
                    journal
                        .canonical(
                            Capability::Collection,
                            &Canonical {
                                schema_version: 1,
                                request: CanonicalRequest {
                                    request_id: pending.request_id,
                                    delivery_sequence: pending.delivery_sequence,
                                    status: CanonicalStatus::Failed,
                                    reason: Some("inventory_authority_changed".into()),
                                    report_id: None,
                                    report_sha256: None,
                                    operation_nonce: pending.operation_nonce,
                                },
                                receipt: None,
                            },
                        )
                        .unwrap();
                }
                3 => {
                    let path = fixture.dir.join("requests.json");
                    let mut bytes = std::fs::read(&path).unwrap();
                    bytes.push(b'\n');
                    std::fs::write(path, bytes).unwrap();
                }
                4 => {
                    journal.recover_collection(None).unwrap();
                }
                _ => {}
            }
            let after_change = saved(&fixture);
            assert!(
                pinned.publish(&mut journal, intent, &current).is_err(),
                "case {change}"
            );
            let record = record.lock().unwrap();
            assert!(record.writes.is_empty());
            assert_eq!(record.reads, 1);
            assert_eq!(record.closes, 1);
            drop(record);
            drop(journal);
            unfinished(&fixture, if change == 0 { &after_change } else { &before });
        }
    }

    #[test]
    fn malformed_partial_or_missing_ack_preserves_submitted_scope_without_retry() {
        for raw in [
            b"{\"schema_version\":1,\"id\":2,\"operation\":\"publish_observation\",\"phase\":\"published\"}\n".as_slice(),
            b"{\"schema_version\":1,\"id\":true,\"operation\":\"publish_observation\",\"phase\":\"published\"}\n",
            b"{\"schema_version\":1,\"id\":1.0,\"operation\":\"publish_observation\",\"phase\":\"published\"}\n",
            b"{\"schema_version\":1,\"id\":1,\"operation\":\"await_open\",\"phase\":\"published\"}\n",
            b"{\"schema_version\":1,\"id\":1,\"operation\":\"publish_observation\",\"phase\":\"scan_proposed\"}\n",
            b"{\"schema_version\":1,\"id\":1,\"operation\":\"publish_observation\",\"phase\":\"published\",\"extra\":0}\n",
            b"{\"schema_version\":1,\"id\":1,\"id\":1,\"operation\":\"publish_observation\",\"phase\":\"published\"}\n",
            b"{\"schema_version\":1",b"",
        ] {
            let fixture=Fixture::new();let session=negotiated();let mut journal=fixture.ready(&session);
            let intent=journal.admit_native_collection(REPORT,1,1,&clock(1001),"bbbbbbbbbbbbbbbb",&session).unwrap();let before=saved(&fixture);
            let (mut exchange,record)=scripted(&fixture);exchange.frames[1]=raw.to_vec();
            let pinned=PinnedSession::admit(exchange,expected()).unwrap();
            assert!(pinned.publish(&mut journal,intent,&session).is_err());
            let record=record.lock().unwrap();assert_eq!(record.writes.len(),1);assert_eq!(record.closes,1);drop(record);
            drop(journal);unfinished(&fixture,&before);
        }
    }

    #[test]
    fn visible_write_failure_and_postcallback_disk_change_never_mint_published_session() {
        for change_disk in [false, true] {
            let fixture = Fixture::new();
            let session = negotiated();
            let mut journal = fixture.ready(&session);
            let intent = journal
                .admit_native_collection(REPORT, 1, 1, &clock(1001), "bbbbbbbbbbbbbbbb", &session)
                .unwrap();
            let before = saved(&fixture);
            let (mut exchange, record) = scripted(&fixture);
            exchange.fail_write = !change_disk;
            exchange.change_on_ack = change_disk;
            let pinned = PinnedSession::admit(exchange, expected()).unwrap();
            assert!(pinned.publish(&mut journal, intent, &session).is_err());
            if change_disk {
                assert!(journal.pending(Capability::Collection).is_err());
                assert_eq!(
                    std::fs::read(fixture.dir.join("requests.json"))
                        .unwrap()
                        .last(),
                    Some(&b'\n')
                );
            }
            let record = record.lock().unwrap();
            assert_eq!(record.writes.len(), 1);
            assert_eq!(record.closes, 1);
            drop(record);
            drop(journal);
            unfinished(&fixture, &before);
        }
    }

    #[test]
    fn expiry_or_clock_failure_is_absorbing_even_after_ack_and_postsnapshot() {
        for sample in [3, 4, 5, 6, 7, 8] {
            let fixture = Fixture::new();
            let session = negotiated();
            let mut journal = fixture.ready(&session);
            let intent = journal
                .admit_native_collection(REPORT, 1, 1, &clock(1001), "bbbbbbbbbbbbbbbb", &session)
                .unwrap();
            let before = saved(&fixture);
            let (mut exchange, record) = scripted(&fixture);
            exchange.times[sample] = clock(121002);
            let pinned = PinnedSession::admit(exchange, expected()).unwrap();
            assert!(
                pinned.publish(&mut journal, intent, &session).is_err(),
                "sample {sample}"
            );
            let record = record.lock().unwrap();
            assert_eq!(record.writes.len(), usize::from(sample >= 5));
            if sample == 8 {
                assert_eq!(record.reads, 2);
                assert_eq!(record.samples, 9);
            }
            assert_eq!(record.closes, 1);
            drop(record);
            drop(journal);
            unfinished(&fixture, &before);
        }
        for changed_boot in [false, true] {
            let fixture = Fixture::new();
            let session = negotiated();
            let mut journal = fixture.ready(&session);
            let intent = journal
                .admit_native_collection(REPORT, 1, 1, &clock(1001), "bbbbbbbbbbbbbbbb", &session)
                .unwrap();
            let (mut exchange, record) = scripted(&fixture);
            exchange.times[3] = clock(1001);
            if changed_boot {
                exchange.times[3].boot_id = "00000000-0000-4000-8000-000000000003".into();
            }
            let pinned = PinnedSession::admit(exchange, expected()).unwrap();
            assert!(pinned.publish(&mut journal, intent, &session).is_err());
            assert!(record.lock().unwrap().writes.is_empty());
        }
    }
}
