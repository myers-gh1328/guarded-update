//! Test-only raw protected status reader: no typed Root or liveness authority.

use serde_json::Value;
use std::fs::{File, Metadata};
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::MetadataExt;
use std::time::Instant;

unsafe extern "C" {
    fn openat(dirfd: i32, path: *const i8, flags: i32, ...) -> i32;
}
// ARM uses its own UAPI bit assignments for AArch32 compatibility.
// https://github.com/torvalds/linux/blob/master/arch/arm64/include/uapi/asm/fcntl.h
#[cfg(all(target_os = "linux", any(target_arch = "arm", target_arch = "aarch64")))]
const DIRECTORY: i32 = 0x4000;
#[cfg(all(target_os = "linux", any(target_arch = "x86", target_arch = "x86_64")))]
const DIRECTORY: i32 = 0x10000;
#[cfg(all(target_os = "linux", any(target_arch = "arm", target_arch = "aarch64")))]
const NOFOLLOW: i32 = 0x8000;
#[cfg(all(target_os = "linux", any(target_arch = "x86", target_arch = "x86_64")))]
const NOFOLLOW: i32 = 0x20000;
#[cfg(target_os = "linux")]
const NONBLOCK: i32 = 0x800;
#[cfg(target_os = "linux")]
const CLOEXEC: i32 = 0x80000;
#[cfg(target_os = "macos")]
const DIRECTORY: i32 = 0x100000;
#[cfg(target_os = "macos")]
const NOFOLLOW: i32 = 0x100;
#[cfg(target_os = "macos")]
const NONBLOCK: i32 = 0x4;
#[cfg(target_os = "macos")]
const CLOEXEC: i32 = 0x1000000;
const ERROR: &str = "Protected reporter status unavailable";
const PARTS: [&[u8]; 3] = [b"run\0", b"command-center-inventory-refresh\0", b"status\0"];
type Result<T> = std::result::Result<T, &'static str>;

fn before(deadline: Instant) -> Result<()> {
    if Instant::now() < deadline {
        Ok(())
    } else {
        Err(ERROR)
    }
}
fn open_child(parent: &File, name: &[u8], directory: bool) -> Result<File> {
    if !name.ends_with(&[0]) || name[..name.len() - 1].contains(&0) {
        return Err(ERROR);
    }
    let flags = NOFOLLOW | NONBLOCK | CLOEXEC | if directory { DIRECTORY } else { 0 };
    // SAFETY: name has a trailing NUL, parent is borrowed and flags require no mode.
    let fd = unsafe { openat(parent.as_raw_fd(), name.as_ptr().cast(), flags) };
    if fd < 0 {
        return Err(ERROR);
    }
    // SAFETY: openat returned a new descriptor exclusively owned here.
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn stable(info: &Metadata) -> (u64, u64, u32, u32, u32, u64, u64, i64, i64, i64, i64) {
    (
        info.dev(),
        info.ino(),
        info.mode(),
        info.uid(),
        info.gid(),
        info.nlink(),
        info.size(),
        info.mtime(),
        info.mtime_nsec(),
        info.ctime(),
        info.ctime_nsec(),
    )
}
fn valid_dir(info: &Metadata, owner: u32) -> bool {
    info.is_dir() && info.uid() == owner && info.mode() & 0o022 == 0
}

const SAFE: u64 = 9_007_199_254_740_991;
fn fields<'a>(value: &'a Value, names: &[&str]) -> Result<&'a serde_json::Map<String, Value>> {
    let object = value.as_object().ok_or(ERROR)?;
    if object.len() != names.len() || names.iter().any(|name| !object.contains_key(*name)) {
        return Err(ERROR);
    }
    Ok(object)
}
fn safe(value: &Value) -> Result<u64> {
    value.as_u64().filter(|number| *number <= SAFE).ok_or(ERROR)
}
fn hex(value: &Value, size: usize) -> bool {
    value.as_str().is_some_and(|text| {
        text.len() == size
            && text
                .bytes()
                .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
    })
}
fn nonce(value: &Value) -> Result<u64> {
    if !hex(value, 32) {
        return Err(ERROR);
    }
    let text = value.as_str().ok_or(ERROR)?;
    let count = u64::from_str_radix(&text[..16], 16).map_err(|_| ERROR)?;
    if count == 0 || count > SAFE {
        Err(ERROR)
    } else {
        Ok(count)
    }
}
fn boot(value: &Value) -> bool {
    value.as_str().is_some_and(|text| {
        text.len() == 36
            && text.bytes().enumerate().all(|(i, v)| {
                if [8, 13, 18, 23].contains(&i) {
                    v == b'-'
                } else {
                    v.is_ascii_digit() || (b'a'..=b'f').contains(&v)
                }
            })
    })
}
fn utc(value: &Value) -> bool {
    value.as_str().is_some_and(super::reporter_obs::checked_at)
}
fn nullable(value: &Value, check: impl Fn(&Value) -> bool) -> bool {
    value.is_null() || check(value)
}
fn observation(value: &Value, receipt: bool) -> Result<()> {
    const LEASE: [&str; 6] = [
        "nonce",
        "boot_id",
        "cache_generation",
        "policy_generation",
        "lock_open_boottime_ms",
        "expires_boottime_ms",
    ];
    const RECEIPT: [&str; 11] = [
        "nonce",
        "boot_id",
        "cache_generation",
        "policy_generation",
        "lock_open_boottime_ms",
        "expires_boottime_ms",
        "lock_held_until_boottime_ms",
        "released_boottime_ms",
        "outcome",
        "installed_before_sha256",
        "installed_after_sha256",
    ];
    fields(value, if receipt { &RECEIPT } else { &LEASE })?;
    nonce(&value["nonce"])?;
    if !boot(&value["boot_id"])
        || !hex(&value["cache_generation"], 32)
        || !hex(&value["policy_generation"], 64)
    {
        return Err(ERROR);
    }
    let opened = safe(&value["lock_open_boottime_ms"])?;
    let expires = safe(&value["expires_boottime_ms"])?;
    if expires.checked_sub(opened).is_none_or(|span| span > 120000) {
        return Err(ERROR);
    }
    if receipt {
        let held = safe(&value["lock_held_until_boottime_ms"])?;
        let released = safe(&value["released_boottime_ms"])?;
        let outcome = value["outcome"].as_str().ok_or(ERROR)?;
        if held < opened
            || released < held
            || !matches!(outcome, "released" | "expired" | "unconfirmed")
            || !hex(&value["installed_before_sha256"], 64)
            || !hex(&value["installed_after_sha256"], 64)
            || (outcome == "released"
                && (released > expires
                    || value["installed_before_sha256"] != value["installed_after_sha256"]))
        {
            return Err(ERROR);
        }
    }
    Ok(())
}
pub(super) fn validate_status(value: &Value) -> Result<()> {
    fields(
        value,
        &[
            "schema_version",
            "operation_nonce",
            "phase",
            "reason",
            "policy_generation",
            "cache_generation",
            "successful_checked_at",
            "started_at",
            "finished_at",
            "attempt",
            "observation_lease",
            "observation_receipt",
        ],
    )?;
    if value["schema_version"].as_u64() != Some(1) {
        return Err(ERROR);
    }
    let phase = value["phase"].as_str().ok_or(ERROR)?;
    if !matches!(
        phase,
        "received" | "running" | "succeeded" | "deferred" | "failed" | "unconfirmed"
    ) {
        return Err(ERROR);
    }
    let reason = &value["reason"];
    if matches!(phase, "received" | "running" | "succeeded") {
        if !reason.is_null() {
            return Err(ERROR);
        }
    } else if !reason.as_str().is_some_and(|r| {
        matches!(
            r,
            "busy"
                | "package_manager_busy"
                | "executor_busy"
                | "minimum_interval"
                | "policy_unsupported"
                | "policy_changed"
                | "repository_failed"
                | "timeout"
                | "resource_limit"
                | "cleanup_unconfirmed"
                | "cache_unavailable"
                | "state_inconsistent"
                | "invalid_request"
                | "lease_expired"
                | "internal_error"
        )
    }) {
        return Err(ERROR);
    }
    if !value["operation_nonce"].is_null() {
        nonce(&value["operation_nonce"])?;
    }
    if !nullable(&value["policy_generation"], |v| hex(v, 64))
        || !nullable(&value["cache_generation"], |v| hex(v, 32))
        || !nullable(&value["successful_checked_at"], utc)
        || !nullable(&value["started_at"], utc)
        || !nullable(&value["finished_at"], utc)
    {
        return Err(ERROR);
    }
    if (!value["cache_generation"].is_null() || !value["successful_checked_at"].is_null())
        && (value["cache_generation"].is_null()
            || value["policy_generation"].is_null()
            || value["successful_checked_at"].is_null())
    {
        return Err(ERROR);
    }
    let attempt = &value["attempt"];
    if attempt.is_null() {
        if !matches!(phase, "deferred" | "failed" | "unconfirmed")
            || !value["operation_nonce"].is_null()
            || !value["started_at"].is_null()
            || !value["finished_at"].is_null()
        {
            return Err(ERROR);
        }
    } else {
        fields(
            attempt,
            &[
                "correlator",
                "helper_sequence",
                "boot_id",
                "accepted_boottime_ms",
                "started_boottime_ms",
                "finished_boottime_ms",
            ],
        )?;
        if nonce(&attempt["correlator"])? != safe(&attempt["helper_sequence"])?
            || attempt["correlator"] != value["operation_nonce"]
            || !boot(&attempt["boot_id"])
        {
            return Err(ERROR);
        }
        let accepted = safe(&attempt["accepted_boottime_ms"])?;
        let started = if attempt["started_boottime_ms"].is_null() {
            None
        } else {
            Some(safe(&attempt["started_boottime_ms"])?)
        };
        let finished = if attempt["finished_boottime_ms"].is_null() {
            None
        } else {
            Some(safe(&attempt["finished_boottime_ms"])?)
        };
        if started.is_some_and(|n| n < accepted)
            || finished.is_some_and(|n| n < started.unwrap_or(accepted))
            || (phase == "received" && (started.is_some() || finished.is_some()))
            || (phase == "deferred" && started.is_some())
            || (phase == "running" && (started.is_none() || finished.is_some()))
            || (phase == "succeeded"
                && (started.is_none()
                    || finished.is_none()
                    || finished.unwrap_or(0) - started.unwrap_or(0) > 600000))
            || (!value["started_at"].is_null() && started.is_none())
            || (!value["finished_at"].is_null() && finished.is_none())
        {
            return Err(ERROR);
        }
    }
    if phase == "succeeded"
        && (value["cache_generation"].is_null()
            || value["policy_generation"].is_null()
            || value["successful_checked_at"].is_null())
    {
        return Err(ERROR);
    }
    let lease = &value["observation_lease"];
    let receipt = &value["observation_receipt"];
    if !lease.is_null() {
        observation(lease, false)?;
        if lease["cache_generation"] != value["cache_generation"]
            || lease["policy_generation"] != value["policy_generation"]
        {
            return Err(ERROR);
        }
    }
    if !receipt.is_null() {
        observation(receipt, true)?;
    }
    if !lease.is_null() && !receipt.is_null() && lease["nonce"] == receipt["nonce"] {
        return Err(ERROR);
    }
    Ok(())
}

pub(super) struct StatusReader {
    dirs: Vec<File>,
    owner: u32,
    group: u32,
}
impl StatusReader {
    #[cfg(target_os = "linux")]
    pub(super) fn fixed() -> Result<Self> {
        unsafe extern "C" {
            fn geteuid() -> u32;
            fn getegid() -> u32;
        }
        // SAFETY: these identity queries take no pointers and do not modify state.
        let (uid, gid) = unsafe { (geteuid(), getegid()) };
        let marker = std::env::var("GITHUB_ACTIONS").ok();
        admit_fixed(
            uid,
            gid,
            marker.as_deref(),
            || {
                let file = File::open("/proc/self/cgroup").map_err(|_| ERROR)?;
                let mut raw = Vec::new();
                file.take(4097).read_to_end(&mut raw).map_err(|_| ERROR)?;
                Ok(raw)
            },
            || Self::open_from(File::open("/").map_err(|_| ERROR)?, 0, 60002),
        )
    }
    fn open_from(root: File, owner: u32, group: u32) -> Result<Self> {
        let mut dirs = vec![root];
        for part in PARTS {
            let child = open_child(dirs.last().ok_or(ERROR)?, part, true)?;
            dirs.push(child);
        }
        let result = Self { dirs, owner, group };
        result.verify()?;
        Ok(result)
    }
    fn verify(&self) -> Result<()> {
        if self.dirs.len() != 4
            || self.dirs.iter().any(|file| {
                !file
                    .metadata()
                    .is_ok_and(|metadata| valid_dir(&metadata, self.owner))
            })
        {
            return Err(ERROR);
        }
        for (index, part) in PARTS.iter().enumerate() {
            let named = open_child(&self.dirs[index], part, true)?
                .metadata()
                .map_err(|_| ERROR)?;
            let held = self.dirs[index + 1].metadata().map_err(|_| ERROR)?;
            if !valid_dir(&named, self.owner)
                || (named.dev(), named.ino()) != (held.dev(), held.ino())
            {
                return Err(ERROR);
            }
        }
        let status = self.dirs[3].metadata().map_err(|_| ERROR)?;
        if status.gid() != self.group || status.mode() & 0o7777 != 0o750 {
            return Err(ERROR);
        }
        Ok(())
    }
    fn valid_file(&self, info: &Metadata, dev: u64) -> bool {
        info.is_file()
            && info.uid() == self.owner
            && info.gid() == self.group
            && info.mode() & 0o7777 == 0o640
            && info.nlink() == 1
            && info.dev() == dev
            && info.size() > 0
            && info.size() <= 65536
    }
    pub(super) fn read(&self, deadline: Instant) -> Result<Value> {
        self.read_with(deadline, || {})
    }
    fn read_with(&self, deadline: Instant, after_read: impl FnOnce()) -> Result<Value> {
        before(deadline)?;
        self.verify()?;
        before(deadline)?;
        let dir = &self.dirs[3];
        let dev = dir.metadata().map_err(|_| ERROR)?.dev();
        let mut file = open_child(dir, b"status.json\0", false)?;
        let initial = file.metadata().map_err(|_| ERROR)?;
        if !self.valid_file(&initial, dev) {
            return Err(ERROR);
        }
        before(deadline)?;
        let mut bytes = Vec::new();
        file.by_ref()
            .take(65537)
            .read_to_end(&mut bytes)
            .map_err(|_| ERROR)?;
        after_read();
        before(deadline)?;
        let after = file.metadata().map_err(|_| ERROR)?;
        let named = open_child(dir, b"status.json\0", false)?
            .metadata()
            .map_err(|_| ERROR)?;
        if !self.valid_file(&after, dev)
            || !self.valid_file(&named, dev)
            || stable(&initial) != stable(&after)
            || stable(&after) != stable(&named)
            || bytes.len() as u64 != initial.size()
        {
            return Err(ERROR);
        }
        self.verify()?;
        before(deadline)?;
        let parsed = super::reporter_frame::parse_object(&bytes).map_err(|_| ERROR)?;
        let after_parse = file.metadata().map_err(|_| ERROR)?;
        let final_named = open_child(dir, b"status.json\0", false)?
            .metadata()
            .map_err(|_| ERROR)?;
        if !self.valid_file(&after_parse, dev)
            || !self.valid_file(&final_named, dev)
            || stable(&initial) != stable(&after_parse)
            || stable(&initial) != stable(&final_named)
        {
            return Err(ERROR);
        }
        self.verify()?;
        before(deadline)?;
        Ok(parsed)
    }
}

fn admit_fixed<T>(
    uid: u32,
    gid: u32,
    marker: Option<&str>,
    read_group: impl FnOnce() -> Result<Vec<u8>>,
    open: impl FnOnce() -> Result<T>,
) -> Result<T> {
    if uid != 60002 || gid != 60002 || marker != Some("true") {
        return Err(ERROR);
    }
    let group = read_group()?;
    if group!=b"0::/command.slice/command-center.slice/command-center-inventory.slice/command-center-inventory.service\n" {return Err(ERROR);}
    open()
}

#[cfg(test)]
mod tests {
    use super::{StatusReader, validate_status};
    use serde_json::{Value, json};
    use std::os::unix::fs::PermissionsExt;
    use std::time::{Duration, Instant};

    #[test]
    fn fixed_status_gate_denies_before_reading_or_opening_any_status() {
        use std::cell::Cell;
        let reads = Cell::new(0);
        let opens = Cell::new(0);
        let run = |uid, gid, marker, cgroup: &[u8]| {
            super::admit_fixed(
                uid,
                gid,
                marker,
                || {
                    reads.set(reads.get() + 1);
                    Ok(cgroup.to_vec())
                },
                || {
                    opens.set(opens.get() + 1);
                    Ok(())
                },
            )
        };
        assert!(run(0, 60002, Some("true"), b"ignored").is_err());
        assert!(run(60002, 0, Some("true"), b"ignored").is_err());
        assert!(run(60002, 60002, None, b"ignored").is_err());
        assert_eq!((reads.get(), opens.get()), (0, 0));
        assert!(run(60002, 60002, Some("true"), b"0::/wrong\n").is_err());
        assert_eq!((reads.get(), opens.get()), (1, 0));
        assert!(run(60002,60002,Some("true"),b"0::/command.slice/command-center.slice/command-center-inventory.slice/command-center-inventory.service\n").is_ok());
        assert_eq!((reads.get(), opens.get()), (2, 1));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn fixed_status_constructor_rejects_ordinary_test_runner() {
        assert!(StatusReader::fixed().is_err());
    }

    fn status() -> Value {
        json!({"schema_version":1,"operation_nonce":null,"phase":"deferred","reason":"cache_unavailable","policy_generation":"b".repeat(64),"cache_generation":"a".repeat(32),"successful_checked_at":"2026-01-01T00:00:00.123456Z","started_at":null,"finished_at":null,"attempt":null,"observation_lease":null,"observation_receipt":null})
    }

    #[test]
    fn platform_open_flags_match_system_python() {
        let output = super::super::process::SystemTools
            .run_with_timeout(
                "/usr/bin/python3",
                &[
                    "-I",
                    "-B",
                    "-c",
                    "import os;print(os.O_DIRECTORY,os.O_NOFOLLOW,os.O_NONBLOCK,os.O_CLOEXEC)",
                ],
                &[],
                256,
                Duration::from_secs(5),
            )
            .unwrap();
        let text = std::str::from_utf8(&output).unwrap();
        let actual: Vec<i32> = text
            .split_whitespace()
            .map(|value| value.parse().unwrap())
            .collect();
        assert_eq!(
            actual,
            [
                super::DIRECTORY,
                super::NOFOLLOW,
                super::NONBLOCK,
                super::CLOEXEC
            ]
        );
    }

    #[test]
    fn validates_public_status_fields_without_inventing_lease_authority() {
        let mut value = status();
        value["observation_lease"] = json!({"nonce":"0000000000000009".to_owned()+&"d".repeat(16),"boot_id":"00000000-0000-0000-0000-000000000000","cache_generation":"a".repeat(32),"policy_generation":"b".repeat(64),"lock_open_boottime_ms":10,"expires_boottime_ms":120010});
        assert!(validate_status(&value).is_ok());
        let mut invalid = value.clone();
        invalid.as_object_mut().unwrap().remove("attempt");
        assert!(validate_status(&invalid).is_err());
        let mut invalid = value.clone();
        invalid["observation_lease"]["lock_open_boottime_ms"] = json!(false);
        assert!(validate_status(&invalid).is_err());
        let mut invalid = value.clone();
        invalid["observation_lease"]["cache_generation"] = json!("c".repeat(32));
        assert!(validate_status(&invalid).is_err());
        let mut invalid = value.clone();
        invalid["reason"] = json!("invented");
        assert!(validate_status(&invalid).is_err());
        let mut invalid = value.clone();
        invalid["successful_checked_at"] = json!("2026-02-30T00:00:00Z");
        assert!(validate_status(&invalid).is_err());
    }

    #[test]
    fn validates_attempt_and_timestamp_boundaries() {
        let mut v = status();
        let token = "0000000000000001".to_owned() + &"e".repeat(16);
        v["phase"] = json!("succeeded");
        v["reason"] = Value::Null;
        v["operation_nonce"] = json!(token);
        v["attempt"] = json!({"correlator":token,"helper_sequence":1,"boot_id":"00000000-0000-0000-0000-000000000000","accepted_boottime_ms":10,"started_boottime_ms":11,"finished_boottime_ms":600011});
        for timestamp in [
            "2024-02-29T23:59:59Z",
            "2024-02-29T23:59:59.1Z",
            "2024-02-29T23:59:59.123456Z",
        ] {
            v["successful_checked_at"] = json!(timestamp);
            assert!(validate_status(&v).is_ok());
        }
        let mut invalid = v.clone();
        invalid["attempt"]["finished_boottime_ms"] = json!(600012);
        assert!(validate_status(&invalid).is_err());
        let mut invalid = v.clone();
        invalid["attempt"]["helper_sequence"] = json!(1.0);
        assert!(validate_status(&invalid).is_err());
        let mut invalid = v.clone();
        invalid["attempt"]["correlator"] = json!("0000000000000000".to_owned() + &"e".repeat(16));
        assert!(validate_status(&invalid).is_err());
        let mut invalid = v.clone();
        invalid["successful_checked_at"] = json!("2023-02-29T00:00:00Z");
        assert!(validate_status(&invalid).is_err());
        let mut invalid = v.clone();
        invalid["successful_checked_at"] = json!("2024-02-29T00:00:00.1234567Z");
        assert!(validate_status(&invalid).is_err());
        let mut invalid = v.clone();
        invalid["attempt"]["started_boottime_ms"] = Value::Null;
        assert!(validate_status(&invalid).is_err());
    }

    #[test]
    fn prior_expired_receipt_is_valid_but_never_a_released_receipt() {
        let mut v = status();
        v["observation_receipt"] = json!({"nonce":"0000000000000008".to_owned()+&"d".repeat(16),"boot_id":"00000000-0000-0000-0000-000000000000","cache_generation":"c".repeat(32),"policy_generation":"d".repeat(64),"lock_open_boottime_ms":10,"expires_boottime_ms":20,"lock_held_until_boottime_ms":21,"released_boottime_ms":22,"outcome":"expired","installed_before_sha256":"e".repeat(64),"installed_after_sha256":"f".repeat(64)});
        assert!(validate_status(&v).is_ok());
        v["observation_receipt"]["outcome"] = json!("released");
        assert!(validate_status(&v).is_err());
        v["observation_receipt"]["outcome"] = json!("unconfirmed");
        assert!(validate_status(&v).is_ok());
        v["observation_receipt"]["lock_held_until_boottime_ms"] = json!(9);
        assert!(validate_status(&v).is_err());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn typed_status_matches_python_public_status_vectors() {
        let valid = status();
        let mut vectors = vec![valid.clone()];
        let mut missing = valid.clone();
        missing.as_object_mut().unwrap().remove("attempt");
        vectors.push(missing);
        let mut boolean = valid.clone();
        boolean["schema_version"] = json!(true);
        vectors.push(boolean);
        let mut bad_date = valid.clone();
        bad_date["successful_checked_at"] = json!("2026-02-29T00:00:00Z");
        vectors.push(bad_date);
        let mut reason = valid.clone();
        reason["reason"] = json!("invented");
        vectors.push(reason);
        let mut old = valid.clone();
        old["observation_receipt"] = json!({"nonce":"0000000000000008".to_owned()+&"d".repeat(16),"boot_id":"00000000-0000-0000-0000-000000000000","cache_generation":"c".repeat(32),"policy_generation":"d".repeat(64),"lock_open_boottime_ms":10,"expires_boottime_ms":20,"lock_held_until_boottime_ms":21,"released_boottime_ms":22,"outcome":"expired","installed_before_sha256":"e".repeat(64),"installed_after_sha256":"f".repeat(64)});
        vectors.push(old.clone());
        old["observation_receipt"]["outcome"] = json!("released");
        vectors.push(old);
        let raw = serde_json::to_vec(&vectors).unwrap();
        let scripts = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts");
        let source = "import sys,json; sys.path.insert(0,sys.argv[1]); from inventory_refresh_status import PublicStatus\ndef valid(v):\n try: PublicStatus.create(v); return True\n except Exception: return False\nprint(json.dumps([valid(v) for v in json.load(sys.stdin)]))";
        let output = super::super::process::SystemTools
            .run_with_timeout(
                "/usr/bin/python3",
                &["-I", "-B", "-c", source, scripts.to_str().unwrap()],
                &raw,
                1024,
                Duration::from_secs(5),
            )
            .unwrap();
        let expected: Vec<bool> = serde_json::from_slice(&output).unwrap();
        let actual: Vec<bool> = vectors
            .iter()
            .map(|value| validate_status(value).is_ok())
            .collect();
        assert_eq!(actual, expected);
    }

    #[test]
    fn reads_only_a_protected_duplicate_free_status_object() {
        let root = std::env::temp_dir().join(format!(
            "inventory-status-{}",
            crate::inventory::transport::report_id().unwrap()
        ));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let run = root.join("run");
        let runtime = run.join("command-center-inventory-refresh");
        let status = runtime.join("status");
        for dir in [&run, &runtime, &status] {
            std::fs::create_dir(dir).unwrap();
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o750)).unwrap();
        }
        let path = status.join("status.json");
        std::fs::write(&path, b"{\"schema_version\":1,\"value\":{\"x\":2}}").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        let rootfile = std::fs::File::open(&root).unwrap();
        use std::os::unix::fs::MetadataExt;
        let owner = rootfile.metadata().unwrap().uid();
        let group = rootfile.metadata().unwrap().gid();
        let reader = StatusReader::open_from(rootfile, owner, group).unwrap();
        assert_eq!(
            reader
                .read(Instant::now() + Duration::from_secs(1))
                .unwrap()["value"]["x"],
            2
        );
        let replacement = status.join("new-status");
        std::fs::write(&replacement, b"{\"other\":3}").unwrap();
        std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o640)).unwrap();
        let result = reader.read_with(Instant::now() + Duration::from_secs(1), || {
            std::fs::rename(&replacement, &path).unwrap()
        });
        assert!(result.is_err());
        assert_eq!(
            reader
                .read(Instant::now() + Duration::from_secs(1))
                .unwrap()["other"],
            3
        );
        for raw in [
            b"{\"value\":{\"x\":1,\"x\":2}}".as_slice(),
            b"{\"id\":1,\"\\u0069d\":2}",
            b"[]",
            b"{} garbage",
            b"{\"x\":\xff}",
        ] {
            std::fs::write(&path, raw).unwrap();
            assert!(
                reader
                    .read(Instant::now() + Duration::from_secs(1))
                    .is_err()
            );
        }
        std::fs::write(&path, vec![b' '; 65537]).unwrap();
        assert!(
            reader
                .read(Instant::now() + Duration::from_secs(1))
                .is_err()
        );
        std::fs::write(&path, b"{}").unwrap();
        assert!(reader.read(Instant::now()).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(
            reader
                .read(Instant::now() + Duration::from_secs(1))
                .is_err()
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        let link = status.join("second");
        std::fs::hard_link(&path, &link).unwrap();
        assert!(
            reader
                .read(Instant::now() + Duration::from_secs(1))
                .is_err()
        );
        std::fs::remove_file(link).unwrap();
        let original = status.join("original");
        std::fs::rename(&path, &original).unwrap();
        std::os::unix::fs::symlink(&original, &path).unwrap();
        assert!(
            reader
                .read(Instant::now() + Duration::from_secs(1))
                .is_err()
        );
        std::fs::remove_file(&path).unwrap();
        std::fs::rename(original, &path).unwrap();
        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o770)).unwrap();
        assert!(
            reader
                .read(Instant::now() + Duration::from_secs(1))
                .is_err()
        );
        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o750)).unwrap();
        let old = runtime.join("old-status");
        std::fs::rename(&status, &old).unwrap();
        std::fs::create_dir(&status).unwrap();
        std::fs::set_permissions(&status, std::fs::Permissions::from_mode(0o750)).unwrap();
        std::fs::write(status.join("status.json"), b"{}").unwrap();
        assert!(
            reader
                .read(Instant::now() + Duration::from_secs(1))
                .is_err()
        );
        drop(reader);
        std::fs::remove_dir_all(root).unwrap();
    }
}
