use super::process::{SystemTools, Tools};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

pub const MAX_REPORT: usize = 8 * 1024 * 1024;
const MAX_SEQUENCE: u64 = 9_007_199_254_740_991;

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Schedule {
    pub enrollment_id: String,
    pub sequence: u64,
    pub collected_at_secs: u64,
    pub acknowledged_sha256: Option<String>,
    pub retry_at: u64,
    pub retry_delay: u64,
    pub permanent_error: bool,
    #[serde(default)]
    pub source_revision: u64,
}

pub fn matches_receipt(report: &Value, digest: &str, receipt: &Value) -> bool {
    receipt["schema_version"] == 1
        && receipt["report_id"] == report["report_id"]
        && receipt["sequence"] == report["sequence"]
        && receipt["enrollment_id"] == report["enrollment_id"]
        && receipt["sha256"] == digest
        && receipt["accepted_at"].is_string()
        && matches!(
            receipt["disposition"].as_str(),
            Some("current" | "comparison" | "history")
        )
}

pub fn protected(path: &Path, directory: bool) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "Required protected path unavailable")?;
    if metadata.file_type().is_symlink()
        || (directory && !metadata.is_dir())
        || (!directory && !metadata.is_file())
    {
        return Err("Protected path has invalid type".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        static UID: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
        let uid = if let Some(uid) = UID.get() {
            *uid
        } else {
            let id = SystemTools
                .text("/usr/bin/id", &["-u"], 64)?
                .trim()
                .parse::<u32>()
                .map_err(|_| "Cannot determine reporting identity")?;
            let _ = UID.set(id);
            id
        };
        if !path.is_absolute()
            || path.components().any(|c| {
                matches!(
                    c,
                    std::path::Component::ParentDir | std::path::Component::CurDir
                )
            })
        {
            return Err("Private path must be absolute and normalized".into());
        }
        if metadata.uid() != uid {
            return Err("Private path must belong to reporting identity".into());
        }
        if metadata.mode() & 0o077 != 0 {
            return Err("Private file/directory requires owner-only permissions".into());
        }
        for parent in path.ancestors().skip(1) {
            let parent_meta =
                fs::symlink_metadata(parent).map_err(|_| "Protected ancestor unavailable")?;
            let sticky_root = parent_meta.uid() == 0 && parent_meta.mode() & 0o1000 != 0;
            if parent_meta.file_type().is_symlink()
                || !parent_meta.is_dir()
                || ![0, uid].contains(&parent_meta.uid())
                || (parent_meta.mode() & 0o022 != 0 && !sticky_root)
            {
                return Err("Private path ancestor is not trusted".into());
            }
        }
    }
    Ok(())
}

pub fn read(path: &Path, limit: usize) -> Result<Vec<u8>, String> {
    protected(path, false)?;
    let mut bytes = Vec::new();
    let before = fs::symlink_metadata(path).map_err(|_| "Private file unavailable")?;
    let mut options = OpenOptions::new();
    options.read(true);
    nofollow(&mut options);
    let file = options.open(path).map_err(|_| "Private file unavailable")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let after = file.metadata().map_err(|_| "Private file unavailable")?;
        if (before.dev(), before.ino(), before.uid(), before.mode())
            != (after.dev(), after.ino(), after.uid(), after.mode())
        {
            return Err("Private file changed during admission".into());
        }
    }
    file.take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "Private file unreadable")?;
    if bytes.len() > limit {
        return Err("Private file exceeds limit".into());
    }
    Ok(bytes)
}

pub fn atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path.parent().ok_or("State parent missing")?;
    protected(parent, true)?;
    let temporary = path.with_extension("pending");
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    // A .pending file can remain after power loss. It is never authoritative;
    // validate it before removing, then write a new exclusive replacement.
    if temporary.exists() {
        protected(&temporary, false)?;
        fs::remove_file(&temporary).map_err(|_| "Cannot reconcile temporary state")?;
    }
    let mut file = options
        .open(&temporary)
        .map_err(|_| "Cannot create state replacement")?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| "Cannot persist state replacement")?;
    fs::rename(&temporary, path).map_err(|_| "Cannot replace state")?;
    File::open(parent)
        .and_then(|file| file.sync_all())
        .map_err(|_| "Cannot persist state directory".into())
}

pub struct Store {
    pub dir: PathBuf,
    pub schedule: Schedule,
}
impl Store {
    pub fn load(dir: &Path, enrollment: &str) -> Result<Self, String> {
        protected(dir, true)?;
        let path = dir.join("schedule.json");
        let schedule:Schedule=serde_json::from_slice(&read(&path,65536)?).map_err(|_|"Inventory state missing or invalid; provision a new enrollment rather than reset sequence")?;
        if schedule.enrollment_id != enrollment || schedule.sequence > MAX_SEQUENCE {
            return Err("Enrollment state mismatch; re-enrollment required".into());
        }
        let store = Self {
            dir: dir.to_owned(),
            schedule,
        };
        Ok(store)
    }
    pub fn initialize(dir: &Path, enrollment: &str) -> Result<(), String> {
        protected(dir, true)?;
        if dir.join("schedule.json").exists() || dir.join("latest.json").exists() {
            return Err("Existing enrollment state cannot be reset".into());
        }
        let schedule = Schedule {
            enrollment_id: enrollment.into(),
            ..Default::default()
        };
        atomic(
            &dir.join("schedule.json"),
            &serde_json::to_vec(&schedule).map_err(|_| "Cannot encode state")?,
        )
    }
    pub fn save(&self) -> Result<(), String> {
        atomic(
            &self.dir.join("schedule.json"),
            &serde_json::to_vec(&self.schedule).map_err(|_| "Cannot encode state")?,
        )
    }
    pub fn reserve(&mut self) -> Result<u64, String> {
        if self.schedule.sequence >= MAX_SEQUENCE {
            return Err("Sequence exhausted; re-enrollment required".into());
        }
        self.schedule.sequence += 1;
        self.save()?;
        Ok(self.schedule.sequence)
    }
    pub fn latest(&self) -> Result<Option<Value>, String> {
        let path = self.dir.join("latest.json");
        if !path.exists() {
            return Ok(None);
        }
        let report: Value = serde_json::from_slice(&read(&path, MAX_REPORT)?)
            .map_err(|_| "Latest inventory report invalid")?;
        if report["enrollment_id"] != self.schedule.enrollment_id
            || report["sequence"]
                .as_u64()
                .is_none_or(|seq| seq == 0 || seq > self.schedule.sequence)
        {
            return Err("Latest report sequence is inconsistent; re-enrollment required".into());
        }
        Ok(Some(report))
    }
    pub fn replace(&mut self, report: &Value, now: u64) -> Result<(), String> {
        let bytes = serde_json::to_vec(report).map_err(|_| "Cannot encode inventory")?;
        if bytes.len() > MAX_REPORT {
            return Err("Inventory report exceeds 8 MiB encoded limit".into());
        }
        atomic(&self.dir.join("latest.json"), &bytes)?;
        self.schedule.collected_at_secs = now;
        self.schedule.acknowledged_sha256 = None;
        self.schedule.retry_at = 0;
        self.schedule.retry_delay = 0;
        self.schedule.permanent_error = false;
        self.save()
    }
}

fn nofollow(options: &mut OpenOptions) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        #[cfg(target_os = "macos")]
        options.custom_flags(0x100);
        #[cfg(target_os = "linux")]
        options.custom_flags(0x20000);
    }
}
pub struct Lock {
    _file: File,
}
impl Lock {
    pub fn acquire(dir: &Path) -> Result<Self, String> {
        protected(dir, true)?;
        let path = dir.join("running.lock");
        let mut options = OpenOptions::new();
        options.create(true).read(true).write(true).truncate(false);
        nofollow(&mut options);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options
            .open(&path)
            .map_err(|_| "Inventory lock unavailable")?;
        protected(&path, false)?;
        file.try_lock()
            .map_err(|_| "Inventory agent already running")?;
        Ok(Self { _file: file })
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use serde_json::json;
    pub struct TestDir(pub PathBuf);
    impl TestDir {
        pub fn new() -> Self {
            let base = fs::canonicalize(std::env::temp_dir()).unwrap();
            let path = base.join(format!(
                "cc-inventory-test-{}-{}",
                std::process::id(),
                super::super::transport::random_hex(8).unwrap()
            ));
            fs::create_dir(&path).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            }
            Self(path)
        }
    }
    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn sequence_reservation_survives_interrupted_collection_and_latest_replaces() {
        let temp = TestDir::new();
        Store::initialize(&temp.0, "epoch").unwrap();
        let mut store = Store::load(&temp.0, "epoch").unwrap();
        assert_eq!(store.reserve().unwrap(), 1);
        drop(store);
        let mut store = Store::load(&temp.0, "epoch").unwrap();
        assert_eq!(store.reserve().unwrap(), 2);
        store
            .replace(
                &json!({"enrollment_id":"epoch","sequence":2,"report_id":"new"}),
                100,
            )
            .unwrap();
        assert_eq!(store.reserve().unwrap(), 3);
        store
            .replace(
                &json!({"enrollment_id":"epoch","sequence":3,"report_id":"newer"}),
                200,
            )
            .unwrap();
        assert_eq!(store.latest().unwrap().unwrap()["report_id"], "newer");
        assert_eq!(fs::read_dir(&temp.0).unwrap().count(), 2);
        assert!(Store::initialize(&temp.0, "epoch").is_err());
        assert!(Store::load(&temp.0, "other-epoch").is_err());
    }
    #[test]
    fn advisory_lock_releases_without_removing_lock_file() {
        let temp = TestDir::new();
        let lock = Lock::acquire(&temp.0).unwrap();
        assert!(Lock::acquire(&temp.0).is_err());
        drop(lock);
        assert!(Lock::acquire(&temp.0).is_ok());
        assert!(temp.0.join("running.lock").exists());
    }
    #[test]
    #[cfg(unix)]
    fn private_read_rejects_symlinks_ancestors_and_public_permissions() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let temp = TestDir::new();
        let file = temp.0.join("data");
        atomic(&file, b"safe").unwrap();
        let link = temp.0.join("link");
        symlink(&file, &link).unwrap();
        assert!(read(&link, 16).is_err());
        let linkdir = temp.0.join("directory");
        symlink(&temp.0, &linkdir).unwrap();
        assert!(read(&linkdir.join("data"), 16).is_err());
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read(&file, 16).is_err());
    }
    #[test]
    fn old_receipt_cannot_acknowledge_new_latest_report() {
        let latest = json!({"report_id":"new","sequence":2,"enrollment_id":"epoch"});
        let receipt =
            json!({"report_id":"old","sequence":1,"enrollment_id":"epoch","sha256":"oldhash"});
        assert!(!matches_receipt(&latest, "newhash", &receipt));
        let receipt = json!({"schema_version":1,"report_id":"new","sequence":2,"enrollment_id":"epoch","sha256":"newhash","disposition":"current","accepted_at":"2026-01-01T00:00:00Z"});
        assert!(matches_receipt(&latest, "newhash", &receipt));
    }
}
