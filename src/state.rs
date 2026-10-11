//! State and history (ADR-0001 D13) and the single-instance lock (D1).
//!
//! `state.json` holds held items, approvals and last screened verdicts.
//! Each run writes one `history/<run-id>.json`. A dry run writes history
//! but never changes `state.json`.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub const STATE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct State {
    pub schema_version: u32,
    /// Items held back, keyed by item name.
    pub held: BTreeMap<String, Held>,
    /// Versions the user approved, keyed by item name.
    pub approvals: BTreeMap<String, String>,
    /// The last screened version and verdict, keyed by item name.
    pub last_screened: BTreeMap<String, Screened>,
    /// When each waiting version was first seen, keyed by item name, for
    /// the wait-days safety check.
    pub first_seen: BTreeMap<String, Seen>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Seen {
    pub version: String,
    /// Unix seconds.
    pub at: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Held {
    pub version: String,
    pub reason: String,
    pub since: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Screened {
    pub version: String,
    pub verdict: String,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct StateDir {
    root: PathBuf,
}

/// History is for seeing what recent runs did, not an archive.
pub const KEEP_DAYS: i64 = 14;
/// Kept however old, so a computer that was off still shows its last runs.
pub const KEEP_RUNS: usize = 10;
/// A log larger than this is moved to `<name>.1` before the next run.
pub const LOG_LIMIT: u64 = 1_000_000;

/// Held while a run is in progress; dropping it releases the lock.
#[derive(Debug)]
pub struct RunLock {
    _file: File,
}

impl StateDir {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn history_dir(&self) -> PathBuf {
        self.root.join("history")
    }

    /// Takes the single-instance lock, or fails if another copy holds it.
    pub fn lock(&self) -> Result<RunLock, String> {
        self.ensure_root()?;
        let path = self.root.join("lock");
        let file = private_options()
            .read(true)
            .write(true)
            .truncate(false)
            .open(&path)
            .map_err(|e| format!("cannot open lock file {}: {e}", path.display()))?;
        match file.try_lock() {
            Ok(()) => Ok(RunLock { _file: file }),
            Err(std::fs::TryLockError::WouldBlock) => Err(format!(
                "another guarded-update is running (lock held on {})",
                path.display()
            )),
            Err(std::fs::TryLockError::Error(e)) => {
                Err(format!("cannot lock {}: {e}", path.display()))
            }
        }
    }

    /// A missing state file is an empty state.
    pub fn load(&self) -> Result<State, String> {
        let path = self.root.join("state.json");
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(State {
                    schema_version: STATE_SCHEMA_VERSION,
                    ..State::default()
                });
            }
            Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
        };
        serde_json::from_str(&text).map_err(|e| format!("{} is not valid: {e}", path.display()))
    }

    /// Writes atomically (temp file, then rename) with mode 0600.
    pub fn save(&self, state: &State) -> Result<(), String> {
        self.ensure_root()?;
        let path = self.root.join("state.json");
        let tmp = self.root.join("state.json.tmp");
        let text = serde_json::to_string_pretty(state).map_err(|e| e.to_string())?;
        write_new(&tmp, &text, true)?;
        std::fs::rename(&tmp, &path).map_err(|e| format!("cannot replace {}: {e}", path.display()))
    }

    /// Writes `history/<run_id>.json` and returns its path.
    pub fn write_history(
        &self,
        run_id: &str,
        record: &serde_json::Value,
    ) -> Result<PathBuf, String> {
        let dir = self.history_dir();
        std::fs::create_dir_all(&dir)
            .map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
        let text = serde_json::to_string_pretty(record).map_err(|e| e.to_string())?;
        // Two runs can start in the same second; never overwrite one.
        for n in 1..100 {
            let name = if n == 1 {
                format!("{run_id}.json")
            } else {
                format!("{run_id}-{n}.json")
            };
            let path = dir.join(name);
            if path.exists() {
                continue;
            }
            write_new(&path, &text, false)?;
            return Ok(path);
        }
        Err(format!("too many history files for run {run_id}"))
    }

    /// Deletes history older than `KEEP_DAYS`, always keeping the newest
    /// `KEEP_RUNS` runs. Returns how many files went.
    pub fn prune_history(&self, now: i64) -> Result<usize, String> {
        let cutoff = crate::timefmt::compact(now - KEEP_DAYS * 86_400);
        let mut removed = 0;
        for path in self.list_history()?.into_iter().skip(KEEP_RUNS) {
            // Run ids are UTC timestamps, so names compare as times.
            let name = path.file_name().map(|n| n.to_string_lossy().into_owned());
            if name.is_some_and(|n| n < cutoff) {
                std::fs::remove_file(&path)
                    .map_err(|e| format!("cannot remove {}: {e}", path.display()))?;
                removed += 1;
            }
        }
        Ok(removed)
    }

    /// History files, newest first.
    pub fn list_history(&self) -> Result<Vec<PathBuf>, String> {
        let dir = self.history_dir();
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(format!("cannot read {}: {e}", dir.display())),
        };
        let mut files: Vec<PathBuf> = entries
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "json"))
            .collect();
        // Run ids are UTC timestamps, so name order is time order.
        files.sort();
        files.reverse();
        Ok(files)
    }

    fn ensure_root(&self) -> Result<(), String> {
        std::fs::create_dir_all(&self.root)
            .map_err(|e| format!("cannot create {}: {e}", self.root.display()))
    }
}

/// Moves `path` to `<path>.1`, replacing the older copy, once it is
/// larger than `limit` bytes.
pub fn rotate_log(path: &Path, limit: u64) -> Result<(), String> {
    match std::fs::metadata(path) {
        Ok(meta) if meta.len() > limit => {
            let mut old = path.as_os_str().to_owned();
            old.push(".1");
            std::fs::rename(path, PathBuf::from(old))
                .map_err(|e| format!("cannot move aside {}: {e}", path.display()))
        }
        _ => Ok(()),
    }
}

fn private_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
}

/// Replaces `path` atomically (temp file, then rename) with mode 0600,
/// creating its directory if needed.
pub fn write_private(path: &Path, text: &str) -> Result<(), String> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)
            .map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    }
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    // A leftover temp file could carry wider permissions; start fresh.
    let _ = std::fs::remove_file(&tmp);
    write_new(&tmp, text.trim_end_matches('\n'), false)?;
    std::fs::rename(&tmp, path).map_err(|e| format!("cannot replace {}: {e}", path.display()))
}

/// Writes a file with mode 0600. `replace` allows truncating an existing
/// file (temp files); otherwise an existing file is an error.
fn write_new(path: &Path, text: &str, replace: bool) -> Result<(), String> {
    let mut options = private_options();
    options.write(true);
    if replace {
        options.truncate(true);
    } else {
        options.create_new(true);
    }
    let mut file = options
        .open(path)
        .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    file.write_all(text.as_bytes())
        .and_then(|()| file.write_all(b"\n"))
        .and_then(|()| file.sync_all())
        .map_err(|e| format!("cannot write {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> StateDir {
        let dir = std::env::temp_dir().join(format!("gu-state-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        StateDir::new(dir)
    }

    #[test]
    fn second_lock_fails_until_first_is_dropped() {
        let dir = temp("lock");
        let first = dir.lock().unwrap();
        let err = dir.lock().unwrap_err();
        assert!(err.contains("another guarded-update"), "{err}");
        drop(first);
        // Tests spawn processes concurrently; a forked child holds a copy
        // of the lock descriptor until it execs, so allow a short retry.
        let relocked = (0..50).any(|_| {
            dir.lock().is_ok() || {
                std::thread::sleep(std::time::Duration::from_millis(20));
                false
            }
        });
        assert!(relocked);
    }

    #[test]
    fn runs_in_the_same_second_keep_separate_history() {
        let dir = temp("samesecond");
        let a = dir
            .write_history("20261010T000000Z", &serde_json::json!({"a": 1}))
            .unwrap();
        let b = dir
            .write_history("20261010T000000Z", &serde_json::json!({"b": 2}))
            .unwrap();
        assert_ne!(a, b);
        assert!(b.to_string_lossy().ends_with("20261010T000000Z-2.json"));
    }

    #[test]
    fn missing_state_loads_empty_and_round_trips() {
        let dir = temp("roundtrip");
        let empty = dir.load().unwrap();
        assert!(empty.held.is_empty());
        let mut state = State {
            schema_version: STATE_SCHEMA_VERSION,
            ..State::default()
        };
        state.approvals.insert("jq".into(), "1.8.1".into());
        dir.save(&state).unwrap();
        assert_eq!(dir.load().unwrap(), state);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.root().join("state.json"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn corrupt_state_is_an_error_not_an_empty_state() {
        let dir = temp("corrupt");
        std::fs::create_dir_all(dir.root()).unwrap();
        std::fs::write(dir.root().join("state.json"), "{not json").unwrap();
        assert!(dir.load().unwrap_err().contains("state.json"));
    }

    #[test]
    fn history_is_written_per_run_and_listed_newest_first() {
        let dir = temp("history");
        dir.write_history("20261009T010000Z", &serde_json::json!({"n": 1}))
            .unwrap();
        let second = dir
            .write_history("20261010T010000Z", &serde_json::json!({"n": 2}))
            .unwrap();
        let listed = dir.list_history().unwrap();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0], second);
        let text = std::fs::read_to_string(&second).unwrap();
        assert!(text.contains("\"n\": 2"));
    }

    #[test]
    fn old_history_goes_but_the_newest_runs_always_stay() {
        let dir = temp("prune");
        let day = 86_400;
        let now = 100 * day;
        // Twelve runs a day apart, the newest today.
        for n in 0..12 {
            let id = crate::timefmt::compact(now - n * day);
            dir.write_history(&id, &serde_json::json!({})).unwrap();
        }
        assert_eq!(dir.prune_history(now).unwrap(), 0, "all within 14 days");
        // Three weeks later, only the newest ten are left.
        let later = now + 21 * day;
        assert_eq!(dir.prune_history(later).unwrap(), 2);
        let listed = dir.list_history().unwrap();
        assert_eq!(listed.len(), KEEP_RUNS);
        assert!(listed[0].ends_with(format!("{}.json", crate::timefmt::compact(now))));
        // Many runs in a day: older ones past 14 days still go.
        for n in 0..KEEP_RUNS as i64 {
            dir.write_history(&crate::timefmt::compact(later + n), &serde_json::json!({}))
                .unwrap();
        }
        assert_eq!(dir.prune_history(later).unwrap(), KEEP_RUNS);
        assert_eq!(dir.list_history().unwrap().len(), KEEP_RUNS);
        let _ = std::fs::remove_dir_all(dir.root());
    }

    #[test]
    fn a_big_log_is_moved_aside_and_replaces_the_old_one() {
        let dir = temp("rotate");
        std::fs::create_dir_all(dir.root()).unwrap();
        let log = dir.root().join("run.log");
        let old = dir.root().join("run.log.1");
        rotate_log(&log, 10).unwrap();
        assert!(!old.exists(), "a missing log is fine");
        std::fs::write(&log, "small").unwrap();
        rotate_log(&log, 10).unwrap();
        assert!(log.exists() && !old.exists(), "under the limit stays");
        std::fs::write(&old, "older").unwrap();
        std::fs::write(&log, "more than ten bytes").unwrap();
        rotate_log(&log, 10).unwrap();
        assert!(!log.exists());
        assert_eq!(
            std::fs::read_to_string(&old).unwrap(),
            "more than ten bytes"
        );
        let _ = std::fs::remove_dir_all(dir.root());
    }
}
