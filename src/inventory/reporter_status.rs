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
#[cfg(target_os = "linux")]
const DIRECTORY: i32 = 0x10000;
#[cfg(target_os = "linux")]
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

struct StatusReader {
    dirs: Vec<File>,
    owner: u32,
    group: u32,
}
impl StatusReader {
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
    fn read(&self, deadline: Instant) -> Result<Value> {
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

#[cfg(test)]
mod tests {
    use super::StatusReader;
    use std::os::unix::fs::PermissionsExt;
    use std::time::{Duration, Instant};

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
