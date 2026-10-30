//! Test-only, exclusive no-replace request publication; no runtime authority.

use std::fs::{File, Metadata};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
use std::os::unix::fs::MetadataExt;
use std::time::Instant;

unsafe extern "C" {
    fn openat(fd: i32, path: *const i8, flags: i32, ...) -> i32;
    fn renameat2(oldfd: i32, old: *const i8, newfd: i32, new: *const i8, flags: u32) -> i32;
    fn close(fd: i32) -> i32;
    fn geteuid() -> u32;
    fn getegid() -> u32;
}

#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
const DIRECTORY: i32 = 0x4000;
#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
const NOFOLLOW: i32 = 0x8000;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
const DIRECTORY: i32 = 0x10000;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
const NOFOLLOW: i32 = 0x20000;
const NONBLOCK: i32 = 0x800;
const CLOEXEC: i32 = 0x80000;
const ERROR: &str = "Request fixture publication uncertain";
type Result<T> = std::result::Result<T, &'static str>;

fn opened(parent: &File, name: &[u8], flags: i32, mode: u32) -> Result<File> {
    // SAFETY: callers use fixed or locally generated NUL-terminated names.
    let fd = unsafe { openat(parent.as_raw_fd(), name.as_ptr().cast(), flags, mode) };
    if fd < 0 {
        return Err(ERROR);
    }
    // SAFETY: openat returned a new owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn checked_close(file: File) -> Result<()> {
    // SAFETY: ownership was consumed and close is attempted exactly once.
    if unsafe { close(file.into_raw_fd()) } == 0 {
        Ok(())
    } else {
        Err(ERROR)
    }
}

fn same(a: &Metadata, b: &Metadata) -> bool {
    a.dev() == b.dev()
        && a.ino() == b.ino()
        && a.mode() == b.mode()
        && a.uid() == b.uid()
        && a.gid() == b.gid()
        && a.nlink() == b.nlink()
}

fn stable(a: &Metadata, b: &Metadata) -> bool {
    same(a, b)
        && a.size() == b.size()
        && a.mtime() == b.mtime()
        && a.mtime_nsec() == b.mtime_nsec()
        && a.ctime() == b.ctime()
        && a.ctime_nsec() == b.ctime_nsec()
}

fn valid_nonce(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && u64::from_str_radix(&value[..16], 16)
            .is_ok_and(|sequence| (1..=9_007_199_254_740_991).contains(&sequence))
}

/// Held and named fixture ancestry, under trusted-kernel/exclusive-mutation
/// assumptions. This supplies no production identity or maintenance authority.
pub(super) struct FixedParent {
    files: Vec<File>,
    owner: u32,
}

impl FixedParent {
    const PARTS: [&'static [u8]; 2] = [b"run\0", b"command-center-inventory-cas-fixture\0"];

    pub(super) fn fixed() -> Result<Self> {
        let root = File::open("/").map_err(|_| ERROR)?;
        Self::from_root(root, 0)
    }

    fn from_root(root: File, owner: u32) -> Result<Self> {
        let mut chain = Self {
            files: vec![root],
            owner,
        };
        let result = (|| -> Result<()> {
            for name in Self::PARTS {
                let parent = chain.files.last().ok_or(ERROR)?;
                chain.files.push(opened(
                    parent,
                    name,
                    DIRECTORY | NOFOLLOW | NONBLOCK | CLOEXEC,
                    0,
                )?);
            }
            chain.verify()
        })();
        if result.is_err() {
            let _ = chain.close();
            return Err(ERROR);
        }
        Ok(chain)
    }

    pub(super) fn parent(&self) -> Result<&File> {
        self.files.last().ok_or(ERROR)
    }

    pub(super) fn verify(&self) -> Result<()> {
        if self.files.len() != Self::PARTS.len() + 1 {
            return Err(ERROR);
        }
        for (index, held) in self.files.iter().enumerate() {
            let metadata = held.metadata().map_err(|_| ERROR)?;
            if !metadata.is_dir() || metadata.uid() != self.owner || metadata.mode() & 0o022 != 0 {
                return Err(ERROR);
            }
            if index > 0 {
                let named = opened(
                    &self.files[index - 1],
                    Self::PARTS[index - 1],
                    DIRECTORY | NOFOLLOW | NONBLOCK | CLOEXEC,
                    0,
                )?;
                let named_meta = named.metadata().map_err(|_| ERROR);
                let closed = checked_close(named);
                if !same(&metadata, &named_meta?) {
                    return Err(ERROR);
                }
                closed?;
            }
        }
        Ok(())
    }

    pub(super) fn close(self) -> Result<()> {
        let mut failed = false;
        for file in self.files.into_iter().rev() {
            if checked_close(file).is_err() {
                failed = true;
            }
        }
        if failed { Err(ERROR) } else { Ok(()) }
    }
}

#[derive(Clone, Copy)]
enum Fault<'a> {
    None,
    ShortWrite,
    FileSync,
    BeforeRename,
    DirectorySync,
    Close,
    BeforeRenameHook(&'a dyn Fn()),
}

/// Borrowed parent and its ancestry must be exclusively controlled and verified
/// by the caller throughout; errors preserve all possibly published state.
fn publish(
    parent: &File,
    owner: u32,
    reporter: u32,
    group: u32,
    nonce: &str,
    deadline: Instant,
) -> Result<()> {
    publish_fault(parent, owner, reporter, group, nonce, deadline, Fault::None)
}

fn publish_fault(
    parent: &File,
    owner: u32,
    reporter: u32,
    group: u32,
    nonce: &str,
    deadline: Instant,
    fault: Fault<'_>,
) -> Result<()> {
    publish_inner(
        parent,
        owner,
        reporter,
        group,
        nonce,
        deadline,
        (fault, &|| Ok(())),
    )
}

pub(super) fn publish_checked(
    parent: &File,
    owner: u32,
    reporter: u32,
    group: u32,
    nonce: &str,
    deadline: Instant,
    ancestry: &dyn Fn() -> Result<()>,
) -> Result<()> {
    publish_inner(
        parent,
        owner,
        reporter,
        group,
        nonce,
        deadline,
        (Fault::None, ancestry),
    )
}

fn publish_inner(
    parent: &File,
    owner: u32,
    reporter: u32,
    group: u32,
    nonce: &str,
    deadline: Instant,
    controls: (Fault<'_>, &dyn Fn() -> Result<()>),
) -> Result<()> {
    let (fault, ancestry) = controls;
    if Instant::now() >= deadline
        || !valid_nonce(nonce)
        || unsafe { geteuid() } != reporter
        || unsafe { getegid() } != group
    {
        return Err(ERROR);
    }
    ancestry()?;
    let parent_before = parent.metadata().map_err(|_| ERROR)?;
    if !parent_before.is_dir() || parent_before.uid() != owner || parent_before.mode() & 0o022 != 0
    {
        return Err(ERROR);
    }
    let inbox = opened(
        parent,
        b"observation\0",
        DIRECTORY | NOFOLLOW | NONBLOCK | CLOEXEC,
        0,
    )?;
    let mut temp: Option<File> = None;
    let mut published: Option<File> = None;
    let outcome = (|| -> Result<()> {
        let initial = inbox.metadata().map_err(|_| ERROR)?;
        let verify = || -> Result<()> {
            ancestry()?;
            if Instant::now() >= deadline {
                return Err(ERROR);
            }
            let current_parent = parent.metadata().map_err(|_| ERROR)?;
            if !same(&parent_before, &current_parent) {
                return Err(ERROR);
            }
            let held = inbox.metadata().map_err(|_| ERROR)?;
            let named = opened(
                parent,
                b"observation\0",
                DIRECTORY | NOFOLLOW | NONBLOCK | CLOEXEC,
                0,
            )?;
            let named_meta = named.metadata().map_err(|_| ERROR);
            let closed = checked_close(named);
            let named_meta = named_meta?;
            closed?;
            if Instant::now() >= deadline {
                return Err(ERROR);
            }
            if !held.is_dir()
                || held.uid() != owner
                || held.gid() != group
                || held.mode() & 0o7777 != 0o770
                || !same(&initial, &held)
                || !same(&held, &named_meta)
            {
                return Err(ERROR);
            }
            Ok(())
        };
        verify()?;
        // SAFETY: the held directory and static NUL-terminated name are valid.
        let existing = unsafe {
            openat(
                inbox.as_raw_fd(),
                c"request".as_ptr().cast(),
                NOFOLLOW | NONBLOCK | CLOEXEC,
                0,
            )
        };
        if existing >= 0 {
            // SAFETY: openat returned an owned descriptor, closed exactly once.
            let _ = unsafe { close(existing) };
            return Err(ERROR);
        }
        if std::io::Error::last_os_error().raw_os_error() != Some(2) {
            return Err(ERROR);
        }
        verify()?;
        let name = format!(".request-{nonce}\0");
        let mut file = opened(
            &inbox,
            name.as_bytes(),
            1 | 0x40 | 0x80 | NOFOLLOW | NONBLOCK | CLOEXEC,
            0o600,
        )?;
        let write_result = (|| -> Result<()> {
            if matches!(fault, Fault::ShortWrite) {
                file.write_all(&nonce.as_bytes()[..8]).map_err(|_| ERROR)?;
                return Err(ERROR);
            }
            file.write_all(nonce.as_bytes()).map_err(|_| ERROR)?;
            if matches!(fault, Fault::FileSync) {
                return Err(ERROR);
            }
            file.sync_all().map_err(|_| ERROR)?;
            let info = file.metadata().map_err(|_| ERROR)?;
            if !info.is_file()
                || info.uid() != reporter
                || info.gid() != group
                || info.mode() & 0o7777 != 0o600
                || info.nlink() != 1
                || info.size() != 32
                || info.dev() != initial.dev()
            {
                return Err(ERROR);
            }
            verify()?;
            let mut named = opened(&inbox, name.as_bytes(), NOFOLLOW | NONBLOCK | CLOEXEC, 0)?;
            let checked = (|| -> Result<()> {
                let before = named.metadata().map_err(|_| ERROR)?;
                let mut bytes = Vec::new();
                Read::by_ref(&mut named)
                    .take(33)
                    .read_to_end(&mut bytes)
                    .map_err(|_| ERROR)?;
                let after = named.metadata().map_err(|_| ERROR)?;
                if bytes != nonce.as_bytes() || !stable(&info, &before) || !stable(&before, &after)
                {
                    return Err(ERROR);
                }
                Ok(())
            })();
            let closed = checked_close(named);
            checked?;
            closed?;
            verify()?;
            if let Fault::BeforeRenameHook(hook) = fault {
                hook();
            }
            verify()?;
            if matches!(fault, Fault::BeforeRename) {
                return Err(ERROR);
            }
            // SAFETY: held directory descriptors and NUL-terminated names; no replacement is allowed.
            if unsafe {
                renameat2(
                    inbox.as_raw_fd(),
                    name.as_ptr().cast(),
                    inbox.as_raw_fd(),
                    c"request".as_ptr().cast(),
                    1,
                )
            } != 0
            {
                return Err(ERROR);
            }
            if matches!(fault, Fault::DirectorySync) {
                return Err(ERROR);
            }
            inbox.sync_all().map_err(|_| ERROR)?;
            verify()?;
            let mut reader = opened(&inbox, b"request\0", NOFOLLOW | NONBLOCK | CLOEXEC, 0)?;
            let result = (|| -> Result<()> {
                let before = reader.metadata().map_err(|_| ERROR)?;
                let mut bytes = Vec::new();
                Read::by_ref(&mut reader)
                    .take(33)
                    .read_to_end(&mut bytes)
                    .map_err(|_| ERROR)?;
                let after = reader.metadata().map_err(|_| ERROR)?;
                if bytes != nonce.as_bytes() || !same(&info, &before) || !stable(&before, &after) {
                    return Err(ERROR);
                }
                let named = opened(&inbox, b"request\0", NOFOLLOW | NONBLOCK | CLOEXEC, 0)?;
                let named_info = named.metadata().map_err(|_| ERROR);
                let closed = checked_close(named);
                if !stable(&after, &named_info?) {
                    return Err(ERROR);
                }
                closed?;
                verify()?;
                Ok(())
            })();
            published = Some(reader);
            result
        })();
        temp = Some(file);
        write_result
    })();
    let mut failed = outcome.is_err();
    for file in [published, temp, Some(inbox)].into_iter().flatten() {
        if checked_close(file).is_err() {
            failed = true;
        }
    }
    if ancestry().is_err() {
        failed = true;
    }
    if failed || matches!(fault, Fault::Close) || Instant::now() >= deadline {
        Err(ERROR)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn nonce_requires_a_positive_safe_sequence_and_lowercase_hex() {
        assert!(super::valid_nonce("0000000000000001abcdefabcdefabcd"));
        assert!(!super::valid_nonce("0000000000000000abcdefabcdefabcd"));
        assert!(!super::valid_nonce("0020000000000000abcdefabcdefabcd"));
        assert!(!super::valid_nonce("0000000000000001ABCDEFabcdefabcd"));
    }

    #[test]
    fn exclusive_publication_never_replaces_an_existing_request() {
        let path = std::env::temp_dir().join(format!("request-fixture-{}", std::process::id()));
        std::fs::create_dir(&path).unwrap();
        std::fs::create_dir(path.join("observation")).unwrap();
        std::fs::set_permissions(
            path.join("observation"),
            std::fs::Permissions::from_mode(0o770),
        )
        .unwrap();
        let parent = std::fs::File::open(&path).unwrap();
        let identity = parent.metadata().unwrap();
        use std::os::unix::fs::MetadataExt;
        let nonce = "0000000000000001abcdefabcdefabcd";
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        assert!(
            super::publish_checked(
                &parent,
                identity.uid(),
                identity.uid(),
                identity.gid(),
                nonce,
                deadline,
                &|| Err(super::ERROR)
            )
            .is_err()
        );
        assert!(!path.join("observation/request").exists());
        std::os::unix::fs::symlink("missing", path.join("observation/request")).unwrap();
        assert!(
            super::publish(
                &parent,
                identity.uid(),
                identity.uid(),
                identity.gid(),
                nonce,
                deadline
            )
            .is_err()
        );
        assert!(
            std::fs::symlink_metadata(path.join("observation/request"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
        std::fs::remove_file(path.join("observation/request")).unwrap();
        std::fs::write(path.join("foreign"), b"foreign").unwrap();
        std::fs::hard_link(path.join("foreign"), path.join("observation/request")).unwrap();
        assert!(
            super::publish(
                &parent,
                identity.uid(),
                identity.uid(),
                identity.gid(),
                nonce,
                deadline
            )
            .is_err()
        );
        assert_eq!(std::fs::read(path.join("foreign")).unwrap(), b"foreign");
        std::fs::remove_file(path.join("observation/request")).unwrap();
        assert!(
            super::publish(
                &parent,
                identity.uid(),
                identity.uid(),
                identity.gid(),
                nonce,
                std::time::Instant::now()
            )
            .is_err()
        );
        assert!(!path.join("observation/request").exists());
        std::fs::set_permissions(
            path.join("observation"),
            std::fs::Permissions::from_mode(0o777),
        )
        .unwrap();
        assert!(
            super::publish(
                &parent,
                identity.uid(),
                identity.uid(),
                identity.gid(),
                nonce,
                deadline
            )
            .is_err()
        );
        assert!(!path.join("observation/request").exists());
        std::fs::set_permissions(
            path.join("observation"),
            std::fs::Permissions::from_mode(0o770),
        )
        .unwrap();
        super::publish(
            &parent,
            identity.uid(),
            identity.uid(),
            identity.gid(),
            nonce,
            deadline,
        )
        .unwrap();
        assert_eq!(
            std::fs::read(path.join("observation/request")).unwrap(),
            nonce.as_bytes()
        );
        let script = r#"
import os, sys
sys.path.insert(0, sys.argv[1])
from inventory_refresh_io import Inbox
fd = os.open(sys.argv[2], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
box = Inbox(fd, 'observation', int(sys.argv[3]), int(sys.argv[4]), owner=int(sys.argv[3]))
try:
    assert box.read() == (sys.argv[5], 1)
finally:
    box.close()
    os.close(fd)
"#;
        let mut child = std::process::Command::new("/usr/bin/python3")
            .args(["-I", "-B", "-S", "-c", script])
            .arg(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts"))
            .arg(&path)
            .arg(identity.uid().to_string())
            .arg(identity.gid().to_string())
            .arg(nonce)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let status = loop {
            assert!(std::time::Instant::now() < deadline);
            match child.try_wait().unwrap() {
                Some(status) => break status,
                None => std::thread::sleep(std::time::Duration::from_millis(2)),
            }
        };
        assert!(status.success() && std::time::Instant::now() < deadline);
        assert!(
            super::publish(
                &parent,
                identity.uid(),
                identity.uid(),
                identity.gid(),
                nonce,
                deadline
            )
            .is_err()
        );
        assert_eq!(
            std::fs::read(path.join("observation/request")).unwrap(),
            nonce.as_bytes()
        );
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn interrupted_publication_preserves_uncertain_state() {
        use std::os::unix::fs::MetadataExt;
        let faults = [
            super::Fault::ShortWrite,
            super::Fault::FileSync,
            super::Fault::BeforeRename,
            super::Fault::DirectorySync,
            super::Fault::Close,
        ];
        for (index, fault) in faults.into_iter().enumerate() {
            let path =
                std::env::temp_dir().join(format!("request-fault-{}-{index}", std::process::id()));
            std::fs::create_dir(&path).unwrap();
            std::fs::create_dir(path.join("observation")).unwrap();
            std::fs::set_permissions(
                path.join("observation"),
                std::fs::Permissions::from_mode(0o770),
            )
            .unwrap();
            let parent = std::fs::File::open(&path).unwrap();
            let info = parent.metadata().unwrap();
            let nonce = "0000000000000001abcdefabcdefabcd";
            assert!(
                super::publish_fault(
                    &parent,
                    info.uid(),
                    info.uid(),
                    info.gid(),
                    nonce,
                    std::time::Instant::now() + std::time::Duration::from_secs(10),
                    fault
                )
                .is_err()
            );
            let request = path.join("observation/request");
            if matches!(fault, super::Fault::DirectorySync | super::Fault::Close) {
                assert_eq!(std::fs::read(request).unwrap(), nonce.as_bytes());
            } else {
                assert!(!request.exists());
                assert!(path.join(format!("observation/.request-{nonce}")).exists());
            }
            std::fs::remove_dir_all(path).unwrap();
        }
    }

    #[test]
    fn competing_destination_and_replaced_inbox_fail_closed() {
        use std::os::unix::fs::MetadataExt;
        for replacement in [false, true] {
            let path = std::env::temp_dir()
                .join(format!("request-race-{}-{replacement}", std::process::id()));
            std::fs::create_dir(&path).unwrap();
            let inbox = path.join("observation");
            std::fs::create_dir(&inbox).unwrap();
            std::fs::set_permissions(&inbox, std::fs::Permissions::from_mode(0o770)).unwrap();
            let parent = std::fs::File::open(&path).unwrap();
            let info = parent.metadata().unwrap();
            let nonce = "0000000000000001abcdefabcdefabcd";
            let hook = || {
                if replacement {
                    std::fs::rename(&inbox, path.join("old-observation")).unwrap();
                    std::fs::create_dir(&inbox).unwrap();
                    std::fs::set_permissions(&inbox, std::fs::Permissions::from_mode(0o770))
                        .unwrap();
                }
                std::fs::write(inbox.join("request"), b"foreign").unwrap();
            };
            assert!(
                super::publish_fault(
                    &parent,
                    info.uid(),
                    info.uid(),
                    info.gid(),
                    nonce,
                    std::time::Instant::now() + std::time::Duration::from_secs(10),
                    super::Fault::BeforeRenameHook(&hook)
                )
                .is_err()
            );
            assert_eq!(std::fs::read(inbox.join("request")).unwrap(), b"foreign");
            let old = if replacement {
                path.join("old-observation")
            } else {
                inbox
            };
            assert!(old.join(format!(".request-{nonce}")).exists());
            std::fs::remove_dir_all(path).unwrap();
        }
    }

    #[test]
    fn failed_caller_ancestry_check_prevents_publication() {
        use std::os::unix::fs::MetadataExt;
        let path = std::env::temp_dir().join(format!("request-ancestry-{}", std::process::id()));
        std::fs::create_dir(&path).unwrap();
        std::fs::create_dir(path.join("observation")).unwrap();
        std::fs::set_permissions(
            path.join("observation"),
            std::fs::Permissions::from_mode(0o770),
        )
        .unwrap();
        let parent = std::fs::File::open(&path).unwrap();
        let info = parent.metadata().unwrap();
        let valid = std::cell::Cell::new(true);
        let guard = || {
            if valid.get() {
                Ok(())
            } else {
                Err(super::ERROR)
            }
        };
        let hook = || valid.set(false);
        let nonce = "0000000000000001abcdefabcdefabcd";
        assert!(
            super::publish_inner(
                &parent,
                info.uid(),
                info.uid(),
                info.gid(),
                nonce,
                std::time::Instant::now() + std::time::Duration::from_secs(10),
                (super::Fault::BeforeRenameHook(&hook), &guard)
            )
            .is_err()
        );
        assert!(!path.join("observation/request").exists());
        assert!(path.join(format!("observation/.request-{nonce}")).exists());
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn ancestry_detects_a_replaced_parent() {
        use std::os::unix::fs::MetadataExt;
        let path = std::env::temp_dir().join(format!("request-chain-{}", std::process::id()));
        std::fs::create_dir(&path).unwrap();
        std::fs::create_dir(path.join("run")).unwrap();
        std::fs::create_dir(path.join("run/command-center-inventory-cas-fixture")).unwrap();
        let root = std::fs::File::open(&path).unwrap();
        let owner = root.metadata().unwrap().uid();
        let chain = super::FixedParent::from_root(root, owner).unwrap();
        chain.verify().unwrap();
        std::fs::rename(path.join("run"), path.join("old-run")).unwrap();
        std::fs::create_dir(path.join("run")).unwrap();
        assert!(chain.verify().is_err());
        chain.close().unwrap();
        std::fs::remove_dir_all(path).unwrap();
    }
}
