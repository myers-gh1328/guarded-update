//! Fail-closed consumption records. A record existing in any state forbids replay.
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;

/// Both claim identity and executor nonce are consumed before any package operation.
/// An interrupted record is intentionally never removed or automatically retried.
pub(crate) fn consume(directory: &Path, claim_id: &str, nonce: &str) -> Result<(), String> {
    consume_owned(directory, claim_id, nonce, 0)
}

#[cfg(unix)]
fn checked_directory(directory: &Path, owner: u32) -> Result<File, String> {
    use std::os::unix::fs::MetadataExt;
    if !directory.is_absolute() {
        return Err("Journal directory must be absolute".into());
    }
    for component in directory.ancestors() {
        let metadata =
            std::fs::symlink_metadata(component).map_err(|_| "Cannot inspect journal directory")?;
        if !metadata.is_dir() || metadata.uid() != owner || metadata.mode() & 0o022 != 0 {
            return Err(
                "Journal ancestry must be owned by the executor and not writable by others".into(),
            );
        }
    }
    let before =
        std::fs::symlink_metadata(directory).map_err(|_| "Cannot inspect journal directory")?;
    let handle = File::open(directory).map_err(|_| "Cannot open journal directory")?;
    let after = handle
        .metadata()
        .map_err(|_| "Cannot inspect journal directory handle")?;
    if before.dev() != after.dev() || before.ino() != after.ino() {
        return Err("Journal directory changed during open".into());
    }
    Ok(handle)
}
#[cfg(not(unix))]
fn checked_directory(_: &Path, _: u32) -> Result<File, String> {
    Err("Execution journal requires Unix".into())
}
fn valid_id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn consume_owned(directory: &Path, claim_id: &str, nonce: &str, owner: u32) -> Result<(), String> {
    if !valid_id(claim_id) || !valid_id(nonce) {
        return Err("Invalid execution identity".into());
    }
    let directory_handle = checked_directory(directory, owner)?;
    // Separate exclusive records prevent reuse of either a claim or a nonce.
    // Any partial write remains consumed. Failures never undo an earlier record.
    for (kind, identity) in [("claim", claim_id), ("nonce", nonce)] {
        let path = directory.join(format!("{kind}-{identity}"));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut record = options
            .open(path)
            .map_err(|_| "Execution identity already consumed or journal unavailable")?;
        record
            .write_all(
                format!("guarded-update-execution-journal-v1\n{claim_id}\n{nonce}\nstarted\n")
                    .as_bytes(),
            )
            .and_then(|()| record.sync_all())
            .map_err(|_| "Cannot persist execution consumption")?;
        directory_handle
            .sync_all()
            .map_err(|_| "Cannot persist journal directory")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn malformed_identity_cannot_create_paths() {
        assert!(consume(Path::new("/does-not-exist"), "../escape", &"a".repeat(32)).is_err());
        assert!(!valid_id(&"A".repeat(32)));
    }
    #[test]
    fn relative_or_missing_directory_is_rejected() {
        assert!(consume(Path::new("relative"), &"a".repeat(32), &"b".repeat(32)).is_err());
        assert!(
            consume(
                Path::new("/does-not-exist"),
                &"a".repeat(32),
                &"b".repeat(32)
            )
            .is_err()
        );
    }
    #[cfg(unix)]
    #[test]
    fn writable_ancestor_and_symlink_are_rejected() {
        let directory =
            std::env::temp_dir().join(format!("guarded-journal-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        assert!(checked_directory(&directory, 0).is_err());
        let link = directory.join("link");
        std::os::unix::fs::symlink(&directory, &link).unwrap();
        assert!(checked_directory(&link, 0).is_err());
        std::fs::remove_file(link).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }
}
