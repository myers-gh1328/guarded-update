//! Root helper entry point. All input is supplied by the installed root adapter.
use crate::exec::{Runner, SystemRunner};
use crate::execution_claim::ExecutionClaim;
use crate::execution_gate::{ArchiveEvidence, ArchiveInspector, ExecutionManifest, LocalEvidence};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ValidationInput {
    manifest: String,
    evidence: LocalEvidence,
    stream: String,
    archives: BTreeMap<String, ArchiveEvidence>,
    claim: ExecutionClaim,
    nonce: String,
    manifest_sha256: String,
}
struct Inspector(BTreeMap<String, ArchiveEvidence>);
impl ArchiveInspector for Inspector {
    fn inspect(&self, path: &str) -> Result<ArchiveEvidence, String> {
        let value = self
            .0
            .get(path)
            .ok_or("Archive was not pinned by root helper")?;
        Ok(ArchiveEvidence {
            package: value.package.clone(),
            version: value.version.clone(),
            sha256: value.sha256.clone(),
        })
    }
    fn is_upgrade(&self, old: &str, new: &str) -> Result<bool, String> {
        let output = SystemRunner::new(Duration::from_secs(10)).run(
            "/usr/bin/dpkg",
            &["--compare-versions", old, "lt", new],
            &[("LC_ALL", "C")],
        )?;
        match output.code {
            Some(0) => Ok(true),
            Some(1) => Ok(false),
            _ => Err("Debian version comparison failed".into()),
        }
    }
}
#[cfg(unix)]
fn read_root(path: &Path, max: u64) -> Result<Vec<u8>, String> {
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;
    if !path.is_absolute() {
        return Err("Validation input requires an absolute path".into());
    }
    for ancestor in path.ancestors().skip(1) {
        let metadata = std::fs::symlink_metadata(ancestor)
            .map_err(|_| "Cannot inspect validation ancestry")?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err("Validation ancestry must be root-owned and not writable by others".into());
        }
    }
    let before = std::fs::symlink_metadata(path).map_err(|_| "Cannot inspect validation input")?;
    if !before.is_file() || before.uid() != 0 || before.mode() & 0o022 != 0 || before.len() > max {
        return Err("Validation input must be a bounded root-owned regular file".into());
    }
    let file = std::fs::File::open(path).map_err(|_| "Cannot open validation input")?;
    let after = file
        .metadata()
        .map_err(|_| "Cannot inspect input descriptor")?;
    if before.dev() != after.dev() || before.ino() != after.ino() {
        return Err("Validation input changed during open".into());
    }
    let mut bytes = Vec::new();
    file.take(max + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "Cannot read validation input")?;
    if bytes.len() as u64 > max {
        return Err("Validation input exceeds limit".into());
    }
    Ok(bytes)
}
#[cfg(not(unix))]
fn read_root(_: &Path, _: u64) -> Result<Vec<u8>, String> {
    Err("Executor requires Unix".into())
}

pub(crate) fn validate(input_path: &Path, key_path: &Path, journal: &Path) -> Result<(), String> {
    let mut input: ValidationInput =
        serde_json::from_slice(&read_root(input_path, 16 * 1024 * 1024)?)
            .map_err(|_| "Invalid validation request")?;
    let now = || {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|t| t.as_secs())
            .map_err(|_| "Invalid executor clock".to_owned())
    };
    input.evidence.now_unix = now()?;
    let manifest: ExecutionManifest = crate::execution_gate::decode_manifest(&input.manifest)?;
    input.claim.validate(
        &manifest.device_id,
        &manifest.proposal_id,
        &input.manifest_sha256,
        &input.nonce,
        input.evidence.now_unix,
    )?;
    let runner = SystemRunner::new(Duration::from_secs(10));
    let digest = runner.run_input(
        "/usr/bin/openssl",
        &["dgst", "-sha256", "-hex"],
        &[("LC_ALL", "C")],
        Some(&input.manifest),
    )?;
    if !digest.success()
        || digest.stdout.split_whitespace().last() != Some(input.manifest_sha256.as_str())
    {
        return Err("Manifest digest mismatch".into());
    }
    read_root(key_path, 16384)?;
    // Signature file is a fresh root-only sibling of the trusted validation input.
    let signature_path = input_path.with_extension("signature");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut signature_file = options
        .open(&signature_path)
        .map_err(|_| "Cannot create signature file")?;
    use std::io::Write;
    let signature: Vec<u8> = input
        .claim
        .signature
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap_or(""), 16).unwrap_or(0))
        .collect();
    signature_file
        .write_all(&signature)
        .map_err(|_| "Cannot write signature")?;
    let verified = runner.run_input(
        "/usr/bin/openssl",
        &[
            "dgst",
            "-sha256",
            "-verify",
            key_path.to_str().ok_or("Invalid key path")?,
            "-signature",
            signature_path.to_str().ok_or("Invalid signature path")?,
        ],
        &[("LC_ALL", "C")],
        Some(&input.claim.message()),
    );
    let _ = std::fs::remove_file(signature_path);
    if !verified?.success() {
        return Err("Controller execution signature rejected".into());
    }
    crate::execution_gate::validate_gate(
        &manifest,
        &input.evidence,
        &input.stream,
        &Inspector(input.archives),
    )?;
    // Signature and archive inspection can be slow. Recheck expiration immediately
    // before durable consumption rather than trusting the input's timestamp.
    input.claim.validate(
        &manifest.device_id,
        &manifest.proposal_id,
        &input.manifest_sha256,
        &input.nonce,
        now()?,
    )?;
    crate::execution_journal::consume(
        journal,
        &input.claim.claim_id.replace('-', ""),
        &input.nonce,
    )
}
