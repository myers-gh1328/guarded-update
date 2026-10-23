//! Dormant, pure transaction validation. This module cannot install packages.
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const MAX_STREAM_BYTES: usize = 8 * 1024 * 1024;
const MAX_CHANGES: usize = 5000;
const MAX_AGE_SECS: u64 = 3600;

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PackageVersion {
    pub version: String,
    pub architecture: String,
    pub multi_arch: String,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManifestChange {
    pub package: String,
    pub old: Option<PackageVersion>,
    pub new: PackageVersion,
    pub archive_sha256: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExecutionManifest {
    pub schema_version: u32,
    pub kind: String,
    pub device_id: String,
    pub proposal_id: String,
    pub generated_at_unix: u64,
    pub metadata_checked_at_unix: Option<u64>,
    pub metadata_valid_until_unix: Option<u64>,
    pub repository_identity_verified: bool,
    pub package_state_sha256: String,
    pub repository_state_sha256: String,
    pub held_packages: Vec<String>,
    pub changes: Vec<ManifestChange>,
}
pub(crate) fn decode_manifest(input: &str) -> Result<ExecutionManifest, String> {
    if input.len() > 2 * 1024 * 1024 {
        return Err("Execution manifest exceeds limit".into());
    }
    serde_json::from_str(input).map_err(|_| "Invalid execution manifest".into())
}
/// Supplied by a future trusted local collector, never copied from the server.
pub(crate) struct LocalEvidence {
    pub device_id: String,
    pub now_unix: u64,
    pub package_state_sha256: String,
    pub repository_state_sha256: String,
    pub held_packages: Vec<String>,
    pub repository_identity_verified: bool,
    pub metadata_checked_at_unix: u64,
    pub metadata_valid_until_unix: u64,
    pub package_state_clean: bool,
}
/// A production implementation must inspect a pinned, trusted archive handle;
/// following the stream's path or trusting its basename is insufficient.
pub(crate) struct ArchiveEvidence {
    pub package: String,
    pub version: PackageVersion,
    pub sha256: String,
}
pub(crate) trait ArchiveInspector {
    fn inspect(&self, untrusted_path: &str) -> Result<ArchiveEvidence, String>;
    /// Must implement Debian ordering (including epochs, revisions and tilde),
    /// not lexical or semver comparison. Equal/reinstall returns false.
    fn is_upgrade(&self, old: &str, new: &str) -> Result<bool, String>;
}
#[derive(Debug)]
enum Action {
    Unpack(String),
    Configure,
    Remove,
}
#[derive(Debug)]
struct HookChange {
    package: String,
    old: Option<PackageVersion>,
    new: Option<PackageVersion>,
    direction: String,
    action: Action,
}

fn hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 256
        && (s.as_bytes()[0].is_ascii_lowercase() || s.as_bytes()[0].is_ascii_digit())
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"+.-".contains(&b))
}
fn arch(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.as_bytes()[0].is_ascii_alphanumeric()
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn version(v: &PackageVersion) -> bool {
    !v.version.is_empty()
        && v.version.len() <= 1024
        && v.version.as_bytes()[0].is_ascii_digit()
        && v.version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".+:~-".contains(&b))
        && arch(&v.architecture)
        && matches!(
            v.multi_arch.as_str(),
            "none" | "no" | "same" | "foreign" | "allowed"
        )
}
fn normalized(mut v: PackageVersion) -> PackageVersion {
    if v.multi_arch == "no" {
        v.multi_arch = "none".into();
    }
    v
}
fn read_version(fields: &[&str]) -> Result<Option<PackageVersion>, String> {
    if fields[0] == "-" {
        if fields[1] != "-" || !matches!(fields[2], "none" | "no") {
            return Err("Invalid absent package version".into());
        }
        return Ok(None);
    }
    let v = PackageVersion {
        version: fields[0].into(),
        architecture: fields[1].into(),
        multi_arch: fields[2].into(),
    };
    if !version(&v) {
        return Err("Invalid package version or architecture".into());
    }
    Ok(Some(normalized(v)))
}
/// APT v3: name old-version old-arch old-multi direction new-version
/// new-arch new-multi action. Configuration is opaque data, never applied.
fn parse_hook(stream: &str) -> Result<Vec<HookChange>, String> {
    if stream.len() > MAX_STREAM_BYTES
        || !stream.ends_with('\n')
        || stream.bytes().any(|b| b.is_ascii_control() && b != b'\n')
    {
        return Err("Invalid or truncated APT hook stream".into());
    }
    let mut lines = stream.split_terminator('\n');
    if lines.next() != Some("VERSION 3") {
        return Err("APT hook protocol v3 required".into());
    }
    let mut separator = false;
    for line in lines.by_ref() {
        if line.is_empty() {
            separator = true;
            break;
        }
        if line.len() > 16384 || !line.contains('=') {
            return Err("Invalid hook configuration".into());
        }
    }
    if !separator {
        return Err("Missing hook configuration separator".into());
    }
    let mut result = Vec::new();
    let mut seen = BTreeSet::new();
    for line in lines {
        if line.len() > 16384 || result.len() >= MAX_CHANGES * 2 {
            return Err("APT hook exceeds bounds".into());
        }
        let f: Vec<_> = line.split(' ').collect();
        if f.len() != 9
            || f.iter().any(|s| s.is_empty())
            || !name(f[0])
            || !matches!(f[4], "<" | ">" | "=")
        {
            return Err("Invalid v3 package action".into());
        }
        let old = read_version(&f[1..4])?;
        let new = read_version(&f[5..8])?;
        let action = match f[8] {
            "**CONFIGURE**" => Action::Configure,
            "**REMOVE**" => Action::Remove,
            p if p.starts_with('/')
                && p.ends_with(".deb")
                && !p.contains("/../")
                && !p.contains("/./") =>
            {
                Action::Unpack(p.into())
            }
            _ => return Err("Unsupported hook action".into()),
        };
        let phase = match action {
            Action::Unpack(_) => "unpack",
            Action::Configure => "configure",
            Action::Remove => "remove",
        };
        let architecture = new
            .as_ref()
            .or(old.as_ref())
            .ok_or("Missing package identity")?
            .architecture
            .clone();
        if !seen.insert((f[0].to_owned(), architecture, phase)) {
            return Err("Duplicate package action".into());
        }
        result.push(HookChange {
            package: f[0].into(),
            old,
            new,
            direction: f[4].into(),
            action,
        });
    }
    Ok(result)
}
/// This is evidence validation only, NOT a signed claim or execution permit.
/// No public constructor, persistence, dispatch, filesystem or process adapter.
#[derive(Debug)]
pub(crate) struct ValidatedTransaction {
    _private: (),
}

pub(crate) fn validate_gate(
    manifest: &ExecutionManifest,
    local: &LocalEvidence,
    stream: &str,
    inspector: &dyn ArchiveInspector,
) -> Result<ValidatedTransaction, String> {
    let fail = || "Execution transaction evidence does not match".to_owned();
    if manifest.schema_version != 1
        || manifest.kind != "apt-execution-manifest"
        || manifest.device_id != local.device_id
        || manifest.device_id.is_empty()
        || manifest.device_id.len() > 128
        || !manifest
            .device_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
        || !hex(&manifest.proposal_id, 32)
        || !local.package_state_clean
        || !manifest.repository_identity_verified
        || !local.repository_identity_verified
        || !hex(&manifest.package_state_sha256, 64)
        || manifest.package_state_sha256 != local.package_state_sha256
        || !hex(&manifest.repository_state_sha256, 64)
        || manifest.repository_state_sha256 != local.repository_state_sha256
        || manifest.generated_at_unix > local.now_unix
        || local.now_unix.saturating_sub(manifest.generated_at_unix) > MAX_AGE_SECS
        || manifest.metadata_checked_at_unix != Some(local.metadata_checked_at_unix)
        || manifest.metadata_valid_until_unix != Some(local.metadata_valid_until_unix)
        || local.metadata_checked_at_unix > manifest.generated_at_unix
        || local
            .now_unix
            .saturating_sub(local.metadata_checked_at_unix)
            > MAX_AGE_SECS
        || local.metadata_valid_until_unix <= local.now_unix
        || manifest.changes.is_empty()
        || manifest.changes.len() > MAX_CHANGES
        || manifest.held_packages.len() > MAX_CHANGES
        || local.held_packages.len() > MAX_CHANGES
    {
        return Err(fail());
    }
    let mut held = BTreeSet::new();
    for p in manifest.held_packages.iter().chain(&local.held_packages) {
        let mut parts = p.split(':');
        let bare = parts.next().ok_or_else(fail)?;
        if !name(bare) || parts.next().is_some_and(|a| !arch(a)) || parts.next().is_some() {
            return Err(fail());
        }
        held.insert(bare);
    }
    let mut expected = BTreeMap::new();
    for c in &manifest.changes {
        if !name(&c.package)
            || !version(&c.new)
            || !hex(&c.archive_sha256, 64)
            || held.contains(c.package.as_str())
            || c.old
                .as_ref()
                .is_some_and(|o| !version(o) || o.architecture != c.new.architecture)
        {
            return Err(fail());
        }
        if let Some(old) = &c.old
            && !inspector.is_upgrade(&old.version, &c.new.version)?
        {
            return Err("Downgrade or reinstall is prohibited".into());
        }
        if expected
            .insert((c.package.as_str(), c.new.architecture.as_str()), c)
            .is_some()
        {
            return Err(fail());
        }
    }
    let actions = parse_hook(stream)?;
    let mut unpacked = BTreeSet::new();
    let mut configured = BTreeSet::new();
    for a in actions {
        let new = a.new.as_ref().ok_or_else(fail)?;
        let key = (a.package.as_str(), new.architecture.as_str());
        let approved = expected.get(&key).ok_or_else(fail)?;
        if a.direction != "<"
            || a.old != approved.old.clone().map(normalized)
            || *new != normalized(approved.new.clone())
        {
            return Err(fail());
        }
        match a.action {
            Action::Remove => return Err("Removals are prohibited".into()),
            Action::Configure => {
                configured.insert((a.package.clone(), new.architecture.clone()));
            }
            Action::Unpack(path) => {
                let archive = inspector.inspect(&path)?;
                if archive.package != a.package
                    || normalized(archive.version) != *new
                    || archive.sha256 != approved.archive_sha256
                {
                    return Err("Archive identity or SHA256 mismatch".into());
                }
                unpacked.insert((a.package.clone(), new.architecture.clone()));
            }
        }
    }
    if unpacked.len() != expected.len() || configured != unpacked {
        return Err("Incomplete APT transaction".into());
    }
    Ok(ValidatedTransaction { _private: () })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_actual_v3_and_rejects_protocol_downgrade_or_truncation() {
        let stream = "VERSION 3\nAPT::Architecture=armhf\n\nfoo 1 armhf none < 2 armhf none /cache/foo.deb\nfoo 1 armhf none < 2 armhf none **CONFIGURE**\n";
        assert_eq!(parse_hook(stream).unwrap().len(), 2);
        for bad in [
            stream.replace("VERSION 3", "VERSION 2"),
            stream.trim_end().to_owned(),
            stream.replace("armhf none <", "<"),
        ] {
            assert!(parse_hook(&bad).is_err());
        }
    }
}

#[cfg(test)]
mod gate_tests {
    use super::*;
    struct Inspector {
        hash: String,
        upgrade: bool,
        package: String,
    }
    impl ArchiveInspector for Inspector {
        fn inspect(&self, _: &str) -> Result<ArchiveEvidence, String> {
            Ok(ArchiveEvidence {
                package: self.package.clone(),
                version: version("2"),
                sha256: self.hash.clone(),
            })
        }
        fn is_upgrade(&self, _: &str, _: &str) -> Result<bool, String> {
            Ok(self.upgrade)
        }
    }
    // Test-only archive adapter. Production execution has no filesystem adapter.
    struct FixtureArchiveInspector {
        archive: std::path::PathBuf,
    }
    impl FixtureArchiveInspector {
        fn new(path: &str) -> Self {
            Self {
                archive: std::path::PathBuf::from(path),
            }
        }
        fn field(&self, field: &str) -> Result<String, String> {
            let output = std::process::Command::new("/usr/bin/dpkg-deb")
                .arg("--field")
                .arg(&self.archive)
                .arg(field)
                .output()
                .map_err(|_| "Fixture metadata command failed")?;
            if !output.status.success() || output.stdout.len() > 4096 {
                return Err("Invalid fixture metadata".into());
            }
            String::from_utf8(output.stdout)
                .map(|s| s.trim().to_owned())
                .map_err(|_| "Invalid fixture text".into())
        }
    }
    impl ArchiveInspector for FixtureArchiveInspector {
        fn inspect(&self, path: &str) -> Result<ArchiveEvidence, String> {
            let metadata = std::fs::symlink_metadata(path).map_err(|_| "Missing fixture")?;
            if !metadata.is_file()
                || metadata.len() > 1024 * 1024
                || std::path::Path::new(path) != self.archive
            {
                return Err("Unexpected fixture archive".into());
            }
            let output = std::process::Command::new("/usr/bin/sha256sum")
                .arg("--")
                .arg(&self.archive)
                .output()
                .map_err(|_| "Fixture hash failed")?;
            if !output.status.success() || output.stdout.len() > 4096 {
                return Err("Invalid fixture hash".into());
            }
            let hash = String::from_utf8(output.stdout)
                .map_err(|_| "Invalid hash text")?
                .split_whitespace()
                .next()
                .ok_or("Missing hash")?
                .to_owned();
            let multi = self.field("Multi-Arch")?;
            Ok(ArchiveEvidence {
                package: self.field("Package")?,
                version: PackageVersion {
                    version: self.field("Version")?,
                    architecture: self.field("Architecture")?,
                    multi_arch: if multi.is_empty() {
                        "none".into()
                    } else {
                        multi
                    },
                },
                sha256: hash,
            })
        }
        fn is_upgrade(&self, _: &str, _: &str) -> Result<bool, String> {
            Err("Fixture covers new installation only".into())
        }
    }
    fn version(s: &str) -> PackageVersion {
        PackageVersion {
            version: s.into(),
            architecture: "armhf".into(),
            multi_arch: "none".into(),
        }
    }
    fn fixture() -> (ExecutionManifest, LocalEvidence, Inspector, String) {
        let m = ExecutionManifest {
            schema_version: 1,
            kind: "apt-execution-manifest".into(),
            device_id: "fixture".into(),
            proposal_id: "a".repeat(32),
            generated_at_unix: 1000,
            metadata_checked_at_unix: Some(1000),
            metadata_valid_until_unix: Some(2000),
            repository_identity_verified: true,
            package_state_sha256: "b".repeat(64),
            repository_state_sha256: "c".repeat(64),
            held_packages: vec![],
            changes: vec![ManifestChange {
                package: "foo".into(),
                old: Some(version("1")),
                new: version("2"),
                archive_sha256: "d".repeat(64),
            }],
        };
        let e = LocalEvidence {
            device_id: "fixture".into(),
            now_unix: 1001,
            package_state_sha256: "b".repeat(64),
            repository_state_sha256: "c".repeat(64),
            held_packages: vec![],
            repository_identity_verified: true,
            metadata_checked_at_unix: 1000,
            metadata_valid_until_unix: 2000,
            package_state_clean: true,
        };
        let i = Inspector {
            hash: "d".repeat(64),
            upgrade: true,
            package: "foo".into(),
        };
        (m,e,i,"VERSION 3\n\nfoo 1 armhf none < 2 armhf none /cache/foo.deb\nfoo 1 armhf none < 2 armhf none **CONFIGURE**\n".into())
    }
    #[test]
    fn new_dependency_install_requires_exact_unpack_and_configure_set() {
        let (mut m, e, i, s) = fixture();
        m.changes[0].old = None;
        let fresh = s.replace("foo 1 armhf none", "foo - - none");
        assert!(validate_gate(&m, &e, &fresh, &i).is_ok());
        assert!(
            validate_gate(
                &m,
                &e,
                &fresh.replace("foo - - none < 2 armhf none **CONFIGURE**\n", ""),
                &i
            )
            .is_err()
        );
        let duplicate = format!("{fresh}foo - - none < 2 armhf none **CONFIGURE**\n");
        assert!(validate_gate(&m, &e, &duplicate, &i).is_err());
        let extra = format!(
            "{fresh}extra - - none < 2 armhf none /cache/extra.deb\nextra - - none < 2 armhf none **CONFIGURE**\n"
        );
        assert!(validate_gate(&m, &e, &extra, &i).is_err());
    }
    #[test]
    #[ignore = "requires explicit disposable Linux APT hook harness"]
    fn disposable_linux_real_apt_hook_stream_matches_archive() {
        assert_eq!(std::env::consts::OS, "linux");
        assert_eq!(
            std::env::var("GUARDED_UPDATE_DISPOSABLE_TEST").as_deref(),
            Ok("1")
        );
        let stream_path =
            std::env::var("GUARDED_UPDATE_HOOK_STREAM_FILE").expect("harness stream path");
        let archive_path =
            std::env::var("GUARDED_UPDATE_FIXTURE_ARCHIVE").expect("fixture archive path");
        let inspector = FixtureArchiveInspector::new(&archive_path);
        let archive = inspector
            .inspect(&archive_path)
            .expect("inspect generated fixture");
        let (mut manifest, local, _, _) = fixture();
        manifest.changes = vec![ManifestChange {
            package: archive.package,
            old: None,
            new: archive.version,
            archive_sha256: archive.sha256,
        }];
        let stream = std::fs::read_to_string(stream_path).expect("captured APT hook");
        assert!(validate_gate(&manifest, &local, &stream, &inspector).is_ok());
        manifest.changes[0].archive_sha256 = "0".repeat(64);
        assert!(validate_gate(&manifest, &local, &stream, &inspector).is_err());
    }
    #[test]
    fn exact_transaction_validates_but_is_not_execution_authorization() {
        let (m, e, i, s) = fixture();
        assert!(validate_gate(&m, &e, &s, &i).is_ok());
    }
    #[test]
    fn rejects_drift_and_untrusted_or_stale_evidence() {
        for case in 0..11 {
            let (mut m, mut e, mut i, s) = fixture();
            match case {
                0 => m.repository_identity_verified = false,
                1 => m.metadata_checked_at_unix = None,
                2 => e.now_unix = 5000,
                3 => e.package_state_sha256 = "e".repeat(64),
                4 => e.repository_state_sha256 = "e".repeat(64),
                5 => m.held_packages.push("foo".into()),
                6 => e.held_packages.push("foo:armhf".into()),
                7 => i.hash = "e".repeat(64),
                8 => i.upgrade = false,
                9 => i.package = "bar".into(),
                _ => m.changes.push(m.changes[0].clone()),
            }
            assert!(validate_gate(&m, &e, &s, &i).is_err(), "case {case}");
        }
    }
    #[test]
    fn rejects_removals_reinstalls_extra_missing_and_duplicate_actions() {
        let (m, e, i, s) = fixture();
        for bad in [
            s.replace("<", ">"),
            s.replace("<", "="),
            s.replace("/cache/foo.deb", "**REMOVE**"),
            s.replace("**CONFIGURE**", "**UNKNOWN**"),
            "VERSION 3\n\n".into(),
            format!("{s}foo 1 armhf none < 2 armhf none /cache/foo.deb\n"),
            format!("{s}extra - - none < 2 armhf none /cache/extra.deb\n"),
        ] {
            assert!(validate_gate(&m, &e, &bad, &i).is_err(), "{bad}");
        }
    }
    #[test]
    fn rejects_archive_metadata_or_architecture_substitution() {
        let (m, e, i, s) = fixture();
        assert!(validate_gate(&m, &e, &s.replace("2 armhf", "2 arm64"), &i).is_err());
        assert!(validate_gate(&m, &e, &s.replace("foo 1", "foo 0"), &i).is_err());
    }
}

#[cfg(test)]
mod ingestion_tests {
    use super::*;
    #[test]
    fn malformed_oversized_and_command_bearing_manifests_fail_closed() {
        for input in [
            "{".to_owned(),
            " ".repeat(2 * 1024 * 1024 + 1),
            r#"{"schema_version":1,"command":"sh"}"#.into(),
        ] {
            assert!(decode_manifest(&input).is_err());
        }
    }
    #[test]
    fn hook_input_bounds_and_unsupported_actions_fail_closed() {
        for input in [
            "VERSION 1\n\n".to_owned(),
            "VERSION 3\nkey=value\n".to_owned(),
            "VERSION 3\n\nfoo - armhf none < 2 armhf none /a.deb\n".to_owned(),
            "VERSION 3\n\nfoo - - none < 2 armhf none **ERROR**\n".to_owned(),
            "VERSION 3\n\nfoo - - none < 2 armhf none relative.deb\n".to_owned(),
            format!("VERSION 3\n{}\n\n", "x".repeat(16385)),
            "x".repeat(MAX_STREAM_BYTES + 1),
        ] {
            assert!(parse_hook(&input).is_err());
        }
    }
}

#[cfg(test)]
mod additional_tests {
    use super::*;
    #[test]
    fn architecture_must_start_with_alphanumeric_character() {
        assert!(parse_hook("VERSION 3\n\nfoo - - none < 2 --armhf none /cache/foo.deb\n").is_err());
    }
}
