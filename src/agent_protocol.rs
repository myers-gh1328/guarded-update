//! Remote-only reporting. Device requests and controller approvals use separate keys.
use crate::exec::SystemRunner;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

const MAX_BYTES: usize = 1024 * 1024;
const MAX_STATE_BYTES: usize = 2 * MAX_BYTES;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RemoteConfig {
    pub schema_version: u32,
    pub server_url: String,
    pub device_id: String,
    pub private_key_file: PathBuf,
    pub approval_public_key_file: PathBuf,
    pub state_dir: PathBuf,
    #[serde(default = "report_interval")]
    pub report_every_secs: u64,
}
fn report_interval() -> u64 {
    3600
}

fn read_checked(path: &Path, private: bool) -> Result<String, String> {
    read_checked_limit(path, private, MAX_BYTES)
}
fn read_checked_limit(path: &Path, private: bool, max_bytes: usize) -> Result<String, String> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "Required agent file is unavailable")?;
    if !metadata.is_file() || metadata.len() > max_bytes as u64 {
        return Err("Agent file must be a bounded regular file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & if private { 0o077 } else { 0o022 } != 0 {
            return Err("Agent file permissions are too broad".into());
        }
    }
    fs::read_to_string(path).map_err(|_| "Cannot read agent file".into())
}

impl RemoteConfig {
    pub(crate) fn load(path: &Path) -> Result<Self, String> {
        let config: Self = toml::from_str(&read_checked(path, true)?)
            .map_err(|_| "Invalid remote agent configuration")?;
        config.validate()?;
        Ok(config)
    }
    fn validate(&self) -> Result<(), String> {
        if self.schema_version != 1
            || self.device_id.is_empty()
            || self.device_id.len() > 128
            || !self
                .device_id
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
            || !(300..=86400).contains(&self.report_every_secs)
        {
            return Err("Invalid remote agent identity, schema or reporting interval".into());
        }
        let origin = self
            .server_url
            .strip_prefix("https://")
            .ok_or("Remote agent requires HTTPS")?;
        let host = origin.strip_suffix('/').unwrap_or(origin);
        if host.is_empty()
            || !host
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b".:-".contains(&c))
            || host.starts_with('-')
            || host.matches(':').count() > 1
        {
            return Err("Server URL must be a bare HTTPS origin".into());
        }
        if let Some((_, port)) = host.split_once(':')
            && port.parse::<u16>().ok().filter(|p| *p != 0).is_none()
        {
            return Err("Invalid server port".into());
        }
        for path in [
            &self.private_key_file,
            &self.approval_public_key_file,
            &self.state_dir,
        ] {
            if !path.is_absolute() {
                return Err("Agent file paths must be absolute".into());
            }
        }
        Ok(())
    }
}

pub(crate) fn request_message(
    device: &str,
    method: &str,
    path: &str,
    timestamp: u64,
    nonce: &str,
    hash: &str,
) -> String {
    format!("guarded-update-v1\n{device}\n{method}\n{path}\n{timestamp}\n{nonce}\n{hash}")
}
fn is_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn random_id() -> Result<String, String> {
    let mut bytes = [0u8; 16];
    File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .map_err(|_| "Cannot read system randomness")?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}
fn tool(program: &str, args: &[&str], input: Option<&str>) -> Result<String, String> {
    let out = SystemRunner::new(Duration::from_secs(40))
        .run_input(program, args, &[("LC_ALL", "C")], input)
        .map_err(|_| "Agent prerequisite command failed")?;
    if !out.success() || out.stdout.len() > MAX_BYTES {
        return Err("Agent prerequisite command failed or exceeded response limit".into());
    }
    Ok(out.stdout)
}
fn digest(text: &str) -> Result<String, String> {
    let output = tool("/usr/bin/openssl", &["dgst", "-sha256", "-hex"], Some(text))?;
    let hash = output
        .split_whitespace()
        .last()
        .ok_or("Missing SHA256 output")?;
    if !is_hex(hash, 64) {
        return Err("Invalid SHA256 output".into());
    }
    Ok(hash.to_owned())
}
fn curl_quote(text: &str) -> Result<String, String> {
    if text
        .chars()
        .any(|c| c.is_control() && c != '\n' && c != '\r' && c != '\t')
    {
        return Err("Invalid curl configuration text".into());
    }
    Ok(format!(
        "\"{}\"",
        text.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
            .replace('\r', "\\r")
            .replace('\t', "\\t")
    ))
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Decision {
    id: String,
    device_id: String,
    proposal_id: String,
    report_sha256: String,
    issued_at_unix: u64,
    expires_at_unix: u64,
    allow_service_restarts: bool,
    allow_reboot: bool,
    execution_allowed: bool,
    status: String,
    signature: String,
}
impl Decision {
    fn message(&self) -> String {
        format!(
            "guarded-update-approval-v1\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
            self.id,
            self.device_id,
            self.proposal_id,
            self.report_sha256,
            self.issued_at_unix,
            self.expires_at_unix,
            self.allow_service_restarts,
            self.allow_reboot,
            self.execution_allowed
        )
    }
}

fn validate_response(
    value: &Value,
    proposal_id: &str,
    device_id: &str,
    report_hash: &str,
    now: u64,
) -> Result<Option<Decision>, String> {
    if value["schema_version"] != 1 || value["proposal_id"] != proposal_id {
        return Err("Approval response identity or schema mismatch".into());
    }
    let status = value["status"].as_str().ok_or("Missing approval status")?;
    if ![
        "pending",
        "approved",
        "rejected",
        "revoked",
        "expired",
        "superseded",
    ]
    .contains(&status)
    {
        return Err("Unknown approval status".into());
    }
    if status != "approved" {
        if value.get("decision") != Some(&Value::Null) {
            return Err("Unexpected decision for inactive proposal".into());
        }
        return Ok(None);
    }
    let decision: Decision = serde_json::from_value(value["decision"].clone())
        .map_err(|_| "Invalid signed approval shape")?;
    if decision.proposal_id != proposal_id
        || decision.device_id != device_id
        || decision.report_sha256 != report_hash
        || decision.status != "approved"
        || decision.id.is_empty()
        || decision.id.len() > 128
        || decision.id.contains(['\r', '\n'])
        || decision.allow_reboot
        || decision.execution_allowed
        || decision.expires_at_unix <= now
        || decision.issued_at_unix > now.saturating_add(300)
        || decision.expires_at_unix <= decision.issued_at_unix
        || decision
            .expires_at_unix
            .saturating_sub(decision.issued_at_unix)
            > 86400
        || decision.signature.len() < 128
        || decision.signature.len() > 144
        || !decision.signature.len().is_multiple_of(2)
        || !is_hex(&decision.signature, decision.signature.len())
    {
        return Err("Approval binding, permission or validity check failed".into());
    }
    Ok(Some(decision))
}

struct TempFile(PathBuf);
impl TempFile {
    fn bytes(directory: &Path, bytes: &[u8]) -> Result<Self, String> {
        let path = directory.join(format!(".agent-{}", random_id()?));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&path)
            .map_err(|_| "Cannot create private agent file")?;
        let guard = Self(path);
        file.write_all(bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| "Cannot persist private agent file")?;
        Ok(guard)
    }
}
impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}
fn verify_decision(config: &RemoteConfig, decision: &Decision) -> Result<(), String> {
    let bytes: Vec<u8> = decision
        .signature
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap_or(""), 16).unwrap_or(0))
        .collect();
    let signature = TempFile::bytes(&config.state_dir, &bytes)?;
    read_checked(&config.approval_public_key_file, false)?;
    tool(
        "/usr/bin/openssl",
        &[
            "dgst",
            "-sha256",
            "-verify",
            config
                .approval_public_key_file
                .to_str()
                .ok_or("Invalid public key path")?,
            "-signature",
            signature.0.to_str().ok_or("Invalid signature path")?,
        ],
        Some(&decision.message()),
    )?;
    Ok(())
}

trait Transport {
    fn request(&self, method: &str, path: &str, body: &str, now: u64) -> Result<Value, String>;
}
struct SignedTransport<'a>(&'a RemoteConfig);
impl Transport for SignedTransport<'_> {
    fn request(&self, method: &str, path: &str, body: &str, now: u64) -> Result<Value, String> {
        let config = self.0;
        read_checked(&config.private_key_file, true)?;
        let nonce = random_id()?;
        let canonical =
            request_message(&config.device_id, method, path, now, &nonce, &digest(body)?);
        let signed = tool(
            "/usr/bin/openssl",
            &[
                "dgst",
                "-sha256",
                "-sign",
                config
                    .private_key_file
                    .to_str()
                    .ok_or("Invalid private key path")?,
                "-hex",
            ],
            Some(&canonical),
        )?;
        let signature = signed
            .split_whitespace()
            .last()
            .ok_or("Missing request signature")?;
        if signature.len() < 128 || signature.len() > 144 || !is_hex(signature, signature.len()) {
            return Err("Invalid request signature output".into());
        }
        let mut input = format!(
            "url = {}\nrequest = {}\n",
            curl_quote(&format!(
                "{}{path}",
                config.server_url.trim_end_matches('/')
            ))?,
            curl_quote(method)?
        );
        for header in [
            format!("X-Device-Id: {}", config.device_id),
            format!("X-Device-Timestamp: {now}"),
            format!("X-Device-Nonce: {nonce}"),
            format!("X-Device-Signature: {signature}"),
            "Content-Type: application/json".into(),
        ] {
            input.push_str(&format!("header = {}\n", curl_quote(&header)?));
        }
        if method == "POST" {
            input.push_str(&format!("data-binary = {}\n", curl_quote(body)?));
        }
        let response = tool(
            "/usr/bin/curl",
            &[
                "--disable",
                "--silent",
                "--show-error",
                "--fail",
                "--proto",
                "=https",
                "--tlsv1.2",
                "--max-time",
                "30",
                "--max-filesize",
                "1048576",
                "--config",
                "-",
            ],
            Some(&input),
        )?;
        serde_json::from_str(&response).map_err(|_| "Invalid dashboard JSON response".into())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Report {
    schema_version: u32,
    proposal_id: String,
    proposal: Value,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RemoteState {
    schema_version: u32,
    report: Report,
    collected_at: u64,
    last_status: Option<String>,
    verified_approval: Option<Decision>,
}
fn persist(config: &RemoteConfig, state: &RemoteState) -> Result<(), String> {
    let json = serde_json::to_vec(state).map_err(|_| "Cannot encode agent state")?;
    if json.len() > MAX_STATE_BYTES {
        return Err("Agent state exceeds storage limit".into());
    }
    let file = TempFile::bytes(&config.state_dir, &json)?;
    fs::rename(&file.0, config.state_dir.join("remote-state.json"))
        .map_err(|_| "Cannot replace agent state")?;
    File::open(&config.state_dir)
        .and_then(|dir| dir.sync_all())
        .map_err(|_| "Cannot sync agent state directory")?;
    Ok(())
}
struct AgentLock(File);
impl Drop for AgentLock {
    fn drop(&mut self) {
        // A concurrent fork can temporarily inherit this descriptor. Unlock the
        // shared open-file description rather than waiting for every copy to close.
        let _ = self.0.unlock();
    }
}

fn state_directory(path: &Path) -> Result<AgentLock, String> {
    if !path.exists() {
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder
            .create(path)
            .map_err(|_| "Create the agent state parent directory first")?;
    }
    let metadata =
        fs::symlink_metadata(path).map_err(|_| "Agent state directory is unavailable")?;
    if !metadata.is_dir() {
        return Err("Agent state path must be a directory, not a symlink".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("Agent state directory must be private (0700)".into());
        }
    }
    let lock_path = path.join("remote.lock");
    if lock_path.exists() {
        read_checked(&lock_path, true)?;
    }
    let mut options = OpenOptions::new();
    options.create(true).truncate(false).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(lock_path)
        .map_err(|_| "Cannot open remote agent lock")?;
    file.try_lock()
        .map_err(|_| "Another remote agent is running")?;
    Ok(AgentLock(file))
}

pub(crate) fn sync(
    config: &RemoteConfig,
    collect: impl FnOnce() -> Result<Value, String>,
    now: u64,
) -> Result<String, String> {
    let transport = SignedTransport(config);
    sync_with(config, collect, now, &transport, |decision| {
        verify_decision(config, decision)
    })
}

fn sync_with(
    config: &RemoteConfig,
    collect: impl FnOnce() -> Result<Value, String>,
    now: u64,
    transport: &dyn Transport,
    verify: impl Fn(&Decision) -> Result<(), String>,
) -> Result<String, String> {
    config.validate()?;
    let _lock = state_directory(&config.state_dir)?;
    read_checked(&config.private_key_file, true)?;
    read_checked(&config.approval_public_key_file, false)?;
    let state_path = config.state_dir.join("remote-state.json");
    let old = if state_path.exists() {
        Some(
            serde_json::from_str::<RemoteState>(&read_checked_limit(
                &state_path,
                true,
                MAX_STATE_BYTES,
            )?)
            .map_err(|_| "Invalid remote state; no report sent")?,
        )
    } else {
        None
    };
    if old.as_ref().is_some_and(|s| {
        s.schema_version != 1
            || s.report.schema_version != 1
            || !is_hex(&s.report.proposal_id, 32)
            || s.collected_at > now.saturating_add(300)
    }) {
        return Err("Unsupported or invalid remote state".into());
    }
    let mut state = match old {
        Some(state) if now.saturating_sub(state.collected_at) < config.report_every_secs => state,
        _ => RemoteState {
            schema_version: 1,
            report: Report {
                schema_version: 1,
                proposal_id: random_id()?,
                proposal: collect()?,
            },
            collected_at: now,
            last_status: None,
            verified_approval: None,
        },
    };
    let body = serde_json::to_string(&state.report).map_err(|_| "Cannot encode report")?;
    if body.len() > MAX_BYTES {
        return Err("Update report exceeds request limit".into());
    }
    // Persist exact report before sending: retries keep the same ID and bytes.
    state.verified_approval = None;
    state.last_status = None;
    persist(config, &state)?;
    let hash = digest(&body)?;
    let posted = transport.request("POST", "/api/agent/v1/proposals", &body, now)?;
    validate_response(
        &posted,
        &state.report.proposal_id,
        &config.device_id,
        &hash,
        now,
    )?;
    let response = transport.request(
        "GET",
        &format!(
            "/api/agent/v1/decisions?proposal_id={}",
            state.report.proposal_id
        ),
        "",
        now,
    )?;
    let decision = validate_response(
        &response,
        &state.report.proposal_id,
        &config.device_id,
        &hash,
        now,
    )?;
    if let Some(ref approved) = decision {
        verify(approved)?;
    }
    state.last_status = response["status"].as_str().map(str::to_owned);
    state.verified_approval = decision;
    persist(config, &state)?;
    Ok(format!(
        "Remote proposal status: {}. Reporting build; no packages installed.",
        state.last_status.as_deref().unwrap_or("unknown")
    ))
}

#[cfg(feature = "apt-executor")]
pub(crate) fn signed_post(
    config: &RemoteConfig,
    path: &str,
    body: &str,
    now: u64,
) -> Result<Value, String> {
    SignedTransport(config).request("POST", path, body, now)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestDirectory(PathBuf);
    impl TestDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "guarded-update-remote-test-{}",
                random_id().unwrap()
            ));
            fs::create_dir(&path).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            }
            Self(path)
        }
        fn config(&self) -> RemoteConfig {
            let private = TempFile::bytes(&self.0, b"test-key-reference").unwrap();
            let public = TempFile::bytes(&self.0, b"test-public-reference").unwrap();
            let config = RemoteConfig {
                schema_version: 1,
                server_url: "https://controller.example.test".into(),
                device_id: "device-a".into(),
                private_key_file: private.0.clone(),
                approval_public_key_file: public.0.clone(),
                state_dir: self.0.join("state"),
                report_every_secs: 3600,
            };
            // Files remain inside the directory until its Drop cleanup.
            std::mem::forget(private);
            std::mem::forget(public);
            config
        }
    }
    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    struct PendingTransport(std::cell::RefCell<Vec<String>>);
    impl Transport for PendingTransport {
        fn request(&self, method: &str, path: &str, body: &str, _: u64) -> Result<Value, String> {
            let id = if method == "POST" {
                let report: Value = serde_json::from_str(body).unwrap();
                self.0.borrow_mut().push(body.into());
                report["proposal_id"].as_str().unwrap().to_owned()
            } else {
                path.split_once('=').unwrap().1.to_owned()
            };
            Ok(
                serde_json::json!({"schema_version":1,"proposal_id":id,"status":"pending","decision":null}),
            )
        }
    }

    #[test]
    fn lock_release_is_explicit_even_if_a_child_inherited_the_descriptor() {
        let dir = TestDirectory::new();
        let config = dir.config();
        let lock = state_directory(&config.state_dir).unwrap();
        let inherited = lock.0.try_clone().unwrap();
        drop(lock);
        let next = state_directory(&config.state_dir);
        assert!(
            next.is_ok(),
            "inherited descriptors must not retain the completed cycle lock"
        );
        drop(inherited);
    }

    #[test]
    fn node_generated_signatures_match_the_rust_openssl_protocol() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../tests/fixtures/guarded-update-protocol-v1.json"
        ))
        .unwrap();
        let request = &fixture["request"];
        let text = |field: &str| request[field].as_str().unwrap();
        assert_eq!(digest(text("body")).unwrap(), text("body_sha256"));
        let canonical = request_message(
            text("device_id"),
            text("method"),
            text("path"),
            text("timestamp").parse().unwrap(),
            text("nonce"),
            text("body_sha256"),
        );
        assert_eq!(canonical, text("canonical"));
        let dir = TestDirectory::new();
        let mut config = dir.config();
        let signature_bytes: Vec<_> = text("signature")
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect();
        let sig = TempFile::bytes(&dir.0, &signature_bytes).unwrap();
        let pubkey = TempFile::bytes(&dir.0, text("public_key").as_bytes()).unwrap();
        tool(
            "/usr/bin/openssl",
            &[
                "dgst",
                "-sha256",
                "-verify",
                pubkey.0.to_str().unwrap(),
                "-signature",
                sig.0.to_str().unwrap(),
            ],
            Some(&canonical),
        )
        .unwrap();
        let decision: Decision =
            serde_json::from_value(fixture["approval"]["decision"].clone()).unwrap();
        assert_eq!(
            decision.message(),
            fixture["approval"]["canonical"].as_str().unwrap()
        );
        let approval_key = TempFile::bytes(
            &dir.0,
            fixture["approval"]["public_key"]
                .as_str()
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
        config.approval_public_key_file = approval_key.0.clone();
        let lock = state_directory(&config.state_dir).unwrap();
        drop(lock);
        verify_decision(&config, &decision).unwrap();
    }

    #[test]
    fn maximum_report_does_not_make_saved_state_unreadable() {
        let dir = TestDirectory::new();
        let config = dir.config();
        let transport = PendingTransport(std::cell::RefCell::new(Vec::new()));
        sync_with(
            &config,
            || Ok(Value::String("x".repeat(MAX_BYTES - 128))),
            10000,
            &transport,
            |_| panic!(),
        )
        .unwrap();
        sync_with(
            &config,
            || panic!("reuse report"),
            10300,
            &transport,
            |_| panic!(),
        )
        .unwrap();
    }

    #[test]
    fn polling_reuses_exact_report_then_refreshes_after_interval() {
        let dir = TestDirectory::new();
        let config = dir.config();
        let transport = PendingTransport(std::cell::RefCell::new(Vec::new()));
        sync_with(
            &config,
            || Ok(serde_json::json!({"fixture":true})),
            10000,
            &transport,
            |_| panic!("no approval to verify"),
        )
        .unwrap();
        sync_with(
            &config,
            || panic!("must not recollect during polling"),
            10300,
            &transport,
            |_| panic!(),
        )
        .unwrap();
        assert_eq!(transport.0.borrow()[0], transport.0.borrow()[1]);
        sync_with(
            &config,
            || Ok(serde_json::json!({"fixture":true})),
            13600,
            &transport,
            |_| panic!(),
        )
        .unwrap();
        assert_ne!(transport.0.borrow()[1], transport.0.borrow()[2]);
        let state: RemoteState = serde_json::from_str(
            &read_checked(&config.state_dir.join("remote-state.json"), true).unwrap(),
        )
        .unwrap();
        assert_eq!(state.last_status.as_deref(), Some("pending"));
        assert!(state.verified_approval.is_none());
    }

    #[test]
    fn outage_persists_report_before_send_and_retry_keeps_id() {
        struct Offline;
        impl Transport for Offline {
            fn request(&self, _: &str, _: &str, _: &str, _: u64) -> Result<Value, String> {
                Err("offline".into())
            }
        }
        let dir = TestDirectory::new();
        let config = dir.config();
        assert!(sync_with(&config, || Ok(Value::Null), 10000, &Offline, |_| panic!()).is_err());
        let before = read_checked(&config.state_dir.join("remote-state.json"), true).unwrap();
        let before: RemoteState = serde_json::from_str(&before).unwrap();
        let transport = PendingTransport(std::cell::RefCell::new(Vec::new()));
        sync_with(
            &config,
            || panic!("retry must preserve proposal"),
            10300,
            &transport,
            |_| panic!(),
        )
        .unwrap();
        let retried: Report = serde_json::from_str(&transport.0.borrow()[0]).unwrap();
        assert_eq!(retried.proposal_id, before.report.proposal_id);
    }

    #[test]
    fn invalid_config_and_corrupt_state_fail_closed() {
        let dir = TestDirectory::new();
        let mut config = dir.config();
        for origin in [
            "http://controller.test",
            "https://user@controller.test",
            "https://controller.test/path",
            "https://controller.test?x=y",
        ] {
            config.server_url = origin.into();
            assert!(config.validate().is_err());
        }
        config.server_url = "https://controller.test".into();
        let _lock = state_directory(&config.state_dir).unwrap();
        drop(_lock);
        fs::write(config.state_dir.join("remote-state.json"), "garbage").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                config.state_dir.join("remote-state.json"),
                fs::Permissions::from_mode(0o600),
            )
            .unwrap();
        }
        let transport = PendingTransport(std::cell::RefCell::new(Vec::new()));
        assert!(sync_with(&config, || panic!(), 10000, &transport, |_| panic!()).is_err());
        assert!(transport.0.borrow().is_empty());
    }

    #[test]
    fn openssl_digest_and_controller_approval_signatures_are_verified() {
        assert_eq!(
            digest("abc").unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let dir = TestDirectory::new();
        let mut config = dir.config();
        let private = dir.0.join("controller.pem");
        tool(
            "/usr/bin/openssl",
            &[
                "ecparam",
                "-name",
                "prime256v1",
                "-genkey",
                "-noout",
                "-out",
                private.to_str().unwrap(),
            ],
            None,
        )
        .unwrap();
        let public = tool(
            "/usr/bin/openssl",
            &["pkey", "-in", private.to_str().unwrap(), "-pubout"],
            None,
        )
        .unwrap();
        config.approval_public_key_file = dir.0.join("controller-public.pem");
        fs::write(&config.approval_public_key_file, public).unwrap();
        let lock = state_directory(&config.state_dir).unwrap();
        drop(lock);
        let mut decision = Decision {
            id: "approval-a".into(),
            device_id: "device-a".into(),
            proposal_id: "a".repeat(32),
            report_sha256: "b".repeat(64),
            issued_at_unix: 10000,
            expires_at_unix: 13600,
            allow_service_restarts: true,
            allow_reboot: false,
            execution_allowed: false,
            status: "approved".into(),
            signature: String::new(),
        };
        let signed = tool(
            "/usr/bin/openssl",
            &[
                "dgst",
                "-sha256",
                "-sign",
                private.to_str().unwrap(),
                "-hex",
            ],
            Some(&decision.message()),
        )
        .unwrap();
        decision.signature = signed.split_whitespace().last().unwrap().into();
        verify_decision(&config, &decision).unwrap();
        decision.expires_at_unix += 1;
        assert!(verify_decision(&config, &decision).is_err());
        let value = serde_json::json!({"schema_version":1,"proposal_id": "a".repeat(32),"status":"approved","decision":decision});
        assert!(
            validate_response(
                &value,
                &"a".repeat(32),
                "other-device",
                &"b".repeat(64),
                11000
            )
            .is_err()
        );
        assert!(
            validate_response(&value, &"a".repeat(32), "device-a", &"c".repeat(64), 11000).is_err()
        );
        assert!(
            validate_response(&value, &"a".repeat(32), "device-a", &"b".repeat(64), 14000).is_err()
        );
    }
    #[test]
    fn inactive_response_requires_an_explicit_null_decision() {
        let response =
            serde_json::json!({"schema_version":1,"proposal_id":"a".repeat(32),"status":"pending"});
        assert!(
            validate_response(&response, &"a".repeat(32), "device-a", &"b".repeat(64), 123)
                .is_err()
        );
    }

    #[test]
    fn canonical_request_binds_identity_method_path_body_and_replay_fields() {
        assert_eq!(
            request_message(
                "device-a",
                "POST",
                "/api/agent/v1/proposals",
                123,
                "nonce",
                "hash"
            ),
            "guarded-update-v1\ndevice-a\nPOST\n/api/agent/v1/proposals\n123\nnonce\nhash"
        );
    }

    #[test]
    fn unknown_execution_permission_is_rejected() {
        let response = serde_json::json!({"schema_version":1,"proposal_id":"a".repeat(32),"status":"approved","decision": {"execution_allowed":true}});
        assert!(
            validate_response(&response, &"a".repeat(32), "device-a", &"b".repeat(64), 123)
                .is_err()
        );
    }
}
