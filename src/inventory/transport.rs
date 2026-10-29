use super::{
    process::{SystemTools, Tools},
    state,
};
use serde::Deserialize;
use serde_json::Value;
use std::path::{Path, PathBuf};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub schema_version: u32,
    pub server_url: String,
    pub device_id: String,
    pub enrollment_id: String,
    pub key_id: String,
    pub reporting_private_key_file: PathBuf,
    pub state_dir: PathBuf,
}

pub fn token(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 128
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
}
fn valid_origin(text: &str) -> bool {
    let Some(host) = text.strip_prefix("https://") else {
        return false;
    };
    !host.is_empty()
        && host.len() <= 253
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-.:".contains(&b))
        && !host.starts_with('.')
        && !host.ends_with('.')
}
impl Config {
    pub fn load(path: &Path) -> Result<Self, String> {
        if SystemTools.text("/usr/bin/id", &["-u"], 64)?.trim() == "0" {
            return Err(
                "Inventory reporting must run as its unprivileged reporting identity".into(),
            );
        }
        let bytes = state::read(path, 65536)?;
        let config: Self = toml::from_str(
            std::str::from_utf8(&bytes).map_err(|_| "Invalid reporting configuration")?,
        )
        .map_err(|_| "Invalid reporting configuration")?;
        if config.schema_version != 1
            || !valid_origin(&config.server_url)
            || !token(&config.device_id)
            || !token(&config.key_id)
            || !uuid(&config.enrollment_id)
            || !config.reporting_private_key_file.is_absolute()
            || !config.state_dir.is_absolute()
        {
            return Err("Invalid reporting configuration or identity".into());
        }
        state::protected(&config.reporting_private_key_file, false)?;
        state::protected(&config.state_dir, true)?;
        let key_path = config
            .reporting_private_key_file
            .to_str()
            .ok_or("Invalid key path")?;
        let description = SystemTools.run(
            "/usr/bin/openssl",
            &["pkey", "-in", key_path, "-text", "-noout"],
            &[],
            8192,
        )?;
        if !String::from_utf8_lossy(&description).contains("prime256v1") {
            return Err("Reporting key must be P-256".into());
        }
        Ok(config)
    }
}
pub fn uuid(text: &str) -> bool {
    text.len() == 36
        && text.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
}
pub fn canonical(
    device: &str,
    enrollment: &str,
    key: &str,
    path: &str,
    now: u64,
    nonce: &str,
    digest: &str,
) -> String {
    format!(
        "command-center-inventory-v1\n{device}\n{enrollment}\n{key}\nPOST\n{path}\n{now}\n{nonce}\n{digest}"
    )
}
fn quote(text: &str) -> Result<String, String> {
    if text.contains(['\r', '\0']) {
        return Err("Invalid transport field".into());
    }
    Ok(format!(
        "\"{}\"",
        text.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
    ))
}
pub fn random_hex(bytes: usize) -> Result<String, String> {
    let output = SystemTools.text(
        "/usr/bin/openssl",
        &["rand", "-hex", &bytes.to_string()],
        256,
    )?;
    let text = output.trim();
    if text.len() != bytes * 2 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("Secure randomness unavailable".into());
    }
    Ok(text.to_lowercase())
}
pub fn report_id() -> Result<String, String> {
    let mut bytes = random_hex(16)?.into_bytes();
    bytes[12] = b'4';
    bytes[16] = b'8';
    let h = String::from_utf8(bytes).map_err(|_| "Secure randomness unavailable")?;
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    ))
}
pub struct Response {
    pub status: u16,
    pub body: Value,
    pub retry_after: u64,
}
fn request_config(
    config: &Config,
    path: &str,
    body: &str,
    now: u64,
    nonce: &str,
    digest: &str,
    signature: &str,
) -> Result<String, String> {
    let mut request = format!(
        "url = {}\nrequest = \"POST\"\n",
        quote(&format!("{}{path}", config.server_url))?
    );
    for header in [
        "Content-Type: application/json".to_owned(),
        "Expect:".to_owned(),
        format!("x-device-id: {}", config.device_id),
        format!("x-device-enrollment: {}", config.enrollment_id),
        format!("x-device-key-id: {}", config.key_id),
        format!("x-device-timestamp: {now}"),
        format!("x-device-nonce: {nonce}"),
        format!("x-device-signature: {signature}"),
        format!("x-device-body-sha256: {digest}"),
    ] {
        request.push_str(&format!("header = {}\n", quote(&header)?));
    }
    request.push_str(&format!("data-binary = {}\n", quote(body)?));
    Ok(request)
}
pub fn post(config: &Config, path: &str, body: &str, now: u64) -> Result<Response, String> {
    post_inner(
        config,
        path,
        body,
        now,
        #[cfg(test)]
        None,
    )
}

#[cfg(test)]
pub(super) fn post_fixture(
    config: &Config,
    path: &str,
    body: &str,
    now: u64,
    ca: &Path,
) -> Result<Response, String> {
    let port = config
        .server_url
        .strip_prefix("https://127.0.0.1:")
        .ok_or("Fixture endpoint must be loopback")?;
    if port.is_empty()
        || !port.bytes().all(|b| b.is_ascii_digit())
        || port.parse::<u16>().ok().is_none_or(|p| p == 0)
    {
        return Err("Fixture endpoint must be loopback".into());
    }
    state::protected(ca, false)?;
    post_inner(config, path, body, now, Some(ca))
}

fn post_inner(
    config: &Config,
    path: &str,
    body: &str,
    now: u64,
    #[cfg(test)] ca: Option<&Path>,
) -> Result<Response, String> {
    if !matches!(
        path,
        "/api/agent/v1/inventory/check-ins" | "/api/agent/v1/inventory/reports"
    ) {
        return Err("Unknown reporting endpoint".into());
    }
    let nonce = random_hex(16)?;
    let digest = SystemTools.sha256(body.as_bytes())?;
    let message = canonical(
        &config.device_id,
        &config.enrollment_id,
        &config.key_id,
        path,
        now,
        &nonce,
        &digest,
    );
    let key = config
        .reporting_private_key_file
        .to_str()
        .ok_or("Invalid key path")?;
    let signature = SystemTools.run(
        "/usr/bin/openssl",
        &["dgst", "-sha256", "-sign", key],
        message.as_bytes(),
        256,
    )?;
    let signature = signature
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let request = request_config(config, path, body, now, &nonce, &digest, &signature)?;
    let args = vec![
        "--disable",
        "--silent",
        "--show-error",
        "--proto",
        "=https",
        "--max-redirs",
        "0",
        "--connect-timeout",
        "10",
        "--max-time",
        "90",
        "--max-filesize",
        "65536",
        "--include",
        "--suppress-connect-headers",
        "--write-out",
        "\n%{http_code}",
        "--config",
        "-",
    ];
    #[cfg(test)]
    let args = if let Some(ca) = ca {
        let mut args = args;
        args.extend(["--cacert", ca.to_str().ok_or("Invalid fixture CA path")?]);
        args
    } else {
        args
    };
    let output = SystemTools.run("/usr/bin/curl", &args, request.as_bytes(), 128 * 1024)?;
    let text = String::from_utf8(output).map_err(|_| "Invalid reporting response")?;
    let (response, status) = text.rsplit_once('\n').ok_or("Invalid reporting response")?;
    let status = status
        .parse::<u16>()
        .map_err(|_| "Invalid reporting status")?;
    let (headers, body) = response
        .split_once("\r\n\r\n")
        .ok_or("Invalid reporting headers")?;
    let retry_after = headers
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("retry-after"))
        .and_then(|(_, value)| value.trim().parse::<u64>().ok())
        .unwrap_or(0)
        .min(86400);
    let body = serde_json::from_str(body).unwrap_or(Value::Null);
    Ok(Response {
        status,
        body,
        retry_after,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn retire_tls(child: &mut std::process::Child, root: &Path, ready: bool) -> Result<(), String> {
        if child
            .try_wait()
            .map_err(|_| "TLS fixture status unknown")?
            .is_none()
        {
            child.kill().map_err(|_| "TLS fixture stop unknown")?;
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            if child
                .try_wait()
                .map_err(|_| "TLS fixture status unknown")?
                .is_some()
            {
                break;
            }
            if std::time::Instant::now() >= deadline {
                return Err("TLS fixture stop unknown".into());
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        if !ready {
            return Err("TLS fixture startup unknown; scratch retained".into());
        }
        std::fs::remove_dir_all(root).map_err(|_| "TLS fixture cleanup unknown".into())
    }
    #[test]
    fn unready_tls_child_is_stopped_but_its_directory_is_retained() {
        use std::os::unix::fs::PermissionsExt;
        use std::process::{Command, Stdio};
        let root = std::fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "inventory-tls-uncertain-{}",
                random_hex(16).unwrap()
            ));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut child = Command::new("/usr/bin/python3")
            .args(["-I", "-c", "import time; time.sleep(30)"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        assert!(retire_tls(&mut child, &root, false).is_err());
        assert!(child.try_wait().unwrap().is_some());
        assert!(root.is_dir());
        std::fs::remove_dir(&root).unwrap();
    }
    #[test]
    fn fixture_ca_never_authorizes_non_loopback_destinations() {
        let config = Config {
            schema_version: 1,
            server_url: "https://example.test:8443".into(),
            device_id: "test".into(),
            enrollment_id: "00000000-0000-4000-8000-000000000001".into(),
            key_id: "test".into(),
            reporting_private_key_file: "/unused".into(),
            state_dir: "/unused".into(),
        };
        assert!(
            post_fixture(
                &config,
                "/api/agent/v1/inventory/check-ins",
                "{}",
                1,
                Path::new("/unused")
            )
            .is_err()
        );
    }

    #[test]
    fn fixture_trust_rejects_missing_invalid_or_untrusted_ca_path() {
        let config = Config {
            schema_version: 1,
            server_url: "https://127.0.0.1:4443".into(),
            device_id: "test".into(),
            enrollment_id: "00000000-0000-4000-8000-000000000001".into(),
            key_id: "test".into(),
            reporting_private_key_file: "/unused".into(),
            state_dir: "/unused".into(),
        };
        assert!(
            post_fixture(
                &config,
                "/api/agent/v1/inventory/check-ins",
                "{}",
                1,
                Path::new("/missing-ca")
            )
            .is_err()
        );
    }

    #[test]
    fn fixture_curl_requires_matching_private_ca_and_ip_san_without_redirects() {
        use std::os::unix::fs::PermissionsExt;
        use std::process::{Child, Command, Stdio};
        struct Fixture {
            child: Child,
            root: PathBuf,
            ready: bool,
            retirement_attempted: bool,
        }
        impl Drop for Fixture {
            fn drop(&mut self) {
                if !self.retirement_attempted {
                    let _ = self.child.kill();
                }
            }
        }
        impl Fixture {
            fn retire(&mut self) -> Result<(), String> {
                if self.retirement_attempted {
                    return Err("TLS fixture retirement already attempted".into());
                }
                self.retirement_attempted = true;
                retire_tls(&mut self.child, &self.root, self.ready)
            }
        }
        fn fixture(san: &str) -> (Fixture, Config) {
            let root = std::fs::canonicalize(std::env::temp_dir())
                .unwrap()
                .join(format!("inventory-tls-{}", random_hex(16).unwrap()));
            std::fs::create_dir(&root).unwrap();
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
            let child = Command::new("/usr/bin/python3")
                .args([
                    "-I",
                    "-B",
                    concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/tests/inventory_tls_fixture.py"
                    ),
                    root.to_str().unwrap(),
                    san,
                ])
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let mut fixture = Fixture {
                child,
                root,
                ready: false,
                retirement_attempted: false,
            };
            let start = std::time::Instant::now();
            while !fixture.root.join("port").exists() {
                assert!(
                    fixture.child.try_wait().unwrap().is_none(),
                    "Fixture TLS server exited"
                );
                assert!(
                    start.elapsed() < std::time::Duration::from_secs(15),
                    "Fixture TLS server startup timed out"
                );
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            let port = std::fs::read_to_string(fixture.root.join("port"))
                .unwrap()
                .parse::<u16>()
                .unwrap();
            fixture.ready = true;
            let config = Config {
                schema_version: 1,
                server_url: format!("https://127.0.0.1:{port}"),
                device_id: "synthetic".into(),
                enrollment_id: "00000000-0000-4000-8000-000000000001".into(),
                key_id: "synthetic".into(),
                reporting_private_key_file: fixture.root.join("device.key"),
                state_dir: fixture.root.clone(),
            };
            (fixture, config)
        }
        let (mut good, config) = fixture("ip");
        let path = "/api/agent/v1/inventory/check-ins";
        assert_eq!(
            post_fixture(&config, path, "{}", 1, &good.root.join("server.pem"))
                .unwrap()
                .status,
            200
        );
        assert!(post_fixture(&config, path, "{}", 1, &good.root.join("other.pem")).is_err());
        assert_eq!(
            post_fixture(
                &config,
                "/api/agent/v1/inventory/reports",
                "{}",
                1,
                &good.root.join("server.pem")
            )
            .unwrap()
            .status,
            302
        );
        good.retire().unwrap();
        drop(good);
        let (mut wrong, config) = fixture("wrong");
        assert!(post_fixture(&config, path, "{}", 1, &wrong.root.join("server.pem")).is_err());
        wrong.retire().unwrap();
    }
    #[test]
    fn purpose_bound_canonical_request_has_no_trailing_newline() {
        assert_eq!(
            canonical(
                "host",
                "epoch",
                "key",
                "/api/agent/v1/inventory/check-ins",
                10,
                "nonce",
                "digest"
            ),
            "command-center-inventory-v1\nhost\nepoch\nkey\nPOST\n/api/agent/v1/inventory/check-ins\n10\nnonce\ndigest"
        );
    }
    #[test]
    fn wire_admission_digest_matches_the_signed_exact_request_body() {
        let body = "{\"a\":1}";
        let digest = SystemTools.sha256(body.as_bytes()).unwrap();
        let config = Config {
            schema_version: 1,
            server_url: "https://example.test".into(),
            device_id: "device".into(),
            enrollment_id: "epoch".into(),
            key_id: "key".into(),
            reporting_private_key_file: "/unused".into(),
            state_dir: "/unused".into(),
        };
        let request = request_config(
            &config,
            "/api/agent/v1/inventory/check-ins",
            body,
            10,
            "nonce",
            &digest,
            "signature",
        )
        .unwrap();
        assert!(request.contains(&format!("header = \"x-device-body-sha256: {digest}\"\n")));
        assert!(
            canonical(
                "device",
                "epoch",
                "key",
                "/api/agent/v1/inventory/check-ins",
                10,
                "nonce",
                &digest
            )
            .ends_with(&digest)
        );
    }
    #[test]
    fn origin_rejects_redirect_credentials_and_paths() {
        for origin in [
            "http://example.test",
            "https://x@y",
            "https://example.test/path",
            "https://example.test?x",
            "https://example.test\n",
        ] {
            assert!(!valid_origin(origin));
        }
        assert!(valid_origin("https://example.test:8443"));
    }
}
