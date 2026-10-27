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
pub fn post(config: &Config, path: &str, body: &str, now: u64) -> Result<Response, String> {
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
    ] {
        request.push_str(&format!("header = {}\n", quote(&header)?));
    }
    request.push_str(&format!("data-binary = {}\n", quote(body)?));
    let output = SystemTools.run(
        "/usr/bin/curl",
        &[
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
        ],
        request.as_bytes(),
        128 * 1024,
    )?;
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
