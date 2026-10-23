//! Unprivileged, bounded transport for root-authored requests. No install authority.
use crate::agent_protocol::RemoteConfig;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

const LIMIT: u64 = 2 * 1024 * 1024;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema_version: u32,
    expires_at_unix: u64,
    kind: String,
    request_id: String,
    body: Value,
    #[serde(default)]
    claim_id: Option<String>,
}
#[derive(Serialize)]
struct Response {
    schema_version: u32,
    request_id: String,
    http_status: u16,
    body: Value,
}
fn hex_id(s: &str) -> bool {
    s.len() == 32
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}
fn route(r: &Request) -> Result<String, String> {
    if r.schema_version != 1 || !hex_id(&r.request_id) || !r.body.is_object() {
        return Err("Invalid broker request".into());
    }
    match (r.kind.as_str(), r.claim_id.as_deref()) {
        ("preparation-poll", None) => Ok("/api/agent/v1/preparation-poll".into()),
        ("preparation-status", None) => Ok("/api/agent/v1/preparation-status".into()),
        ("manifest", None) => Ok("/api/agent/v1/execution-manifests".into()),
        ("status", None) => Ok("/api/agent/v1/execution-status".into()),
        ("claim", None) => Ok("/api/agent/v1/execution-claims".into()),
        ("result", Some(id))
            if id.len() == 36 && id.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-') =>
        {
            Ok(format!("/api/agent/v1/execution-claims/{id}/result"))
        }
        _ => Err("Unsupported broker request".into()),
    }
}

fn validate_request(bytes: &[u8]) -> Result<Request, String> {
    if bytes.len() as u64 > LIMIT {
        return Err("Broker request exceeds limit".into());
    }
    let request: Request = serde_json::from_slice(bytes).map_err(|_| "Invalid broker JSON")?;
    route(&request)?;
    Ok(request)
}
/// Read only root-authored queue entries; signing credentials stay unprivileged.
pub(crate) fn run(
    config: &RemoteConfig,
    requests: &Path,
    responses: &Path,
    now: u64,
) -> Result<String, String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
        let metadata = fs::symlink_metadata(requests).map_err(|_| "Missing root broker queue")?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err("Broker queue must be root-owned and not writable by broker".into());
        }
        let out =
            fs::symlink_metadata(responses).map_err(|_| "Missing broker response directory")?;
        if !out.is_dir() || out.permissions().mode() & 0o077 != 0 {
            return Err("Broker responses must be private".into());
        }
        let mut completed = 0;
        let mut attempted = 0;
        let mut paths: Vec<_> = fs::read_dir(requests)
            .map_err(|_| "Cannot enumerate broker queue")?
            .take(4096)
            .filter_map(Result::ok)
            .map(|e| e.path())
            .collect();
        paths.sort();
        for path in paths {
            let Some(id) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            if !hex_id(id) || path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            let target = responses.join(format!("{id}.json"));
            if target.symlink_metadata().is_ok() {
                continue;
            }
            let mut opts = OpenOptions::new();
            opts.read(true);
            #[cfg(target_os = "linux")]
            opts.custom_flags(0x20000); // O_NOFOLLOW
            #[cfg(target_os = "macos")]
            opts.custom_flags(0x100); // O_NOFOLLOW
            let Ok(file) = opts.open(&path) else {
                continue;
            };
            let Ok(meta) = file.metadata() else {
                continue;
            };
            if !meta.is_file() || meta.uid() != 0 || meta.mode() & 0o022 != 0 || meta.len() > LIMIT
            {
                continue;
            }
            let mut bytes = Vec::new();
            if file.take(LIMIT + 1).read_to_end(&mut bytes).is_err() {
                continue;
            }
            let Ok(request) = validate_request(&bytes) else {
                continue;
            };
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| "Invalid broker clock")?
                .as_secs()
                .max(now);
            if request.request_id != id
                || request.expires_at_unix <= now
                || request.expires_at_unix > now.saturating_add(120)
            {
                continue;
            }
            if attempted >= 4 {
                break;
            }
            attempted += 1;
            let body =
                serde_json::to_string(&request.body).map_err(|_| "Cannot encode broker body")?;
            let Ok(result) =
                crate::agent_protocol::signed_post(config, &route(&request)?, &body, now)
            else {
                continue;
            };
            let response = Response {
                schema_version: 1,
                request_id: id.into(),
                http_status: 200,
                body: result,
            };
            let bytes =
                serde_json::to_vec(&response).map_err(|_| "Cannot encode broker response")?;
            if bytes.len() as u64 > LIMIT {
                continue;
            }
            let temporary = responses.join(format!(".{id}.tmp"));
            let mut options = OpenOptions::new();
            options.write(true).create_new(true).mode(0o600);
            let mut file = options
                .open(&temporary)
                .map_err(|_| "Cannot create broker response")?;
            file.write_all(&bytes)
                .and_then(|_| file.sync_all())
                .map_err(|_| "Cannot persist broker response")?;
            fs::rename(&temporary, &target).map_err(|_| "Cannot publish broker response")?;
            File::open(responses)
                .and_then(|d| d.sync_all())
                .map_err(|_| "Cannot sync broker response directory")?;
            completed += 1;
        }
        Ok(format!("Transported {completed} executor requests"))
    }
    #[cfg(not(unix))]
    {
        let _ = (config, requests, responses, now);
        Err("Executor broker requires Unix".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn request_routes_cannot_choose_commands_or_arbitrary_urls() {
        assert!(super::validate_request(br#"{}"#).is_err());
        let request = |kind: &str, claim_id| Request {
            schema_version: 1,
            expires_at_unix: 200,
            kind: kind.into(),
            request_id: "a".repeat(32),
            body: serde_json::json!({}),
            claim_id,
        };
        assert_eq!(
            route(&request("manifest", None)).unwrap(),
            "/api/agent/v1/execution-manifests"
        );
        assert_eq!(
            route(&request("claim", None)).unwrap(),
            "/api/agent/v1/execution-claims"
        );
        for (kind, expected) in [
            ("preparation-poll", "/api/agent/v1/preparation-poll"),
            ("preparation-status", "/api/agent/v1/preparation-status"),
        ] {
            assert_eq!(route(&request(kind, None)).unwrap(), expected);
            assert!(route(&request(kind, Some("a".repeat(36)))).is_err());
        }
        assert!(route(&request("https://evil.invalid", None)).is_err());
        assert!(route(&request("result", Some("../secret".into()))).is_err());
        assert!(serde_json::from_str::<Request>(r#"{"schema_version":1,"kind":"claim","request_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","body":{},"command":"sh"}"#).is_err());
    }
}
