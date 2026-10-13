//! Service configuration for the AI check (ADR-0001 D8): the config files
//! a launchd service names in its arguments, with secret values removed,
//! so the model can see whether a change touches what the service uses.
//! Nothing here can hold an update: a file that cannot be shown is named
//! in the prompt with the reason, and the check goes on from the notes.

use std::path::{Path, PathBuf};

use crate::redact::MASK;

/// At most this much of one file is shown; a longer file is not shown.
pub const FILE_CHARS: usize = 12_000;
/// At most this much configuration goes into one question.
pub const TOTAL_CHARS: usize = 24_000;

const EXTENSIONS: &[&str] = &[
    "yml",
    "yaml",
    "toml",
    "json",
    "conf",
    "cfg",
    "ini",
    "properties",
];

/// File names that suggest secrets are never read.
const SECRET_NAMES: &[&str] = &[
    "env", "secret", "token", "key", "pass", "cred", "auth", "pem", "crt",
];

/// Keys whose values are masked, on top of the redaction layer's own.
const SECRET_KEYS: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "token",
    "credential",
    "community",
    "authorization",
    "api_key",
    "apikey",
    "access_key",
    "private_key",
    "auth_key",
];

/// Keys that name where a secret is kept, or a count, not the secret.
const LOCATION_SUFFIXES: &[&str] = &["_file", "_path", "_dir", "tokens"];

/// One config file of a service, or why it is not shown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceConfig {
    pub label: String,
    pub path: String,
    pub shown: Result<String, String>,
}

/// Config file paths in a service's arguments (the program excluded):
/// `-flag=/path`, `--flag /path` and bare `/path`, with a config
/// extension and no secret-like file name.
pub fn config_paths(args: &[String]) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = Vec::new();
    for arg in args {
        let value = match arg.split_once('=') {
            Some((_, v)) if !arg.starts_with('/') => v,
            _ => arg.as_str(),
        };
        if !value.starts_with('/') {
            continue;
        }
        let path = PathBuf::from(value);
        let config_ext = path
            .extension()
            .and_then(|x| x.to_str())
            .is_some_and(|x| EXTENSIONS.contains(&x.to_ascii_lowercase().as_str()));
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();
        let secret_name = SECRET_NAMES.iter().any(|w| name.contains(w));
        if config_ext && !secret_name && !paths.contains(&path) {
            paths.push(path);
        }
    }
    paths
}

/// The key of a `key: value` or `key = value` line, lower case, and
/// where its value starts.
fn key_and_value(line: &str) -> Option<(String, usize)> {
    let start = line.len() - line.trim_start().len();
    let rest = &line[start..];
    let rest_start = start + (rest.len() - rest.trim_start_matches(['-', ' ']).len());
    let body = &line[rest_start..];
    let sep = body.find([':', '='])?;
    let key = body[..sep]
        .trim()
        .trim_matches(['"', '\''])
        .to_ascii_lowercase();
    if key.is_empty() || key.contains(' ') {
        return None;
    }
    Some((key, rest_start + sep + 1))
}

/// `scheme://user:pass@host` -> `scheme://[REDACTED]@host`.
fn mask_userinfo(line: &str) -> String {
    let mut out = String::new();
    let mut rest = line;
    while let Some(at) = rest.find("://") {
        let (head, tail) = rest.split_at(at + 3);
        out.push_str(head);
        let end = tail
            .find(|c: char| c == '/' || c.is_whitespace() || c == '"' || c == '\'')
            .unwrap_or(tail.len());
        match tail[..end].rfind('@') {
            Some(a) if tail[..a].contains(':') => {
                out.push_str(MASK);
                out.push_str(&tail[a..end]);
            }
            _ => out.push_str(&tail[..end]),
        }
        rest = &tail[end..];
    }
    out.push_str(rest);
    out
}

/// Removes secret values from a config file: values of secret-named keys,
/// private key blocks and passwords in URLs. The whole prompt still goes
/// through the redaction layer afterwards.
pub fn mask(text: &str) -> String {
    let mut lines = Vec::new();
    let mut in_block = false;
    for line in text.lines() {
        if line.contains("-----BEGIN ") {
            in_block = true;
        }
        if in_block {
            if line.contains("-----END ") {
                in_block = false;
            }
            let indent = &line[..line.len() - line.trim_start().len()];
            lines.push(format!("{indent}{MASK}"));
            continue;
        }
        let masked = match key_and_value(line) {
            Some((key, at))
                if SECRET_KEYS.iter().any(|w| key.contains(w))
                    && !LOCATION_SUFFIXES.iter().any(|s| key.ends_with(s))
                    && !line[at..].trim().is_empty() =>
            {
                format!("{} {MASK}", &line[..at])
            }
            _ => line.to_string(),
        };
        lines.push(mask_userinfo(&masked));
    }
    lines.join("\n")
}

/// Every config file of `services` (`(label, arguments)`), masked and
/// within the size limits. `read` returns a file's text or why not.
pub fn gather(
    services: &[(String, Vec<String>)],
    read: &dyn Fn(&Path) -> Result<String, String>,
) -> Vec<ServiceConfig> {
    let mut configs: Vec<ServiceConfig> = Vec::new();
    let mut used = 0;
    for (label, args) in services {
        for path in config_paths(args.get(1..).unwrap_or_default()) {
            let shown_path = path.display().to_string();
            if configs.iter().any(|c| c.path == shown_path) {
                continue;
            }
            let shown = read(&path).map(|text| mask(&text)).and_then(|text| {
                let n = text.chars().count();
                if n > FILE_CHARS {
                    Err(format!("too long to show ({n} characters)"))
                } else if used + n > TOTAL_CHARS {
                    Err("not shown: other configuration already fills the space".into())
                } else {
                    used += n;
                    Ok(text)
                }
            });
            configs.push(ServiceConfig {
                label: label.clone(),
                path: shown_path,
                shown,
            });
        }
    }
    configs
}

/// The prompt section for `configs`; empty when there are none.
pub fn prompt(configs: &[ServiceConfig]) -> String {
    let mut text = String::new();
    for c in configs {
        match &c.shown {
            Ok(body) => text.push_str(&format!(
                "\nConfiguration of {} ({}), secret values removed:\n<<<\n{body}\n>>>\n",
                c.label, c.path
            )),
            Err(why) => text.push_str(&format!(
                "\nConfiguration of {} ({}): {why}\n",
                c.label, c.path
            )),
        }
    }
    text
}

/// Reads a config file from disk: a regular file of a sane size.
pub fn read_file(path: &Path) -> Result<String, String> {
    let meta = std::fs::metadata(path).map_err(|_| "could not be read".to_string())?;
    if !meta.is_file() {
        return Err("not a file".into());
    }
    if meta.len() > 1_000_000 {
        return Err(format!("too long to show ({} bytes)", meta.len()));
    }
    std::fs::read_to_string(path).map_err(|_| "could not be read as text".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn config_files_come_from_the_arguments() {
        let args = strings(&[
            "-httpListenAddr=127.0.0.1:8428",
            "-promscrape.config=/opt/homebrew/etc/vm/scrape.yml",
            "-storageDataPath=/opt/homebrew/var/vm-data",
            "--config",
            "/h/app/config.toml",
            "-c",
            "/etc/x.conf",
            "/h/.env",
            "/h/secrets.yaml",
            "/h/api-key.json",
            "/h/app/config.toml",
            "run",
        ]);
        assert_eq!(
            config_paths(&args),
            [
                PathBuf::from("/opt/homebrew/etc/vm/scrape.yml"),
                PathBuf::from("/h/app/config.toml"),
                PathBuf::from("/etc/x.conf"),
            ]
        );
    }

    #[test]
    fn secret_values_are_masked_and_the_rest_kept() {
        let text = "\
scrape_configs:
  - job_name: nas
    basic_auth:
      username: admin
      password: hunter2hunter
    authorization:
      credentials: abc
    bearer_token_file: /h/token
    max_tokens: 4096
    params:
      community: [\"not-public\"]
    relabel_configs:
      - source_labels: [__address__]
        regex: \"(a|b).*\"
remote_write:
  - url: https://user:pw123@example.com/api
tls:
  key: |
    -----BEGIN PRIVATE KEY-----
    MIIabc
    -----END PRIVATE KEY-----
  \"api_key\" = \"zzz\"";
        let masked = mask(text);
        for secret in [
            "hunter2hunter",
            "abc\n",
            "not-public",
            "pw123",
            "MIIabc",
            "zzz",
        ] {
            assert!(!masked.contains(secret), "{secret} left in:\n{masked}");
        }
        for kept in [
            "username: admin",
            "bearer_token_file: /h/token",
            "max_tokens: 4096",
            "regex: \"(a|b).*\"",
            "https://[REDACTED]@example.com/api",
            "    authorization:",
            "      password: [REDACTED]",
        ] {
            assert!(masked.contains(kept), "{kept} missing from:\n{masked}");
        }
        assert_eq!(masked.lines().count(), text.lines().count());
    }

    #[test]
    fn a_file_that_cannot_be_shown_is_named_with_the_reason() {
        let services = vec![
            (
                "com.example.a".to_string(),
                strings(&["/bin/a", "-config=/c/a.yml", "-extra=/c/big.yml"]),
            ),
            (
                "com.example.b".to_string(),
                strings(&["/bin/b", "/c/a.yml", "/c/gone.toml"]),
            ),
        ];
        let read = |p: &Path| match p.to_str() {
            Some("/c/a.yml") => Ok("password: x1\nport: 1".to_string()),
            Some("/c/big.yml") => Ok("x".repeat(FILE_CHARS + 1)),
            _ => Err("could not be read".to_string()),
        };
        let configs = gather(&services, &read);
        assert_eq!(configs.len(), 3, "a.yml once, though both services use it");
        assert_eq!(configs[0].shown, Ok("password: [REDACTED]\nport: 1".into()));
        assert_eq!(
            configs[1].shown,
            Err(format!("too long to show ({} characters)", FILE_CHARS + 1))
        );
        assert_eq!(configs[2].label, "com.example.b");
        assert_eq!(configs[2].shown, Err("could not be read".into()));
        let text = prompt(&configs);
        assert!(text.contains(
            "Configuration of com.example.a (/c/a.yml), secret values removed:\n<<<\npassword: [REDACTED]\nport: 1\n>>>"
        ));
        assert!(text.contains("Configuration of com.example.b (/c/gone.toml): could not be read"));
        assert_eq!(prompt(&[]), "");
    }

    #[test]
    fn configuration_beyond_the_total_is_not_shown() {
        let services = vec![(
            "s".to_string(),
            strings(&["/bin/s", "/c/1.yml", "/c/2.yml", "/c/3.yml"]),
        )];
        let read = |_: &Path| Ok("y".repeat(FILE_CHARS));
        let configs = gather(&services, &read);
        assert!(configs[0].shown.is_ok() && configs[1].shown.is_ok());
        assert!(
            configs[2]
                .shown
                .as_ref()
                .unwrap_err()
                .starts_with("not shown")
        );
    }
}
