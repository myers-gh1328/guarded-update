//! HTTPS GETs for release metadata, through the system `curl` (no TLS
//! crates). The optional GitHub token is read from its file at request
//! time and handed to curl on stdin, so it never appears in arguments,
//! logs or the process list.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::Value;

use crate::exec::SystemRunner;

pub trait Http {
    /// GETs `url` and parses JSON. `github` adds GitHub API headers and the
    /// token, when one is configured.
    fn get_json(&self, url: &str, github: bool) -> Result<Value, String>;

    /// Talks to a model server the user chose, which may be plain HTTP on
    /// this computer or the local network. GET when `body` is `None`,
    /// otherwise POST it as JSON.
    fn model_json(
        &self,
        url: &str,
        body: Option<&Value>,
        api_key_file: Option<&Path>,
        timeout: Duration,
    ) -> Result<Value, String> {
        let _ = (url, body, api_key_file, timeout);
        Err("model servers are not available here".into())
    }
}

pub struct CurlHttp {
    runner: SystemRunner,
    timeout: Duration,
    github_token_file: Option<PathBuf>,
}

impl CurlHttp {
    pub fn new(timeout: Duration, github_token_file: Option<PathBuf>) -> Self {
        Self {
            // Leave curl's own --max-time room to fail first.
            runner: SystemRunner::new(timeout + Duration::from_secs(5)),
            timeout,
            github_token_file,
        }
    }
}

/// curl arguments. With `token_on_stdin`, curl reads one extra header line
/// from stdin (`-H @-`).
pub fn curl_args(url: &str, github: bool, token_on_stdin: bool, timeout: Duration) -> Vec<String> {
    let mut args: Vec<String> = [
        "--silent",
        "--show-error",
        "--fail",
        "--location",
        "--proto",
        "=https",
        "--max-time",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect();
    args.push(timeout.as_secs().max(1).to_string());
    args.push("--user-agent".into());
    args.push(concat!("guarded-update/", env!("CARGO_PKG_VERSION")).into());
    if github {
        for header in [
            "Accept: application/vnd.github+json",
            "X-GitHub-Api-Version: 2022-11-28",
        ] {
            args.push("--header".into());
            args.push(header.into());
        }
        if token_on_stdin {
            args.push("--header".into());
            args.push("@-".into());
        }
    }
    args.push("--".into());
    args.push(url.into());
    args
}

/// Reads a token file; the error names the file, never its contents.
pub fn read_token(path: &Path) -> Result<String, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read token file {}: {}", path.display(), e.kind()))?;
    let token = text.trim();
    if token.is_empty() {
        return Err(format!("token file {} is empty", path.display()));
    }
    Ok(token.to_string())
}

/// curl arguments for a model server: HTTP allowed (the user chose the
/// address), JSON body on stdin, optional header file for the API key.
pub fn model_args(
    url: &str,
    post: bool,
    header_file: Option<&Path>,
    timeout: Duration,
) -> Vec<String> {
    let mut args: Vec<String> = [
        "--silent",
        "--show-error",
        "--fail-with-body",
        "--proto",
        "=http,https",
        "--max-time",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect();
    args.push(timeout.as_secs().max(1).to_string());
    args.push("--user-agent".into());
    args.push(concat!("guarded-update/", env!("CARGO_PKG_VERSION")).into());
    if post {
        args.extend(
            [
                "--header",
                "Content-Type: application/json",
                "--data-binary",
                "@-",
            ]
            .map(String::from),
        );
    }
    if let Some(file) = header_file {
        args.push("--header".into());
        args.push(format!("@{}", file.display()));
    }
    args.push("--".into());
    args.push(url.into());
    args
}

/// A 0600 file holding the Authorization header, removed when dropped,
/// so the key never appears in arguments.
struct HeaderFile(PathBuf);

impl HeaderFile {
    fn new(key_file: &Path) -> Result<Self, String> {
        let token = read_token(key_file)?;
        let path = std::env::temp_dir().join(format!(
            "guarded-update-auth-{}-{}",
            std::process::id(),
            crate::timefmt::now_secs()
        ));
        crate::state::write_private(&path, &format!("Authorization: Bearer {token}"))?;
        Ok(Self(path))
    }
}

impl Drop for HeaderFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

impl Http for CurlHttp {
    fn model_json(
        &self,
        url: &str,
        body: Option<&Value>,
        api_key_file: Option<&Path>,
        timeout: Duration,
    ) -> Result<Value, String> {
        let header = api_key_file.map(HeaderFile::new).transpose()?;
        let args = model_args(
            url,
            body.is_some(),
            header.as_ref().map(|h| h.0.as_path()),
            timeout,
        );
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let input = body.map(Value::to_string);
        let runner = SystemRunner::new(timeout + Duration::from_secs(5));
        let out = runner.run_input("curl", &args, &[], input.as_deref())?;
        drop(header);
        if !out.success() {
            let detail = if out.stdout.trim().is_empty() {
                out.stderr.trim().to_string()
            } else {
                out.stdout.trim().chars().take(300).collect()
            };
            return Err(format!("{url}: {detail}"));
        }
        serde_json::from_str(&out.stdout).map_err(|e| format!("{url}: invalid JSON: {e}"))
    }

    fn get_json(&self, url: &str, github: bool) -> Result<Value, String> {
        let header = match (&self.github_token_file, github) {
            (Some(path), true) => Some(format!("Authorization: Bearer {}\n", read_token(path)?)),
            _ => None,
        };
        let args = curl_args(url, github, header.is_some(), self.timeout);
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let out = self
            .runner
            .run_input("curl", &args, &[], header.as_deref())?;
        if !out.success() {
            return Err(format!("GET {url}: {}", out.stderr.trim()));
        }
        serde_json::from_str(&out.stdout).map_err(|e| format!("GET {url}: invalid JSON: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_only_fail_on_http_errors_and_url_last() {
        let args = curl_args(
            "https://pypi.org/pypi/x/json",
            false,
            false,
            Duration::from_secs(30),
        );
        let joined = args.join(" ");
        assert!(joined.contains("--proto =https"));
        assert!(joined.contains("--fail"));
        assert!(joined.contains("--max-time 30"));
        assert!(!joined.contains("github"));
        assert_eq!(
            &args[args.len() - 2..],
            ["--", "https://pypi.org/pypi/x/json"]
        );
    }

    #[test]
    fn github_token_is_read_from_stdin_never_from_arguments() {
        let args = curl_args(
            "https://api.github.com/x",
            true,
            true,
            Duration::from_secs(30),
        );
        assert!(args.windows(2).any(|w| w == ["--header", "@-"]));
        assert!(!args.iter().any(|a| a.contains("Authorization")));
        let without = curl_args(
            "https://api.github.com/x",
            true,
            false,
            Duration::from_secs(30),
        );
        assert!(!without.iter().any(|a| a == "@-"));
    }

    #[test]
    fn model_servers_may_use_http_and_never_get_the_key_in_arguments() {
        let args = model_args(
            "http://127.0.0.1:11434/v1/chat/completions",
            true,
            Some(Path::new("/tmp/h")),
            Duration::from_secs(120),
        );
        let joined = args.join(" ");
        assert!(joined.contains("--proto =http,https"));
        assert!(joined.contains("--data-binary @-"));
        assert!(joined.contains("--header @/tmp/h"));
        assert!(!joined.contains("Bearer"));
        let get = model_args("http://x/v1/models", false, None, Duration::from_secs(5));
        assert!(!get.iter().any(|a| a == "--data-binary"));
    }

    #[test]
    fn token_file_is_trimmed() {
        let path = std::env::temp_dir().join(format!("gu-token-{}", std::process::id()));
        std::fs::write(&path, "  tok-value-123\n").unwrap();
        assert_eq!(read_token(&path).unwrap(), "tok-value-123");
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn empty_or_missing_token_file_is_an_error_naming_the_file() {
        let path = std::env::temp_dir().join(format!("gu-token-empty-{}", std::process::id()));
        std::fs::write(&path, "\n").unwrap();
        assert!(read_token(&path).unwrap_err().contains("empty"));
        std::fs::remove_file(&path).unwrap();
        assert!(read_token(&path).unwrap_err().contains("gu-token-empty"));
    }
}
