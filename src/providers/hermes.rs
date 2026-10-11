//! Hermes Agent stable releases (ADR-0001 D7). Only `vX.Y.Z` tags with a
//! major of at most three digits count, ordered by GitHub release date, so
//! the older calendar tags (`v2026.9.24`) never outrank `v0.21.x`.
//! Detection never runs `hermes update`, which fetches from git.

use std::cmp::Ordering;

use serde_json::Value;

use crate::exec::Runner;
use crate::http::Http;
use crate::model::{Action, Change, Detection, Group, Source, Update};
use crate::version;

/// The release version from `hermes --version`, for example
/// `Hermes Agent v0.21.5+4410.g2ec7703 (2026.9.24)` -> `0.21.5`.
pub fn parse_installed(text: &str) -> Option<String> {
    let first = text.lines().next()?;
    first.split_whitespace().find_map(|word| {
        let core = word.strip_prefix('v')?.split(['+', '-']).next()?;
        is_three_numbers(core, usize::MAX).then(|| core.to_string())
    })
}

/// `X.Y.Z`, all digits, with a major of at most `max_major_digits`.
fn is_three_numbers(text: &str, max_major_digits: usize) -> bool {
    let parts: Vec<&str> = text.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
        && parts[0].len() <= max_major_digits
}

/// `v0.21.6` -> `0.21.6`; calendar tags and rc tags -> `None`.
fn stable_tag(tag: &str) -> Option<String> {
    let core = tag.strip_prefix('v')?;
    is_three_numbers(core, 3).then(|| core.to_string())
}

/// The newest stable release as `(tag, version)`.
pub fn latest_stable(releases: &Value) -> Option<(String, String)> {
    releases
        .as_array()?
        .iter()
        .filter(|r| r["draft"] == false && r["prerelease"] == false)
        .filter_map(|r| {
            let tag = r["tag_name"].as_str()?;
            let version = stable_tag(tag)?;
            let published = r["published_at"].as_str().unwrap_or("");
            Some((published.to_string(), tag.to_string(), version))
        })
        // RFC 3339 UTC strings sort in time order.
        .max_by(|a, b| a.0.cmp(&b.0))
        .map(|(_, tag, version)| (tag, version))
}

pub fn detect(runner: &dyn Runner, http: &dyn Http, command: &str, repo: &str) -> Detection {
    let mut det = Detection::default();
    let installed = match runner.run(command, &["--version"], &[]) {
        Ok(out) if out.success() => parse_installed(&out.stdout),
        Ok(out) => {
            det.errors.push(format!(
                "`{command} --version` exited with {:?}: {}",
                out.code,
                out.stderr.trim()
            ));
            return det;
        }
        Err(e) => {
            det.errors.push(e);
            return det;
        }
    };
    let Some(installed) = installed else {
        det.errors.push(format!(
            "cannot read a vX.Y.Z version from `{command} --version`"
        ));
        return det;
    };
    let url = format!("https://api.github.com/repos/{repo}/releases?per_page=50");
    let latest = match http.get_json(&url, true) {
        Ok(body) => latest_stable(&body),
        Err(e) => {
            det.errors.push(e);
            return det;
        }
    };
    let Some((tag, latest)) = latest else {
        det.errors
            .push(format!("no stable vX.Y.Z release found for {repo}"));
        return det;
    };
    if version::compare(&latest, &installed) == Some(Ordering::Greater) {
        det.updates.push(Update {
            source: Source::Hermes,
            name: "hermes".into(),
            installed: format!("v{installed}"),
            available: tag,
            change: Change::Version,
            action: Action::Update,
            note: Some("no rollback: a failure holds and alerts".into()),
        });
        det.groups.push(Group {
            source: Source::Hermes,
            members: vec!["hermes".into()],
            new_dependencies: Vec::new(),
        });
    }
    det
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::CmdOutput;
    use serde_json::json;

    fn releases() -> Value {
        json!([
            {"tag_name": "v0.21.6", "published_at": "2026-10-08T11:51:57Z", "draft": false, "prerelease": false},
            {"tag_name": "v2026.9.24", "published_at": "2026-09-24T10:09:38Z", "draft": false, "prerelease": false},
            {"tag_name": "v0.22.0", "published_at": "2026-10-09T00:00:00Z", "draft": false, "prerelease": true},
            {"tag_name": "v0.23.0", "published_at": "2026-10-09T01:00:00Z", "draft": true, "prerelease": false},
            {"tag_name": "rc.3-v0.21.7", "published_at": "2026-10-09T02:00:00Z", "draft": false, "prerelease": false},
            {"tag_name": "v0.21.5", "published_at": "2026-10-01T00:00:00Z", "draft": false, "prerelease": false}
        ])
    }

    #[test]
    fn installed_version_is_read_from_version_banner() {
        let text = "Hermes Agent v0.21.5+4410.g2ec7703 (2026.9.24) \u{b7} upstream b56a1024\nInstall directory: /x\n";
        assert_eq!(parse_installed(text), Some("0.21.5".to_string()));
        assert_eq!(
            parse_installed("Hermes Agent v0.21.6"),
            Some("0.21.6".to_string())
        );
        assert_eq!(parse_installed("nonsense"), None);
    }

    #[test]
    fn latest_stable_skips_calendar_prerelease_draft_and_rc_tags() {
        assert_eq!(
            latest_stable(&releases()),
            Some(("v0.21.6".to_string(), "0.21.6".to_string()))
        );
    }

    struct Fake(&'static str);
    impl Runner for Fake {
        fn run(&self, _: &str, args: &[&str], _: &[(&str, &str)]) -> Result<CmdOutput, String> {
            assert_eq!(args, ["--version"]);
            Ok(CmdOutput {
                code: Some(0),
                stdout: self.0.into(),
                stderr: String::new(),
            })
        }
    }
    struct FakeHttp(Value);
    impl Http for FakeHttp {
        fn get_json(&self, url: &str, github: bool) -> Result<Value, String> {
            assert!(github);
            assert!(
                url.starts_with("https://api.github.com/repos/NousResearch/hermes-agent/releases")
            );
            Ok(self.0.clone())
        }
    }

    #[test]
    fn newer_stable_release_is_an_update_with_its_own_group() {
        let det = detect(
            &Fake("Hermes Agent v0.21.5+4410.g2ec7703 (2026.9.24)\n"),
            &FakeHttp(releases()),
            "hermes",
            "NousResearch/hermes-agent",
        );
        assert!(det.errors.is_empty(), "{:?}", det.errors);
        assert_eq!(det.updates.len(), 1);
        let u = &det.updates[0];
        assert_eq!(
            (u.installed.as_str(), u.available.as_str()),
            ("v0.21.5", "v0.21.6")
        );
        assert_eq!(u.change, Change::Version);
        assert_eq!(u.action, Action::Update);
        assert_eq!(det.groups[0].source, Source::Hermes);
    }

    #[test]
    fn current_install_has_no_update() {
        let det = detect(
            &Fake("Hermes Agent v0.21.6\n"),
            &FakeHttp(releases()),
            "hermes",
            "NousResearch/hermes-agent",
        );
        assert!(det.updates.is_empty());
        assert!(det.errors.is_empty());
    }

    #[test]
    fn unreadable_version_is_an_error() {
        let det = detect(
            &Fake("??"),
            &FakeHttp(releases()),
            "hermes",
            "NousResearch/hermes-agent",
        );
        assert!(det.errors[0].contains("hermes --version"));
    }
}
