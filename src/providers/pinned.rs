//! Versions pinned in git, for example a Python package version in an
//! Ansible variable. Alert only: guarded-update never edits the pin.

use std::cmp::Ordering;

use serde_json::Value;

use crate::config::PinnedConfig;
use crate::http::Http;
use crate::model::{Action, Change, Detection, Source, Update};
use crate::version;

#[derive(Debug, PartialEq, Eq)]
pub enum PinSource {
    PyPi(String),
    GitHub(String),
}

pub fn parse_source(text: &str) -> Option<PinSource> {
    match text.split_once(':')? {
        ("pypi", name) if !name.is_empty() => Some(PinSource::PyPi(name.to_string())),
        ("github", repo) if repo.contains('/') => Some(PinSource::GitHub(repo.to_string())),
        _ => None,
    }
}

/// `true` when `latest` is newer than `current`.
pub fn is_newer(current: &str, latest: &str) -> bool {
    match version::compare(latest, current) {
        Some(order) => order == Ordering::Greater,
        // Unreadable: any difference is worth an alert.
        None => current.trim() != latest.trim(),
    }
}

/// The latest version string from a PyPI JSON or GitHub release response.
pub fn latest_version(source: &PinSource, body: &Value) -> Option<String> {
    let raw = match source {
        PinSource::PyPi(_) => body["info"]["version"].as_str()?,
        PinSource::GitHub(_) => body["tag_name"].as_str()?,
    };
    Some(raw.trim_start_matches('v').to_string())
}

pub fn detect<'a, I>(http: &dyn Http, pins: I) -> Detection
where
    I: IntoIterator<Item = (&'a String, &'a PinnedConfig)>,
{
    let mut det = Detection::default();
    for (name, pin) in pins {
        let Some(source) = parse_source(&pin.source) else {
            det.errors.push(format!(
                "pinned {name}: unsupported source `{}`",
                pin.source
            ));
            continue;
        };
        let (url, github) = match &source {
            PinSource::PyPi(package) => (format!("https://pypi.org/pypi/{package}/json"), false),
            PinSource::GitHub(repo) => (
                format!("https://api.github.com/repos/{repo}/releases/latest"),
                true,
            ),
        };
        let latest = match http.get_json(&url, github) {
            Ok(body) => latest_version(&source, &body),
            Err(e) => {
                det.errors.push(format!("pinned {name}: {e}"));
                continue;
            }
        };
        let Some(latest) = latest else {
            det.errors.push(format!(
                "pinned {name}: no version in the response from {url}"
            ));
            continue;
        };
        if is_newer(&pin.current, &latest) {
            det.updates.push(Update {
                source: Source::Pinned,
                name: name.clone(),
                installed: pin.current.clone(),
                available: latest,
                change: Change::Version,
                action: Action::AlertOnly,
                note: pin.pinned_in.as_ref().map(|p| format!("pinned in {p}")),
            });
        }
    }
    det
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sources_parse() {
        assert_eq!(
            parse_source("pypi:example-lib"),
            Some(PinSource::PyPi("example-lib".into()))
        );
        assert_eq!(
            parse_source("github:a/b"),
            Some(PinSource::GitHub("a/b".into()))
        );
        assert_eq!(parse_source("npm:x"), None);
    }

    #[test]
    fn version_comparison_handles_prefixes_and_lengths() {
        assert!(is_newer("0.7.6", "0.7.10"));
        assert!(is_newer("v1.2", "1.3.0"));
        assert!(!is_newer("0.7.6", "0.7.6"));
        assert!(!is_newer("0.8.0", "0.7.9"));
    }

    #[test]
    fn latest_is_read_from_pypi_and_github_shapes() {
        let pypi = json!({"info": {"version": "0.7.7"}});
        assert_eq!(
            latest_version(&PinSource::PyPi("x".into()), &pypi),
            Some("0.7.7".into())
        );
        let gh = json!({"tag_name": "v1.4.0"});
        assert_eq!(
            latest_version(&PinSource::GitHub("a/b".into()), &gh),
            Some("1.4.0".into())
        );
    }

    struct FakeHttp;
    impl Http for FakeHttp {
        fn get_json(&self, url: &str, github: bool) -> Result<Value, String> {
            match url {
                "https://pypi.org/pypi/example-lib/json" => {
                    assert!(!github);
                    Ok(json!({"info": {"version": "0.7.7"}}))
                }
                "https://api.github.com/repos/a/b/releases/latest" => {
                    assert!(github);
                    Ok(json!({"tag_name": "v1.0.0"}))
                }
                other => Err(format!("unexpected {other}")),
            }
        }
    }

    #[test]
    fn newer_pins_are_alert_only_updates() {
        let pins = [
            (
                "example-lib".to_string(),
                PinnedConfig {
                    current: "0.7.6".into(),
                    source: "pypi:example-lib".into(),
                    pinned_in: Some("inventory".into()),
                },
            ),
            (
                "tool".to_string(),
                PinnedConfig {
                    current: "1.0.0".into(),
                    source: "github:a/b".into(),
                    pinned_in: None,
                },
            ),
        ];
        let det = detect(&FakeHttp, pins.iter().map(|(k, v)| (k, v)));
        assert!(det.errors.is_empty(), "{:?}", det.errors);
        assert_eq!(det.updates.len(), 1);
        assert_eq!(det.updates[0].action, Action::AlertOnly);
        assert_eq!(det.updates[0].available, "0.7.7");
        assert!(det.groups.is_empty());
    }
}
