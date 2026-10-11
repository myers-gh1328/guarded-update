//! macOS and Apple software updates from `softwareupdate -l`. Alert only:
//! guarded-update never installs them.

use crate::exec::Runner;
use crate::model::{Action, Change, Detection, Source, Update};

#[derive(Debug, PartialEq, Eq)]
pub struct Available {
    pub label: String,
    pub title: String,
    pub version: String,
    pub restart: bool,
}

pub fn parse(text: &str) -> Vec<Available> {
    let mut found: Vec<Available> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if let Some(label) = line.strip_prefix("* Label:") {
            found.push(Available {
                label: label.trim().to_string(),
                title: label.trim().to_string(),
                version: String::new(),
                restart: false,
            });
        } else if line.starts_with("Title:")
            && let Some(current) = found.last_mut()
        {
            for field in line.split(',') {
                if let Some((key, value)) = field.split_once(':') {
                    match key.trim() {
                        "Title" => current.title = value.trim().to_string(),
                        "Version" => current.version = value.trim().to_string(),
                        "Action" => current.restart = value.trim() == "restart",
                        _ => {}
                    }
                }
            }
        }
    }
    found
}

pub fn detect(runner: &dyn Runner) -> Detection {
    let mut det = Detection::default();
    if !cfg!(target_os = "macos") {
        det.errors
            .push("the macOS provider is enabled on a host that is not macOS".into());
        return det;
    }
    let listing = match runner.run("softwareupdate", &["--list"], &[]) {
        Ok(out) if out.success() => out.stdout,
        Ok(out) => {
            det.errors.push(format!(
                "`softwareupdate --list` exited with {:?}: {}",
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
    let os_version = runner
        .run("sw_vers", &["-productVersion"], &[])
        .ok()
        .filter(|o| o.success())
        .map(|o| o.stdout.trim().to_string());
    for item in parse(&listing) {
        let installed = if item.title.starts_with("macOS") {
            os_version.clone().unwrap_or_else(|| "-".into())
        } else {
            "-".into()
        };
        det.updates.push(Update {
            source: Source::Macos,
            name: item.title,
            installed,
            available: item.version,
            change: Change::Version,
            action: Action::AlertOnly,
            note: item.restart.then(|| "needs a restart".to_string()),
        });
    }
    det
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "Software Update Tool\n\nFinding available software\nSoftware Update found the following new or updated software:\n* Label: Safari27.0TahoeAuto-27.0\n\tTitle: Safari, Version: 27.0, Size: 249465KiB, Recommended: YES, \n* Label: macOS Tahoe 26.7.1-25G241\n\tTitle: macOS Tahoe 26.7.1, Version: 26.7.1, Size: 3040400KiB, Recommended: YES, Action: restart, \n";

    #[test]
    fn parses_labels_titles_versions_and_restart() {
        let found = parse(SAMPLE);
        assert_eq!(found.len(), 2);
        assert_eq!(
            found[1],
            Available {
                label: "macOS Tahoe 26.7.1-25G241".into(),
                title: "macOS Tahoe 26.7.1".into(),
                version: "26.7.1".into(),
                restart: true,
            }
        );
        assert!(!found[0].restart);
    }

    #[test]
    fn nothing_available_parses_empty() {
        assert!(
            parse(
                "Software Update Tool\n\nFinding available software\nNo new software available.\n"
            )
            .is_empty()
        );
    }
}
