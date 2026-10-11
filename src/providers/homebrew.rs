//! Homebrew formulas and casks.

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;

use crate::exec::{HOMEBREW_ENV, Runner};
use crate::model::{Action, Change, Detection, Group, Source, Update};

#[derive(Debug, Deserialize)]
struct Outdated {
    formulae: Vec<OutdatedItem>,
    casks: Vec<OutdatedItem>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OutdatedItem {
    pub name: String,
    pub installed_versions: Vec<String>,
    pub current_version: String,
    #[serde(default)]
    pub pinned: bool,
}

/// Parsed `brew upgrade --dry-run` output.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct DryRun {
    /// New dependencies as `(name, version)`.
    pub install: Vec<(String, String)>,
    /// Requested or outdated packages that would upgrade.
    pub upgrade: Vec<String>,
    /// Installed dependents that would upgrade too.
    pub dependents: Vec<String>,
}

pub fn parse_outdated(json: &str) -> Result<(Vec<OutdatedItem>, Vec<OutdatedItem>), String> {
    let parsed: Outdated = serde_json::from_str(json)
        .map_err(|e| format!("cannot parse `brew outdated --json=v2`: {e}"))?;
    Ok((parsed.formulae, parsed.casks))
}

/// `14.4.0_1` -> `14.4.0`.
pub fn strip_revision(version: &str) -> &str {
    match version.rsplit_once('_') {
        Some((base, rev)) if !rev.is_empty() && rev.chars().all(|c| c.is_ascii_digit()) => base,
        _ => version,
    }
}

/// `1.25.0` -> `1.25.0_1` is a rebuild; `14.4.0_1` -> `14.5.0` is not.
pub fn change_kind(installed: &str, available: &str) -> Change {
    if strip_revision(installed) == strip_revision(available) {
        Change::Rebuild
    } else {
        Change::Version
    }
}

pub fn parse_dry_run(text: &str) -> DryRun {
    #[derive(Clone, Copy)]
    enum Section {
        None,
        Install,
        Upgrade,
        Dependents,
    }
    let mut section = Section::None;
    let mut dry = DryRun::default();
    for line in text.lines() {
        if let Some(header) = line.strip_prefix("==> ") {
            section = if header.starts_with("Would install") {
                Section::Install
            } else if header.starts_with("Would upgrade") && header.contains("dependent") {
                Section::Dependents
            } else if header.starts_with("Would upgrade") {
                Section::Upgrade
            } else {
                Section::None
            };
            continue;
        }
        let tokens: Vec<&str> = line.split_whitespace().collect();
        match section {
            Section::Install if tokens.len() == 2 => {
                dry.install
                    .push((tokens[0].to_string(), tokens[1].to_string()));
            }
            Section::Upgrade if tokens.len() >= 4 && tokens[2] == "->" => {
                dry.upgrade.push(tokens[0].to_string());
            }
            Section::Dependents if tokens.len() >= 4 && tokens[2] == "->" => {
                dry.dependents.push(tokens[0].to_string());
            }
            _ => {}
        }
    }
    dry
}

/// Casks with a `pkg` artifact need sudo to install (ADR-0001 D5).
pub fn pkg_casks(json: &str) -> Result<BTreeSet<String>, String> {
    let value: serde_json::Value = serde_json::from_str(json)
        .map_err(|e| format!("cannot parse `brew info --cask --json=v2`: {e}"))?;
    let casks = value["casks"]
        .as_array()
        .ok_or("`brew info --cask --json=v2` has no casks list")?;
    Ok(casks
        .iter()
        .filter(|cask| {
            cask["artifacts"]
                .as_array()
                .is_some_and(|arts| arts.iter().any(|a| a.get("pkg").is_some()))
        })
        .filter_map(|cask| cask["token"].as_str().map(str::to_string))
        .collect())
}

/// Joins formulas whose upgrades touch the same packages into one group.
pub fn build_groups(dry_runs: &[(String, DryRun)]) -> Vec<Group> {
    let mut index: BTreeMap<String, usize> = BTreeMap::new();
    let mut parent: Vec<usize> = Vec::new();
    fn find(parent: &mut [usize], mut i: usize) -> usize {
        while parent[i] != i {
            parent[i] = parent[parent[i]];
            i = parent[i];
        }
        i
    }
    let mut id = |name: &str, parent: &mut Vec<usize>| -> usize {
        *index.entry(name.to_string()).or_insert_with(|| {
            parent.push(parent.len());
            parent.len() - 1
        })
    };
    let mut roots = Vec::new();
    for (requested, dry) in dry_runs {
        let root = id(requested, &mut parent);
        roots.push(root);
        for name in dry.upgrade.iter().chain(&dry.dependents) {
            let other = id(name, &mut parent);
            let (a, b) = (find(&mut parent, root), find(&mut parent, other));
            if a != b {
                parent[b] = a;
            }
        }
    }
    let names: Vec<(String, usize)> = index.into_iter().collect();
    let mut groups: BTreeMap<usize, (BTreeSet<String>, BTreeSet<String>)> = BTreeMap::new();
    for (name, i) in &names {
        let root = find(&mut parent, *i);
        groups.entry(root).or_default().0.insert(name.clone());
    }
    for ((_, dry), i) in dry_runs.iter().zip(roots) {
        let root = find(&mut parent, i);
        let deps = &mut groups.entry(root).or_default().1;
        for (name, version) in &dry.install {
            deps.insert(format!("{name} {version}"));
        }
    }
    let mut out: Vec<Group> = groups
        .into_values()
        .map(|(members, deps)| Group {
            source: Source::HomebrewFormula,
            members: members.into_iter().collect(),
            new_dependencies: deps.into_iter().collect(),
        })
        .collect();
    out.sort_by(|a, b| a.members.cmp(&b.members));
    out
}

pub struct Homebrew<'a> {
    pub runner: &'a dyn Runner,
    pub command: &'a str,
    pub greedy_casks: bool,
}

impl Homebrew<'_> {
    fn brew(&self, args: &[&str]) -> Result<String, String> {
        let out = self.runner.run(self.command, args, HOMEBREW_ENV)?;
        if out.success() {
            Ok(out.stdout)
        } else {
            Err(format!(
                "`brew {}` exited with {:?}: {}",
                args.join(" "),
                out.code,
                out.stderr.trim()
            ))
        }
    }

    /// `brew update` refreshes package metadata only; nothing installed
    /// changes.
    pub fn refresh(&self) -> Result<(), String> {
        self.brew(&["update", "--quiet"]).map(|_| ())
    }

    pub fn detect(&self) -> Detection {
        let mut det = Detection::default();
        let mut args = vec!["outdated", "--json=v2"];
        if self.greedy_casks {
            args.push("--greedy");
        }
        let (formulae, casks) = match self.brew(&args).and_then(|out| parse_outdated(&out)) {
            Ok(lists) => lists,
            Err(e) => {
                det.errors.push(e);
                return det;
            }
        };

        let mut dry_runs = Vec::new();
        for item in &formulae {
            let action = if item.pinned {
                Action::PinnedInHomebrew
            } else {
                Action::Update
            };
            det.updates
                .push(update(Source::HomebrewFormula, item, action, None));
            if item.pinned {
                continue;
            }
            match self.brew(&["upgrade", "--dry-run", "--formula", &item.name]) {
                Ok(out) => dry_runs.push((item.name.clone(), parse_dry_run(&out))),
                Err(e) => {
                    det.errors.push(e);
                    dry_runs.push((item.name.clone(), DryRun::default()));
                }
            }
        }
        det.groups.extend(build_groups(&dry_runs));

        if casks.is_empty() {
            return det;
        }
        let mut info_args = vec!["info", "--cask", "--json=v2"];
        info_args.extend(casks.iter().map(|c| c.name.as_str()));
        let pkg = match self.brew(&info_args).and_then(|out| pkg_casks(&out)) {
            Ok(set) => Some(set),
            Err(e) => {
                det.errors.push(e);
                None
            }
        };
        for item in &casks {
            let (action, note) = match &pkg {
                _ if item.pinned => (Action::PinnedInHomebrew, None),
                Some(set) if set.contains(&item.name) => (
                    Action::ManualSudo,
                    Some("pkg installer needs sudo".to_string()),
                ),
                Some(_) => (Action::Update, None),
                // Unknown installer type: never assume it is safe.
                None => (
                    Action::ManualSudo,
                    Some("installer type unknown".to_string()),
                ),
            };
            if action == Action::Update {
                det.groups.push(Group {
                    source: Source::HomebrewCask,
                    members: vec![item.name.clone()],
                    new_dependencies: Vec::new(),
                });
            }
            det.updates
                .push(update(Source::HomebrewCask, item, action, note));
        }
        det
    }
}

fn update(source: Source, item: &OutdatedItem, action: Action, note: Option<String>) -> Update {
    let installed = item.installed_versions.last().cloned().unwrap_or_default();
    Update {
        source,
        name: item.name.clone(),
        change: change_kind(&installed, &item.current_version),
        installed,
        available: item.current_version.clone(),
        action,
        note,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::CmdOutput;
    use std::cell::RefCell;

    const OUTDATED: &str = r#"{"formulae":[
      {"name":"ansible","installed_versions":["14.4.0_1"],"current_version":"14.5.0","pinned":false,"pinned_version":null},
      {"name":"libngtcp2","installed_versions":["1.25.0"],"current_version":"1.25.0_1","pinned":false,"pinned_version":null},
      {"name":"node@24","installed_versions":["24.21.0_1"],"current_version":"24.21.0_2","pinned":false,"pinned_version":null},
      {"name":"hashicorp/tap/terraform","installed_versions":["1.16.4"],"current_version":"1.16.5","pinned":false,"pinned_version":null},
      {"name":"jq","installed_versions":["1.7.1"],"current_version":"1.8.1","pinned":true,"pinned_version":"1.7.1"}
    ],"casks":[
      {"name":"claude-code@latest","installed_versions":["2.1.294"],"current_version":"2.1.295","pinned":false,"pinned_version":null},
      {"name":"tailscale-app","installed_versions":["1.90.1"],"current_version":"1.90.2","pinned":false,"pinned_version":null}
    ]}"#;

    const DRY_LIBNGTCP2: &str = "==> Would install 1 dependency:\nopenssl@4 4.0.3\n==> Would upgrade 1 requested outdated package\nlibngtcp2 1.25.0 -> 1.25.0_1 (426.8KB)\n==> Would upgrade 1 dependent\nnode@24 24.21.0_1 -> 24.21.0_2 (21.1MB)\n";

    const DRY_ANSIBLE: &str = "==> Downloading bottle manifests\n\u{2714}\u{fe0e} Bottle Manifest ansible (14.5.0)\n==> Would install 1 dependency:\nopenssl@4 4.0.3\n==> Would upgrade 1 requested outdated package\nansible 14.4.0_1 -> 14.5.0 (68.8MB)\n";

    const DRY_ALIGNED: &str = "==> Would upgrade 2 outdated packages\nlibngtcp2                1.25.0    -> 1.25.0_1 (426.8KB)\nhashicorp/tap/terraform  1.16.4    -> 1.16.5\nSome casks with `auto_updates true` or `version :latest` may still require `--greedy`,\n";

    const CASK_INFO: &str = r#"{"formulae":[],"casks":[
      {"token":"tailscale-app","artifacts":[{"uninstall":[{}]},{"pkg":["Tailscale.pkg"]},{"zap":[{}]}]},
      {"token":"claude-code@latest","artifacts":[{"binary":["claude"],"target":"claude"},{"zap":[{}]}]}
    ]}"#;

    #[test]
    fn outdated_json_is_parsed() {
        let (formulae, casks) = parse_outdated(OUTDATED).unwrap();
        assert_eq!(formulae.len(), 5);
        assert_eq!(casks.len(), 2);
        assert_eq!(formulae[3].name, "hashicorp/tap/terraform");
        assert!(formulae[4].pinned);
    }

    #[test]
    fn revision_only_bumps_are_rebuilds() {
        assert_eq!(change_kind("1.25.0", "1.25.0_1"), Change::Rebuild);
        assert_eq!(change_kind("24.21.0_1", "24.21.0_2"), Change::Rebuild);
        assert_eq!(change_kind("14.4.0_1", "14.5.0"), Change::Version);
        assert_eq!(change_kind("2.1.294", "2.1.295"), Change::Version);
    }

    #[test]
    fn dry_run_sections_are_parsed() {
        assert_eq!(
            parse_dry_run(DRY_LIBNGTCP2),
            DryRun {
                install: vec![("openssl@4".into(), "4.0.3".into())],
                upgrade: vec!["libngtcp2".into()],
                dependents: vec!["node@24".into()],
            }
        );
    }

    #[test]
    fn dry_run_ignores_progress_and_hint_lines_and_aligned_columns() {
        assert_eq!(
            parse_dry_run(DRY_ANSIBLE).upgrade,
            vec!["ansible".to_string()]
        );
        assert_eq!(
            parse_dry_run(DRY_ALIGNED).upgrade,
            vec![
                "libngtcp2".to_string(),
                "hashicorp/tap/terraform".to_string()
            ]
        );
        assert!(parse_dry_run(DRY_ALIGNED).install.is_empty());
    }

    #[test]
    fn pkg_casks_need_sudo() {
        let set = pkg_casks(CASK_INFO).unwrap();
        assert!(set.contains("tailscale-app"));
        assert!(!set.contains("claude-code@latest"));
    }

    #[test]
    fn overlapping_upgrades_join_into_one_group() {
        let groups = build_groups(&[
            ("ansible".into(), parse_dry_run(DRY_ANSIBLE)),
            ("libngtcp2".into(), parse_dry_run(DRY_LIBNGTCP2)),
            (
                "node@24".into(),
                parse_dry_run(
                    "==> Would upgrade 1 requested outdated package\nnode@24 24.21.0_1 -> 24.21.0_2\n",
                ),
            ),
        ]);
        assert_eq!(groups.len(), 2);
        let ngtcp = groups
            .iter()
            .find(|g| g.members.contains(&"libngtcp2".to_string()))
            .unwrap();
        assert_eq!(
            ngtcp.members,
            vec!["libngtcp2".to_string(), "node@24".to_string()]
        );
        assert_eq!(ngtcp.new_dependencies, vec!["openssl@4 4.0.3".to_string()]);
        // A shared new dependency alone does not join groups.
        let ansible = groups
            .iter()
            .find(|g| g.members.contains(&"ansible".to_string()))
            .unwrap();
        assert_eq!(ansible.members, vec!["ansible".to_string()]);
    }

    /// Answers by matching the joined argument list.
    struct FakeRunner {
        answers: Vec<(&'static str, &'static str)>,
        calls: RefCell<Vec<String>>,
    }

    impl Runner for FakeRunner {
        fn run(
            &self,
            _program: &str,
            args: &[&str],
            env: &[(&str, &str)],
        ) -> Result<CmdOutput, String> {
            assert!(env.contains(&("HOMEBREW_NO_AUTO_UPDATE", "1")));
            assert!(env.contains(&("HOMEBREW_NO_INSTALL_CLEANUP", "1")));
            let joined = args.join(" ");
            self.calls.borrow_mut().push(joined.clone());
            let stdout = self
                .answers
                .iter()
                .find(|(prefix, _)| joined == *prefix)
                .map(|(_, out)| (*out).to_string())
                .ok_or_else(|| format!("unexpected call: {joined}"))?;
            Ok(CmdOutput {
                code: Some(0),
                stdout,
                stderr: String::new(),
            })
        }
    }

    #[test]
    fn detect_classifies_groups_and_never_upgrades() {
        let runner = FakeRunner {
            answers: vec![
                ("outdated --json=v2", OUTDATED),
                ("upgrade --dry-run --formula ansible", DRY_ANSIBLE),
                ("upgrade --dry-run --formula libngtcp2", DRY_LIBNGTCP2),
                (
                    "upgrade --dry-run --formula node@24",
                    "==> Would upgrade 1 requested outdated package\nnode@24 24.21.0_1 -> 24.21.0_2\n",
                ),
                (
                    "upgrade --dry-run --formula hashicorp/tap/terraform",
                    "==> Would upgrade 1 requested outdated package\nhashicorp/tap/terraform 1.16.4 -> 1.16.5\n",
                ),
                (
                    "info --cask --json=v2 claude-code@latest tailscale-app",
                    CASK_INFO,
                ),
            ],
            calls: RefCell::new(Vec::new()),
        };
        let brew = Homebrew {
            runner: &runner,
            command: "brew",
            greedy_casks: false,
        };
        let det = brew.detect();
        assert!(det.errors.is_empty(), "{:?}", det.errors);
        assert_eq!(det.updates.len(), 7);
        let by_name = |n: &str| det.updates.iter().find(|u| u.name == n).unwrap().clone();
        assert_eq!(by_name("libngtcp2").change, Change::Rebuild);
        assert_eq!(by_name("ansible").action, Action::Update);
        assert_eq!(by_name("jq").action, Action::PinnedInHomebrew);
        assert_eq!(by_name("tailscale-app").action, Action::ManualSudo);
        assert_eq!(by_name("tailscale-app").source, Source::HomebrewCask);
        // ansible, libngtcp2+node@24, terraform, and one per installable cask.
        assert_eq!(det.groups.len(), 4);
        for call in runner.calls.borrow().iter() {
            assert!(
                call.starts_with("outdated")
                    || call.starts_with("info")
                    || call.starts_with("upgrade --dry-run"),
                "unexpected brew call: {call}"
            );
        }
        // No dry run for a formula Homebrew has pinned.
        assert!(!runner.calls.borrow().iter().any(|c| c.ends_with(" jq")));
    }

    #[test]
    fn greedy_adds_the_flag() {
        let runner = FakeRunner {
            answers: vec![(
                "outdated --json=v2 --greedy",
                r#"{"formulae":[],"casks":[]}"#,
            )],
            calls: RefCell::new(Vec::new()),
        };
        let brew = Homebrew {
            runner: &runner,
            command: "brew",
            greedy_casks: true,
        };
        let det = brew.detect();
        assert!(det.errors.is_empty(), "{:?}", det.errors);
        assert!(det.updates.is_empty());
    }

    #[test]
    fn brew_failure_is_reported_not_fatal() {
        struct Failing;
        impl Runner for Failing {
            fn run(&self, _: &str, _: &[&str], _: &[(&str, &str)]) -> Result<CmdOutput, String> {
                Ok(CmdOutput {
                    code: Some(1),
                    stdout: String::new(),
                    stderr: "Error: boom".into(),
                })
            }
        }
        let brew = Homebrew {
            runner: &Failing,
            command: "brew",
            greedy_casks: false,
        };
        let det = brew.detect();
        assert!(det.updates.is_empty());
        assert!(det.errors[0].contains("boom"));
    }
}
