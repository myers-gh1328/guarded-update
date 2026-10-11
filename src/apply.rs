//! Updates one planned group (ADR-0001 D3, D4): `brew upgrade` for its
//! members, a check that the new version is the screened one, then
//! a restart and health check of every service it affects. A failure is
//! restarted and checked once more, then the group is held. There is no
//! rollback yet: a failed update stays in place and is held.

use std::collections::BTreeMap;
use std::time::Duration;

use serde::Serialize;

use crate::app::{PlannedGroup, Watch, check_health, short_name};
use crate::exec::{HOMEBREW_ENV, Runner};
use crate::model::{Detection, Source};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "result", content = "detail", rename_all = "lowercase")]
pub enum Outcome {
    Updated,
    Failed(String),
    Skipped(String),
}

#[derive(Debug, Clone, Serialize)]
pub struct GroupResult {
    pub members: Vec<String>,
    pub outcome: Outcome,
    /// Services restarted and found healthy.
    pub restarted: Vec<String>,
    /// Members still below their screened version.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub not_updated: Vec<String>,
    /// Homebrew's error when it failed but every member was updated anyway.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
}

/// Lines of Homebrew output to keep from an error.
const ERROR_LINES: usize = 10;

/// Homebrew's error: from the first `Error:` line on, or the last line.
fn brew_error(stderr: &str) -> String {
    let lines: Vec<&str> = stderr.lines().filter(|l| !l.trim().is_empty()).collect();
    let start = lines.iter().position(|l| l.starts_with("Error:"));
    let kept: Vec<&str> = match start {
        Some(i) => lines[i..].iter().take(ERROR_LINES).copied().collect(),
        None => lines.last().copied().into_iter().collect(),
    };
    if kept.is_empty() {
        "no error output".into()
    } else {
        kept.iter()
            .map(|l| l.chars().take(200).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n")
    }
}

pub struct Applier<'a> {
    pub runner: &'a dyn Runner,
    pub brew: &'a str,
    pub greedy_casks: bool,
    /// Waits between health checks; a no-op in tests.
    pub sleep: &'a dyn Fn(Duration),
    pub poll: Duration,
    /// Health checks per restart before it counts as failed.
    pub checks: u32,
}

impl Applier<'_> {
    pub fn apply(
        &self,
        group: &PlannedGroup,
        det: &Detection,
        watched: &BTreeMap<String, Watch>,
    ) -> GroupResult {
        let result = |outcome, restarted| GroupResult {
            members: group.members.clone(),
            outcome,
            restarted,
            not_updated: vec![],
            warning: None,
        };
        let cask = match group.source {
            Source::HomebrewFormula => false,
            Source::HomebrewCask => true,
            Source::Hermes => {
                return result(
                    Outcome::Skipped("updating Hermes is not built yet; update it by hand".into()),
                    vec![],
                );
            }
            Source::Pinned | Source::Macos => {
                return result(Outcome::Skipped("alert only".into()), vec![]);
            }
        };
        let mut args = vec!["upgrade", if cask { "--cask" } else { "--formula" }];
        if cask && self.greedy_casks {
            args.push("--greedy");
        }
        args.extend(group.members.iter().map(String::as_str));
        // Homebrew can fail after the new versions are in place (a link
        // conflict, say), so the versions decide, not its exit code.
        let error = match self.runner.run(self.brew, &args, HOMEBREW_ENV) {
            Ok(out) if out.success() => None,
            Ok(out) => Some(brew_error(&out.stderr)),
            Err(e) => return result(Outcome::Failed(format!("brew upgrade: {e}")), vec![]),
        };
        let with_error = |why: String| match &error {
            Some(e) => format!("{why}\nHomebrew said:\n{e}"),
            None => why,
        };
        let behind = match self.behind(group, det, cask) {
            Ok(behind) => behind,
            Err(e) => return result(Outcome::Failed(with_error(e)), vec![]),
        };
        if !behind.is_empty() {
            let why = behind
                .iter()
                .map(|(name, version)| format!("{name} is not at {version} after the update"))
                .collect::<Vec<_>>()
                .join("; ");
            return GroupResult {
                not_updated: behind.into_iter().map(|(name, _)| name).collect(),
                ..result(Outcome::Failed(with_error(why)), vec![])
            };
        }
        let mut restarted = Vec::new();
        for label in &group.services {
            let Some(service) = watched.get(label) else {
                continue;
            };
            match self.restart(label, service) {
                Ok(()) => restarted.push(label.clone()),
                Err(e) => return result(Outcome::Failed(with_error(e)), restarted),
            }
        }
        GroupResult {
            warning: error,
            ..result(Outcome::Updated, restarted)
        }
    }

    /// Members whose installed versions lack the screened one, with it.
    fn behind(
        &self,
        group: &PlannedGroup,
        det: &Detection,
        cask: bool,
    ) -> Result<Vec<(String, String)>, String> {
        let mut args = vec!["list"];
        if cask {
            args.push("--cask");
        }
        args.push("--versions");
        args.extend(group.members.iter().map(String::as_str));
        let out = self
            .runner
            .run(self.brew, &args, HOMEBREW_ENV)
            .map_err(|e| format!("cannot check the installed versions: {e}"))?;
        let installed: BTreeMap<&str, Vec<&str>> = out
            .stdout
            .lines()
            .filter_map(|line| {
                let mut words = line.split_whitespace();
                Some((words.next()?, words.collect()))
            })
            .collect();
        Ok(group
            .members
            .iter()
            .filter_map(|member| {
                let update = det.updates.iter().find(|u| &u.name == member)?;
                let versions = installed
                    .get(short_name(member))
                    .or_else(|| installed.get(member.as_str()));
                (!versions.is_some_and(|v| v.contains(&update.available.as_str())))
                    .then(|| (member.clone(), update.available.clone()))
            })
            .collect())
    }

    /// Restarts a service and waits for its health check, trying twice.
    fn restart(&self, label: &str, service: &Watch) -> Result<(), String> {
        let mut last = String::new();
        for _ in 0..2 {
            if let Some((program, args)) = service.restart.split_first() {
                let args: Vec<&str> = args.iter().map(String::as_str).collect();
                match self.runner.run(program, &args, &[]) {
                    Ok(out) if out.success() => {}
                    Ok(out) => last = format!("restart exited with {:?}", out.code),
                    Err(e) => last = e,
                }
            }
            for _ in 0..self.checks.max(1) {
                (self.sleep)(self.poll);
                match check_health(service, self.runner) {
                    None | Some(Ok(())) => return Ok(()),
                    Some(Err(e)) => last = e,
                }
            }
        }
        Err(format!(
            "{label} did not come back after two restarts: {last}"
        ))
    }
}

/// Update order (ADR-0001 D4): groups that restart nothing first, then
/// service groups, Hermes last.
pub fn order(groups: &mut [&PlannedGroup]) {
    groups.sort_by_key(|g| {
        (
            g.source == Source::Hermes,
            !g.services.is_empty(),
            g.members.clone(),
        )
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::Decision;
    use crate::exec::CmdOutput;
    use crate::model::{Action, Change, Update};
    use std::cell::RefCell;

    /// Answers by command prefix; records every call.
    struct Script {
        answers: Vec<(&'static str, i32, &'static str)>,
        calls: RefCell<Vec<String>>,
    }

    impl Runner for Script {
        fn run(
            &self,
            program: &str,
            args: &[&str],
            _: &[(&str, &str)],
        ) -> Result<CmdOutput, String> {
            let joined = format!("{program} {}", args.join(" "));
            self.calls.borrow_mut().push(joined.clone());
            let (_, code, stdout) = self
                .answers
                .iter()
                .find(|(prefix, _, _)| joined.starts_with(prefix))
                .ok_or_else(|| format!("unexpected call: {joined}"))?;
            Ok(CmdOutput {
                code: Some(*code),
                // A failing answer's text is its stderr ("Error: boom" if none).
                stdout: if *code == 0 {
                    (*stdout).into()
                } else {
                    String::new()
                },
                stderr: match (*code, *stdout) {
                    (0, _) => String::new(),
                    (_, "") => "Error: boom".into(),
                    (_, text) => text.into(),
                },
            })
        }
    }

    fn update(name: &str, installed: &str, available: &str, source: Source) -> Update {
        Update {
            source,
            name: name.into(),
            installed: installed.into(),
            available: available.into(),
            change: Change::Version,
            action: Action::Update,
            note: None,
        }
    }

    fn group(members: &[&str], services: &[&str], source: Source) -> PlannedGroup {
        PlannedGroup {
            source,
            members: members.iter().map(|s| (*s).to_string()).collect(),
            new_dependencies: vec![],
            services: services.iter().map(|s| (*s).to_string()).collect(),
            decision: Decision::Update,
            reason: String::new(),
            checks: vec![],
            ai: vec![],
        }
    }

    fn det() -> Detection {
        Detection {
            updates: vec![
                update("node", "26.11.0", "26.11.1", Source::HomebrewFormula),
                update(
                    "hashicorp/tap/terraform",
                    "1.16.4",
                    "1.16.5",
                    Source::HomebrewFormula,
                ),
                update(
                    "claude-code@latest",
                    "2.1.294",
                    "2.1.295",
                    Source::HomebrewCask,
                ),
            ],
            ..Detection::default()
        }
    }

    fn web() -> BTreeMap<String, Watch> {
        [(
            "com.web".to_string(),
            Watch {
                packages: vec!["node".into()],
                restart: vec![
                    "launchctl".into(),
                    "kickstart".into(),
                    "-k".into(),
                    "gui/501/com.web".into(),
                ],
                health: vec!["launchctl".into(), "list".into(), "com.web".into()],
                health_expect: Some("\"PID\"".into()),
                root: false,
            },
        )]
        .into()
    }

    fn applier<'a>(runner: &'a Script, sleep: &'a dyn Fn(Duration)) -> Applier<'a> {
        Applier {
            runner,
            brew: "brew",
            greedy_casks: true,
            sleep,
            poll: Duration::from_secs(2),
            checks: 3,
        }
    }

    #[test]
    fn a_service_group_is_upgraded_verified_restarted_and_checked() {
        let runner = Script {
            answers: vec![
                ("brew upgrade --formula node", 0, ""),
                ("brew list --versions node", 0, "node 26.11.0 26.11.1\n"),
                ("launchctl kickstart -k gui/501/com.web", 0, ""),
                ("launchctl list com.web", 0, "{\n\t\"PID\" = 7;\n}"),
            ],
            calls: RefCell::default(),
        };
        let r = applier(&runner, &|_| {}).apply(
            &group(&["node"], &["com.web"], Source::HomebrewFormula),
            &det(),
            &web(),
        );
        assert_eq!(r.outcome, Outcome::Updated);
        assert_eq!(r.restarted, ["com.web"]);
        assert_eq!(runner.calls.borrow().len(), 4);
    }

    #[test]
    fn a_service_that_stays_down_fails_the_group_after_two_restarts() {
        let runner = Script {
            answers: vec![
                ("brew upgrade --formula node", 0, ""),
                ("brew list --versions node", 0, "node 26.11.1\n"),
                ("launchctl kickstart", 0, ""),
                (
                    "launchctl list com.web",
                    0,
                    "{\n\t\"LastExitStatus\" = 256;\n}",
                ),
            ],
            calls: RefCell::default(),
        };
        let waited = RefCell::new(0);
        let sleep = |_: Duration| *waited.borrow_mut() += 1;
        let r = applier(&runner, &sleep).apply(
            &group(&["node"], &["com.web"], Source::HomebrewFormula),
            &det(),
            &web(),
        );
        let Outcome::Failed(why) = r.outcome else {
            panic!("{:?}", r.outcome)
        };
        assert!(
            why.contains("com.web did not come back after two restarts"),
            "{why}"
        );
        let kicks = runner
            .calls
            .borrow()
            .iter()
            .filter(|c| c.contains("kickstart"))
            .count();
        assert_eq!(kicks, 2);
        assert_eq!(*waited.borrow(), 6, "three checks after each restart");
    }

    #[test]
    fn a_failed_upgrade_or_wrong_version_is_a_failure_with_no_restart() {
        let failing = Script {
            answers: vec![("brew upgrade", 1, "")],
            calls: RefCell::default(),
        };
        let r = applier(&failing, &|_| {}).apply(
            &group(&["node"], &["com.web"], Source::HomebrewFormula),
            &det(),
            &web(),
        );
        assert!(
            matches!(r.outcome, Outcome::Failed(ref w) if w.contains("Error: boom")),
            "{:?}",
            r.outcome
        );
        assert!(
            !failing
                .calls
                .borrow()
                .iter()
                .any(|c| c.contains("kickstart"))
        );
        let stale = Script {
            answers: vec![("brew upgrade", 0, ""), ("brew list", 0, "node 26.11.0\n")],
            calls: RefCell::default(),
        };
        let r = applier(&stale, &|_| {}).apply(
            &group(&["node"], &["com.web"], Source::HomebrewFormula),
            &det(),
            &web(),
        );
        assert!(
            matches!(r.outcome, Outcome::Failed(ref w) if w.contains("node is not at 26.11.1"))
        );
        assert!(!stale.calls.borrow().iter().any(|c| c.contains("kickstart")));
    }

    const LINK_ERROR: &str = "==> Pouring certifi--2026.7.22_1.arm64_tahoe.bottle.tar.gz
Error: The `brew link` step did not complete successfully
The formula built, but is not symlinked into /opt/homebrew
Could not symlink lib/python3.14/site-packages/certifi/__init__.py
Target /opt/homebrew/lib/python3.14/site-packages/certifi/__init__.py
already exists. You may want to remove it:

To force the link and overwrite all conflicting files:
  brew link --overwrite certifi
";

    #[test]
    fn a_brew_error_after_every_member_reached_the_new_version_still_counts_as_updated() {
        let runner = Script {
            answers: vec![
                ("brew upgrade --formula node", 1, LINK_ERROR),
                ("brew list --versions node", 0, "node 26.11.0 26.11.1\n"),
                ("launchctl kickstart -k gui/501/com.web", 0, ""),
                ("launchctl list com.web", 0, "{\n\t\"PID\" = 7;\n}"),
            ],
            calls: RefCell::default(),
        };
        let r = applier(&runner, &|_| {}).apply(
            &group(&["node"], &["com.web"], Source::HomebrewFormula),
            &det(),
            &web(),
        );
        assert_eq!(r.outcome, Outcome::Updated);
        assert_eq!(r.restarted, ["com.web"], "services are still checked");
        let warning = r.warning.expect("the brew error is kept");
        assert!(
            warning.starts_with("Error: The `brew link` step"),
            "{warning}"
        );
        assert!(
            warning.contains("brew link --overwrite certifi"),
            "{warning}"
        );
        assert!(!warning.contains("Pouring"), "only the error, not progress");
    }

    #[test]
    fn a_failed_upgrade_names_the_members_left_behind_and_the_brew_error() {
        let runner = Script {
            answers: vec![
                (
                    "brew upgrade --formula node hashicorp/tap/terraform",
                    1,
                    LINK_ERROR,
                ),
                (
                    "brew list --versions",
                    0,
                    "node 26.11.0 26.11.1\nterraform 1.16.4\n",
                ),
            ],
            calls: RefCell::default(),
        };
        let r = applier(&runner, &|_| {}).apply(
            &group(
                &["node", "hashicorp/tap/terraform"],
                &[],
                Source::HomebrewFormula,
            ),
            &det(),
            &BTreeMap::new(),
        );
        let Outcome::Failed(why) = &r.outcome else {
            panic!("{:?}", r.outcome)
        };
        assert_eq!(r.not_updated, ["hashicorp/tap/terraform"]);
        assert!(
            why.contains("hashicorp/tap/terraform is not at 1.16.5"),
            "{why}"
        );
        assert!(why.contains("brew link --overwrite certifi"), "{why}");
    }

    #[test]
    fn casks_use_greedy_and_tap_formulae_match_by_short_name() {
        let runner = Script {
            answers: vec![
                ("brew upgrade --cask --greedy claude-code@latest", 0, ""),
                (
                    "brew list --cask --versions claude-code@latest",
                    0,
                    "claude-code@latest 2.1.295\n",
                ),
                ("brew upgrade --formula hashicorp/tap/terraform", 0, ""),
                (
                    "brew list --versions hashicorp/tap/terraform",
                    0,
                    "terraform 1.16.5\n",
                ),
            ],
            calls: RefCell::default(),
        };
        let a = applier(&runner, &|_| {});
        let none = BTreeMap::new();
        let cask = a.apply(
            &group(&["claude-code@latest"], &[], Source::HomebrewCask),
            &det(),
            &none,
        );
        assert_eq!(cask.outcome, Outcome::Updated);
        let tap = a.apply(
            &group(&["hashicorp/tap/terraform"], &[], Source::HomebrewFormula),
            &det(),
            &none,
        );
        assert_eq!(tap.outcome, Outcome::Updated);
    }

    #[test]
    fn hermes_is_skipped_and_order_puts_services_then_hermes_last() {
        let runner = Script {
            answers: vec![],
            calls: RefCell::default(),
        };
        let r = applier(&runner, &|_| {}).apply(
            &group(&["hermes"], &[], Source::Hermes),
            &det(),
            &BTreeMap::new(),
        );
        assert!(matches!(r.outcome, Outcome::Skipped(_)));
        assert!(runner.calls.borrow().is_empty());
        let h = group(&["hermes"], &[], Source::Hermes);
        let s = group(&["node"], &["com.web"], Source::HomebrewFormula);
        let t = group(&["jq"], &[], Source::HomebrewFormula);
        let mut list = vec![&h, &s, &t];
        order(&mut list);
        let names: Vec<&str> = list.iter().map(|g| g.members[0].as_str()).collect();
        assert_eq!(names, ["jq", "node", "hermes"]);
    }
}
