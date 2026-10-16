//! Commands: `check`, `run --dry-run`, `validate`, `explain`.
//!
//! Detection and planning only. Nothing here installs, upgrades, pins,
//! restarts or edits package state; the only files written are the log,
//! the lock and one history file per dry run.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::{Map, Value, json};

use crate::apply;
use crate::cli::{self, Cli, Command};
use crate::config::{self, Config, Loaded, Policy, Screening};
use crate::exec::Runner;
use crate::http::Http;
use crate::model::{Action, Change, Detection, Source, Update};
use crate::output::Output;
use crate::providers::{hermes, homebrew, macos, pinned};
use crate::redact::Redactor;
use crate::scan::{self, ServiceMap};
use crate::schedule;
use crate::screen::{self, Notes};
use crate::setup;
use crate::state::{State, StateDir};
use crate::timefmt;

pub const EXIT_OK: u8 = 0;
pub const EXIT_PARTIAL: u8 = 1;
pub const EXIT_USAGE: u8 = 2;
pub const EXIT_NOT_YET: u8 = 3;
pub const EXIT_CONFIG: u8 = 4;
pub const EXIT_BUSY: u8 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Decision {
    /// Would be screened, then updated if the screen passes.
    Update,
    Hold,
    Ignore,
}

#[derive(Debug, Clone, Serialize)]
pub struct PlannedGroup {
    pub source: Source,
    pub members: Vec<String>,
    pub new_dependencies: Vec<String>,
    /// launchd services the upgrade affects.
    pub services: Vec<String>,
    pub decision: Decision,
    pub reason: String,
    /// Safety checks that passed with a remark, e.g. no release notes.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub checks: Vec<String>,
    /// Every question the AI was asked about this group, in full.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ai: Vec<crate::ai::Record>,
}

/// `hashicorp/tap/terraform` -> `terraform`: services name packages by
/// their short name.
pub fn short_name(package: &str) -> &str {
    package.rsplit('/').next().unwrap_or(package)
}

/// A service that upgrades can affect: from the saved scan (loaded and
/// linked to a package), with any config entry for the same label taking
/// precedence field by field.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Watch {
    pub packages: Vec<String>,
    pub restart: Vec<String>,
    pub health: Vec<String>,
    pub health_expect: Option<String>,
    /// Restarting it needs root, so groups that touch it are held.
    pub root: bool,
}

pub fn watched(config: &Config, map: Option<&ServiceMap>) -> BTreeMap<String, Watch> {
    let mut all = BTreeMap::new();
    for service in map.map(|m| m.services.as_slice()).unwrap_or_default() {
        if !service.loaded || service.links.is_empty() {
            continue;
        }
        let uid = map.map(|m| m.uid.as_str()).unwrap_or_default();
        let d = scan::defaults_for(service, uid);
        all.insert(
            service.label.clone(),
            Watch {
                packages: service.links.iter().map(|(p, _)| p.clone()).collect(),
                restart: d.restart,
                health: d.health,
                health_expect: d.health_expect,
                root: service.root,
            },
        );
    }
    for (label, c) in &config.services {
        let w = all.entry(label.clone()).or_default();
        if !c.packages.is_empty() {
            w.packages = c.packages.clone();
        }
        if !c.restart.is_empty() {
            w.restart = c.restart.clone();
        }
        if !c.health.is_empty() {
            w.health = c.health.clone();
            w.health_expect = c.health_expect.clone();
        }
        w.root |= c.requires_root;
    }
    all
}

/// Services affected by a group, and the ones among them that need root.
pub fn affected_services(
    members: &[String],
    watched: &BTreeMap<String, Watch>,
) -> (Vec<String>, Vec<String>) {
    let mut all = Vec::new();
    let mut root = Vec::new();
    for (label, service) in watched {
        let touched = members.iter().any(|m| {
            service
                .packages
                .iter()
                .any(|p| p == short_name(m) || p == m)
        });
        if touched {
            all.push(label.clone());
            if service.root {
                root.push(label.clone());
            }
        }
    }
    (all, root)
}

pub struct HealthResult {
    pub label: String,
    pub outcome: Result<(), String>,
}

/// Runs every service's health command.
/// Runs one service's health command; `None` when it has none.
pub fn check_health(service: &Watch, runner: &dyn Runner) -> Option<Result<(), String>> {
    let (program, args) = service.health.split_first()?;
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    Some(match runner.run(program, &args, &[]) {
        Err(e) => Err(e),
        Ok(out) if !out.success() => Err(format!(
            "health command exited with {}",
            out.code.map_or("a signal".to_string(), |c| c.to_string())
        )),
        Ok(out) => match &service.health_expect {
            Some(expect) if !out.stdout.contains(expect.as_str()) => {
                Err(format!("output does not contain `{expect}`"))
            }
            _ => Ok(()),
        },
    })
}

pub fn run_health_checks(
    watched: &BTreeMap<String, Watch>,
    runner: &dyn Runner,
) -> Vec<HealthResult> {
    watched
        .iter()
        .filter_map(|(label, service)| {
            Some(HealthResult {
                label: label.clone(),
                outcome: check_health(service, runner)?,
            })
        })
        .collect()
}

/// Starts the wait for each newly seen version and forgets versions that
/// are no longer waiting.
pub fn record_first_seen(state: &mut State, det: &Detection, now: u64) {
    let waiting: BTreeMap<&str, &str> = det
        .updates
        .iter()
        .map(|u| (u.name.as_str(), u.available.as_str()))
        .collect();
    state
        .first_seen
        .retain(|name, seen| waiting.get(name.as_str()) == Some(&seen.version.as_str()));
    for u in &det.updates {
        state
            .first_seen
            .entry(u.name.clone())
            .or_insert_with(|| crate::state::Seen {
                version: u.available.clone(),
                at: now,
            });
    }
}

/// Asks the AI about one update: its release notes and the services that
/// use it. Any answer that is not ok holds it.
pub type AskAi<'a> = dyn FnMut(&Update, &str, &[String]) -> Vec<crate::ai::Record> + 'a;

/// Holds every group the plan would update where a safety check
/// objects to any member (ADR-0001 D8).
pub fn apply_rules(
    plan: &mut Plan,
    det: &Detection,
    rules: &Screening,
    state: &State,
    now: u64,
    notes: &mut dyn FnMut(&Update) -> Notes,
    ai: &mut AskAi,
) {
    for group in plan
        .groups
        .iter_mut()
        .filter(|g| g.decision == Decision::Update)
    {
        let mut reasons = Vec::new();
        for member in &group.members {
            let Some(update) = det.updates.iter().find(|u| &u.name == member) else {
                continue;
            };
            // The user approved this exact version; the rules are advice.
            if state.approvals.get(member) == Some(&update.available) {
                continue;
            }
            let seen = state.first_seen.get(member).map_or(now, |s| s.at);
            let mut missing = None;
            let mut fetch = || {
                let n = notes(update);
                if let Notes::Missing(why) = &n {
                    missing = Some(format!("{member}: {why}"));
                }
                n
            };
            let services = group.services.clone();
            let mut records = Vec::new();
            let mut ask = |text: &str| {
                let mut asked = ai(update, text, &services);
                if asked.is_empty() {
                    let mut failed = crate::ai::Record::new(update, text, 0, 0);
                    failed.error = Some("no review records were returned".into());
                    asked.push(failed);
                }
                let reason = asked.iter().find_map(crate::ai::Record::hold_reason);
                records.extend(asked);
                reason
            };
            let held = screen::holds(update, rules, seen, now, &mut fetch, &mut ask);
            if !records.is_empty() && records.iter().all(|r| r.hold_reason().is_none()) {
                let why: Vec<&str> = records.iter().map(|r| r.reason.as_str()).collect();
                group
                    .checks
                    .push(format!("{member}: AI check ok: {}", why.join("; ")));
            }
            group.ai.extend(records);
            reasons.extend(held.into_iter().map(|r| format!("{member}: {r}")));
            group.checks.extend(missing);
        }
        if !reasons.is_empty() {
            group.decision = Decision::Hold;
            group.reason = format!("safety check: {}", reasons.join("; "));
        }
    }
}

/// GitHub's largest page, and how many pages one update may read.
const RELEASES_PER_PAGE: usize = 100;
const RELEASE_PAGES: u32 = 10;

/// Release notes from the update's GitHub project, found from Homebrew's
/// homepage and download URLs (or the configured Hermes repository).
fn fetch_notes(update: &Update, cfg: &Config, runner: &dyn Runner, http: &dyn Http) -> Notes {
    let brew = cfg.providers.homebrew.command.as_str();
    let repo = match update.source {
        Source::Hermes => Some(cfg.providers.hermes.github_repo.clone()),
        Source::HomebrewFormula | Source::HomebrewCask => {
            let kind = if update.source == Source::HomebrewCask {
                "--cask"
            } else {
                "--formula"
            };
            runner
                .run(
                    brew,
                    &["info", "--json=v2", kind, &update.name],
                    crate::exec::HOMEBREW_ENV,
                )
                .ok()
                .filter(|o| o.success())
                .and_then(|o| serde_json::from_str::<Value>(&o.stdout).ok())
                .and_then(|v| {
                    let item = v["formulae"].get(0).or_else(|| v["casks"].get(0))?.clone();
                    let urls = [
                        item["urls"]["stable"]["url"].as_str(),
                        item["url"].as_str(),
                        item["homepage"].as_str(),
                        item["urls"]["head"]["url"].as_str(),
                    ];
                    let urls: Vec<&str> = urls.into_iter().flatten().collect();
                    screen::github_repo(&urls)
                })
        }
        Source::Pinned | Source::Macos => None,
    };
    let Some(repo) = repo else {
        return Notes::Missing("no GitHub project found, so release notes were not read".into());
    };
    let fetched = screen::collect_releases(
        &update.installed,
        RELEASES_PER_PAGE,
        RELEASE_PAGES,
        &mut |page| {
            http.get_json(
                &format!(
                    "https://api.github.com/repos/{repo}/releases?per_page={RELEASES_PER_PAGE}&page={page}"
                ),
                true,
            )
        },
    );
    let (releases, complete) = match fetched {
        Ok(fetched) => fetched,
        Err(e) => return Notes::Missing(format!("could not read release notes from {repo}: {e}")),
    };
    if !complete {
        return Notes::Incomplete(format!(
            "only the newest {} releases on {repo} could be read, not every one since {}; a person should check",
            releases.len(),
            update.installed
        ));
    }
    let releases = Value::Array(releases);
    if cfg.screening.ai.url.is_some()
        && !screen::notes_complete(&releases, &update.installed, &update.available)
    {
        return Notes::Incomplete("AI review needs release notes for the target version and nonempty notes for every published release in the range".into());
    }
    match screen::notes_between(&releases, &update.installed, &update.available) {
        Some(text) => Notes::Found(text),
        None => Notes::Missing(format!("no release notes on {repo} for these versions")),
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Plan {
    pub report_only: bool,
    pub groups: Vec<PlannedGroup>,
    pub manual: Vec<Update>,
    pub pinned_in_homebrew: Vec<Update>,
    pub alert_only: Vec<Update>,
    pub ignored: Vec<String>,
}

/// Decides what a real run would do with each group, from the user's
/// policies and held items. Hermes goes last (ADR-0001 D4).
pub fn plan(det: &Detection, loaded: &Loaded, state: &State, map: Option<&ServiceMap>) -> Plan {
    let watched = watched(&loaded.config, map);
    let report_only = !loaded.config.enabled;
    let find = |name: &str| det.updates.iter().find(|u| u.name == name);
    let effective = |name: &str| -> Policy {
        let approved = find(name).is_some_and(|u| state.approvals.get(name) == Some(&u.available));
        if approved {
            Policy::Auto
        } else {
            loaded.policy_for(name).0
        }
    };
    let mut plan = Plan {
        report_only,
        ..Plan::default()
    };

    for group in &det.groups {
        let held: Vec<String> = group
            .members
            .iter()
            .filter_map(|m| {
                let h = state.held.get(m)?;
                let current = find(m).is_none_or(|u| u.available == h.version);
                current.then(|| format!("{m} held at {}: {}", h.version, h.reason))
            })
            .collect();
        let policies: Vec<(String, Policy)> = group
            .members
            .iter()
            .map(|m| (m.clone(), effective(m)))
            .collect();
        let (services, root) = affected_services(&group.members, &watched);
        let (decision, reason) = if report_only {
            (Decision::Hold, "report only (enabled = false)".to_string())
        } else if !root.is_empty() {
            (
                Decision::Hold,
                format!("restart needs root: {}; update it by hand", root.join(", ")),
            )
        } else if !held.is_empty() {
            (Decision::Hold, held.join("; "))
        } else if policies.iter().all(|(_, p)| *p == Policy::Auto) {
            (Decision::Update, "every member is set to auto".to_string())
        } else if policies.iter().all(|(_, p)| *p == Policy::Ignore) {
            (
                Decision::Ignore,
                "every member is set to ignore".to_string(),
            )
        } else {
            let blocking: Vec<String> = policies
                .iter()
                .filter(|(_, p)| *p != Policy::Auto)
                .map(|(m, p)| format!("{m} ({p})"))
                .collect();
            (
                Decision::Hold,
                format!("not set to auto: {}", blocking.join(", ")),
            )
        };
        if decision == Decision::Ignore {
            plan.ignored.extend(group.members.iter().cloned());
        }
        plan.groups.push(PlannedGroup {
            source: group.source,
            members: group.members.clone(),
            new_dependencies: group.new_dependencies.clone(),
            services,
            decision,
            reason,
            checks: Vec::new(),
            ai: Vec::new(),
        });
    }
    plan.groups
        .sort_by_key(|g| (g.source == Source::Hermes, g.members.clone()));

    for update in &det.updates {
        let list = match update.action {
            Action::Update => continue,
            Action::AlertOnly => &mut plan.alert_only,
            Action::ManualSudo => &mut plan.manual,
            Action::PinnedInHomebrew => &mut plan.pinned_in_homebrew,
        };
        if effective(&update.name) == Policy::Ignore {
            plan.ignored.push(update.name.clone());
        } else {
            list.push(update.clone());
        }
    }
    plan.ignored.sort();
    plan.ignored.dedup();
    plan
}

fn describe(update: &Update) -> String {
    let change = match update.change {
        Change::Rebuild => " (rebuild)",
        Change::Version => "",
    };
    let note = update
        .note
        .as_ref()
        .map(|n| format!(" ({n})"))
        .unwrap_or_default();
    if update.installed == "-" {
        return format!("{} {}{change}{note}", update.name, update.available);
    }
    format!(
        "{} {} -> {}{change}{note}",
        update.name, update.installed, update.available
    )
}

fn describe_group(members: &[String], deps: &[String], det: &Detection) -> String {
    let parts: Vec<String> = members
        .iter()
        .map(|m| match det.updates.iter().find(|u| &u.name == m) {
            Some(u) => describe(u),
            None => m.clone(),
        })
        .collect();
    let mut text = parts.join(", ");
    if !deps.is_empty() {
        text.push_str(&format!("  + new: {}", deps.join(", ")));
    }
    text
}

pub fn render_check(det: &Detection) -> String {
    let mut lines = Vec::new();
    let count = |s: Source| det.updates.iter().filter(|u| u.source == s).count();
    let summary: Vec<String> = [
        Source::HomebrewFormula,
        Source::HomebrewCask,
        Source::Hermes,
        Source::Pinned,
        Source::Macos,
    ]
    .into_iter()
    .filter(|s| count(*s) > 0)
    .map(|s| format!("{} {}", count(s), s.label()))
    .collect();
    if det.updates.is_empty() {
        lines.push("No updates available.".to_string());
    } else {
        lines.push(format!(
            "{} updates available: {}.",
            det.updates.len(),
            summary.join(", ")
        ));
        lines.push(String::new());
        let width = det.updates.iter().map(|u| u.name.len()).max().unwrap_or(0);
        for u in &det.updates {
            let change = match u.change {
                Change::Rebuild => "rebuild",
                Change::Version => "version",
            };
            let action = match u.action {
                Action::Update => String::new(),
                Action::AlertOnly => "  [alert only]".to_string(),
                Action::ManualSudo => {
                    format!("  [manual: {}]", u.note.as_deref().unwrap_or("needs sudo"))
                }
                Action::PinnedInHomebrew => "  [pinned with brew pin]".to_string(),
            };
            lines.push(format!(
                "  {:<8} {:<width$}  {} -> {}  {change}{action}",
                u.source.label(),
                u.name,
                u.installed,
                u.available
            ));
        }
    }
    if !det.groups.is_empty() {
        lines.push(String::new());
        lines.push("Dependency groups (each is upgraded as one unit):".to_string());
        for (i, g) in det.groups.iter().enumerate() {
            let mut text = g.members.join(", ");
            if !g.new_dependencies.is_empty() {
                text.push_str(&format!("  + new: {}", g.new_dependencies.join(", ")));
            }
            lines.push(format!("  {}. {text}", i + 1));
        }
    }
    push_errors(&mut lines, &det.errors);
    lines.join("\n")
}

fn push_errors(lines: &mut Vec<String>, errors: &[String]) {
    if !errors.is_empty() {
        lines.push(String::new());
        lines.push(format!("Errors ({}):", errors.len()));
        lines.extend(errors.iter().map(|e| format!("  - {e}")));
    }
}

fn push_section(lines: &mut Vec<String>, title: &str, items: Vec<String>) {
    if items.is_empty() {
        return;
    }
    lines.push(String::new());
    lines.push(format!("{title} ({}):", items.len()));
    lines.extend(items.into_iter().map(|i| format!("  - {i}")));
}

pub fn render_plan(plan: &Plan, det: &Detection, run_id: &str, history: &Path) -> String {
    let mut lines = vec![format!(
        "guarded-update dry run {run_id}: nothing was changed."
    )];
    if plan.report_only {
        lines.push("Report only: `enabled = false` in the config.".to_string());
    }
    let groups = |d: Decision| -> Vec<String> {
        plan.groups
            .iter()
            .filter(|g| g.decision == d)
            .map(|g| {
                let mut text = describe_group(&g.members, &g.new_dependencies, det);
                if !g.services.is_empty() {
                    text.push_str(&format!("\n      restarts: {}", g.services.join(", ")));
                }
                for check in &g.checks {
                    text.push_str(&format!("\n      note: {check}"));
                }
                if d == Decision::Hold {
                    format!("{text}\n      why: {}", indent(&g.reason, "        "))
                } else {
                    text
                }
            })
            .collect()
    };
    push_section(
        &mut lines,
        "Passed the safety checks; would update",
        groups(Decision::Update),
    );
    push_section(&mut lines, "Held", groups(Decision::Hold));
    push_section(
        &mut lines,
        "Needs manual action (sudo), never attempted",
        plan.manual.iter().map(describe).collect(),
    );
    push_section(
        &mut lines,
        "Pinned with brew pin",
        plan.pinned_in_homebrew.iter().map(describe).collect(),
    );
    push_section(
        &mut lines,
        "Alert only, never updated",
        plan.alert_only.iter().map(describe).collect(),
    );
    if !plan.ignored.is_empty() {
        lines.push(String::new());
        lines.push(format!("Ignored: {}", plan.ignored.join(", ")));
    }
    if det.updates.is_empty() {
        lines.push(String::new());
        lines.push("No updates available.".to_string());
    }
    push_errors(&mut lines, &det.errors);
    lines.push(String::new());
    lines.push(format!("History: {}", history.display()));
    lines.join("\n")
}

/// Builds the HTTP client once the config is known.
pub type HttpFactory<'a> = &'a dyn Fn(&Config) -> Box<dyn Http>;

fn fields(pairs: &[(&str, Value)]) -> Map<String, Value> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), v.clone()))
        .collect()
}

fn home() -> Result<PathBuf, String> {
    std::env::home_dir().ok_or_else(|| "cannot find the home directory".to_string())
}

fn config_paths(cli: &Cli) -> Result<(PathBuf, PathBuf), String> {
    let dir = || -> Result<PathBuf, String> {
        Ok(match std::env::var_os("GUARDED_UPDATE_CONFIG_DIR") {
            Some(dir) => PathBuf::from(dir),
            None => home()?.join(".config/guarded-update"),
        })
    };
    let base = match &cli.config {
        Some(p) => p.clone(),
        None => dir()?.join("base.toml"),
    };
    let overrides = match &cli.overrides {
        Some(p) => p.clone(),
        None => dir()?.join("overrides.toml"),
    };
    Ok((base, overrides))
}

fn state_dir(cli: &Cli, config: &Config) -> Result<PathBuf, String> {
    if let Some(dir) = &cli.state_dir {
        return Ok(dir.clone());
    }
    if let Some(dir) = &config.paths.state_dir {
        return Ok(dir.clone());
    }
    Ok(match std::env::var_os("GUARDED_UPDATE_STATE_DIR") {
        Some(dir) => PathBuf::from(dir),
        None => home()?.join(".local/state/guarded-update"),
    })
}

fn detect_all(
    loaded: &Loaded,
    cli: &Cli,
    runner: &dyn Runner,
    http: &dyn Http,
    out: &Output,
) -> Detection {
    let cfg = &loaded.config;
    let mut det = Detection::default();
    let record = |name: &str, part: Detection, det: &mut Detection| {
        out.log(
            if part.errors.is_empty() {
                "info"
            } else {
                "warn"
            },
            "provider_done",
            fields(&[
                ("provider", json!(name)),
                ("updates", json!(part.updates.len())),
                ("groups", json!(part.groups.len())),
                ("errors", json!(part.errors)),
            ]),
        );
        det.extend(part);
    };
    let hb = &cfg.providers.homebrew;
    if hb.enabled {
        let brew = homebrew::Homebrew {
            runner,
            command: &hb.command,
            greedy_casks: hb.greedy_casks,
        };
        if hb.refresh && !cli.no_refresh {
            match brew.refresh() {
                Ok(()) => out.log("info", "refresh_done", Map::new()),
                Err(e) => det
                    .errors
                    .push(format!("brew update failed; using cached metadata: {e}")),
            }
        }
        record("homebrew", brew.detect(), &mut det);
    }
    let hermes_cfg = &cfg.providers.hermes;
    if hermes_cfg.enabled {
        let part = hermes::detect(runner, http, &hermes_cfg.command, &hermes_cfg.github_repo);
        record("hermes", part, &mut det);
    }
    if !cfg.providers.pinned.is_empty() {
        record(
            "pinned",
            pinned::detect(http, &cfg.providers.pinned),
            &mut det,
        );
    }
    if cfg.providers.macos.enabled {
        record("macos", macos::detect(runner), &mut det);
    }
    det
}

fn explain(loaded: &Loaded, item: Option<&str>, out: &Output) -> u8 {
    if let Some(item) = item {
        let (policy, key, layer) = loaded.policy_for(item);
        out.stdout(&format!(
            "{item}: policy = {policy} (from {key}, {layer} layer)"
        ));
        if let Some(url) = loaded
            .config
            .items
            .get(item)
            .and_then(|i| i.notes_url.as_ref())
        {
            let layer = loaded.origin(&format!("items.{item}.notes_url"));
            out.stdout(&format!("{item}: notes_url = {url} ({layer} layer)"));
        }
        return EXIT_OK;
    }
    for (layer, path) in &loaded.files {
        out.stdout(&format!("{layer} layer: {}", path.display()));
    }
    if loaded.files.is_empty() {
        out.stdout("No config files found; every setting is a default.");
    }
    let table = match toml::Table::try_from(&loaded.config) {
        Ok(table) => table,
        Err(e) => {
            out.stderr(&format!("cannot show the config: {e}"));
            return EXIT_PARTIAL;
        }
    };
    let mut rows = Vec::new();
    flatten("", &toml::Value::Table(table), &mut rows);
    for (key, value) in rows {
        out.stdout(&format!("{key} = {value} ({})", loaded.origin(&key)));
    }
    EXIT_OK
}

fn flatten(prefix: &str, value: &toml::Value, rows: &mut Vec<(String, String)>) {
    match value {
        toml::Value::Table(table) => {
            for (k, v) in table {
                let key = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                flatten(&key, v, rows);
            }
        }
        leaf => rows.push((prefix.to_string(), leaf.to_string())),
    }
}

/// `services.toml` lives next to the overrides file.
fn services_path(overrides: &Path) -> PathBuf {
    overrides
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("services.toml")
}

/// A line to show before `check`, `run` and `validate` output when the
/// saved service list is missing or the launchd folders have changed.
fn map_notice(map: Option<&ServiceMap>) -> Option<String> {
    if !cfg!(target_os = "macos") {
        return None;
    }
    let Some(map) = map else {
        return Some(
            "No saved service list yet, so no restarts are planned. Run `guarded-update setup`."
                .into(),
        );
    };
    let home = home().ok()?;
    let (added, removed) = map.changes(&scan::plist_files(&home));
    if added.is_empty() && removed.is_empty() {
        return None;
    }
    Some(format!(
        "The saved service list is out of date ({} new, {} removed). Run `guarded-update setup --rescan`.",
        added.len(),
        removed.len()
    ))
}

/// Scans launchd on this host. Returns an empty scan with a note where
/// scanning is not supported or Homebrew is missing.
fn scan_host(cfg: &Config, runner: &dyn Runner) -> (scan::Scan, String) {
    let prefix = brew_lines(runner, &cfg.providers.homebrew.command, &["--prefix"]).pop();
    let uid = brew_lines(runner, "id", &["-u"]).pop().unwrap_or_default();
    let host_scan = match (prefix, cfg!(target_os = "macos"), home()) {
        (Some(prefix), true, Ok(home)) => scan::scan(
            &scan::HostSource {
                runner,
                home: home.clone(),
            },
            &prefix,
            &home,
        ),
        (_, false, _) => scan::Scan {
            warnings: vec!["Service scanning supports macOS launchd only in this version.".into()],
            ..scan::Scan::default()
        },
        _ => scan::Scan {
            warnings: vec!["Homebrew was not found, so no services were scanned.".into()],
            ..scan::Scan::default()
        },
    };
    (host_scan, uid)
}

fn rescan(
    loaded: &Loaded,
    path: &Path,
    old: Option<&ServiceMap>,
    runner: &dyn Runner,
    out: &Output,
) -> u8 {
    out.stdout("Scanning this computer's services...");
    let (host_scan, uid) = scan_host(&loaded.config, runner);
    for warning in &host_scan.warnings {
        out.stdout(&format!("note: {warning}"));
    }
    let map = ServiceMap::from_scan(host_scan, &uid, &timefmt::rfc3339(timefmt::now_secs()));
    let running = map.services.iter().filter(|s| s.loaded).count();
    out.stdout(&format!(
        "Found {} services ({running} running).",
        map.services.len()
    ));
    let old_labels: BTreeMap<&str, &scan::Service> = old
        .map(|m| m.services.iter().map(|s| (s.label.as_str(), s)).collect())
        .unwrap_or_default();
    let new_labels: BTreeMap<&str, &scan::Service> =
        map.services.iter().map(|s| (s.label.as_str(), s)).collect();
    let packages = |s: &scan::Service| {
        s.links
            .iter()
            .map(|(p, via)| format!("{p} ({})", via.describe()))
            .collect::<Vec<_>>()
            .join(", ")
    };
    // A first scan has nothing to compare with.
    let new_labels = if old.is_some() {
        new_labels
    } else {
        BTreeMap::new()
    };
    for (label, s) in &new_labels {
        match old_labels.get(label) {
            None => out.stdout(&format!("  + {label}  {}", packages(s))),
            Some(o) if o.links != s.links => out.stdout(&format!("  ~ {label}  {}", packages(s))),
            Some(_) => {}
        }
    }
    for label in old_labels.keys().filter(|l| !new_labels.contains_key(*l)) {
        out.stdout(&format!("  - {label}"));
    }
    if let Err(e) = map.save(path) {
        out.stderr(&e);
        return EXIT_PARTIAL;
    }
    out.log(
        "info",
        "services_scanned",
        fields(&[
            ("path", json!(path.display().to_string())),
            ("services", json!(map.services.len())),
        ]),
    );
    out.stdout(&format!(
        "Saved {}. Your choices in the overrides file were not changed.",
        path.display()
    ));
    EXIT_OK
}

fn brew_lines(runner: &dyn Runner, command: &str, args: &[&str]) -> Vec<String> {
    match runner.run(command, args, crate::exec::HOMEBREW_ENV) {
        Ok(out) if out.success() => out
            .stdout
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect(),
        _ => Vec::new(),
    }
}

/// Setup's link to model servers, through the same HTTP layer as runs.
struct HttpProbe<'a> {
    http: &'a dyn Http,
    ai: &'a config::Ai,
}

/// A key file for one probe: the saved file, or a pasted key in a
/// private temporary file that is removed afterwards.
struct ProbeKey(Option<PathBuf>, bool);

impl ProbeKey {
    fn new(key: &setup::ApiKey) -> Result<Self, String> {
        Ok(match key {
            setup::ApiKey::None => Self(None, false),
            setup::ApiKey::File(file) => Self(Some(file.clone()), false),
            setup::ApiKey::New(text) => {
                let path = std::env::temp_dir()
                    .join(format!("guarded-update-setup-key-{}", std::process::id()));
                crate::state::write_private(&path, text)?;
                Self(Some(path), true)
            }
        })
    }
}

impl Drop for ProbeKey {
    fn drop(&mut self) {
        if let (Some(path), true) = (&self.0, self.1) {
            let _ = std::fs::remove_file(path);
        }
    }
}

impl setup::AiProbe for HttpProbe<'_> {
    fn models(&self, url: &str, key: &setup::ApiKey) -> Result<Vec<String>, String> {
        let key = ProbeKey::new(key)?;
        crate::ai::models(self.http, url, key.0.as_deref())
    }
    fn test(
        &self,
        url: &str,
        model: &str,
        key: &setup::ApiKey,
    ) -> Result<std::time::Duration, String> {
        let key = ProbeKey::new(key)?;
        let ai = config::Ai {
            api_key_file: key.0.clone(),
            ..self.ai.clone()
        };
        crate::ai::test_call(self.http, &ai, url, model)
    }
}

/// Model servers on this computer: Ollama and LM Studio on their usual
/// ports. Local requests only; nothing is installed or changed.
fn find_ai_servers(http: &dyn Http) -> Vec<setup::AiServer> {
    let mut servers = Vec::new();
    let quick = std::time::Duration::from_secs(3);
    if let Ok(tags) = http.model_json("http://127.0.0.1:11434/api/tags", None, None, quick) {
        // An Ollama with only embedding models cannot answer, so it is
        // not offered.
        let (chat, _) = crate::ai::ollama_chat_models(&tags);
        if !chat.is_empty() {
            servers.push(setup::AiServer {
                name: "Ollama".into(),
                url: "http://127.0.0.1:11434/v1".into(),
                models: chat,
            });
        }
    }
    if let Ok(models) = crate::ai::models(http, "http://127.0.0.1:1234/v1", None)
        && !models.is_empty()
    {
        servers.push(setup::AiServer {
            name: "LM Studio".into(),
            url: "http://127.0.0.1:1234/v1".into(),
            models,
        });
    }
    servers
}

#[allow(clippy::too_many_arguments)]
fn run_setup(
    loaded: &Loaded,
    base: &Path,
    overrides: &Path,
    map_path: &Path,
    state_root: &Path,
    runner: &dyn Runner,
    http: &dyn Http,
    out: &Output,
) -> u8 {
    let cfg = &loaded.config;
    let brew = cfg.providers.homebrew.command.as_str();
    // A passing line at a terminal; erased once the scan is done.
    let busy = "Looking at this computer…";
    // Keys typed during the scan wait for the first question instead of
    // echoing onto the screen.
    let hold = if out.interactive() {
        out.frame(busy);
        crate::tui::Terminal::open()
    } else {
        out.stdout(busy);
        None
    };
    let leaves = brew_lines(runner, brew, &["leaves", "--installed-on-request"]);
    let casks = brew_lines(runner, brew, &["list", "--cask", "-1"]);
    let mut versions = BTreeMap::new();
    for line in brew_lines(runner, brew, &["list", "--versions"])
        .into_iter()
        .chain(brew_lines(runner, brew, &["list", "--cask", "--versions"]))
    {
        let mut words = line.split_whitespace();
        if let (Some(name), Some(version)) = (words.next(), words.last()) {
            versions.insert(name.to_string(), version.to_string());
        }
    }
    // Tap formulae are listed by short name.
    for name in &leaves {
        if let Some(v) = versions.get(short_name(name)).cloned() {
            versions.insert(name.clone(), v);
        }
    }
    let mut updates = BTreeMap::new();
    if let Ok(o) = runner.run(
        brew,
        &["outdated", "--json=v2", "--greedy"],
        crate::exec::HOMEBREW_ENV,
    ) && let Ok((formulae, outdated_casks)) = homebrew::parse_outdated(&o.stdout)
    {
        for item in formulae.into_iter().chain(outdated_casks) {
            let installed = item.installed_versions.last().cloned().unwrap_or_default();
            let kind = match homebrew::change_kind(&installed, &item.current_version) {
                Change::Rebuild => " rebuild",
                Change::Version => "",
            };
            updates.insert(item.name, format!("{}{kind}", item.current_version));
        }
    }
    let mut sudo_casks = Default::default();
    if !casks.is_empty() {
        let mut args = vec!["info", "--cask", "--json=v2"];
        args.extend(casks.iter().map(String::as_str));
        if let Ok(o) = runner.run(brew, &args, crate::exec::HOMEBREW_ENV)
            && let Ok(set) = homebrew::pkg_casks(&o.stdout)
        {
            sudo_casks = set;
        }
    }
    let hermes_found = runner
        .run(&cfg.providers.hermes.command, &["--version"], &[])
        .is_ok_and(|o| o.success());
    let (host_scan, uid) = scan_host(cfg, runner);
    let existing = match std::fs::read_to_string(overrides) {
        Ok(text) => match text.parse::<toml::Table>() {
            Ok(table) => table,
            Err(e) => {
                out.stderr(&format!(
                    "{} is not valid TOML, so setup will not change it: {e}",
                    overrides.display()
                ));
                return EXIT_CONFIG;
            }
        },
        Err(_) => toml::Table::new(),
    };
    let map = ServiceMap::from_scan(host_scan, &uid, &timefmt::rfc3339(timefmt::now_secs()));
    let ai_servers = find_ai_servers(http);
    let probe = HttpProbe {
        http,
        ai: &cfg.screening.ai,
    };
    let inputs = setup::Inputs {
        ai_servers,
        ai_probe: &probe,
        key_path: overrides
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("secrets/ai-key"),
        new_key: std::cell::RefCell::new(None),
        schedule: cfg!(target_os = "macos"),
        map: &map,
        leaves,
        casks,
        versions,
        updates,
        sudo_casks,
        hermes_found,
        macos: cfg!(target_os = "macos"),
        existing,
    };
    drop(hold);
    if out.interactive() {
        out.frame("\r\x1b[K");
    }
    let mut prompter = setup::StdPrompter::new(out);
    let Some(table) = setup::wizard(&inputs, &mut prompter) else {
        out.stdout("Nothing was saved.");
        return EXIT_OK;
    };
    if let Err(e) = setup::write_overrides(overrides, &table) {
        out.stderr(&e);
        return EXIT_PARTIAL;
    }
    if let Err(e) = map.save(map_path) {
        out.stderr(&e);
        return EXIT_PARTIAL;
    }
    if let Some(key) = inputs.new_key.borrow().as_deref()
        && let Err(e) = crate::state::write_private(&inputs.key_path, key)
    {
        out.stderr(&e);
        return EXIT_PARTIAL;
    }
    out.log(
        "info",
        "setup_saved",
        fields(&[("path", json!(overrides.display().to_string()))]),
    );
    out.stdout(&format!(
        "Saved {} and {}.",
        setup::tilde(&overrides.display().to_string()),
        setup::tilde(&map_path.display().to_string())
    ));
    let when = lookup_schedule(&table);
    let code = match when {
        Some(when) if inputs.schedule => {
            match install_schedule(when, base, overrides, state_root, &map.uid, runner) {
                Ok(text) => {
                    out.stdout(&text);
                    EXIT_OK
                }
                Err(e) => {
                    out.stderr(&format!("The schedule was not set up: {e}"));
                    EXIT_PARTIAL
                }
            }
        }
        _ => EXIT_OK,
    };
    out.stdout("Run `guarded-update validate` to check the config and run the health checks.");
    code
}

fn lookup_schedule(table: &toml::Table) -> Option<schedule::When> {
    table
        .get("schedule")?
        .get("at")?
        .as_str()
        .and_then(schedule::parse)
}

/// Installs the launchd job that runs `run` with the same files setup
/// used. Returns what to tell the user.
fn install_schedule(
    when: schedule::When,
    base: &Path,
    overrides: &Path,
    state_root: &Path,
    uid: &str,
    runner: &dyn Runner,
) -> Result<String, String> {
    let home = home()?;
    let mut lines = Vec::new();
    let job = match when {
        schedule::When::Off => None,
        schedule::When::At(..) => {
            let current = std::env::current_exe()
                .map_err(|e| format!("cannot find this program's path: {e}"))?;
            let exe = if schedule::needs_copy(&current) {
                let copy = schedule::copy_binary(&current, &home)?;
                lines.push(format!(
                    "Copied this program to {}, so the schedule does not depend on the build folder.",
                    setup::tilde(&copy.display().to_string())
                ));
                copy
            } else {
                schedule::brew_link(&current)
                    .filter(|link| link.exists())
                    .unwrap_or(current)
            };
            let absolute = |p: &Path| std::path::absolute(p).unwrap_or_else(|_| p.to_path_buf());
            Some(schedule::Job {
                exe,
                args: vec![
                    "run".into(),
                    "--config".into(),
                    absolute(base).to_string_lossy().into_owned(),
                    "--overrides".into(),
                    absolute(overrides).to_string_lossy().into_owned(),
                    "--state-dir".into(),
                    absolute(state_root).to_string_lossy().into_owned(),
                ],
                log: absolute(state_root).join("logs/launchd.log"),
                path_env: schedule::path_env(&home),
            })
        }
    };
    let none = schedule::Job {
        exe: PathBuf::new(),
        args: vec![],
        log: PathBuf::new(),
        path_env: String::new(),
    };
    schedule::apply(when, job.as_ref().unwrap_or(&none), &home, uid, runner)?;
    lines.push(match when {
        schedule::When::Off => {
            "Not scheduled. Run `guarded-update run` when you want updates.".to_string()
        }
        when => format!(
            "Scheduled: updates run every night at {} ({}).",
            schedule::describe(when),
            setup::tilde(&schedule::plist_path(&home).display().to_string())
        ),
    });
    Ok(lines.join("\n"))
}

/// The config files the scanned `services` name in their arguments,
/// read from the plists as they are now (read-only `plutil`).
fn service_configs(
    services: &[String],
    map: Option<&ServiceMap>,
    runner: &dyn Runner,
) -> Vec<crate::service_config::ServiceConfig> {
    use scan::Source;
    let source = scan::HostSource {
        runner,
        home: PathBuf::new(),
    };
    let args: Vec<(String, Vec<String>)> = services
        .iter()
        .filter_map(|label| map?.services.iter().find(|s| &s.label == label))
        .filter_map(|s| {
            let args = source.arguments(&s.plist).ok()?;
            Some((s.label.clone(), args))
        })
        .collect();
    crate::service_config::gather(&args, &crate::service_config::read_file)
}

#[allow(clippy::too_many_arguments)]
fn run_pass(
    loaded: &Loaded,
    map: Option<&ServiceMap>,
    cli: &Cli,
    dir: &StateDir,
    runner: &dyn Runner,
    http: &dyn Http,
    out: &Output,
    sleep: &dyn Fn(std::time::Duration),
) -> u8 {
    let dry = cli.dry_run;
    let lock = match dir.lock() {
        Ok(lock) => lock,
        Err(e) => {
            out.stderr(&e);
            out.log("warn", "run_busy", Map::new());
            return EXIT_BUSY;
        }
    };
    let started = timefmt::now_secs();
    let run_id = timefmt::compact(started);
    out.log(
        "info",
        "run_start",
        fields(&[("run_id", json!(run_id)), ("dry_run", json!(dry))]),
    );
    let state = match dir.load() {
        Ok(state) => state,
        Err(e) => {
            out.stderr(&format!(
                "state is unreadable; nothing will be updated: {e}"
            ));
            out.log("error", "state_invalid", fields(&[("error", json!(e))]));
            return EXIT_CONFIG;
        }
    };
    let mut state = state;
    let det = detect_all(loaded, cli, runner, http, out);
    let now = u64::try_from(started).unwrap_or(0);
    record_first_seen(&mut state, &det, now);
    if let Err(e) = dir.save(&state) {
        out.stderr(&format!("cannot save state: {e}"));
        return EXIT_PARTIAL;
    }
    let mut plan = plan(&det, loaded, &state, map);
    apply_rules(
        &mut plan,
        &det,
        &loaded.config.screening,
        &state,
        now,
        &mut |u| fetch_notes(u, &loaded.config, runner, http),
        &mut |u, notes, services| {
            let ai = &loaded.config.screening.ai;
            let Some(url) = ai.url.as_deref() else {
                return Vec::new();
            };
            let configs = service_configs(services, map, runner);
            crate::ai::review(u, notes, crate::ai::PART_CHARS, &mut |text, part, parts| {
                // The one path to the model goes through the redaction layer.
                let body = out.redact_value(crate::ai::request(
                    &ai.model, u, text, services, &configs, part, parts,
                ));
                let record = crate::ai::Record::new(u, text, part, parts).with_config(&configs);
                crate::ai::ask(http, ai, url, &body, record)
            })
        },
    );
    for record in plan.groups.iter().flat_map(|g| &g.ai) {
        let mut event = fields(&[("run_id", json!(run_id))]);
        if let Ok(Value::Object(all)) = serde_json::to_value(record) {
            // The notes and raw answer are in the history file.
            event.extend(
                all.into_iter()
                    .filter(|(k, _)| k != "notes" && k != "answer"),
            );
        }
        out.log("info", "ai_checked", event);
    }
    let mut results: Vec<apply::GroupResult> = Vec::new();
    if !dry {
        let watched = watched(&loaded.config, map);
        let applier = apply::Applier {
            runner,
            brew: &loaded.config.providers.homebrew.command,
            greedy_casks: loaded.config.providers.homebrew.greedy_casks,
            sleep,
            poll: std::time::Duration::from_secs(2),
            checks: 15,
        };
        let mut todo: Vec<&PlannedGroup> = plan
            .groups
            .iter()
            .filter(|g| g.decision == Decision::Update)
            .collect();
        apply::order(&mut todo);
        for group in todo {
            out.stdout(&format!("Updating {}...", group.members.join(", ")));
            let result = applier.apply(group, &det, &watched);
            out.log(
                match result.outcome {
                    apply::Outcome::Failed(_) => "error",
                    _ => "info",
                },
                "group_applied",
                fields(&[
                    ("run_id", json!(run_id)),
                    ("members", json!(result.members)),
                    ("outcome", json!(result.outcome)),
                    ("restarted", json!(result.restarted)),
                ]),
            );
            if let apply::Outcome::Failed(why) = &result.outcome {
                for member in to_hold(&result) {
                    let Some(u) = det.updates.iter().find(|u| &u.name == member) else {
                        continue;
                    };
                    state.held.insert(
                        member.clone(),
                        crate::state::Held {
                            version: u.available.clone(),
                            reason: why.clone(),
                            since: timefmt::rfc3339(timefmt::now_secs()),
                        },
                    );
                }
            }
            results.push(result);
            // Save after every group, so a crash leaves a true record.
            if let Err(e) = dir.save(&state) {
                out.stderr(&format!("cannot save state: {e}"));
            }
        }
    }
    let record = out.redact_value(json!({
        "run_id": run_id,
        "started": timefmt::rfc3339(started),
        "finished": timefmt::rfc3339(timefmt::now_secs()),
        "dry_run": dry,
        "version": env!("CARGO_PKG_VERSION"),
        "detection": det,
        "plan": plan,
        "results": results,
    }));
    let history = match dir.write_history(&run_id, &record) {
        Ok(path) => path,
        Err(e) => {
            out.stderr(&format!("cannot write history: {e}"));
            return EXIT_PARTIAL;
        }
    };
    if let Err(e) = dir.prune_history(timefmt::now_secs()) {
        out.stderr(&format!("warning: {e}"));
    }
    drop(lock);
    if dry {
        out.stdout(&render_plan(&plan, &det, &run_id, &history));
    } else {
        out.stdout(&render_run(&results, &plan, &det, &run_id, &history));
    }
    let count = |d: Decision| plan.groups.iter().filter(|g| g.decision == d).count();
    out.log(
        if det.errors.is_empty() {
            "info"
        } else {
            "warn"
        },
        "run_done",
        fields(&[
            ("run_id", json!(run_id)),
            ("dry_run", json!(dry)),
            ("updates", json!(det.updates.len())),
            ("would_update_groups", json!(count(Decision::Update))),
            ("held_groups", json!(count(Decision::Hold))),
            ("manual", json!(plan.manual.len())),
            ("errors", json!(det.errors.len())),
            ("history", json!(history.display().to_string())),
        ]),
    );
    let failed = results
        .iter()
        .any(|r| matches!(r.outcome, apply::Outcome::Failed(_)));
    if det.errors.is_empty() && !failed {
        EXIT_OK
    } else {
        EXIT_PARTIAL
    }
}

/// The members a failed group holds: those left below the screened
/// version, or all of them when the versions were right but a later step
/// (a restart) failed.
pub fn to_hold(result: &apply::GroupResult) -> &[String] {
    if result.not_updated.is_empty() {
        &result.members
    } else {
        &result.not_updated
    }
}

/// Indents every line after the first, for multi-line report entries.
fn indent(text: &str, pad: &str) -> String {
    text.lines().collect::<Vec<_>>().join(&format!("\n{pad}"))
}

/// What a real run did, then what it left for later.
pub fn render_run(
    results: &[apply::GroupResult],
    plan: &Plan,
    det: &Detection,
    run_id: &str,
    history: &Path,
) -> String {
    let count =
        |f: &dyn Fn(&apply::Outcome) -> bool| results.iter().filter(|r| f(&r.outcome)).count();
    let updated = count(&|o| *o == apply::Outcome::Updated);
    let failed = count(&|o| matches!(o, apply::Outcome::Failed(_)));
    let mut lines = vec![format!(
        "guarded-update run {run_id}: {updated} updated, {failed} failed."
    )];
    let describe_result = |r: &apply::GroupResult| {
        let deps = plan
            .groups
            .iter()
            .find(|g| g.members == r.members)
            .map_or(&[][..], |g| &g.new_dependencies[..]);
        describe_group(&r.members, deps, det)
    };
    push_section(
        &mut lines,
        "Updated",
        results
            .iter()
            .filter(|r| r.outcome == apply::Outcome::Updated)
            .map(|r| {
                let mut text = describe_result(r);
                if !r.restarted.is_empty() {
                    text.push_str(&format!(
                        "\n      restarted and healthy: {}",
                        r.restarted.join(", ")
                    ));
                }
                if let Some(warning) = &r.warning {
                    text.push_str(&format!(
                        "\n      Homebrew reported an error:\n        {}",
                        indent(warning, "        ")
                    ));
                }
                text
            })
            .collect(),
    );
    push_section(
        &mut lines,
        "Failed (held; no rollback yet)",
        results
            .iter()
            .filter_map(|r| match &r.outcome {
                apply::Outcome::Failed(why) => Some(format!(
                    "{}\n      why: {}",
                    describe_result(r),
                    indent(why, "        ")
                )),
                _ => None,
            })
            .collect(),
    );
    push_section(
        &mut lines,
        "Skipped",
        results
            .iter()
            .filter_map(|r| match &r.outcome {
                apply::Outcome::Skipped(why) => {
                    Some(format!("{}\n      why: {why}", describe_result(r)))
                }
                _ => None,
            })
            .collect(),
    );
    push_section(
        &mut lines,
        "Held",
        plan.groups
            .iter()
            .filter(|g| g.decision == Decision::Hold)
            .map(|g| {
                format!(
                    "{}\n      why: {}",
                    describe_group(&g.members, &g.new_dependencies, det),
                    indent(&g.reason, "        ")
                )
            })
            .collect(),
    );
    push_section(
        &mut lines,
        "Needs manual action (sudo), never attempted",
        plan.manual.iter().map(describe).collect(),
    );
    lines.push(String::new());
    lines.push(format!("History: {}", history.display()));
    lines.join("\n")
}

pub fn execute(args: &[String], runner: &dyn Runner, http: HttpFactory, out: &mut Output) -> u8 {
    let cli = match cli::parse(args) {
        Ok(cli) => cli,
        Err(e) => {
            out.stderr(&format!("{e}\n\n{}", cli::usage()));
            return EXIT_USAGE;
        }
    };
    match &cli.command {
        Command::Help => {
            out.stdout(&cli::usage());
            return EXIT_OK;
        }
        Command::Version => {
            out.stdout(&format!("guarded-update {}", env!("CARGO_PKG_VERSION")));
            return EXIT_OK;
        }
        Command::NotYet(name) => {
            out.stdout(&format!(
                "`{name}` is not available in this version yet. Nothing was done."
            ));
            return EXIT_NOT_YET;
        }
        _ => {}
    }

    let (base, overrides) = match config_paths(&cli) {
        Ok(paths) => paths,
        Err(e) => {
            out.stderr(&e);
            return EXIT_CONFIG;
        }
    };
    let loaded = match config::load(&base, &overrides) {
        Ok(loaded) => loaded,
        Err(errors) => {
            out.stderr("The config is invalid, so nothing will be updated:");
            for e in &errors {
                out.stderr(&format!("  - {e}"));
            }
            return EXIT_CONFIG;
        }
    };
    let cfg = &loaded.config;
    let mut secret_files = cfg.secrets.files.clone();
    secret_files.extend(cfg.secrets.github_token_file.iter().cloned());
    secret_files.extend(cfg.screening.ai.api_key_file.iter().cloned());
    match Redactor::from_secret_files(&secret_files) {
        Ok(redactor) => out.set_redactor(redactor),
        Err(e) => {
            out.stderr(&format!(
                "The config is invalid, so nothing will be updated:\n  - {e}"
            ));
            return EXIT_CONFIG;
        }
    }
    let state_root = match state_dir(&cli, cfg) {
        Ok(dir) => dir,
        Err(e) => {
            out.stderr(&e);
            return EXIT_CONFIG;
        }
    };
    let log_path = cfg
        .paths
        .log_file
        .clone()
        .unwrap_or_else(|| state_root.join("logs/guarded-update.jsonl"));
    // Old logs and history are trimmed here; nobody has to set this up.
    for log in [&log_path, &state_root.join("logs/launchd.log")] {
        if let Err(e) = crate::state::rotate_log(log, crate::state::LOG_LIMIT) {
            out.stderr(&format!("warning: {e}"));
        }
    }
    if let Err(e) = out.open_log(&log_path) {
        out.stderr(&format!("warning: logging to the console only: {e}"));
    }
    let dir = StateDir::new(state_root);
    let map_path = services_path(&overrides);
    let map = match ServiceMap::load(&map_path) {
        Ok(map) => map,
        Err(e) => {
            out.stderr(&format!(
                "The config is invalid, so nothing will be updated:\n  - {e}"
            ));
            return EXIT_CONFIG;
        }
    };
    if matches!(
        cli.command,
        Command::Check | Command::Run | Command::Validate
    ) && let Some(notice) = map_notice(map.as_ref())
    {
        out.stdout(&notice);
    }
    runner.set_timeout(std::time::Duration::from_secs(cfg.timeouts.command_secs));
    let http = http(cfg);

    match &cli.command {
        Command::Validate => {
            out.stdout("The config is valid.");
            for (layer, path) in &loaded.files {
                out.stdout(&format!("  {layer} layer: {}", path.display()));
            }
            if loaded.files.is_empty() {
                out.stdout("  No config files found; defaults apply and nothing is set to auto.");
            }
            let results = run_health_checks(&watched(cfg, map.as_ref()), runner);
            if results.is_empty() {
                out.stdout("No health checks are configured.");
                return EXIT_OK;
            }
            let failed = results.iter().filter(|r| r.outcome.is_err()).count();
            out.stdout(&format!(
                "Health checks: {} passed, {failed} failed.",
                results.len() - failed
            ));
            for r in &results {
                match &r.outcome {
                    Ok(()) => out.stdout(&format!("  ok    {}", r.label)),
                    Err(e) => out.stdout(&format!("  FAIL  {}: {e}", r.label)),
                }
            }
            out.log(
                if failed == 0 { "info" } else { "warn" },
                "health_checked",
                fields(&[
                    ("passed", json!(results.len() - failed)),
                    ("failed", json!(failed)),
                ]),
            );
            if failed == 0 { EXIT_OK } else { EXIT_PARTIAL }
        }
        Command::Explain(item) => explain(&loaded, item.as_deref(), out),
        Command::Setup if cli.rescan => rescan(&loaded, &map_path, map.as_ref(), runner, out),
        Command::Setup => run_setup(
            &loaded,
            &base,
            &overrides,
            &map_path,
            dir.root(),
            runner,
            http.as_ref(),
            out,
        ),
        Command::Check => {
            let det = detect_all(&loaded, &cli, runner, http.as_ref(), out);
            out.stdout(&render_check(&det));
            if det.errors.is_empty() {
                EXIT_OK
            } else {
                EXIT_PARTIAL
            }
        }
        Command::Run => run_pass(
            &loaded,
            map.as_ref(),
            &cli,
            &dir,
            runner,
            http.as_ref(),
            out,
            &std::thread::sleep,
        ),
        Command::Help | Command::Version | Command::NotYet(_) => EXIT_OK,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::CmdOutput;
    use crate::model::Group;
    use std::cell::RefCell;
    use std::rc::Rc;

    const OUTDATED: &str = r#"{"formulae":[
      {"name":"ansible","installed_versions":["14.4.0_1"],"current_version":"14.5.0","pinned":false},
      {"name":"libngtcp2","installed_versions":["1.25.0"],"current_version":"1.25.0_1","pinned":false},
      {"name":"node@24","installed_versions":["24.21.0_1"],"current_version":"24.21.0_2","pinned":false}
    ],"casks":[
      {"name":"tailscale-app","installed_versions":["1.90.1"],"current_version":"1.90.2","pinned":false}
    ]}"#;
    const DRY_NGTCP: &str = "==> Would install 1 dependency:\nopenssl@4 4.0.3\n==> Would upgrade 1 requested outdated package\nlibngtcp2 1.25.0 -> 1.25.0_1\n==> Would upgrade 1 dependent\nnode@24 24.21.0_1 -> 24.21.0_2\n";
    const CASKS: &str = r#"{"casks":[{"token":"tailscale-app","artifacts":[{"pkg":["x.pkg"]}]}]}"#;

    struct FakeBrew {
        calls: RefCell<Vec<String>>,
        leak: Option<&'static str>,
        /// `brew list --versions` still shows the old version.
        stale: bool,
    }

    impl Runner for FakeBrew {
        fn run(
            &self,
            program: &str,
            args: &[&str],
            _: &[(&str, &str)],
        ) -> Result<CmdOutput, String> {
            let joined = format!("{program} {}", args.join(" "));
            self.calls.borrow_mut().push(joined.clone());
            if let ("brew update --quiet", Some(leak)) = (joined.as_str(), self.leak) {
                return Ok(CmdOutput {
                    code: Some(1),
                    stdout: String::new(),
                    stderr: leak.to_string(),
                });
            }
            if self.stale && joined == "brew list --versions ansible" {
                return Ok(CmdOutput {
                    code: Some(0),
                    stdout: "ansible 14.4.0_1\n".into(),
                    stderr: String::new(),
                });
            }
            let stdout = match joined.as_str() {
                "brew outdated --json=v2" => OUTDATED.to_string(),
                "brew upgrade --dry-run --formula ansible" => {
                    "==> Would upgrade 1 requested outdated package\nansible 14.4.0_1 -> 14.5.0\n".to_string()
                }
                "brew upgrade --dry-run --formula libngtcp2" => DRY_NGTCP.to_string(),
                "brew upgrade --dry-run --formula node@24" => {
                    "==> Would upgrade 1 requested outdated package\nnode@24 24.21.0_1 -> 24.21.0_2\n".to_string()
                }
                "brew info --cask --json=v2 tailscale-app" => CASKS.to_string(),
                "brew upgrade --formula ansible" => String::new(),
                "brew list --versions ansible" => "ansible 14.4.0_1 14.5.0\n".to_string(),
                other => return Err(format!("unexpected call: {other}")),
            };
            Ok(CmdOutput {
                code: Some(0),
                stdout,
                stderr: String::new(),
            })
        }
    }

    struct NoHttp;
    impl Http for NoHttp {
        fn get_json(&self, url: &str, _: bool) -> Result<Value, String> {
            Err(format!("no network in tests: {url}"))
        }
    }

    fn no_http(_: &Config) -> Box<dyn Http> {
        Box::new(NoHttp)
    }

    struct Sandbox {
        dir: PathBuf,
    }

    impl Sandbox {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("gu-app-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Self { dir }
        }

        fn write(&self, name: &str, text: &str) -> PathBuf {
            let path = self.dir.join(name);
            std::fs::write(&path, text).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            }
            path
        }

        fn args(&self, command: &[&str]) -> Vec<String> {
            let mut args: Vec<String> = command.iter().map(|s| (*s).to_string()).collect();
            for (flag, file) in [("--config", "base.toml"), ("--overrides", "overrides.toml")] {
                args.push(flag.into());
                args.push(self.dir.join(file).display().to_string());
            }
            args.push("--state-dir".into());
            args.push(self.dir.join("state").display().to_string());
            args
        }

        fn loaded(&self) -> Loaded {
            config::load(
                &self.dir.join("base.toml"),
                &self.dir.join("overrides.toml"),
            )
            .unwrap()
        }
    }

    fn run(sb: &Sandbox, command: &[&str], brew: &FakeBrew) -> (u8, String, String) {
        let text = |b: &Rc<RefCell<Vec<u8>>>| String::from_utf8(b.borrow().clone()).unwrap();
        let mut attempt = 0;
        loop {
            let (mut out, buf, log) = Output::for_test(Redactor::patterns_only());
            let code = execute(&sb.args(command), brew, &no_http, &mut out);
            // Other tests fork processes concurrently, and a forked child
            // holds a copy of the lock descriptor until it execs, so a
            // run can briefly find the lock taken. Try again.
            attempt += 1;
            if code != EXIT_BUSY || attempt == 25 {
                return (code, text(&buf), text(&log));
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }

    fn brew() -> FakeBrew {
        FakeBrew {
            calls: RefCell::new(Vec::new()),
            leak: None,
            stale: false,
        }
    }

    fn detection() -> Detection {
        let fake = brew();
        homebrew::Homebrew {
            runner: &fake,
            command: "brew",
            greedy_casks: false,
        }
        .detect()
    }

    #[test]
    fn groups_update_only_when_every_member_is_auto() {
        let sb = Sandbox::new("plan");
        sb.write(
            "base.toml",
            "schema_version = 1\n[items.libngtcp2]\npolicy = \"auto\"\n[items.ansible]\npolicy = \"auto\"\n",
        );
        let plan = plan(&detection(), &sb.loaded(), &State::default(), None);
        let find = |m: &str| {
            plan.groups
                .iter()
                .find(|g| g.members.contains(&m.to_string()))
                .unwrap()
        };
        assert_eq!(find("ansible").decision, Decision::Update);
        let ngtcp = find("libngtcp2");
        assert_eq!(ngtcp.decision, Decision::Hold);
        assert!(ngtcp.reason.contains("node@24"), "{}", ngtcp.reason);
        assert_eq!(plan.manual.len(), 1);
        assert_eq!(plan.manual[0].name, "tailscale-app");
    }

    #[test]
    fn held_items_and_approvals_from_state_apply() {
        let sb = Sandbox::new("held");
        sb.write(
            "base.toml",
            "schema_version = 1\n[defaults]\npolicy = \"auto\"\n",
        );
        let mut state = State::default();
        state.held.insert(
            "ansible".into(),
            crate::state::Held {
                version: "14.5.0".into(),
                reason: "screen said breaking".into(),
                since: "2026-10-08T00:00:00Z".into(),
            },
        );
        let plan = plan(&detection(), &sb.loaded(), &state, None);
        let ansible = plan
            .groups
            .iter()
            .find(|g| g.members == ["ansible"])
            .unwrap();
        assert_eq!(ansible.decision, Decision::Hold);
        assert!(ansible.reason.contains("screen said breaking"));
    }

    #[test]
    fn disabled_config_is_report_only() {
        let sb = Sandbox::new("disabled");
        sb.write(
            "base.toml",
            "schema_version = 1\nenabled = false\n[defaults]\npolicy = \"auto\"\n",
        );
        let plan = plan(&detection(), &sb.loaded(), &State::default(), None);
        assert!(plan.report_only);
        assert!(plan.groups.iter().all(|g| g.decision == Decision::Hold));
    }

    #[test]
    fn groups_touching_a_root_service_are_held_even_when_auto() {
        let sb = Sandbox::new("root");
        sb.write(
            "base.toml",
            "schema_version = 1\n[defaults]\npolicy = \"auto\"\n[services.\"com.ollama\"]\npackages = [\"libngtcp2\"]\nrequires_root = true\n[services.\"com.web\"]\npackages = [\"node@24\"]\n",
        );
        let plan = plan(&detection(), &sb.loaded(), &State::default(), None);
        let g = plan
            .groups
            .iter()
            .find(|g| g.members.contains(&"libngtcp2".to_string()))
            .unwrap();
        assert_eq!(g.decision, Decision::Hold);
        assert!(
            g.reason.contains("restart needs root: com.ollama"),
            "{}",
            g.reason
        );
        assert_eq!(
            g.services,
            vec!["com.ollama".to_string(), "com.web".to_string()]
        );
        let ansible = plan
            .groups
            .iter()
            .find(|g| g.members == ["ansible"])
            .unwrap();
        assert_eq!(ansible.decision, Decision::Update);
    }

    #[test]
    fn tap_formulas_match_services_by_short_name() {
        let mut config = Config::default();
        config.services.insert(
            "com.tf".into(),
            crate::config::ServiceConfig {
                packages: vec!["terraform".into()],
                ..Default::default()
            },
        );
        let (services, root) = affected_services(
            &["hashicorp/tap/terraform".to_string()],
            &watched(&config, None),
        );
        assert_eq!(services, vec!["com.tf".to_string()]);
        assert!(root.is_empty());
    }

    #[test]
    fn health_checks_pass_on_exit_zero_and_expected_text() {
        let mut config = Config::default();
        let svc = |health: &[&str], expect: Option<&str>| crate::config::ServiceConfig {
            health: health.iter().map(|s| (*s).to_string()).collect(),
            health_expect: expect.map(str::to_string),
            ..Default::default()
        };
        config
            .services
            .insert("ok".into(), svc(&["sh", "-c", "echo PID 5"], Some("PID")));
        config.services.insert(
            "missing-text".into(),
            svc(&["sh", "-c", "echo idle"], Some("PID")),
        );
        config
            .services
            .insert("exit".into(), svc(&["sh", "-c", "exit 3"], None));
        config.services.insert("none".into(), svc(&[], None));
        let runner = crate::exec::SystemRunner::new(std::time::Duration::from_secs(5));
        let results = run_health_checks(&watched(&config, None), &runner);
        let get = |l: &str| {
            results
                .iter()
                .find(|r| r.label == l)
                .map(|r| r.outcome.clone())
        };
        assert_eq!(get("ok"), Some(Ok(())));
        assert!(get("missing-text").unwrap().unwrap_err().contains("PID"));
        assert!(get("exit").unwrap().unwrap_err().contains("3"));
        assert_eq!(get("none"), None);
    }

    fn mapped(label: &str, root: bool, loaded: bool, packages: &[&str]) -> scan::Service {
        scan::Service {
            label: label.into(),
            plist: format!("/LA/{label}.plist").into(),
            root,
            keep_alive: true,
            loaded,
            program: "/x".into(),
            links: packages
                .iter()
                .map(|p| ((*p).to_string(), scan::Via::Program))
                .collect(),
            venv_python: None,
        }
    }

    fn service_map() -> ServiceMap {
        ServiceMap {
            scanned: "2026-10-10T00:00:00Z".into(),
            uid: "501".into(),
            skipped: vec![],
            services: vec![
                mapped("com.web", false, true, &["node@24"]),
                mapped("com.root", true, true, &["libngtcp2"]),
                mapped("com.off", false, false, &["ansible"]),
                mapped("com.plain", false, true, &[]),
            ],
        }
    }

    #[test]
    fn the_saved_service_list_drives_restarts_and_root_holds() {
        let sb = Sandbox::new("map");
        sb.write(
            "base.toml",
            "schema_version = 1\n[defaults]\npolicy = \"auto\"\n",
        );
        let map = service_map();
        let plan = plan(&detection(), &sb.loaded(), &State::default(), Some(&map));
        let group = |m: &str| {
            plan.groups
                .iter()
                .find(|g| g.members.contains(&m.to_string()))
                .unwrap()
        };
        let ngtcp = group("libngtcp2");
        assert_eq!(ngtcp.services, ["com.root", "com.web"]);
        assert_eq!(ngtcp.decision, Decision::Hold);
        assert!(
            ngtcp.reason.contains("restart needs root: com.root"),
            "{}",
            ngtcp.reason
        );
        let ansible = group("ansible");
        assert!(
            ansible.services.is_empty(),
            "services that are not loaded are skipped"
        );
        assert_eq!(ansible.decision, Decision::Update);
    }

    #[test]
    fn a_config_entry_overrides_the_scan_for_the_same_label() {
        let mut config = Config::default();
        config.services.insert(
            "com.web".into(),
            crate::config::ServiceConfig {
                packages: vec!["ansible".into()],
                health: vec!["true".into()],
                ..Default::default()
            },
        );
        let w = watched(&config, Some(&service_map()));
        let web = &w["com.web"];
        assert_eq!(web.packages, ["ansible"]);
        assert_eq!(web.health, ["true"]);
        assert_eq!(
            web.health_expect, None,
            "a custom check replaces the default expectation"
        );
        assert_eq!(
            web.restart,
            ["launchctl", "kickstart", "-k", "gui/501/com.web"]
        );
        assert!(!w.contains_key("com.off") && !w.contains_key("com.plain"));
        assert!(w["com.root"].root && w["com.root"].health.is_empty());
    }

    struct Launchctl;
    impl Runner for Launchctl {
        fn run(
            &self,
            program: &str,
            args: &[&str],
            _: &[(&str, &str)],
        ) -> Result<CmdOutput, String> {
            assert_eq!(program, "launchctl");
            Ok(CmdOutput {
                code: Some(0),
                stdout: if args[1] == "com.web" {
                    "{\n\t\"PID\" = 42;\n}"
                } else {
                    "{}"
                }
                .into(),
                stderr: String::new(),
            })
        }
    }

    #[test]
    fn default_health_checks_need_a_running_process() {
        let mut map = service_map();
        map.services
            .push(mapped("com.stopped", false, true, &["node"]));
        let results = run_health_checks(&watched(&Config::default(), Some(&map)), &Launchctl);
        let get = |l: &str| {
            results
                .iter()
                .find(|r| r.label == l)
                .map(|r| r.outcome.clone())
        };
        assert_eq!(get("com.web"), Some(Ok(())));
        assert!(get("com.stopped").unwrap().is_err());
        assert_eq!(get("com.root"), None, "root daemons are not checked");
    }

    #[test]
    fn rescan_rewrites_only_the_service_list() {
        let sb = Sandbox::new("rescan");
        sb.write("base.toml", "schema_version = 1\n");
        let before = "schema_version = 1\n[defaults]\npolicy = \"alert\"\n";
        sb.write("overrides.toml", before);
        let (code, stdout, _) = run(&sb, &["setup", "--rescan"], &brew());
        assert_eq!(code, EXIT_OK, "{stdout}");
        assert!(stdout.contains("services.toml"), "{stdout}");
        assert_eq!(
            std::fs::read_to_string(sb.dir.join("overrides.toml")).unwrap(),
            before
        );
        assert!(
            ServiceMap::load(&sb.dir.join("services.toml"))
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn a_missing_service_list_is_reported_not_fatal() {
        let sb = Sandbox::new("nomap");
        sb.write("base.toml", "schema_version = 1\n");
        let (code, stdout, _) = run(&sb, &["validate"], &brew());
        assert_eq!(code, EXIT_OK);
        if cfg!(target_os = "macos") {
            assert!(stdout.contains("guarded-update setup"), "{stdout}");
        }
        sb.write("services.toml", "nonsense = [");
        let (code, text, _) = run(&sb, &["validate"], &brew());
        assert_eq!(code, EXIT_CONFIG);
        assert!(text.contains("--rescan"), "{text}");
    }

    #[test]
    fn hermes_group_is_planned_last() {
        let sb = Sandbox::new("order");
        sb.write("base.toml", "schema_version = 1\n");
        let mut det = detection();
        det.groups.insert(
            0,
            Group {
                source: Source::Hermes,
                members: vec!["hermes".into()],
                new_dependencies: vec![],
            },
        );
        let plan = plan(&det, &sb.loaded(), &State::default(), None);
        assert_eq!(plan.groups.last().unwrap().source, Source::Hermes);
    }

    #[test]
    fn dry_run_records_first_sight_and_changes_no_packages() {
        let sb = Sandbox::new("dryrun");
        sb.write(
            "base.toml",
            "schema_version = 1\n[items.ansible]\npolicy = \"auto\"\n",
        );
        // Leftovers from long ago: eleven old runs and a big launchd log.
        std::fs::create_dir_all(sb.dir.join("state/history")).unwrap();
        std::fs::create_dir_all(sb.dir.join("state/logs")).unwrap();
        for n in 0..11 {
            sb.write(&format!("state/history/20200101T0000{n:02}Z.json"), "{}");
        }
        sb.write(
            "state/logs/launchd.log",
            &"x".repeat(crate::state::LOG_LIMIT as usize + 1),
        );
        let fake = brew();
        let (code, stdout, log) = run(&sb, &["run", "--dry-run", "--no-refresh"], &fake);
        assert_eq!(code, EXIT_OK, "{stdout}");
        assert!(stdout.contains("nothing was changed"), "{stdout}");
        assert!(sb.dir.join("state/logs/launchd.log.1").exists());
        let kept = StateDir::new(sb.dir.join("state")).list_history().unwrap();
        assert_eq!(
            kept.len(),
            crate::state::KEEP_RUNS,
            "this run and the newest old ones"
        );
        for path in kept {
            if path
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("2020")
            {
                std::fs::remove_file(path).unwrap();
            }
        }
        assert!(
            stdout.contains("ansible: waiting 2 more days after 14.5.0 first appeared"),
            "{stdout}"
        );
        assert!(stdout.contains("tailscale-app"), "{stdout}");
        let history = std::fs::read_dir(sb.dir.join("state/history"))
            .unwrap()
            .count();
        assert_eq!(history, 1);
        let dir = StateDir::new(sb.dir.join("state"));
        let state = dir.load().unwrap();
        assert_eq!(state.first_seen["ansible"].version, "14.5.0");
        assert_eq!(state.first_seen.len(), 4, "every waiting update");
        for call in fake.calls.borrow().iter() {
            assert!(
                call.starts_with("brew outdated")
                    || call.starts_with("brew info")
                    || call.starts_with("brew upgrade --dry-run"),
                "a dry run must not change anything: {call}"
            );
        }
        assert!(log.contains("\"event\":\"run_done\""), "{log}");
        // The lock was released. Other tests fork processes concurrently,
        // and a forked child holds a copy of the lock descriptor until it
        // execs, so allow a short retry.
        let released = (0..50).any(|_| {
            dir.lock().is_ok() || {
                std::thread::sleep(std::time::Duration::from_millis(20));
                false
            }
        });
        assert!(released);
    }

    #[test]
    fn first_sight_is_kept_until_the_version_changes() {
        let mut state = State::default();
        let det = detection();
        record_first_seen(&mut state, &det, 100);
        record_first_seen(&mut state, &det, 900);
        assert_eq!(state.first_seen["ansible"].at, 100);
        state.first_seen.get_mut("ansible").unwrap().version = "14.4.9".into();
        state.first_seen.insert(
            "gone".into(),
            crate::state::Seen {
                version: "1".into(),
                at: 1,
            },
        );
        record_first_seen(&mut state, &det, 900);
        assert_eq!(
            state.first_seen["ansible"].at, 900,
            "a newer version restarts the wait"
        );
        assert!(!state.first_seen.contains_key("gone"));
    }

    #[test]
    fn safety_checks_hold_groups_that_would_update() {
        let sb = Sandbox::new("rules");
        sb.write(
            "base.toml",
            "schema_version = 1\n[defaults]\npolicy = \"auto\"\n",
        );
        let det = detection();
        let loaded = sb.loaded();
        let mut state = State::default();
        let long_ago = 0;
        record_first_seen(&mut state, &det, long_ago);
        let now = 30 * 24 * 3600;
        let mut plan = plan(&det, &loaded, &state, None);
        let mut asked = Vec::new();
        apply_rules(
            &mut plan,
            &det,
            &loaded.config.screening,
            &state,
            now,
            &mut |u| {
                asked.push(u.name.clone());
                if u.name == "ansible" {
                    Notes::Found("v14.5.0\n- Removed support for old inventories".into())
                } else {
                    Notes::Missing("no GitHub project found".into())
                }
            },
            &mut |_, _, _| Vec::new(),
        );
        let group = |m: &str| {
            plan.groups
                .iter()
                .find(|g| g.members.contains(&m.to_string()))
                .unwrap()
        };
        let ansible = group("ansible");
        assert_eq!(ansible.decision, Decision::Hold);
        assert!(
            ansible
                .reason
                .contains("ansible: release notes say \"removed\": - Removed support"),
            "{}",
            ansible.reason
        );
        let ngtcp = group("libngtcp2");
        assert_eq!(ngtcp.decision, Decision::Update, "{}", ngtcp.reason);
        assert!(
            ngtcp.checks.is_empty(),
            "rebuilds have no new notes: {:?}",
            ngtcp.checks
        );
        assert!(!asked.contains(&"libngtcp2".to_string()));
        assert!(
            !asked.contains(&"tailscale-app".to_string()),
            "manual items are not screened"
        );

        // Approving the exact version releases it from the rules.
        state.approvals.insert("ansible".into(), "14.5.0".into());
        let mut plan = super::plan(&det, &loaded, &state, None);
        let mut breaking = |_: &Update| Notes::Found("breaking".into());
        apply_rules(
            &mut plan,
            &det,
            &loaded.config.screening,
            &state,
            now,
            &mut breaking,
            &mut |_, _, _| Vec::new(),
        );
        let ansible = plan
            .groups
            .iter()
            .find(|g| g.members == ["ansible"])
            .unwrap();
        assert_eq!(ansible.decision, Decision::Update, "{}", ansible.reason);
    }

    #[test]
    fn the_ai_can_hold_and_its_passes_are_noted() {
        let sb = Sandbox::new("ai");
        sb.write(
            "base.toml",
            "schema_version = 1\n[defaults]\npolicy = \"auto\"\n[screening.ai]\nurl = \"http://127.0.0.1:9/v1\"\n",
        );
        let mut det = detection();
        det.updates
            .iter_mut()
            .find(|u| u.name == "ansible")
            .unwrap()
            .available = "15.0.0".into();
        let loaded = sb.loaded();
        let mut state = State::default();
        record_first_seen(&mut state, &det, 0);
        let mut plan = plan(&det, &loaded, &state, None);
        let mut notes = |_: &Update| Notes::Found("Breaking: removed support for Windows".into());
        let long = format!("drops Python 3.9 {}", "and more ".repeat(40));
        let mut ai = |u: &Update, notes: &str, _: &[String]| {
            let mut r = crate::ai::Record::new(u, notes, 1, 1);
            r.answer = "{\"verdict\": ...}".into();
            if u.name == "ansible" {
                r.verdict = crate::ai::Outcome::Hold;
                r.reason = long.clone();
            } else {
                r.verdict = crate::ai::Outcome::Ok;
                r.reason = "only fixes".into();
            }
            vec![r]
        };
        apply_rules(
            &mut plan,
            &det,
            &loaded.config.screening,
            &state,
            30 * 24 * 3600,
            &mut notes,
            &mut ai,
        );
        let ansible = plan
            .groups
            .iter()
            .find(|g| g.members == ["ansible"])
            .unwrap();
        assert_eq!(ansible.decision, Decision::Hold);
        assert!(
            ansible
                .reason
                .contains(&format!("ansible: AI check: {long}")),
            "never cut: {}",
            ansible.reason
        );
        assert_eq!(ansible.ai.len(), 1, "the whole answer is kept");
        // An ok is kept too, with its reason.
        let mut plan = super::plan(&det, &loaded, &state, None);
        apply_rules(
            &mut plan,
            &det,
            &loaded.config.screening,
            &state,
            30 * 24 * 3600,
            &mut notes,
            &mut |u: &Update, notes: &str, _: &[String]| {
                let mut r = crate::ai::Record::new(u, notes, 1, 1);
                r.verdict = crate::ai::Outcome::Ok;
                r.reason = "only fixes".into();
                r.answer = "{}".into();
                vec![r]
            },
        );
        let passed = plan
            .groups
            .iter()
            .find(|g| g.members == ["ansible"])
            .unwrap();
        assert_eq!(passed.decision, Decision::Update);
        assert_eq!(passed.checks, ["ansible: AI check ok: only fixes"]);
        let saved = serde_json::to_string(&plan).unwrap();
        assert!(saved.contains("\"answer\"") && saved.contains("\"verdict\":\"ok\""));
        let ngtcp = plan
            .groups
            .iter()
            .find(|g| g.members.contains(&"libngtcp2".to_string()))
            .unwrap();
        assert_eq!(
            ngtcp.decision,
            Decision::Update,
            "rebuilds are not sent to the AI"
        );
        assert!(ngtcp.checks.is_empty());
        let mut empty = super::plan(&det, &loaded, &state, None);
        apply_rules(
            &mut empty,
            &det,
            &loaded.config.screening,
            &state,
            30 * 24 * 3600,
            &mut notes,
            &mut |_, _, _| Vec::new(),
        );
        let held = empty
            .groups
            .iter()
            .find(|g| g.members == ["ansible"])
            .unwrap();
        assert_eq!(held.decision, Decision::Hold);
        assert!(held.reason.contains("no review records"));
    }

    #[test]
    fn refresh_runs_brew_update_unless_disabled() {
        let sb = Sandbox::new("refresh");
        sb.write("base.toml", "schema_version = 1\n");
        let fake = brew();
        let (code, _, _) = run(&sb, &["check"], &fake);
        // `brew update` is not answered by the fake, so it is reported.
        assert_eq!(code, EXIT_PARTIAL);
        assert_eq!(fake.calls.borrow()[0], "brew update --quiet");
    }

    #[test]
    fn a_real_run_updates_what_passed_and_records_it() {
        let sb = Sandbox::new("realrun");
        sb.write(
            "base.toml",
            "schema_version = 1\n[items.ansible]\npolicy = \"auto\"\n[screening]\nwait_days = 0\n",
        );
        let fake = brew();
        let (code, stdout, log) = run(&sb, &["run", "--no-refresh"], &fake);
        assert_eq!(code, EXIT_OK, "{stdout}");
        assert!(stdout.contains("1 updated, 0 failed"), "{stdout}");
        assert!(
            stdout.contains("Updated (1):\n  - ansible 14.4.0_1 -> 14.5.0"),
            "{stdout}"
        );
        assert!(
            stdout.contains("not set to auto"),
            "held groups are listed: {stdout}"
        );
        let upgrades: Vec<String> = fake
            .calls
            .borrow()
            .iter()
            .filter(|c| {
                c.starts_with("brew upgrade --formula") || c.starts_with("brew upgrade --cask")
            })
            .cloned()
            .collect();
        assert_eq!(
            upgrades,
            ["brew upgrade --formula ansible"],
            "only what passed"
        );
        assert!(log.contains("\"event\":\"group_applied\""), "{log}");
        let history = std::fs::read_dir(sb.dir.join("state/history"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let record: Value =
            serde_json::from_str(&std::fs::read_to_string(history).unwrap()).unwrap();
        assert_eq!(record["dry_run"], false);
        assert_eq!(record["results"][0]["outcome"]["result"], "updated");
    }

    #[test]
    fn a_failed_update_is_held_in_state() {
        let sb = Sandbox::new("failrun");
        sb.write(
            "base.toml",
            "schema_version = 1\n[items.ansible]\npolicy = \"auto\"\n[screening]\nwait_days = 0\n[providers.homebrew]\ncommand = \"brew\"\n",
        );
        let fake = FakeBrew {
            calls: RefCell::new(Vec::new()),
            leak: None,
            stale: true,
        };
        let (code, stdout, _) = run(&sb, &["run", "--no-refresh"], &fake);
        assert_eq!(code, EXIT_PARTIAL, "{stdout}");
        assert!(stdout.contains("0 updated, 1 failed"), "{stdout}");
        let state = StateDir::new(sb.dir.join("state")).load().unwrap();
        assert_eq!(state.held["ansible"].version, "14.5.0");
        assert!(
            state.held["ansible"]
                .reason
                .contains("ansible is not at 14.5.0")
        );
        // The next run holds it instead of trying again.
        let fake = brew();
        let (_, stdout, _) = run(&sb, &["run", "--no-refresh"], &fake);
        assert!(stdout.contains("0 updated, 0 failed"), "{stdout}");
        assert!(stdout.contains("ansible held at 14.5.0"), "{stdout}");
    }

    #[test]
    fn the_run_report_shows_homebrew_errors_and_holds_only_what_stayed_behind() {
        let det = Detection {
            updates: vec![
                Update {
                    source: Source::HomebrewFormula,
                    name: "certifi".into(),
                    installed: "1".into(),
                    available: "2".into(),
                    change: Change::Version,
                    action: Action::Update,
                    note: None,
                },
                Update {
                    source: Source::HomebrewFormula,
                    name: "cffi".into(),
                    installed: "1".into(),
                    available: "2".into(),
                    change: Change::Version,
                    action: Action::Update,
                    note: None,
                },
            ],
            ..Detection::default()
        };
        let linked = apply::GroupResult {
            members: vec!["certifi".into()],
            outcome: apply::Outcome::Updated,
            restarted: vec![],
            not_updated: vec![],
            warning: Some("Error: link failed\n  brew link --overwrite certifi".into()),
        };
        let behind = apply::GroupResult {
            members: vec!["certifi".into(), "cffi".into()],
            outcome: apply::Outcome::Failed("cffi is not at 2 after the update".into()),
            restarted: vec![],
            not_updated: vec!["cffi".into()],
            warning: None,
        };
        let text = render_run(
            &[linked, behind.clone()],
            &Plan::default(),
            &det,
            "r1",
            Path::new("h.json"),
        );
        assert!(text.contains("1 updated, 1 failed"), "{text}");
        assert!(
            text.contains("      Homebrew reported an error:\n        Error: link failed\n          brew link --overwrite certifi"),
            "{text}"
        );
        assert_eq!(to_hold(&behind), ["cffi"]);
        let restart = apply::GroupResult {
            not_updated: vec![],
            ..behind
        };
        assert_eq!(to_hold(&restart), ["certifi", "cffi"]);
    }

    #[test]
    fn later_commands_report_not_available() {
        let sb = Sandbox::new("notyet");
        let fake = brew();
        let (code, stdout, _) = run(&sb, &["approve", "jq"], &fake);
        assert_eq!(code, EXIT_NOT_YET);
        assert!(stdout.contains("not available in this version"), "{stdout}");
        assert!(fake.calls.borrow().is_empty());
    }

    #[test]
    fn invalid_config_updates_nothing_and_names_the_problem() {
        let sb = Sandbox::new("invalid");
        sb.write(
            "base.toml",
            "schema_version = 1\n[defaults]\npolicy = \"yolo\"\n",
        );
        let fake = brew();
        let (code, stdout, log) = run(&sb, &["run", "--dry-run"], &fake);
        assert_eq!(code, EXIT_CONFIG);
        assert!(stdout.contains("yolo"), "{stdout}");
        assert!(fake.calls.borrow().is_empty());
        assert!(log.is_empty() || log.contains("config_invalid"));
    }

    #[test]
    fn second_copy_exits_busy() {
        let sb = Sandbox::new("busy");
        sb.write("base.toml", "schema_version = 1\n");
        let _held = StateDir::new(sb.dir.join("state")).lock().unwrap();
        let (code, stdout, _) = run(&sb, &["run", "--dry-run", "--no-refresh"], &brew());
        assert_eq!(code, EXIT_BUSY, "{stdout}");
        assert!(stdout.contains("another guarded-update"), "{stdout}");
    }

    #[test]
    fn secret_values_from_referenced_files_never_reach_output_or_history() {
        let sb = Sandbox::new("secrets");
        let secret_file = sb.write("slack.token", "fake-secret-value-42\n");
        sb.write(
            "base.toml",
            &format!(
                "schema_version = 1\n[secrets]\nfiles = [\"{}\"]\n",
                secret_file.display()
            ),
        );
        let fake = FakeBrew {
            calls: RefCell::new(Vec::new()),
            leak: Some("warning: fake-secret-value-42"),
            stale: false,
        };
        // Make the leak visible: brew update fails and its stderr is reported.
        let (_, stdout, log) = run(&sb, &["run", "--dry-run"], &fake);
        assert!(stdout.contains("[REDACTED]"), "{stdout}");
        for text in [&stdout, &log] {
            assert!(!text.contains("fake-secret-value-42"));
        }
        for entry in std::fs::read_dir(sb.dir.join("state/history")).unwrap() {
            let text = std::fs::read_to_string(entry.unwrap().path()).unwrap();
            assert!(!text.contains("fake-secret-value-42"));
        }
    }

    #[test]
    fn explain_shows_the_layer_behind_an_items_policy() {
        let sb = Sandbox::new("explain");
        sb.write(
            "base.toml",
            "schema_version = 1\n[items.jq]\npolicy = \"ignore\"\n",
        );
        sb.write(
            "overrides.toml",
            "schema_version = 1\n[items.jq]\npolicy = \"auto\"\n",
        );
        let (code, stdout, _) = run(&sb, &["explain", "jq"], &brew());
        assert_eq!(code, EXIT_OK);
        assert!(stdout.contains("policy = auto"), "{stdout}");
        assert!(stdout.contains("overrides"), "{stdout}");
        let (_, all, _) = run(&sb, &["explain"], &brew());
        assert!(all.contains("items.jq.policy"), "{all}");
        assert!(
            all.contains("providers.homebrew.refresh = true (default)"),
            "{all}"
        );
    }

    #[test]
    fn validate_reports_ok_with_layers() {
        let sb = Sandbox::new("validate");
        sb.write("base.toml", "schema_version = 1\n");
        let (code, stdout, _) = run(&sb, &["validate"], &brew());
        assert_eq!(code, EXIT_OK);
        assert!(stdout.contains("config is valid"), "{stdout}");
        assert!(stdout.contains("base.toml"), "{stdout}");
    }

    #[test]
    fn updates_without_an_installed_version_show_only_the_new_one() {
        let u = Update {
            source: Source::Macos,
            name: "Safari".into(),
            installed: "-".into(),
            available: "27.0".into(),
            change: Change::Version,
            action: Action::AlertOnly,
            note: None,
        };
        assert_eq!(describe(&u), "Safari 27.0");
    }

    #[test]
    fn validate_runs_health_checks_and_fails_on_a_failure() {
        let sb = Sandbox::new("health");
        sb.write(
            "base.toml",
            "schema_version = 1\n[services.good]\nhealth = [\"true\"]\n[services.bad]\nhealth = [\"false\"]\n",
        );
        let (mut out, buf, _) = Output::for_test(Redactor::patterns_only());
        let runner = crate::exec::SystemRunner::new(std::time::Duration::from_secs(5));
        let code = execute(&sb.args(&["validate"]), &runner, &no_http, &mut out);
        let text = String::from_utf8(buf.borrow().clone()).unwrap();
        assert_eq!(code, EXIT_PARTIAL, "{text}");
        assert!(text.contains("1 passed, 1 failed"), "{text}");
        assert!(text.contains("FAIL  bad"), "{text}");
    }

    #[test]
    fn check_lists_updates_and_groups() {
        let sb = Sandbox::new("check");
        sb.write(
            "base.toml",
            "schema_version = 1\n[providers.homebrew]\nrefresh = false\n",
        );
        let (code, stdout, _) = run(&sb, &["check"], &brew());
        assert_eq!(code, EXIT_OK, "{stdout}");
        assert!(stdout.contains("libngtcp2"), "{stdout}");
        assert!(stdout.contains("rebuild"), "{stdout}");
        assert!(stdout.contains("+ new: openssl@4 4.0.3"), "{stdout}");
    }
}
