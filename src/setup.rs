//! `guarded-update setup`: a few plain questions, then one checklist of
//! every package grouped by what an update does to this computer. Only
//! the default and the packages that differ from it are saved, to the
//! overrides layer; the service scan goes to its own generated file.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::prompt;
use crate::scan::ServiceMap;
use crate::schedule::{self, When};
use crate::tui::{self, Checklist, Page, Row};

/// Asks the user questions; scripted in tests.
pub trait Prompter {
    fn say(&mut self, text: &str);
    /// Background information, shown dimmed.
    fn note(&mut self, text: &str) {
        self.say(text);
    }
    /// Returns the index of the chosen option.
    fn choose(&mut self, question: &str, options: &[(&str, &str)], default: usize) -> usize;
    /// Once input has ended, always `false`, so nothing is saved.
    fn confirm(&mut self, question: &str, default: bool) -> bool;
    /// Lets the user change package policies. `false` means leave
    /// without saving.
    fn checklist(&mut self, list: &mut Checklist) -> bool;
    /// A line of text; `default` when the answer is empty or input ended.
    fn text(&mut self, question: &str, default: &str) -> String;
    /// A line of text that is not shown while it is typed.
    fn secret(&mut self, question: &str) -> String;
    /// Shows `(label, value)` rows numbered 1-9 then 0; one key picks a
    /// row, Enter saves, q leaves. Once input has ended, `Quit`.
    fn menu(&mut self, title: &str, rows: &[(String, String)]) -> MenuPick;
    /// The last question: Save or Don't save. `false` once input ended.
    fn save(&mut self, question: &str) -> bool {
        self.confirm(question, true)
    }
    /// Records an answer as one `✓ title  value` line. Step and failure
    /// lines shown since the last answer are replaced by it.
    fn answered(&mut self, title: &str, value: &str);
    /// A part of a bigger question, such as the AI address; shown until
    /// that question's own answer replaces it.
    fn step(&mut self, title: &str, value: &str) {
        self.answered(title, value);
    }
    /// A part that failed; replaced like a step.
    fn failed(&mut self, title: &str, why: &str) {
        self.say(&format!("✗ {title}: {why}"));
    }
    /// Work in progress, such as a test call.
    fn busy(&mut self, text: &str) {
        self.say(text);
    }
    /// Finishes the busy line with its result, kept as a step.
    fn done(&mut self, text: &str) {
        self.say(text);
    }
}

/// An address cut for display: `http://host:port/…/v1`.
fn short_url(url: &str) -> String {
    let (scheme, rest) = url.split_once("://").unwrap_or(("", url));
    let parts: Vec<&str> = rest.split('/').collect();
    let shown = if parts.len() > 3 {
        format!("{}/…/{}", parts[0], parts[parts.len() - 1])
    } else {
        rest.to_string()
    };
    if scheme.is_empty() {
        shown
    } else {
        format!("{scheme}://{shown}")
    }
}

/// The last reason in an error chain, such as curl's
/// "Couldn't connect to server".
fn short_error(e: &str) -> &str {
    e.rsplit(": ").next().unwrap_or(e).trim()
}

/// A model server found on this computer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AiServer {
    pub name: String,
    /// Base address ending in `/v1`.
    pub url: String,
    pub models: Vec<String>,
}

/// Talks to model servers during setup; faked in tests.
pub trait AiProbe {
    fn models(&self, url: &str, key: &ApiKey) -> Result<Vec<String>, String>;
    /// Sends a sample release note and returns how long the answer took.
    fn test(&self, url: &str, model: &str, key: &ApiKey) -> Result<std::time::Duration, String>;
}

/// The API key for an endpoint during setup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiKey {
    None,
    /// Already saved in this file.
    File(std::path::PathBuf),
    /// Just pasted; written to `Inputs::key_path` only when setup saves.
    New(String),
}

/// What the wizard knows about the host.
pub struct Inputs<'a> {
    pub map: &'a ServiceMap,
    /// Formulae installed on request (`brew leaves --installed-on-request`).
    pub leaves: Vec<String>,
    pub casks: Vec<String>,
    /// Installed version of every formula and cask.
    pub versions: BTreeMap<String, String>,
    /// Waiting updates, e.g. `node@24` -> `24.21.0_2 rebuild`.
    pub updates: BTreeMap<String, String>,
    /// Casks whose installer needs sudo.
    pub sudo_casks: BTreeSet<String>,
    pub hermes_found: bool,
    pub macos: bool,
    /// The current overrides file, or empty.
    pub existing: toml::Table,
    /// Model servers found on this computer.
    pub ai_servers: Vec<AiServer>,
    pub ai_probe: &'a dyn AiProbe,
    /// Where a newly pasted API key is saved (mode 0600).
    pub key_path: std::path::PathBuf,
    /// A key pasted during setup, for the caller to save with the answers.
    pub new_key: std::cell::RefCell<Option<String>>,
    /// Whether setup can install the nightly schedule here (macOS).
    pub schedule: bool,
}

const POLICY_OPTIONS: [(&str, &str); 3] = [
    ("auto", "Update after the safety checks"),
    ("alert", "Tell me; change nothing"),
    ("ignore", "Neither update nor report"),
];

fn as_policy(name: &str) -> Option<&'static str> {
    tui::POLICIES.into_iter().find(|p| *p == name)
}

fn lookup<'t>(table: &'t toml::Table, path: &[&str]) -> Option<&'t toml::Value> {
    let (first, rest) = path.split_first()?;
    rest.iter()
        .try_fold(table.get(*first)?, |v, key| v.get(key))
}

fn set(table: &mut toml::Table, path: &[&str], value: toml::Value) {
    let (last, parents) = path.split_last().expect("non-empty path");
    let mut current = table;
    for key in parents {
        let entry = current
            .entry((*key).to_string())
            .or_insert_with(|| toml::Value::Table(toml::Table::new()));
        if !entry.is_table() {
            *entry = toml::Value::Table(toml::Table::new());
        }
        current = entry.as_table_mut().expect("just made a table");
    }
    current.insert((*last).to_string(), value);
}

fn existing_bool(table: &toml::Table, path: &[&str], fallback: bool) -> bool {
    lookup(table, path)
        .and_then(toml::Value::as_bool)
        .unwrap_or(fallback)
}

fn sorted_by_count(map: BTreeMap<String, Vec<String>>) -> Vec<(String, Vec<String>)> {
    let mut list: Vec<_> = map.into_iter().collect();
    list.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then_with(|| a.0.cmp(&b.0)));
    list
}

/// The four checklist pages: packages that restart services, apps,
/// command-line tools, and what is always updated by hand.
pub fn pages(inputs: &Inputs) -> Vec<Page> {
    let mut restarts: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut by_root: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for service in inputs.map.services.iter().filter(|s| s.loaded) {
        for (pkg, _) in &service.links {
            let target = if service.root {
                &mut by_root
            } else {
                &mut restarts
            };
            target
                .entry(pkg.clone())
                .or_default()
                .push(service.label.clone());
        }
    }
    let row = |name: &str, note: &str, services: Vec<String>| Row {
        name: name.to_string(),
        installed: inputs.versions.get(name).cloned().unwrap_or_default(),
        update: inputs.updates.get(name).cloned(),
        note: note.to_string(),
        services,
    };
    let mut by_hand: Vec<Row> = sorted_by_count(by_root)
        .into_iter()
        .map(|(pkg, labels)| row(&pkg, "runs as root", labels))
        .collect();
    for cask in &inputs.sudo_casks {
        if !by_hand.iter().any(|r| &r.name == cask) {
            by_hand.push(row(cask, "needs an administrator password", Vec::new()));
        }
    }
    let manual: BTreeSet<String> = by_hand.iter().map(|r| r.name.clone()).collect();
    let services: Vec<Row> = sorted_by_count(restarts)
        .into_iter()
        .filter(|(pkg, _)| !manual.contains(pkg))
        .map(|(pkg, labels)| row(&pkg, "", labels))
        .collect();
    let taken: BTreeSet<String> = manual
        .iter()
        .cloned()
        .chain(services.iter().map(|r| r.name.clone()))
        .collect();
    // Tap formulae appear as `owner/tap/name` here but by short name in
    // the service scan.
    let rest = |names: &[String]| -> Vec<Row> {
        names
            .iter()
            .filter(|n| !taken.contains(*n) && !taken.contains(crate::app::short_name(n)))
            .map(|n| row(n, "", Vec::new()))
            .collect()
    };
    vec![
        Page {
            title: "Restarts services",
            note: "Updating these restarts the services that use them, then checks they came back.",
            fixed: false,
            rows: services,
        },
        Page {
            title: "Apps",
            note: "Desktop apps. Homebrew keeps no previous version, so a bad update is held, not rolled back.",
            fixed: false,
            rows: rest(&inputs.casks),
        },
        Page {
            title: "Tools",
            note: "Command-line tools. Nothing restarts when they update.",
            fixed: false,
            rows: rest(&inputs.leaves),
        },
        Page {
            title: "By hand",
            note: "This tool reports updates for these and never applies them.",
            fixed: true,
            rows: by_hand,
        },
    ]
}

/// The optional AI check: pick a model server, prove it answers, save
/// its address and model. `false` when input ended.
fn ai_step(inputs: &Inputs, table: &mut toml::Table, p: &mut dyn Prompter) -> bool {
    let current = lookup(table, &["screening", "ai", "url"])
        .and_then(toml::Value::as_str)
        .map(str::to_string);
    let current_model = lookup(table, &["screening", "ai", "model"])
        .and_then(toml::Value::as_str)
        .map(str::to_string);
    let mut options: Vec<(String, String)> = inputs
        .ai_servers
        .iter()
        .map(|s| {
            let n = s.models.len();
            (
                s.name.clone(),
                format!(
                    "found on this computer, {n} model{}",
                    if n == 1 { "" } else { "s" }
                ),
            )
        })
        .collect();
    let other = options.len();
    options.push((
        "Endpoint".into(),
        "OpenAI-style /v1 server (router, vLLM, …)".into(),
    ));
    options.push(("No AI".into(), "Rules only".into()));
    let none = options.len() - 1;
    let default = match &current {
        Some(url) => inputs
            .ai_servers
            .iter()
            .position(|s| &s.url == url)
            .unwrap_or(other),
        None if inputs.ai_servers.is_empty() => none,
        None => 0,
    };
    let refs: Vec<(&str, &str)> = options
        .iter()
        .map(|(a, b)| (a.as_str(), b.as_str()))
        .collect();
    let choice = p.choose(
        "AI check\nOptional. Reads release notes and can hold an update;\nit can never release one the rules held.",
        &refs,
        default,
    );
    let mut key = ApiKey::None;
    let (url, models) = if choice == none {
        if let Some(screening) = table
            .get_mut("screening")
            .and_then(toml::Value::as_table_mut)
        {
            screening.remove("ai");
        }
        return true;
    } else if choice == other {
        let url = p.text(
            "AI endpoint address\nEnds in /v1, like http://192.168.1.10:8000/v1",
            current.as_deref().unwrap_or(""),
        );
        let url = url.trim().trim_end_matches('/').to_string();
        if url.is_empty() {
            p.failed("AI endpoint", "no address given");
            return true;
        }
        if !(url.starts_with("http://") || url.starts_with("https://")) {
            p.failed("AI endpoint", "must start with http:// or https://");
            return true;
        }
        p.step("AI endpoint", &short_url(&url));
        let saved_key = lookup(table, &["screening", "ai", "api_key_file"])
            .and_then(toml::Value::as_str)
            .map(std::path::PathBuf::from);
        key = if p.confirm(
            "API key\nDoes this endpoint need an API key?",
            saved_key.is_some(),
        ) {
            let pasted = p.secret(if saved_key.is_some() {
                "API key\nPaste a new key, or press Enter to keep the saved one. It goes to a private file, not the config."
            } else {
                "API key\nPaste the key. It goes to a private file, not the config."
            });
            match (pasted.trim(), saved_key) {
                ("", Some(file)) => ApiKey::File(file),
                ("", None) => ApiKey::None,
                (pasted, _) => ApiKey::New(pasted.to_string()),
            }
        } else {
            ApiKey::None
        };
        p.step(
            "API key",
            match &key {
                ApiKey::None => "none",
                ApiKey::File(_) => "saved key",
                ApiKey::New(_) => "new key",
            },
        );
        match inputs.ai_probe.models(&url, &key) {
            Ok(models) => (url, models),
            Err(e) => {
                p.failed("models not listed", short_error(&e));
                (url, Vec::new())
            }
        }
    } else {
        let server = &inputs.ai_servers[choice];
        (server.url.clone(), server.models.clone())
    };
    let model = if models.is_empty() {
        p.text(
            "Model\nThe server did not list its models; type the name to use",
            current_model.as_deref().unwrap_or("auto"),
        )
    } else {
        let shown: Vec<&String> = models.iter().take(9).collect();
        let refs: Vec<(&str, &str)> = shown.iter().map(|m| (m.as_str(), "")).collect();
        let default = shown
            .iter()
            .position(|m| Some(m.as_str()) == current_model.as_deref())
            .unwrap_or(0);
        let i = p.choose("Model\nWhich model should read the notes?", &refs, default);
        shown[i].clone()
    };
    p.step("Model", &model);
    p.busy("Testing…");
    match inputs.ai_probe.test(&url, &model, &key) {
        Ok(took) => p.done(&format!("✓ answered in {:.1} s", took.as_secs_f64())),
        Err(e) => {
            p.failed("test failed", short_error(&e));
            if !p.confirm(
                "Use it anyway?\nWhile it fails, updates that reach the AI check are held.",
                false,
            ) {
                return true;
            }
        }
    }
    set(table, &["screening", "ai", "url"], toml::Value::String(url));
    let key_file = match key {
        ApiKey::None => None,
        ApiKey::File(file) => Some(file),
        ApiKey::New(text) => {
            *inputs.new_key.borrow_mut() = Some(text);
            Some(inputs.key_path.clone())
        }
    };
    match key_file {
        Some(file) => set(
            table,
            &["screening", "ai", "api_key_file"],
            toml::Value::String(file.display().to_string()),
        ),
        None => {
            if let Some(ai) = table
                .get_mut("screening")
                .and_then(|s| s.get_mut("ai"))
                .and_then(toml::Value::as_table_mut)
            {
                ai.remove("api_key_file");
            }
        }
    }
    set(
        table,
        &["screening", "ai", "model"],
        toml::Value::String(model),
    );
    true
}

/// Runs the wizard. Returns the new overrides table, or `None` when the
/// user does not save.
const TIMES: [(&str, &str); 5] = [
    ("3:00 am", "Suggested; a Mac asleep then runs it on waking"),
    ("1:00 am", "Earlier in the night"),
    ("5:00 am", "Closer to morning"),
    ("Another time", "Type a 24-hour time, like 23:30"),
    ("Don't schedule", "Run `guarded-update run` yourself"),
];
const PRESETS: [When; 3] = [When::At(3, 0), When::At(1, 0), When::At(5, 0)];
const ANOTHER: usize = 3;
const OFF: usize = 4;

/// One key picks when the nightly run starts; setup installs it after
/// saving.
fn schedule_step(table: &mut toml::Table, p: &mut dyn Prompter) {
    let current = lookup(table, &["schedule", "at"])
        .and_then(toml::Value::as_str)
        .and_then(schedule::parse);
    let default = match current {
        None => 0,
        Some(When::Off) => OFF,
        Some(w) => PRESETS.iter().position(|x| *x == w).unwrap_or(ANOTHER),
    };
    let choice = p.choose(
        "Nightly run\nWhen should it check for and apply updates each night?",
        &TIMES,
        default,
    );
    let when = match choice {
        OFF => When::Off,
        ANOTHER => {
            let suggested = match current {
                Some(w @ When::At(..)) => schedule::format(w),
                _ => "03:00".into(),
            };
            let mut when = None;
            let mut question = "Nightly run time\n24-hour, like 23:30".to_string();
            for _ in 0..3 {
                let answer = p.text(&question, &suggested);
                match schedule::parse(&answer) {
                    Some(w @ When::At(..)) => {
                        when = Some(w);
                        break;
                    }
                    _ => {
                        question = format!(
                            "Nightly run time\n\"{}\" is not a time. Use 24-hour, like 23:30",
                            answer.trim()
                        )
                    }
                }
            }
            when.unwrap_or(PRESETS[0])
        }
        i => PRESETS[i.min(PRESETS.len() - 1)],
    };
    set(
        table,
        &["schedule", "at"],
        toml::Value::String(schedule::format(when)),
    );
}

/// Shortens paths in the user's home folder to `~/...` for display.
pub fn tilde(text: &str) -> String {
    match std::env::home_dir() {
        Some(home) if !home.as_os_str().is_empty() => {
            text.replace(&home.display().to_string(), "~")
        }
        _ => text.to_string(),
    }
}

fn bold(text: &str) -> String {
    format!("\x1b[1m{text}\x1b[0m")
}

/// One setting the wizard asks about and the menu can change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Setting {
    Policy,
    Hermes,
    Macos,
    Greedy,
    Wait,
    Major,
    Words,
    Ai,
    Schedule,
    Packages,
}

/// What the user picked in the settings menu.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MenuPick {
    Change(usize),
    Save,
    Quit,
}

const WAITS: [(&str, &str); 4] = [
    ("2 days", "Most bad releases get a fix within a day or two"),
    ("7 days", "Safer, but updates arrive a week later"),
    ("1 day", "Shorter wait"),
    ("No wait", "Update as soon as a new version appears"),
];
const WAIT_DAYS: [i64; 4] = [2, 7, 1, 0];

/// The settings that apply on this host, in the order first setup asks.
fn settings(inputs: &Inputs) -> Vec<Setting> {
    use Setting::*;
    [
        Policy, Hermes, Macos, Greedy, Wait, Major, Words, Ai, Schedule, Packages,
    ]
    .into_iter()
    .filter(|s| match s {
        Hermes => inputs.hermes_found,
        Macos => inputs.macos,
        Schedule => inputs.schedule,
        _ => true,
    })
    .collect()
}

fn label(setting: Setting) -> &'static str {
    match setting {
        Setting::Policy => "Updates by default",
        Setting::Hermes => "Hermes Agent releases",
        Setting::Macos => "macOS updates",
        Setting::Greedy => "Apps that update themselves",
        Setting::Wait => "Wait after a release",
        Setting::Major => "Big version jumps",
        Setting::Words => "Warning words in notes",
        Setting::Ai => "AI check",
        Setting::Schedule => "Nightly run",
        Setting::Packages => "Packages",
    }
}

/// The current answer, as the menu shows it.
fn value(setting: Setting, table: &toml::Table, list: &Checklist) -> String {
    let flag = |path: &[&str], fallback: bool, on: &str, off: &str| {
        if existing_bool(table, path, fallback) {
            on.to_string()
        } else {
            off.to_string()
        }
    };
    match setting {
        Setting::Policy => list.default.to_string(),
        Setting::Hermes => flag(
            &["providers", "hermes", "enabled"],
            true,
            "checked",
            "not checked",
        ),
        Setting::Macos => flag(
            &["providers", "macos", "enabled"],
            true,
            "reported",
            "not reported",
        ),
        Setting::Greedy => flag(
            &["providers", "homebrew", "greedy_casks"],
            false,
            "included",
            "left out",
        ),
        Setting::Wait => match lookup(table, &["screening", "wait_days"])
            .and_then(toml::Value::as_integer)
            .unwrap_or(2)
        {
            0 => "no wait".into(),
            1 => "1 day".into(),
            n => format!("{n} days"),
        },
        Setting::Major => flag(
            &["screening", "hold_major"],
            true,
            "held for you",
            "allowed",
        ),
        Setting::Words => flag(
            &["screening", "hold_words"],
            true,
            "held for you",
            "allowed",
        ),
        Setting::Ai => {
            let get = |k: &str| {
                lookup(table, &["screening", "ai", k])
                    .and_then(toml::Value::as_str)
                    .map(str::to_string)
            };
            match get("url") {
                Some(url) => format!(
                    "{} at {}",
                    get("model").unwrap_or_else(|| "auto".into()),
                    url.split("://")
                        .last()
                        .unwrap_or(&url)
                        .split('/')
                        .next()
                        .unwrap_or(&url)
                ),
                None => "off".into(),
            }
        }
        Setting::Schedule => lookup(table, &["schedule", "at"])
            .and_then(toml::Value::as_str)
            .and_then(schedule::parse)
            .map_or("not set".into(), |w| match w {
                When::Off => "not scheduled".into(),
                w => schedule::describe(w),
            }),
        Setting::Packages => match list.exceptions().len() {
            0 => format!("all {}", list.default),
            1 => "1 set differently".into(),
            n => format!("{n} set differently"),
        },
    }
}

/// Asks about one setting and records the answer. `false` when the
/// user left without saving (only the first-run checklist can do that).
fn ask(
    setting: Setting,
    inputs: &Inputs,
    table: &mut toml::Table,
    list: &mut Checklist,
    p: &mut dyn Prompter,
) -> bool {
    let mut yes_no = |table: &mut toml::Table, q: &str, path: &[&str], fallback: bool| {
        let on = p.confirm(q, existing_bool(table, path, fallback));
        set(table, path, toml::Value::Boolean(on));
    };
    match setting {
        Setting::Policy => {
            let default = POLICY_OPTIONS
                .iter()
                .position(|(name, _)| *name == list.default)
                .unwrap_or(0);
            let choice = p.choose(
                "Updates by default\nWhat happens to an update nobody has set otherwise.",
                &POLICY_OPTIONS,
                default,
            );
            list.set_default(as_policy(POLICY_OPTIONS[choice].0).unwrap_or("auto"));
        }
        Setting::Hermes => yes_no(
            table,
            "Hermes Agent releases\nCheck GitHub for new stable Hermes releases?",
            &["providers", "hermes", "enabled"],
            true,
        ),
        Setting::Macos => yes_no(
            table,
            "macOS updates\nReport them? This tool never applies them.",
            &["providers", "macos", "enabled"],
            true,
        ),
        Setting::Greedy => yes_no(
            table,
            "Apps that update themselves\nInclude apps such as copilot-cli that also update on their own?",
            &["providers", "homebrew", "greedy_casks"],
            false,
        ),
        Setting::Wait => {
            let current =
                lookup(table, &["screening", "wait_days"]).and_then(toml::Value::as_integer);
            let wait = p.choose(
                "Wait after a release\nSafety check: days to wait after a new version first appears.",
                &WAITS,
                WAIT_DAYS
                    .iter()
                    .position(|d| Some(*d) == current)
                    .unwrap_or(0),
            );
            set(
                table,
                &["screening", "wait_days"],
                toml::Value::Integer(WAIT_DAYS[wait]),
            );
        }
        Setting::Major => yes_no(
            table,
            "Big version jumps\nSafety check: hold jumps such as 2.x to 3.0 for you to approve?",
            &["screening", "hold_major"],
            true,
        ),
        Setting::Words => yes_no(
            table,
            "Warning words in notes\nSafety check: hold when release notes say breaking, removed or migration?",
            &["screening", "hold_words"],
            true,
        ),
        Setting::Ai => {
            ai_step(inputs, table, p);
        }
        Setting::Schedule => schedule_step(table, p),
        Setting::Packages => {
            let before = list.clone();
            if !p.checklist(list) {
                *list = before;
                return false;
            }
        }
    }
    true
}

/// The settings menu: every current answer on one screen; a number
/// changes one, Enter saves, q leaves without saving.
fn menu(
    inputs: &Inputs,
    table: &mut toml::Table,
    list: &mut Checklist,
    p: &mut dyn Prompter,
) -> bool {
    let all = settings(inputs);
    loop {
        let rows: Vec<(String, String)> = all
            .iter()
            .map(|s| (label(*s).to_string(), value(*s, table, list)))
            .collect();
        match p.menu("guarded-update settings", &rows) {
            MenuPick::Save => return true,
            MenuPick::Quit => return false,
            MenuPick::Change(i) => {
                if let Some(setting) = all.get(i) {
                    // Leaving the checklist here only drops its changes.
                    ask(*setting, inputs, table, list, p);
                }
            }
        }
    }
}

pub fn wizard(inputs: &Inputs, p: &mut dyn Prompter) -> Option<toml::Table> {
    let mut table = inputs.existing.clone();
    let first_run = !table.contains_key("schema_version");
    let pages = pages(inputs);
    let existing = &inputs.existing;
    let current = lookup(existing, &["defaults", "policy"])
        .and_then(toml::Value::as_str)
        .and_then(as_policy)
        .unwrap_or("auto");
    let mut list = Checklist::new(pages, current, &|name| {
        lookup(existing, &["items", name, "policy"])
            .and_then(toml::Value::as_str)
            .and_then(as_policy)
    });
    if first_run {
        p.say(&bold("guarded-update setup"));
        let running: BTreeSet<&str> = inputs
            .map
            .services
            .iter()
            .filter(|s| s.loaded && !s.root && !s.links.is_empty())
            .map(|s| s.label.as_str())
            .collect();
        p.note(&format!(
            "Found {} running services using {} Homebrew packages.",
            running.len(),
            list.pages[0].rows.len()
        ));
        p.say("");
        for setting in settings(inputs) {
            if !ask(setting, inputs, &mut table, &mut list, p) {
                return None;
            }
            p.answered(label(setting), &value(setting, &table, &list));
        }
    } else {
        if !menu(inputs, &mut table, &mut list, p) {
            return None;
        }
    }

    // Keep only real choices.
    set(
        &mut table,
        &["defaults", "policy"],
        toml::Value::String(list.default.into()),
    );
    // Services come from services.toml now; hand-made entries belong in
    // the base config, since only this wizard writes the overrides.
    table.remove("services");
    let listed: BTreeSet<&str> = list.names().into_iter().collect();
    if let Some(items) = table.get_mut("items").and_then(toml::Value::as_table_mut) {
        for (name, item) in items.iter_mut() {
            let Some(item) = item.as_table_mut() else {
                continue;
            };
            let same = item.get("policy").and_then(toml::Value::as_str) == Some(list.default);
            if same || listed.contains(name.as_str()) {
                item.remove("policy");
            }
        }
        items.retain(|_, item| item.as_table().is_none_or(|t| !t.is_empty()));
    }
    for (name, policy) in list.exceptions() {
        set(
            &mut table,
            &["items", &name, "policy"],
            toml::Value::String(policy.into()),
        );
    }
    if table
        .get("items")
        .and_then(toml::Value::as_table)
        .is_some_and(toml::Table::is_empty)
    {
        table.remove("items");
    }
    set(&mut table, &["schema_version"], toml::Value::Integer(1));

    if !first_run {
        // The menu's Enter already meant "save".
        return Some(table);
    }
    p.save("Save these settings?").then_some(table)
}

/// Writes the overrides file: header comment, mode 0600, temp then rename.
pub fn write_overrides(path: &Path, table: &toml::Table) -> Result<(), String> {
    let body = toml::to_string(table).map_err(|e| format!("cannot write the config: {e}"))?;
    crate::state::write_private(
        path,
        &format!(
            "# Written by `guarded-update setup`. Run it again to change these answers.\n\n{body}"
        ),
    )
}

/// Reads answers from stdin; prompts go through the redacting output.
pub struct StdPrompter<'a> {
    pub out: &'a crate::output::Output,
    eof: bool,
    /// Step and failure lines on screen, erased by the next answer.
    steps: usize,
    /// A busy line is drawn without a newline.
    busy: bool,
    busy_text: String,
    /// Keeps keys typed during busy work from echoing onto the screen;
    /// they wait for the next question instead.
    hold: Option<tui::Terminal>,
}

impl<'a> StdPrompter<'a> {
    pub fn new(out: &'a crate::output::Output) -> Self {
        Self {
            out,
            eof: false,
            steps: 0,
            busy: false,
            busy_text: String::new(),
            hold: None,
        }
    }

    /// Clears a busy line so the next output takes its place.
    fn end_busy(&mut self) {
        self.hold = None;
        if self.busy {
            self.out.frame("\r\x1b[K");
            self.busy = false;
        }
    }

    /// Erases the step lines since the last answer, after a moment so
    /// the last result can be read.
    fn end_steps(&mut self) {
        self.end_busy();
        if self.steps > 0 && self.out.interactive() {
            // No echo while waiting, so a key pressed now cannot add a line.
            let hold = tui::Terminal::open();
            std::thread::sleep(std::time::Duration::from_millis(1500));
            drop(hold);
            self.out.frame(&format!("\x1b[{}A\x1b[J", self.steps));
        }
        self.steps = 0;
    }

    /// Prints a step line cut to the window, so erasing counts right.
    fn step_line(&mut self, line: &str) {
        self.end_busy();
        let cols = tui::Terminal::open().map_or(0, |t| t.size().1);
        self.out.stdout(&tui::fit(line, cols));
        self.steps += 1;
    }

    fn read(&mut self) -> Option<String> {
        if self.eof {
            return None;
        }
        let mut line = String::new();
        match std::io::stdin().read_line(&mut line) {
            Ok(0) | Err(_) => {
                self.eof = true;
                None
            }
            Ok(_) => Some(line.trim().to_string()),
        }
    }

    /// Without a terminal: a numbered list, changed by typing numbers
    /// and a policy letter, e.g. `3 7 l`.
    fn numbered(&mut self, list: &mut Checklist) -> bool {
        for _ in 0..MAX_TRIES * 10 {
            let mut numbered = Vec::new();
            for (p, page) in list.pages.iter().enumerate() {
                if page.rows.is_empty() {
                    continue;
                }
                self.out.stdout("");
                self.out.stdout(&format!("{}: {}", page.title, page.note));
                for (r, row) in page.rows.iter().enumerate() {
                    let policy = list.policy(p, r);
                    let label = if page.fixed {
                        "   ".to_string()
                    } else {
                        numbered.push(row.name.clone());
                        format!("{:>3}", numbered.len())
                    };
                    let update = row
                        .update
                        .as_ref()
                        .map_or(String::new(), |u| format!("  -> {u}"));
                    let impact = match row.services.len() {
                        0 => row.note.clone(),
                        n => format!("restarts {n} service{}", if n == 1 { "" } else { "s" }),
                    };
                    self.out.stdout(&format!(
                        " {label}  {:<26} {policy:<7} {impact}{update}",
                        row.name
                    ));
                }
            }
            self.out.stdout("");
            self.out.stdout(&format!(
                "Default: {}. To change packages, type their numbers and a, l or i for auto, alert or ignore (e.g. `3 7 l`). Press Enter when done:",
                list.default
            ));
            let Some(answer) = self.read() else {
                return false;
            };
            if answer.is_empty() {
                return true;
            }
            let mut numbers = Vec::new();
            let mut policy = None;
            let mut bad = false;
            for word in answer.split([' ', ',']).filter(|w| !w.is_empty()) {
                match word.to_ascii_lowercase().as_str() {
                    "a" | "auto" => policy = Some("auto"),
                    "l" | "alert" => policy = Some("alert"),
                    "i" | "ignore" => policy = Some("ignore"),
                    n => match n.parse::<usize>() {
                        Ok(n) if (1..=numbered.len()).contains(&n) => numbers.push(n),
                        _ => bad = true,
                    },
                }
            }
            match policy {
                Some(policy) if !bad && !numbers.is_empty() => {
                    for n in numbers {
                        list.set(&numbered[n - 1], policy);
                    }
                }
                _ => self.out.stdout(&format!(
                    "Type numbers from 1 to {} and one of a, l or i.",
                    numbered.len()
                )),
            }
        }
        false
    }
}

const MAX_TRIES: usize = 5;

/// What one keypress means in the settings menu: 1-9 then 0 pick a row.
fn menu_key(key: tui::Key, rows: usize) -> Option<MenuPick> {
    match key {
        tui::Key::Enter => Some(MenuPick::Save),
        tui::Key::Quit | tui::Key::Char('q' | 'Q') => Some(MenuPick::Quit),
        tui::Key::Char(c) => {
            let n = c.to_digit(10)? as usize;
            let i = if n == 0 { 9 } else { n - 1 };
            (i < rows).then_some(MenuPick::Change(i))
        }
        _ => None,
    }
}

/// The key that picks menu row `i`.
fn menu_digit(i: usize) -> usize {
    (i + 1) % 10
}

/// The settings menu's lines.
fn menu_lines(title: &str, rows: &[(String, String)], hint: &str, color: bool) -> Vec<String> {
    let bold = |t: &str| {
        if color {
            format!("\x1b[1m{t}\x1b[0m")
        } else {
            t.to_string()
        }
    };
    let mut lines = vec![bold(title), String::new()];
    for (i, (label, value)) in rows.iter().enumerate() {
        lines.push(format!(
            "  {}  {label:<width$} {value}",
            menu_digit(i),
            width = prompt::LABEL_WIDTH
        ));
    }
    if !hint.is_empty() {
        lines.push(String::new());
        lines.push(if color {
            format!("\x1b[2m{hint}\x1b[0m")
        } else {
            hint.to_string()
        });
    }
    lines
}

impl StdPrompter<'_> {
    /// Draws a question at the terminal, redraws it after each key and
    /// erases it once answered. `None` when there is no terminal (ask
    /// with plain lines instead). Ctrl-C ends input, so nothing is saved.
    fn interact<T>(
        &mut self,
        draw: &dyn Fn(usize) -> Vec<String>,
        key: &dyn Fn(tui::Key) -> Option<Result<T, ()>>,
    ) -> Option<Result<T, ()>> {
        if self.eof {
            return Some(Err(()));
        }
        if !self.out.interactive() {
            return None;
        }
        self.end_busy();
        let mut term = tui::Terminal::open()?;
        let cols = term.size().1;
        let mut lines = draw(cols);
        self.out.frame(&format!("\x1b[?25l{}", lines.join("\r\n")));
        let answer = loop {
            if let Some(answer) = key(term.read_key()) {
                break answer;
            }
            let next = draw(cols);
            self.out.frame(&format!(
                "{}{}",
                prompt::erase(lines.len()),
                next.join("\r\n")
            ));
            lines = next;
        };
        self.out.frame(&prompt::erase(lines.len()));
        drop(term);
        if answer.is_err() {
            self.eof = true;
        }
        Some(answer)
    }

    /// The plain-text heading for a question without a terminal.
    fn plain_head(&mut self, question: &str) {
        let (title, detail) = prompt::split(question);
        self.out.stdout("");
        self.out.stdout(title);
        if !detail.is_empty() {
            self.out.stdout(detail);
        }
    }
}

impl Prompter for StdPrompter<'_> {
    fn say(&mut self, text: &str) {
        self.end_busy();
        if self.out.interactive() {
            self.out.stdout(text);
        } else {
            self.out
                .stdout(&text.replace("\x1b[1m", "").replace("\x1b[0m", ""));
        }
    }

    fn note(&mut self, text: &str) {
        self.end_busy();
        if self.out.interactive() {
            self.out.stdout(&format!("\x1b[2m{text}\x1b[0m"));
        } else {
            self.out.stdout(text);
        }
    }

    fn answered(&mut self, title: &str, value: &str) {
        self.end_steps();
        let color = self.out.interactive();
        self.out.stdout(&prompt::answered(title, value, color));
    }

    fn step(&mut self, title: &str, value: &str) {
        let color = self.out.interactive();
        self.step_line(&prompt::answered(title, value, color));
    }

    fn failed(&mut self, title: &str, why: &str) {
        let color = self.out.interactive();
        self.step_line(&prompt::failed(title, why, color));
    }

    fn busy(&mut self, text: &str) {
        self.end_busy();
        if self.out.interactive() {
            self.hold = tui::Terminal::open();
            self.out.frame(&format!("  {text}"));
            self.busy = true;
            self.busy_text = text.to_string();
        } else {
            self.out.stdout(&format!("  {text}"));
        }
    }

    fn done(&mut self, text: &str) {
        let line = format!("  {} {text}", self.busy_text);
        self.end_busy();
        let line = if self.out.interactive() {
            line.replacen('✓', "\x1b[32m✓\x1b[0m", 1)
        } else {
            line
        };
        self.step_line(&line);
    }

    fn choose(&mut self, question: &str, options: &[(&str, &str)], default: usize) -> usize {
        let n = options.len();
        let default = default.min(n - 1);
        let cur = std::cell::Cell::new(default);
        match self.interact(
            &|cols| prompt::choice(question, options, cur.get(), default, cols, true),
            &|k| {
                let mut c = cur.get();
                let answer = prompt::choice_key(k, &mut c, n);
                cur.set(c);
                answer
            },
        ) {
            Some(Ok(i)) => return i,
            Some(Err(())) => return default,
            None => {}
        }
        self.plain_head(question);
        for line in prompt::choice("", options, usize::MAX, default, 0, false)
            .iter()
            .skip(2)
            .take(n)
        {
            self.out.stdout(line);
        }
        for _ in 0..MAX_TRIES {
            self.out.stdout(&format!(
                "Type 1-{n} and press Enter (Enter alone picks {}):",
                options[default].0
            ));
            let Some(answer) = self.read() else {
                return default;
            };
            if answer.is_empty() {
                return default;
            }
            match answer.parse::<usize>() {
                Ok(i) if (1..=n).contains(&i) => return i - 1,
                _ => self
                    .out
                    .stdout(&format!("Please type a number from 1 to {n}.")),
            }
        }
        default
    }

    fn save(&mut self, question: &str) -> bool {
        let yes = std::cell::Cell::new(true);
        match self.interact(
            &|cols| {
                let mut lines = vec![String::new()];
                lines.extend(prompt::save(question, yes.get(), cols, true));
                lines
            },
            &|k| {
                let mut y = yes.get();
                let answer = prompt::yes_no_key(k, &mut y);
                yes.set(y);
                answer
            },
        ) {
            Some(Ok(answer)) => answer,
            Some(Err(())) => false,
            None => self.confirm(question, true),
        }
    }

    fn confirm(&mut self, question: &str, default: bool) -> bool {
        let yes = std::cell::Cell::new(default);
        match self.interact(
            &|cols| prompt::yes_no(question, yes.get(), default, cols, true),
            &|k| {
                let mut y = yes.get();
                let answer = prompt::yes_no_key(k, &mut y);
                yes.set(y);
                answer
            },
        ) {
            Some(Ok(answer)) => return answer,
            Some(Err(())) => return false,
            None => {}
        }
        self.plain_head(question);
        for _ in 0..MAX_TRIES {
            self.out.stdout(&format!(
                "Type y or n (Enter alone means {}):",
                if default { "yes" } else { "no" }
            ));
            let Some(answer) = self.read() else {
                return false;
            };
            match answer.to_ascii_lowercase().as_str() {
                "" => return default,
                "y" | "yes" => return true,
                "n" | "no" => return false,
                _ => self.out.stdout("Please answer y or n."),
            }
        }
        default
    }

    fn text(&mut self, question: &str, default: &str) -> String {
        let value = std::cell::RefCell::new(default.to_string());
        match self.interact(
            &|cols| prompt::text(question, &value.borrow(), default, cols, true),
            &|k| prompt::edit_key(k, &mut value.borrow_mut(), default),
        ) {
            Some(Ok(())) => return value.into_inner().trim().to_string(),
            Some(Err(())) => return default.to_string(),
            None => {}
        }
        self.plain_head(question);
        if !default.is_empty() {
            self.out.stdout(&format!(
                "Press Enter to keep {default}, or type a new value:"
            ));
        }
        match self.read() {
            Some(answer) if !answer.is_empty() => answer,
            _ => default.to_string(),
        }
    }

    fn secret(&mut self, question: &str) -> String {
        if self.eof {
            return String::new();
        }
        if self.out.interactive()
            && let Some(mut term) = tui::Terminal::open()
        {
            let lines = prompt::secret(question, term.size().1, true);
            self.out.frame(&format!("\x1b[?25l{}", lines.join("\r\n")));
            let line = term.read_hidden_line();
            self.out.frame(&prompt::erase(lines.len()));
            drop(term);
            return line.unwrap_or_else(|| {
                self.eof = true;
                String::new()
            });
        }
        self.plain_head(question);
        self.read().unwrap_or_default()
    }

    fn menu(&mut self, title: &str, rows: &[(String, String)]) -> MenuPick {
        self.end_steps();
        let rows = &rows[..rows.len().min(10)];
        let n = rows.len();
        let last = menu_digit(n - 1);
        let keys = if n == 10 {
            "1-9, 0".to_string()
        } else {
            format!("1-{n}")
        };
        let hint = format!("{keys} changes a setting · Enter saves · q quits without saving");
        match self.interact(
            &|cols| {
                menu_lines(title, rows, &hint, true)
                    .iter()
                    .map(|l| tui::fit(l, cols))
                    .collect()
            },
            &|k| menu_key(k, n).map(Ok),
        ) {
            Some(Ok(pick)) => {
                if pick == MenuPick::Save {
                    // Leave the settings on screen as the record of what was saved.
                    for line in menu_lines(title, rows, "", true) {
                        self.out.stdout(&line);
                    }
                }
                return pick;
            }
            Some(Err(())) => return MenuPick::Quit,
            None => {}
        }
        self.out.stdout("");
        for line in menu_lines(title, rows, "", false) {
            self.out.stdout(&line);
        }
        for _ in 0..MAX_TRIES {
            self.out.stdout(&format!(
                "Type 1-{last} to change a setting, press Enter to save, or q to quit:"
            ));
            let Some(answer) = self.read() else {
                return MenuPick::Quit;
            };
            match answer.as_str() {
                "" => return MenuPick::Save,
                "q" | "Q" => return MenuPick::Quit,
                a => match a
                    .chars()
                    .next()
                    .map(tui::Key::Char)
                    .and_then(|k| menu_key(k, n))
                {
                    Some(pick) if a.len() == 1 => return pick,
                    _ => self.out.stdout("Please type one of the numbers shown."),
                },
            }
        }
        MenuPick::Quit
    }

    fn checklist(&mut self, list: &mut Checklist) -> bool {
        if self.eof {
            return false;
        }
        if self.out.interactive()
            && let Some(mut term) = tui::Terminal::open()
        {
            let saved = tui::run(list, &mut term, self.out).is_some();
            drop(term);
            return saved;
        }
        self.numbered(list)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::{Service, Via};
    use crate::tui::{Key, Outcome};
    use std::collections::VecDeque;
    use std::path::PathBuf;

    /// Answers and checklist keys from a script; running out of either
    /// simulates end of input.
    struct Scripted {
        answers: VecDeque<&'static str>,
        keys: VecDeque<Key>,
        said: Vec<String>,
        questions: usize,
    }

    impl Scripted {
        fn new(answers: &[&'static str], keys: &[Key]) -> Self {
            Self {
                answers: answers.iter().copied().collect(),
                keys: keys.iter().copied().collect(),
                said: Vec::new(),
                questions: 0,
            }
        }
        fn next(&mut self, question: &str) -> Option<&'static str> {
            self.questions += 1;
            self.said.push(format!("? {question}"));
            self.answers.pop_front()
        }
        fn transcript(&self) -> String {
            self.said.join("\n")
        }
    }

    impl Prompter for Scripted {
        fn say(&mut self, text: &str) {
            self.said.push(text.to_string());
        }
        fn choose(&mut self, question: &str, options: &[(&str, &str)], default: usize) -> usize {
            match self.next(question) {
                Some("") | None => default,
                Some(n) => n.parse::<usize>().unwrap() - 1,
            }
            .min(options.len() - 1)
        }
        fn confirm(&mut self, question: &str, default: bool) -> bool {
            match self.next(question) {
                None => false,
                Some("") => default,
                Some(a) => a.starts_with('y'),
            }
        }
        fn text(&mut self, question: &str, default: &str) -> String {
            match self.next(question) {
                Some("") | None => default.to_string(),
                Some(a) => a.to_string(),
            }
        }
        fn secret(&mut self, question: &str) -> String {
            self.next(question).unwrap_or("").to_string()
        }
        fn answered(&mut self, title: &str, value: &str) {
            self.said.push(format!("✓ {title}: {value}"));
        }
        fn menu(&mut self, title: &str, rows: &[(String, String)]) -> MenuPick {
            for (label, value) in rows {
                self.said.push(format!("{label}: {value}"));
            }
            match self.next(title) {
                None | Some("q") => MenuPick::Quit,
                Some("") => MenuPick::Save,
                Some(n) => menu_key(Key::Char(n.chars().next().unwrap()), rows.len()).unwrap(),
            }
        }
        fn checklist(&mut self, list: &mut Checklist) -> bool {
            self.questions += 1;
            self.said.push(list.render(10, 0, false));
            while let Some(key) = self.keys.pop_front() {
                match list.key(key, 10) {
                    Outcome::Continue => {}
                    outcome => return outcome == Outcome::Done,
                }
            }
            false
        }
    }

    fn svc(label: &str, root: bool, loaded: bool, links: &[&str]) -> Service {
        Service {
            label: label.into(),
            plist: PathBuf::from(format!("/LA/{label}.plist")),
            root,
            keep_alive: true,
            loaded,
            program: "/x".into(),
            links: links
                .iter()
                .map(|p| ((*p).to_string(), Via::Program))
                .collect(),
            venv_python: None,
        }
    }

    fn host_map() -> ServiceMap {
        ServiceMap {
            scanned: "2026-10-10T00:00:00Z".into(),
            uid: "501".into(),
            skipped: vec![],
            services: vec![
                svc("com.example.loki", false, true, &["loki"]),
                svc("com.example.api", false, true, &["node@24"]),
                svc("com.example.board", false, true, &["node@24"]),
                svc("ai.example.llm", false, true, &["python@3.12"]),
                svc("com.ollama", true, true, &["ollama"]),
                svc("com.example.router", false, true, &[]),
                svc("com.example.old-loop", false, false, &["jq"]),
            ],
        }
    }

    /// A model server that lists `qwen` and answers the sample only when
    /// `works`.
    struct Probe {
        works: bool,
    }
    impl AiProbe for Probe {
        fn models(&self, url: &str, key: &ApiKey) -> Result<Vec<String>, String> {
            if url.contains("locked") && *key == ApiKey::None {
                return Err("401 unauthorized".into());
            }
            if url.contains("router") || url.contains("locked") {
                Ok(vec!["auto".into(), "qwen".into()])
            } else {
                Err("connection refused".into())
            }
        }
        fn test(&self, _: &str, _: &str, _: &ApiKey) -> Result<std::time::Duration, String> {
            if self.works {
                Ok(std::time::Duration::from_millis(4800))
            } else {
                Err("the answer is not JSON".into())
            }
        }
    }
    static WORKS: Probe = Probe { works: true };
    static BROKEN: Probe = Probe { works: false };

    fn inputs<'a>(map: &'a ServiceMap, existing: toml::Table, _path: &'a Path) -> Inputs<'a> {
        let names = |list: &[&str]| list.iter().map(|s| (*s).to_string()).collect::<Vec<_>>();
        Inputs {
            map,
            leaves: names(&[
                "jq",
                "loki",
                "node@24",
                "ollama",
                "ripgrep",
                "acme/tap/loki",
            ]),
            casks: names(&["copilot-cli", "tailscale-app"]),
            versions: [("node@24", "24.21.0_1"), ("jq", "1.8.2")]
                .map(|(a, b)| (a.to_string(), b.to_string()))
                .into(),
            updates: [("node@24".to_string(), "24.21.0_2 rebuild".to_string())].into(),
            sudo_casks: ["tailscale-app".to_string()].into(),
            hermes_found: true,
            macos: true,
            existing,
            ai_servers: vec![],
            ai_probe: &WORKS,
            key_path: PathBuf::from("/c/secrets/ai-key"),
            new_key: std::cell::RefCell::new(None),
            schedule: true,
        }
    }

    fn page_names(pages: &[Page], i: usize) -> Vec<&str> {
        pages[i].rows.iter().map(|r| r.name.as_str()).collect()
    }

    fn accept_all() -> Scripted {
        Scripted::new(&["", "", "", "", "", "", "", "", "", ""], &[Key::Enter])
    }

    #[test]
    fn packages_are_grouped_by_what_an_update_does() {
        let map = host_map();
        let path = PathBuf::from("/c/overrides.toml");
        let pages = pages(&inputs(&map, toml::Table::new(), &path));
        assert_eq!(
            page_names(&pages, 0),
            ["node@24", "loki", "python@3.12"],
            "most services first; dependencies such as python@3.12 included"
        );
        assert_eq!(page_names(&pages, 1), ["copilot-cli"]);
        assert_eq!(
            page_names(&pages, 2),
            ["jq", "ripgrep"],
            "a link from a stopped service does not count; tap names match by short name"
        );
        assert_eq!(page_names(&pages, 3), ["ollama", "tailscale-app"]);
        assert!(pages[3].fixed);
        assert_eq!(
            pages[0].rows[0].update.as_deref(),
            Some("24.21.0_2 rebuild")
        );
        assert_eq!(pages[0].rows[0].installed, "24.21.0_1");
    }

    #[test]
    fn the_number_of_questions_does_not_grow_with_the_host() {
        let path = PathBuf::from("/c/overrides.toml");
        let small = host_map();
        let mut big = host_map();
        for i in 0..40 {
            big.services.push(svc(
                &format!("com.x{i}"),
                false,
                true,
                &[&format!("pkg{i}")],
            ));
        }
        let count = |map: &ServiceMap| {
            let mut p = accept_all();
            wizard(&inputs(map, toml::Table::new(), &path), &mut p).unwrap();
            p.questions
        };
        assert_eq!(count(&small), count(&big));
        assert_eq!(
            count(&small),
            11,
            "policy, Hermes, macOS, greedy, wait, big jumps, words, AI, schedule, checklist, save"
        );
    }

    #[test]
    fn only_the_default_and_differences_are_saved() {
        let map = host_map();
        let path = PathBuf::from("/c/overrides.toml");
        let existing: toml::Table = r#"
schema_version = 1
[items.jq]
policy = "auto"
[items.loki]
policy = "alert"
notes_url = "https://example.com/loki"
[items.openssl]
policy = "ignore"
[services."com.example.loki"]
packages = ["loki"]
health = ["launchctl", "list", "com.example.loki"]
"#
        .parse()
        .unwrap();
        // From the menu, open Packages (key 0); on page 1, set node@24 to
        // alert and loki back to the default; Enter saves.
        let mut p = Scripted::new(
            &["0", ""],
            &[Key::Char('l'), Key::Down, Key::Char('a'), Key::Enter],
        );
        let table = wizard(&inputs(&map, existing, &path), &mut p).unwrap();
        let text = toml::to_string(&table).unwrap();
        assert!(!text.contains("[services"), "{text}");
        assert!(!text.contains("[items.jq]"), "matches the default: {text}");
        let policy =
            |name: &str| lookup(&table, &["items", name, "policy"]).and_then(toml::Value::as_str);
        assert_eq!(policy("node@24"), Some("alert"));
        assert_eq!(policy("loki"), None);
        assert!(
            lookup(&table, &["items", "loki", "notes_url"]).is_some(),
            "other settings kept"
        );
        assert_eq!(
            policy("openssl"),
            Some("ignore"),
            "a package not on the list keeps its setting"
        );
        assert_eq!(
            lookup(&table, &["defaults", "policy"]).and_then(toml::Value::as_str),
            Some("auto")
        );
    }

    #[test]
    fn auto_is_the_suggested_default() {
        let map = host_map();
        let path = PathBuf::from("/c/overrides.toml");
        let mut p = accept_all();
        let table = wizard(&inputs(&map, toml::Table::new(), &path), &mut p).unwrap();
        assert_eq!(
            lookup(&table, &["defaults", "policy"]).and_then(toml::Value::as_str),
            Some("auto")
        );
        assert_eq!(lookup(&table, &["items"]), None);
        assert!(
            p.transcript()
                .contains("Found 4 running services using 3 Homebrew packages."),
            "{}",
            p.transcript()
        );
    }

    #[test]
    fn safety_check_answers_are_saved() {
        let map = host_map();
        let path = PathBuf::from("/c/overrides.toml");
        let mut p = Scripted::new(&["", "", "", "", "2", "n", "", "", "", ""], &[Key::Enter]);
        let table = wizard(&inputs(&map, toml::Table::new(), &path), &mut p).unwrap();
        let get = |k: &str| lookup(&table, &["screening", k]).cloned();
        assert_eq!(get("wait_days"), Some(toml::Value::Integer(7)));
        assert_eq!(get("hold_major"), Some(toml::Value::Boolean(false)));
        assert_eq!(get("hold_words"), Some(toml::Value::Boolean(true)));
        let config: crate::config::Config =
            toml::from_str(&toml::to_string(&table).unwrap()).unwrap();
        assert_eq!(
            config.screening.wait_days, 7,
            "the saved file is a valid config"
        );
    }

    fn ai_answers(
        answers: &[&'static str],
        probe: &'static Probe,
        servers: Vec<AiServer>,
    ) -> toml::Table {
        let map = host_map();
        let path = PathBuf::from("/c/overrides.toml");
        let mut all = vec!["", "", "", "", "", "", ""];
        all.extend_from_slice(answers);
        all.extend_from_slice(&["", ""]);
        let mut p = Scripted::new(&all, &[Key::Enter]);
        let mut i = inputs(&map, toml::Table::new(), &path);
        i.ai_probe = probe;
        i.ai_servers = servers;
        wizard(&i, &mut p).unwrap()
    }

    fn ai_setting(table: &toml::Table, key: &str) -> Option<String> {
        lookup(table, &["screening", "ai", key])
            .and_then(toml::Value::as_str)
            .map(str::to_string)
    }

    #[test]
    fn a_server_found_on_this_computer_is_suggested_and_tested() {
        let ollama = AiServer {
            name: "Ollama".into(),
            url: "http://127.0.0.1:11434/v1".into(),
            models: vec!["qwen3:8b".into()],
        };
        // Enter accepts Ollama, then its only model.
        let table = ai_answers(&["", ""], &WORKS, vec![ollama]);
        assert_eq!(
            ai_setting(&table, "url").as_deref(),
            Some("http://127.0.0.1:11434/v1")
        );
        assert_eq!(ai_setting(&table, "model").as_deref(), Some("qwen3:8b"));
    }

    #[test]
    fn another_address_lists_its_models() {
        // 1 = another address (no servers found), then the address, then model 2.
        let table = ai_answers(
            &["1", "http://router:8090/c/gu/v1/", "", "2"],
            &WORKS,
            vec![],
        );
        assert_eq!(
            ai_setting(&table, "url").as_deref(),
            Some("http://router:8090/c/gu/v1")
        );
        assert_eq!(ai_setting(&table, "model").as_deref(), Some("qwen"));
    }

    #[test]
    fn a_pasted_key_is_kept_out_of_the_config_and_saved_by_the_caller() {
        let map = host_map();
        let path = PathBuf::from("/c/overrides.toml");
        let mut p = Scripted::new(
            &[
                "",
                "",
                "",
                "",
                "",
                "",
                "",
                "1",
                "http://locked/v1",
                "y",
                "sk-local-123",
                "2",
                "",
                "",
            ],
            &[Key::Enter],
        );
        let i = inputs(&map, toml::Table::new(), &path);
        let table = wizard(&i, &mut p).unwrap();
        assert_eq!(
            ai_setting(&table, "api_key_file").as_deref(),
            Some("/c/secrets/ai-key")
        );
        assert!(!toml::to_string(&table).unwrap().contains("sk-local-123"));
        assert_eq!(i.new_key.borrow().as_deref(), Some("sk-local-123"));
        assert_eq!(ai_setting(&table, "model").as_deref(), Some("qwen"));
    }

    #[test]
    fn a_failed_test_sets_up_no_ai_unless_the_user_insists() {
        let table = ai_answers(&["1", "http://router/v1", "", "", ""], &BROKEN, vec![]);
        assert_eq!(ai_setting(&table, "url"), None);
        let table = ai_answers(&["1", "http://router/v1", "", "", "y"], &BROKEN, vec![]);
        assert_eq!(
            ai_setting(&table, "url").as_deref(),
            Some("http://router/v1")
        );
    }

    #[test]
    fn no_ai_is_the_default_when_nothing_was_found() {
        let table = ai_answers(&[""], &WORKS, vec![]);
        assert_eq!(lookup(&table, &["screening", "ai"]), None);
    }

    fn schedule_answers(existing: &str, answers: &[&'static str]) -> (Option<String>, String) {
        let map = host_map();
        let path = PathBuf::from("/c/overrides.toml");
        let mut all = vec!["", "", "", "", "", "", "", ""];
        all.extend_from_slice(answers);
        all.push("");
        let mut p = Scripted::new(&all, &[Key::Enter]);
        let table = wizard(&inputs(&map, existing.parse().unwrap(), &path), &mut p).unwrap();
        (
            lookup(&table, &["schedule", "at"])
                .and_then(toml::Value::as_str)
                .map(str::to_string),
            p.transcript(),
        )
    }

    #[test]
    fn the_nightly_run_is_scheduled_with_one_key() {
        let (at, transcript) = schedule_answers("", &[""]);
        assert_eq!(at.as_deref(), Some("03:00"), "Enter takes the suggestion");
        assert!(
            transcript.contains("? Nightly run\n") && transcript.contains("✓ Nightly run: 3:00 am"),
            "{transcript}"
        );
        assert_eq!(schedule_answers("", &["3"]).0.as_deref(), Some("05:00"));
        assert_eq!(schedule_answers("", &["5"]).0.as_deref(), Some("off"));
        // Another time: a bad answer is asked again.
        let (at, transcript) = schedule_answers("", &["4", "11pm", "23:30"]);
        assert_eq!(at.as_deref(), Some("23:30"));
        assert!(
            transcript.contains("\"11pm\" is not a time"),
            "{transcript}"
        );
    }

    #[test]
    fn the_saved_schedule_is_suggested_next_time() {
        let off = "[schedule]\nat = \"off\"\n";
        assert_eq!(schedule_answers(off, &[""]).0.as_deref(), Some("off"));
        let late = "[schedule]\nat = \"23:30\"\n";
        // Enter picks "another time", and Enter again keeps 23:30.
        assert_eq!(
            schedule_answers(late, &["", ""]).0.as_deref(),
            Some("23:30")
        );
        let one = "[schedule]\nat = \"01:00\"\n";
        assert_eq!(schedule_answers(one, &[""]).0.as_deref(), Some("01:00"));
    }

    #[test]
    fn no_schedule_question_where_it_cannot_be_installed() {
        let map = host_map();
        let path = PathBuf::from("/c/overrides.toml");
        let mut p = accept_all();
        let mut i = inputs(&map, toml::Table::new(), &path);
        i.schedule = false;
        let table = wizard(&i, &mut p).unwrap();
        assert_eq!(lookup(&table, &["schedule"]), None);
    }

    const SAVED: &str = r#"
schema_version = 1
[defaults]
policy = "auto"
[providers.homebrew]
greedy_casks = true
[screening]
wait_days = 0
hold_major = true
hold_words = true
[screening.ai]
url = "http://router/v1"
model = "auto"
[schedule]
at = "03:00"
[items."node@24"]
policy = "alert"
"#;

    fn rerun(answers: &[&'static str], keys: &[Key]) -> (Option<toml::Table>, Scripted) {
        let map = host_map();
        let path = PathBuf::from("/c/overrides.toml");
        let mut p = Scripted::new(answers, keys);
        let table = wizard(&inputs(&map, SAVED.parse().unwrap(), &path), &mut p);
        (table, p)
    }

    #[test]
    fn running_setup_again_shows_every_setting_and_changes_only_one() {
        // 9 = Nightly run, then 3 = 5:00 am, then Enter saves.
        let (table, p) = rerun(&["9", "3", ""], &[]);
        let table = table.unwrap();
        let transcript = p.transcript();
        for line in [
            "Updates by default: auto",
            "Wait after a release: no wait",
            "AI check: auto at router",
            "Nightly run: 3:00 am",
            "Packages: 1 set differently",
        ] {
            assert!(
                transcript.contains(line),
                "{line}
{transcript}"
            );
        }
        assert_eq!(p.questions, 3, "menu, the one question, menu");
        assert!(transcript.contains("Nightly run: 5:00 am"), "{transcript}");
        let expected: toml::Table = SAVED.replace("03:00", "05:00").parse().unwrap();
        assert_eq!(table, expected, "nothing else changed");
    }

    #[test]
    fn enter_saves_unchanged_and_q_saves_nothing() {
        let (table, p) = rerun(&[""], &[]);
        assert_eq!(table.unwrap(), SAVED.parse::<toml::Table>().unwrap());
        assert_eq!(p.questions, 1);
        assert!(rerun(&["5", "2", "q"], &[]).0.is_none());
        assert!(rerun(&[], &[]).0.is_none(), "ended input saves nothing");
    }

    #[test]
    fn leaving_the_checklist_from_the_menu_drops_only_its_changes() {
        // 1 = default policy -> alert; 0 = packages, change one, leave.
        let (table, _) = rerun(&["1", "2", "0", ""], &[Key::Char('i'), Key::Quit]);
        let table = table.unwrap();
        assert_eq!(
            lookup(&table, &["defaults", "policy"]).and_then(toml::Value::as_str),
            Some("alert")
        );
        assert_eq!(
            lookup(&table, &["items"]),
            None,
            "node@24 now matches the default; the checklist edit was dropped"
        );
    }

    #[test]
    fn changing_the_default_in_the_checklist_is_saved() {
        let map = host_map();
        let path = PathBuf::from("/c/overrides.toml");
        let mut p = Scripted::new(
            &["", "", "", "", "", "", "", "", "", ""],
            &[Key::Char('d'), Key::Enter],
        );
        let table = wizard(&inputs(&map, toml::Table::new(), &path), &mut p).unwrap();
        assert_eq!(
            lookup(&table, &["defaults", "policy"]).and_then(toml::Value::as_str),
            Some("alert")
        );
    }

    #[test]
    fn leaving_the_checklist_or_ending_input_saves_nothing() {
        let map = host_map();
        let path = PathBuf::from("/c/overrides.toml");
        let mut p = Scripted::new(
            &["", "", "", "", "", "", "", "", "", ""],
            &[Key::Char('l'), Key::Quit],
        );
        assert!(wizard(&inputs(&map, toml::Table::new(), &path), &mut p).is_none());
        let mut p = Scripted::new(&["", ""], &[]);
        assert!(wizard(&inputs(&map, toml::Table::new(), &path), &mut p).is_none());
    }

    #[test]
    fn the_menu_takes_one_key_and_lines_up_with_answers() {
        assert_eq!(menu_key(Key::Char('1'), 10), Some(MenuPick::Change(0)));
        assert_eq!(menu_key(Key::Char('0'), 10), Some(MenuPick::Change(9)));
        assert_eq!(menu_key(Key::Char('0'), 9), None);
        assert_eq!(menu_key(Key::Enter, 3), Some(MenuPick::Save));
        assert_eq!(menu_key(Key::Char('q'), 3), Some(MenuPick::Quit));
        let rows = [("Nightly run".to_string(), "3:00 am".to_string())];
        let menu = menu_lines("Settings", &rows, "", false);
        assert_eq!(
            menu,
            [
                "Settings",
                "",
                "  1  Nightly run                     3:00 am"
            ]
        );
    }

    #[test]
    fn long_addresses_are_cut_in_the_middle() {
        assert_eq!(
            short_url("http://192.168.1.10:8090/c/updates/v1"),
            "http://192.168.1.10:8090/…/v1"
        );
        assert_eq!(short_url("http://127.0.0.1:9/v1"), "http://127.0.0.1:9/v1");
    }

    #[test]
    fn errors_are_cut_to_their_last_reason() {
        assert_eq!(
            short_error(
                "http://h/v1/models: curl: (7) Failed to connect to h port 9 after 0 ms: Couldn't connect to server"
            ),
            "Couldn't connect to server"
        );
        assert_eq!(short_error("timed out"), "timed out");
    }

    #[test]
    fn overrides_are_private_and_replace_the_old_file() {
        let dir = std::env::temp_dir().join(format!("gu-setup-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("overrides.toml");
        let table: toml::Table = "schema_version = 1\n".parse().unwrap();
        write_overrides(&path, &table).unwrap();
        write_overrides(&path, &table).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.starts_with("# Written by `guarded-update setup`"));
        assert!(text.contains("schema_version = 1"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
