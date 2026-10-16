//! Two-layer TOML config (ADR-0001 D12): an optional base file rendered by
//! configuration management, then a local overrides file written only by
//! the setup wizard. Later layers win per leaf key; `explain` reports which
//! layer each effective value came from.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Layer {
    Default,
    Base,
    Overrides,
}

impl fmt::Display for Layer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Layer::Default => "default",
            Layer::Base => "base",
            Layer::Overrides => "overrides",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Policy {
    Auto,
    Alert,
    Ignore,
}

impl fmt::Display for Policy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Policy::Auto => "auto",
            Policy::Alert => "alert",
            Policy::Ignore => "ignore",
        })
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    pub schema_version: Option<u32>,
    /// `false` = report only, never install (the kill switch).
    pub enabled: bool,
    pub defaults: Defaults,
    pub paths: Paths,
    pub secrets: Secrets,
    pub timeouts: Timeouts,
    pub providers: Providers,
    pub screening: Screening,
    pub schedule: Schedule,
    pub items: BTreeMap<String, ItemConfig>,
    /// launchd services keyed by label: what affects them and how to
    /// restart and check them.
    pub services: BTreeMap<String, ServiceConfig>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            schema_version: None,
            enabled: true,
            defaults: Defaults::default(),
            paths: Paths::default(),
            secrets: Secrets::default(),
            timeouts: Timeouts::default(),
            providers: Providers::default(),
            screening: Screening::default(),
            schedule: Schedule::default(),
            items: BTreeMap::new(),
            services: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct Defaults {
    pub policy: Policy,
}

impl Default for Defaults {
    fn default() -> Self {
        Self {
            policy: Policy::Alert,
        }
    }
}

/// When the nightly run starts; setup installs the launchd job from it.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct Schedule {
    /// `HH:MM` (24-hour, local time) or `off`; unset means never asked.
    pub at: Option<String>,
}

/// Safety checks before an `auto` install (ADR-0001 D8). Each can only
/// hold an update.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct Screening {
    /// Days to wait after a version first appears; 0 turns this off.
    pub wait_days: u32,
    /// Hold 2.x -> 3.0 (and 0.21 -> 0.22) without a successful AI review.
    pub hold_major: bool,
    /// Without AI, hold when the release notes contain one of `words`.
    pub hold_words: bool,
    pub words: Vec<String>,
    pub ai: Ai,
}

/// The optional AI check: an OpenAI-compatible model server on this
/// computer or the local network. Off while `url` is unset.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct Ai {
    /// Base address ending in `/v1`, e.g. `http://127.0.0.1:11434/v1`.
    pub url: Option<String>,
    pub model: String,
    /// File holding an API key, when the server needs one.
    pub api_key_file: Option<PathBuf>,
    pub timeout_secs: u64,
}

impl Default for Ai {
    fn default() -> Self {
        Self {
            url: None,
            model: "auto".into(),
            api_key_file: None,
            timeout_secs: 180,
        }
    }
}

impl Default for Screening {
    fn default() -> Self {
        Self {
            wait_days: 2,
            hold_major: true,
            hold_words: true,
            words: ["breaking", "removed", "migration"]
                .map(String::from)
                .to_vec(),
            ai: Ai::default(),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct Paths {
    pub state_dir: Option<PathBuf>,
    pub log_file: Option<PathBuf>,
}

/// Secrets are referenced by path, never written into the config.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct Secrets {
    /// Files whose values must never appear in any output.
    pub files: Vec<PathBuf>,
    /// Optional GitHub token, read only when a request is made.
    pub github_token_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct Timeouts {
    pub command_secs: u64,
    pub http_secs: u64,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            command_secs: 600,
            http_secs: 30,
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct Providers {
    pub homebrew: HomebrewConfig,
    pub hermes: HermesConfig,
    pub macos: MacosConfig,
    /// Versions pinned in git (alert only), keyed by a display name.
    pub pinned: BTreeMap<String, PinnedConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct HomebrewConfig {
    pub enabled: bool,
    pub command: String,
    /// Include casks that update themselves or use `version :latest`.
    pub greedy_casks: bool,
    /// Run `brew update` before detecting.
    pub refresh: bool,
}

impl Default for HomebrewConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            command: "brew".into(),
            greedy_casks: false,
            refresh: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct HermesConfig {
    pub enabled: bool,
    pub command: String,
    pub github_repo: String,
}

impl Default for HermesConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            command: "hermes".into(),
            github_repo: "NousResearch/hermes-agent".into(),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct MacosConfig {
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PinnedConfig {
    /// The version pinned today, for example `0.7.6`.
    pub current: String,
    /// `pypi:<package>` or `github:<owner>/<repo>`.
    pub source: String,
    /// Where the pin lives, shown in reports.
    #[serde(default)]
    pub pinned_in: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct ItemConfig {
    pub policy: Option<Policy>,
    pub notes_url: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, default)]
pub struct ServiceConfig {
    /// Homebrew packages whose upgrade affects this service.
    pub packages: Vec<String>,
    /// Command (no shell) that restarts it.
    pub restart: Vec<String>,
    /// Command (no shell) that exits 0 when it is healthy.
    pub health: Vec<String>,
    /// Text the health command's output must contain.
    pub health_expect: Option<String>,
    /// Restarting it needs root, so updates that affect it are never
    /// attempted.
    pub requires_root: bool,
}

/// A config with the layer each leaf value came from.
#[derive(Debug)]
pub struct Loaded {
    pub config: Config,
    origins: BTreeMap<String, Layer>,
    pub files: Vec<(Layer, PathBuf)>,
}

impl Loaded {
    /// The layer a dotted key (for example `providers.homebrew.refresh`)
    /// came from; keys set by no file are `Default`.
    pub fn origin(&self, key: &str) -> Layer {
        self.origins.get(key).copied().unwrap_or(Layer::Default)
    }

    /// The effective policy for an item and the key that decided it.
    pub fn policy_for(&self, item: &str) -> (Policy, String, Layer) {
        if let Some(policy) = self.config.items.get(item).and_then(|i| i.policy) {
            let key = format!("items.{item}.policy");
            let layer = self.origin(&key);
            return (policy, key, layer);
        }
        let key = "defaults.policy".to_string();
        let layer = self.origin(&key);
        (self.config.defaults.policy, key, layer)
    }
}

/// Merges layers in order; later layers win per leaf. Returns the merged
/// table and the origin of every leaf key.
pub fn merge(layers: Vec<(Layer, toml::Table)>) -> (toml::Table, BTreeMap<String, Layer>) {
    let mut merged = toml::Table::new();
    let mut origins = BTreeMap::new();
    for (layer, table) in layers {
        merge_into(&mut merged, table, layer, "", &mut origins);
    }
    (merged, origins)
}

fn merge_into(
    target: &mut toml::Table,
    source: toml::Table,
    layer: Layer,
    prefix: &str,
    origins: &mut BTreeMap<String, Layer>,
) {
    for (key, value) in source {
        let path = if prefix.is_empty() {
            key.clone()
        } else {
            format!("{prefix}.{key}")
        };
        match (target.get_mut(&key), value) {
            (Some(toml::Value::Table(existing)), toml::Value::Table(incoming)) => {
                merge_into(existing, incoming, layer, &path, origins);
            }
            (_, toml::Value::Table(incoming)) => {
                let mut fresh = toml::Table::new();
                merge_into(&mut fresh, incoming, layer, &path, origins);
                // A table replacing a leaf drops the leaf's recorded origin.
                origins.remove(&path);
                target.insert(key, toml::Value::Table(fresh));
            }
            (_, leaf) => {
                // A leaf replacing a table drops the table's leaf origins.
                let nested = format!("{path}.");
                origins.retain(|k, _| !k.starts_with(&nested));
                origins.insert(path, layer);
                target.insert(key, leaf);
            }
        }
    }
}

/// Loads both layers; a missing file is skipped. Every problem found is
/// returned, not just the first.
pub fn load(base: &Path, overrides: &Path) -> Result<Loaded, Vec<String>> {
    let mut errors = Vec::new();
    let mut layers = Vec::new();
    let mut files = Vec::new();
    for (layer, path) in [(Layer::Base, base), (Layer::Overrides, overrides)] {
        if !path.exists() {
            continue;
        }
        files.push((layer, path.to_path_buf()));
        if let Some(table) = read_layer(layer, path, &mut errors) {
            layers.push((layer, table));
        }
    }
    let (merged, origins) = merge(layers);
    let config = if errors.is_empty() {
        match toml::Value::Table(merged).try_into::<Config>() {
            Ok(config) => Some(config),
            Err(e) => {
                errors.push(format!("merged config: {}", e.message()));
                None
            }
        }
    } else {
        None
    };
    if let Some(config) = &config {
        validate(config, &mut errors);
    }
    match config {
        Some(config) if errors.is_empty() => Ok(Loaded {
            config,
            origins,
            files,
        }),
        _ => Err(errors),
    }
}

fn read_layer(layer: Layer, path: &Path, errors: &mut Vec<String>) -> Option<toml::Table> {
    let shown = path.display();
    check_private(path, errors);
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) => {
            errors.push(format!("{shown}: cannot read ({})", e.kind()));
            return None;
        }
    };
    let table: toml::Table = match text.parse() {
        Ok(table) => table,
        Err(e) => {
            errors.push(format!("{shown} ({layer} layer): {e}"));
            return None;
        }
    };
    match table.get("schema_version").and_then(toml::Value::as_integer) {
        None => errors.push(format!(
            "{shown}: schema_version is required (this version reads schema_version {SCHEMA_VERSION})"
        )),
        Some(v) if v != i64::from(SCHEMA_VERSION) => errors.push(format!(
            "{shown}: schema_version {v} is not supported (this version reads schema_version {SCHEMA_VERSION})"
        )),
        Some(_) => {}
    }
    // Type-check this layer alone so errors name the right file and line.
    if let Err(e) = toml::from_str::<Config>(&text) {
        errors.push(format!("{shown} ({layer} layer): {e}"));
        return None;
    }
    Some(table)
}

fn check_private(path: &Path, errors: &mut Vec<String>) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            let mode = meta.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                errors.push(format!(
                    "{}: must be mode 0600 because restart commands in it run as this user; found {mode:04o}",
                    path.display()
                ));
            }
        }
    }
    #[cfg(not(unix))]
    let _ = (path, errors);
}

fn is_owner_repo(text: &str) -> bool {
    let mut parts = text.split('/');
    let ok = |p: Option<&str>| {
        p.is_some_and(|p| {
            !p.is_empty()
                && p.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        })
    };
    ok(parts.next()) && ok(parts.next()) && parts.next().is_none()
}

fn validate(config: &Config, errors: &mut Vec<String>) {
    if config.timeouts.command_secs == 0 {
        errors.push("timeouts.command_secs must be greater than 0".into());
    }
    if config.timeouts.http_secs == 0 {
        errors.push("timeouts.http_secs must be greater than 0".into());
    }
    if let Some(at) = &config.schedule.at
        && crate::schedule::parse(at).is_none()
    {
        errors.push(format!(
            "schedule.at must be a 24-hour time like \"03:00\" or \"off\", not \"{at}\""
        ));
    }
    if config.screening.wait_days > 365 {
        errors.push("screening.wait_days must be 365 or less".into());
    }
    if let Some(url) = &config.screening.ai.url
        && !(url.starts_with("http://") || url.starts_with("https://"))
    {
        errors.push(format!(
            "screening.ai.url must start with http:// or https://, got `{url}`"
        ));
    }
    if config.screening.ai.timeout_secs == 0 {
        errors.push("screening.ai.timeout_secs must be greater than 0".into());
    }
    if config.screening.words.iter().any(|w| w.trim().is_empty()) {
        errors.push("screening.words must not contain empty words".into());
    }
    if !is_owner_repo(&config.providers.hermes.github_repo) {
        errors.push(format!(
            "providers.hermes.github_repo must be <owner>/<repo>, got `{}`",
            config.providers.hermes.github_repo
        ));
    }
    for (name, pinned) in &config.providers.pinned {
        let valid = match pinned.source.split_once(':') {
            Some(("pypi", package)) => !package.is_empty() && !package.contains('/'),
            Some(("github", repo)) => is_owner_repo(repo),
            _ => false,
        };
        if !valid {
            errors.push(format!(
                "providers.pinned.{name}.source must be `pypi:<package>` or `github:<owner>/<repo>`, got `{}`",
                pinned.source
            ));
        }
        if pinned.current.trim().is_empty() {
            errors.push(format!("providers.pinned.{name}.current must not be empty"));
        }
    }
    for (label, service) in &config.services {
        if service.packages.iter().any(|p| p.trim().is_empty()) {
            errors.push(format!(
                "services.{label}.packages must not contain empty names"
            ));
        }
        for (key, argv) in [("restart", &service.restart), ("health", &service.health)] {
            if argv.first().is_some_and(|p| p.trim().is_empty()) {
                errors.push(format!("services.{label}.{key} must start with a program"));
            }
        }
        if service.health_expect.is_some() && service.health.is_empty() {
            errors.push(format!(
                "services.{label}.health_expect needs a health command"
            ));
        }
    }
    for (name, item) in &config.items {
        if let Some(url) = &item.notes_url
            && !url.starts_with("https://")
        {
            errors.push(format!("items.{name}.notes_url must start with https://"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(text: &str) -> toml::Table {
        text.parse().unwrap()
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("gu-config-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_private(path: &Path, text: &str) {
        std::fs::write(path, text).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    #[test]
    fn later_layer_wins_per_leaf_and_origins_are_recorded() {
        let (merged, origins) = merge(vec![
            (
                Layer::Base,
                table("[providers.homebrew]\nrefresh = false\ngreedy_casks = true\n"),
            ),
            (
                Layer::Overrides,
                table("[providers.homebrew]\nrefresh = true\n"),
            ),
        ]);
        let hb = merged["providers"]["homebrew"].as_table().unwrap();
        assert_eq!(hb["refresh"].as_bool(), Some(true));
        assert_eq!(hb["greedy_casks"].as_bool(), Some(true));
        assert_eq!(origins["providers.homebrew.refresh"], Layer::Overrides);
        assert_eq!(origins["providers.homebrew.greedy_casks"], Layer::Base);
    }

    #[test]
    fn no_files_means_defaults_and_alert_policy() {
        let dir = temp_dir("none");
        let loaded = load(&dir.join("base.toml"), &dir.join("overrides.toml")).unwrap();
        assert!(loaded.files.is_empty());
        assert_eq!(loaded.config.defaults.policy, Policy::Alert);
        assert!(loaded.config.providers.homebrew.enabled);
        assert!(!loaded.config.providers.hermes.enabled);
        assert_eq!(loaded.policy_for("node@24").0, Policy::Alert);
        assert_eq!(loaded.origin("defaults.policy"), Layer::Default);
    }

    #[test]
    fn item_policy_and_its_layer_are_explained() {
        let dir = temp_dir("explain");
        let base = dir.join("base.toml");
        let over = dir.join("overrides.toml");
        write_private(
            &base,
            "schema_version = 1\n[defaults]\npolicy = \"ignore\"\n[items.jq]\npolicy = \"alert\"\n",
        );
        write_private(&over, "schema_version = 1\n[items.jq]\npolicy = \"auto\"\n");
        let loaded = load(&base, &over).unwrap();
        assert_eq!(
            loaded.policy_for("jq"),
            (
                Policy::Auto,
                "items.jq.policy".to_string(),
                Layer::Overrides
            )
        );
        assert_eq!(
            loaded.policy_for("other"),
            (Policy::Ignore, "defaults.policy".to_string(), Layer::Base)
        );
        assert_eq!(loaded.origin("items.jq.policy"), Layer::Overrides);
    }

    #[test]
    fn unknown_keys_bad_values_and_missing_schema_version_are_all_reported() {
        let dir = temp_dir("invalid");
        let base = dir.join("base.toml");
        write_private(&base, "[defaults]\npolicy = \"sometimes\"\nbogus = 1\n");
        let errors = load(&base, &dir.join("overrides.toml")).unwrap_err();
        let all = errors.join("\n");
        assert!(all.contains("schema_version"), "{all}");
        assert!(all.contains("sometimes") || all.contains("bogus"), "{all}");
    }

    #[test]
    fn wrong_schema_version_is_rejected() {
        let dir = temp_dir("schema");
        let base = dir.join("base.toml");
        write_private(&base, "schema_version = 7\n");
        let errors = load(&base, &dir.join("o.toml")).unwrap_err();
        assert!(errors.join("\n").contains("schema_version 7"));
    }

    #[test]
    fn pinned_sources_and_repos_are_validated() {
        let dir = temp_dir("pinned");
        let base = dir.join("base.toml");
        write_private(
            &base,
            "schema_version = 1\n[providers.hermes]\ngithub_repo = \"nope\"\n[providers.pinned.example]\ncurrent = \"0.7.6\"\nsource = \"npm:example\"\n",
        );
        let all = load(&base, &dir.join("o.toml")).unwrap_err().join("\n");
        assert!(all.contains("providers.pinned.example.source"), "{all}");
        assert!(all.contains("providers.hermes.github_repo"), "{all}");
    }

    #[test]
    fn services_are_loaded_and_validated() {
        let dir = temp_dir("services");
        let base = dir.join("base.toml");
        write_private(
            &base,
            "schema_version = 1\n[services.\"com.x.y\"]\npackages = [\"node@24\"]\nrestart = [\"launchctl\", \"kickstart\", \"-k\", \"gui/501/com.x.y\"]\nhealth = [\"launchctl\", \"list\", \"com.x.y\"]\nhealth_expect = \"PID\"\n",
        );
        let loaded = load(&base, &dir.join("o.toml")).unwrap();
        let svc = &loaded.config.services["com.x.y"];
        assert_eq!(svc.packages, vec!["node@24".to_string()]);
        assert!(!svc.requires_root);

        write_private(
            &base,
            "schema_version = 1\n[services.a]\nhealth_expect = \"x\"\nrestart = [\"\"]\n",
        );
        let all = load(&base, &dir.join("o.toml")).unwrap_err().join("\n");
        assert!(all.contains("services.a.restart"), "{all}");
        assert!(all.contains("services.a.health_expect"), "{all}");

        write_private(
            &base,
            "schema_version = 1\n[services.a]\nrestrat = [\"x\"]\n",
        );
        let all = load(&base, &dir.join("o.toml")).unwrap_err().join("\n");
        assert!(all.contains("restrat"), "{all}");
    }

    #[cfg(unix)]
    #[test]
    fn group_or_world_readable_config_is_rejected() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("mode");
        let base = dir.join("base.toml");
        std::fs::write(&base, "schema_version = 1\n").unwrap();
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o644)).unwrap();
        let all = load(&base, &dir.join("o.toml")).unwrap_err().join("\n");
        assert!(all.contains("0600"), "{all}");
    }

    #[test]
    fn the_schedule_takes_a_time_or_off() {
        let dir = temp_dir("schedule");
        let base = dir.join("base.toml");
        write_private(&base, "schema_version = 1\n[schedule]\nat = \"03:00\"\n");
        let loaded = load(&base, &dir.join("o.toml")).unwrap();
        assert_eq!(loaded.config.schedule.at.as_deref(), Some("03:00"));
        write_private(&base, "schema_version = 1\n[schedule]\nat = \"3am\"\n");
        let all = load(&base, &dir.join("o.toml")).unwrap_err().join("\n");
        assert!(all.contains("schedule.at must be"), "{all}");
    }

    #[test]
    fn toml_syntax_errors_name_the_file() {
        let dir = temp_dir("syntax");
        let base = dir.join("base.toml");
        write_private(&base, "schema_version = = 1\n");
        let all = load(&base, &dir.join("o.toml")).unwrap_err().join("\n");
        assert!(all.contains("base.toml"), "{all}");
    }
}
