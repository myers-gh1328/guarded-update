//! What detection produces: available updates and the dependency groups
//! they are applied in (ADR-0001 D3).

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Source {
    HomebrewFormula,
    HomebrewCask,
    Hermes,
    Pinned,
    Macos,
}

impl Source {
    pub fn label(self) -> &'static str {
        match self {
            Source::HomebrewFormula => "formula",
            Source::HomebrewCask => "cask",
            Source::Hermes => "hermes",
            Source::Pinned => "pinned",
            Source::Macos => "macos",
        }
    }
}

/// How the version moved (ADR-0001 D7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Change {
    /// Same upstream version, new Homebrew revision (`_N`).
    Rebuild,
    Version,
}

/// What guarded-update may do with an update.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Action {
    Update,
    /// Reported only, never updated (macOS, versions pinned in git).
    AlertOnly,
    /// Needs root; reported as manual action, never attempted (R13).
    ManualSudo,
    /// Pinned with `brew pin`; Homebrew will not upgrade it.
    PinnedInHomebrew,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Update {
    pub source: Source,
    pub name: String,
    pub installed: String,
    pub available: String,
    pub change: Change,
    pub action: Action,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// One unit of change: everything a single upgrade pulls in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Group {
    pub source: Source,
    /// Every package the upgrade changes, sorted.
    pub members: Vec<String>,
    /// New packages the upgrade would install, as `name version`.
    pub new_dependencies: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Detection {
    pub updates: Vec<Update>,
    pub groups: Vec<Group>,
    pub errors: Vec<String>,
}

impl Detection {
    pub fn extend(&mut self, other: Detection) {
        self.updates.extend(other.updates);
        self.groups.extend(other.groups);
        self.errors.extend(other.errors);
    }
}
