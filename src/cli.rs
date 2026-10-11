//! Hand-written argument parsing (no CLI crate; owner decision 2026-10-09).

use std::path::PathBuf;

/// Every subcommand in ADR-0001 D2. Ones not built yet say so.
pub const COMMANDS: &[&str] = &[
    "setup", "check", "screen", "apply", "report", "run", "validate", "explain", "history",
    "approve", "auto", "ignore",
];

#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    Help,
    Version,
    Check,
    Run,
    Validate,
    Explain(Option<String>),
    Setup,
    /// A D2 command that a later slice implements.
    NotYet(String),
}

#[derive(Debug, PartialEq, Eq)]
pub struct Cli {
    pub command: Command,
    pub dry_run: bool,
    pub no_refresh: bool,
    pub config: Option<PathBuf>,
    pub overrides: Option<PathBuf>,
    pub state_dir: Option<PathBuf>,
    /// `setup --rescan`: refresh the saved service list only.
    pub rescan: bool,
}

pub fn usage() -> String {
    format!(
        "guarded-update {}

Keeps this host's software current overnight, one dependency group at a time.

Usage: guarded-update <command> [options]

Commands:
  check              List available updates and dependency groups
  run                Update what passed the safety checks, restart and
                     health-check affected services, hold failures
  run --dry-run      The same pass without changing anything
  validate           Check the config
  explain [item]     Show effective settings and the layer each came from
  setup              Answer questions to create or change this host's config
  setup --rescan     Refresh the saved list of services, asking nothing
  screen, apply, report, history, approve, auto, ignore
                     Not available in this version

Options:
  --dry-run          Change nothing (accepted by every command)
  --no-refresh       Skip `brew update` before detecting
  --config <path>    Base config (default: ~/.config/guarded-update/base.toml)
  --overrides <path> Overrides (default: ~/.config/guarded-update/overrides.toml)
  --state-dir <path> State, history and lock (default: ~/.local/state/guarded-update)
  -h, --help         Show this help
  -V, --version      Show the version",
        env!("CARGO_PKG_VERSION")
    )
}

pub fn parse(args: &[String]) -> Result<Cli, String> {
    let mut cli = Cli {
        command: Command::Help,
        dry_run: false,
        no_refresh: false,
        config: None,
        overrides: None,
        state_dir: None,
        rescan: false,
    };
    let mut help = false;
    let mut version = false;
    let mut positionals: Vec<String> = Vec::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let (flag, inline) = match arg.split_once('=') {
            Some((f, v)) if f.starts_with("--") => (f, Some(v.to_string())),
            _ => (arg.as_str(), None),
        };
        let mut value = |name: &str| -> Result<PathBuf, String> {
            inline
                .clone()
                .or_else(|| iter.next().cloned())
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
                .ok_or_else(|| format!("{name} needs a value"))
        };
        match flag {
            "-h" | "--help" => help = true,
            "-V" | "--version" => version = true,
            "--dry-run" => cli.dry_run = true,
            "--no-refresh" => cli.no_refresh = true,
            "--config" => cli.config = Some(value("--config")?),
            "--overrides" => cli.overrides = Some(value("--overrides")?),
            "--state-dir" => cli.state_dir = Some(value("--state-dir")?),
            "--rescan" => cli.rescan = true,
            other if other.starts_with('-') => return Err(format!("unknown option: {other}")),
            other => positionals.push(other.to_string()),
        }
    }
    if help {
        return Ok(cli);
    }
    if version {
        cli.command = Command::Version;
        return Ok(cli);
    }
    let Some((name, rest)) = positionals.split_first() else {
        return Ok(cli);
    };
    let no_args = |command: Command| {
        if rest.is_empty() {
            Ok(command)
        } else {
            Err(format!(
                "`{name}` takes no arguments, got `{}`",
                rest.join(" ")
            ))
        }
    };
    cli.command = match name.as_str() {
        "check" => no_args(Command::Check)?,
        "run" => no_args(Command::Run)?,
        "validate" => no_args(Command::Validate)?,
        "setup" => no_args(Command::Setup)?,
        "explain" => match rest {
            [] => Command::Explain(None),
            [item] => Command::Explain(Some(item.clone())),
            _ => return Err("`explain` takes at most one item".into()),
        },
        known if COMMANDS.contains(&known) => Command::NotYet(known.to_string()),
        unknown => return Err(format!("unknown command: {unknown}")),
    };
    if cli.rescan && cli.command != Command::Setup {
        return Err("--rescan works only with `setup`".into());
    }
    Ok(cli)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(list: &[&str]) -> Result<Cli, String> {
        parse(&list.iter().map(|s| (*s).to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn no_arguments_and_help_flags_show_help() {
        assert_eq!(p(&[]).unwrap().command, Command::Help);
        assert_eq!(p(&["--help"]).unwrap().command, Command::Help);
        assert_eq!(p(&["check", "-h"]).unwrap().command, Command::Help);
        assert_eq!(p(&["-V"]).unwrap().command, Command::Version);
    }

    #[test]
    fn options_may_come_before_or_after_the_command() {
        let cli = p(&[
            "--state-dir",
            "/s",
            "run",
            "--dry-run",
            "--no-refresh",
            "--config=/b.toml",
        ])
        .unwrap();
        assert_eq!(cli.command, Command::Run);
        assert!(cli.dry_run && cli.no_refresh);
        assert_eq!(cli.state_dir, Some(PathBuf::from("/s")));
        assert_eq!(cli.config, Some(PathBuf::from("/b.toml")));
    }

    #[test]
    fn explain_takes_an_optional_item() {
        assert_eq!(p(&["explain"]).unwrap().command, Command::Explain(None));
        assert_eq!(
            p(&["explain", "node@24"]).unwrap().command,
            Command::Explain(Some("node@24".into()))
        );
        assert!(p(&["explain", "a", "b"]).is_err());
    }

    #[test]
    fn later_commands_are_recognised_but_not_yet_available() {
        for name in ["screen", "apply", "approve", "history"] {
            assert_eq!(
                p(&[name, "x"]).unwrap().command,
                Command::NotYet(name.into())
            );
        }
    }

    #[test]
    fn mistakes_are_errors() {
        assert!(p(&["frobnicate"]).unwrap_err().contains("unknown command"));
        assert!(p(&["check", "--bogus"]).unwrap_err().contains("--bogus"));
        assert!(p(&["check", "extra"]).is_err());
        assert!(
            p(&["check", "--config"])
                .unwrap_err()
                .contains("needs a value")
        );
    }

    #[test]
    fn rescan_belongs_to_setup_only() {
        let cli = p(&["setup", "--rescan"]).unwrap();
        assert_eq!(cli.command, Command::Setup);
        assert!(cli.rescan);
        assert!(!p(&["setup"]).unwrap().rescan);
        assert!(p(&["check", "--rescan"]).unwrap_err().contains("setup"));
    }
}
