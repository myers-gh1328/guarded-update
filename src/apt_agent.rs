//! Approval-only APT entry point. No installation command is available.
use crate::exec::{Runner, SystemRunner};
use crate::output::Output;
use crate::redact::Redactor;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Operation {
    Install,
    Replace,
    Remove,
}

#[derive(Debug, Serialize)]
struct PackageChange {
    package: String,
    installed: Option<String>,
    target: Option<String>,
    operation: Operation,
    /// APT's source description, not an authenticated repository identity.
    source_description: Option<String>,
}

#[derive(Serialize)]
struct Proposal {
    schema_version: u32,
    kind: &'static str,
    generated_at_unix: u64,
    changes: Vec<PackageChange>,
    explicitly_held_packages: Vec<String>,
    metadata_freshness: &'static str,
    restart_impact: &'static str,
    repository_identity_verified: bool,
    execution_supported: bool,
    coverage: Vec<&'static str>,
}

fn package_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 256
        && name.as_bytes()[0].is_ascii_alphanumeric()
        && name
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"+.-:".contains(&c))
}

// APT appends transient dependency diagnostics after the parenthesized candidate.
// They are not package versions or additional actions. Keep their grammar bounded.
fn without_dependency_annotations(mut text: &str) -> Result<&str, String> {
    text = text.trim_end();
    while text.ends_with(']') {
        let open = text
            .rfind('[')
            .ok_or("Malformed APT dependency annotation")?;
        let annotation = &text[open + 1..text.len() - 1];
        if annotation.len() > 16384 || !annotation.split_whitespace().all(package_name) {
            return Err("Invalid APT dependency annotation".into());
        }
        text = text[..open].trim_end();
    }
    Ok(text)
}

fn parse_simulation(text: &str) -> Result<Vec<PackageChange>, String> {
    let summaries: Vec<_> = text
        .lines()
        .filter(|line| line.ends_with("not upgraded."))
        .collect();
    if summaries.len() != 1 {
        return Err("Missing or duplicate APT transaction summary".into());
    }
    let words: Vec<_> = summaries[0].split_whitespace().collect();
    if words.len() != 12
        || words[1] != "upgraded,"
        || words[3..5] != ["newly", "installed,"]
        || words[6..9] != ["to", "remove", "and"]
        || words[10..12] != ["not", "upgraded."]
    {
        return Err("Unsupported APT transaction summary".into());
    }
    let counts: Vec<usize> = [0, 2, 5, 9]
        .iter()
        .map(|i| words[*i].parse::<usize>())
        .collect::<Result<_, _>>()
        .map_err(|_| "Invalid APT transaction counts")?;
    let mut changes = Vec::new();
    let mut seen = BTreeSet::new();
    let mut configured = BTreeMap::new();
    for line in text.lines() {
        if line.starts_with("E:") {
            return Err("APT reported an error".into());
        }
        let Some((verb, rest)) = line.split_once(' ') else {
            continue;
        };
        if !["Inst", "Remv", "Conf"].contains(&verb) {
            continue;
        }
        let (name, detail) = rest.split_once(' ').ok_or("Incomplete APT transaction")?;
        if !package_name(name) {
            return Err("Invalid APT package identity".into());
        }
        if verb == "Conf" {
            let candidate = without_dependency_annotations(detail)?
                .strip_prefix('(')
                .and_then(|v| v.strip_suffix(')'))
                .ok_or("Invalid APT configuration record")?;
            let (version, source) = candidate
                .split_once(' ')
                .ok_or("Missing APT configuration version")?;
            if version.is_empty() || source.is_empty() {
                return Err("Invalid APT configuration record".into());
            }
            if configured
                .insert(name.to_owned(), version.to_owned())
                .is_some()
            {
                return Err("Duplicate APT configuration".into());
            }
            continue;
        }
        if !seen.insert(name.to_owned()) {
            return Err("Duplicate APT transaction package".into());
        }
        let (installed, tail) = if let Some(old) = detail.strip_prefix('[') {
            let (version, tail) = old.split_once(']').ok_or("Invalid installed version")?;
            if version.is_empty() || version.chars().any(char::is_whitespace) {
                return Err("Invalid installed version".into());
            }
            (Some(version.to_owned()), tail.trim())
        } else {
            (None, detail.trim())
        };
        let tail = without_dependency_annotations(tail)?;
        let (target, source_description, operation) = if verb == "Remv" {
            if installed.is_none() || !tail.is_empty() {
                return Err("Invalid APT removal".into());
            }
            (None, None, Operation::Remove)
        } else {
            let candidate = tail
                .strip_prefix('(')
                .and_then(|s| s.strip_suffix(')'))
                .ok_or("Invalid target version")?;
            let (version, source) = candidate
                .split_once(' ')
                .ok_or("Missing APT source description")?;
            if version.is_empty() || source.is_empty() {
                return Err("Invalid APT candidate".into());
            }
            (
                Some(version.to_owned()),
                Some(source.to_owned()),
                if installed.is_some() {
                    Operation::Replace
                } else {
                    Operation::Install
                },
            )
        };
        changes.push(PackageChange {
            package: name.to_owned(),
            installed,
            target,
            operation,
            source_description,
        });
    }
    let expected: BTreeMap<_, _> = changes
        .iter()
        .filter(|c| c.operation != Operation::Remove)
        .map(|c| (c.package.clone(), c.target.clone().unwrap_or_default()))
        .collect();
    if expected != configured {
        return Err("Incomplete APT simulation: configuration set differs".into());
    }
    if counts[0]
        != changes
            .iter()
            .filter(|c| c.operation == Operation::Replace)
            .count()
        || counts[1]
            != changes
                .iter()
                .filter(|c| c.operation == Operation::Install)
                .count()
        || counts[2]
            != changes
                .iter()
                .filter(|c| c.operation == Operation::Remove)
                .count()
    {
        return Err("APT transaction counts differ from parsed changes".into());
    }
    changes.sort_by(|a, b| a.package.cmp(&b.package));
    Ok(changes)
}

fn proposal(runner: &dyn Runner) -> Result<Proposal, String> {
    let env = &[("LC_ALL", "C"), ("LANG", "C")];
    let held = runner.run("/usr/bin/apt-mark", &["showhold"], env)?;
    if !held.success() {
        return Err("Cannot read APT package holds".into());
    }
    let mut holds: Vec<_> = held.stdout.lines().map(str::to_owned).collect();
    if holds.iter().any(|p| !package_name(p)) {
        return Err("Invalid APT held package".into());
    }
    holds.sort();
    holds.dedup();
    let simulation = runner.run(
        "/usr/bin/apt-get",
        &[
            "--simulate",
            "-o",
            "Debug::NoLocking=1",
            "--with-new-pkgs",
            "upgrade",
        ],
        env,
    )?;
    if !simulation.success() {
        return Err("APT simulation failed; no proposal produced".into());
    }
    if simulation.stdout.len() > 8 * 1024 * 1024 {
        return Err("APT simulation exceeds proposal limit".into());
    }
    let changes = parse_simulation(&simulation.stdout)?;
    if changes.iter().any(|change| {
        holds
            .iter()
            .any(|held| held.split(':').next() == change.package.split(':').next())
    }) {
        return Err(
            "APT proposed a change to an explicitly held package or ambiguous architecture".into(),
        );
    }
    Ok(Proposal {
        schema_version: 1,
        kind: "apt-upgrade-proposal",
        generated_at_unix: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "Invalid clock")?
            .as_secs(),
        changes,
        explicitly_held_packages: holds,
        metadata_freshness: "unknown",
        restart_impact: "unknown",
        repository_identity_verified: false,
        execution_supported: false,
        coverage: vec![
            "Existing APT indexes only; no metadata refresh performed",
            "Resolver upgrade transaction only; held or otherwise deferred candidates may be omitted",
            "Package scripts may restart services; no restart safety guarantee",
            "Installed-version transitions are not yet classified as upgrades versus downgrades",
        ],
    })
}

pub(crate) fn main() -> ExitCode {
    let out = Output::new(Redactor::patterns_only());
    let args: Vec<_> = std::env::args().skip(1).collect();
    match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        #[cfg(feature = "apt-executor")]
        [
            "broker",
            "--config",
            path,
            "--requests",
            requests,
            "--responses",
            responses,
        ] if cfg!(target_os = "linux") => {
            let result = crate::agent_protocol::RemoteConfig::load(std::path::Path::new(path))
                .and_then(|config| {
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map_err(|_| "Invalid clock")?
                        .as_secs();
                    crate::execution_broker::run(
                        &config,
                        std::path::Path::new(requests),
                        std::path::Path::new(responses),
                        now,
                    )
                });
            match result {
                Ok(message) => {
                    out.stdout(&message);
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    out.stdout(&error);
                    ExitCode::from(1)
                }
            }
        }
        #[cfg(feature = "apt-executor")]
        [
            "validate-execution",
            "--input",
            input,
            "--key",
            key,
            "--journal",
            journal,
        ] if cfg!(target_os = "linux") => {
            match crate::execution_validate::validate(
                std::path::Path::new(input),
                std::path::Path::new(key),
                std::path::Path::new(journal),
            ) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    out.stdout(&error);
                    ExitCode::from(1)
                }
            }
        }
        #[cfg(feature = "apt-remote")]
        ["sync", "--config", path] if cfg!(target_os = "linux") => {
            let result = crate::agent_protocol::RemoteConfig::load(std::path::Path::new(path))
                .and_then(|config| {
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map_err(|_| "Invalid clock")?
                        .as_secs();
                    crate::agent_protocol::sync(
                        &config,
                        || {
                            proposal(&SystemRunner::new(Duration::from_secs(120))).and_then(|p| {
                                serde_json::to_value(p)
                                    .map_err(|_| "Cannot encode APT proposal".into())
                            })
                        },
                        now,
                    )
                });
            match result {
                Ok(message) => {
                    out.stdout(&message);
                    ExitCode::SUCCESS
                }
                Err(error) => {
                    out.stdout(&error);
                    ExitCode::from(1)
                }
            }
        }
        ["--version"] => {
            #[cfg(feature = "apt-executor")]
            out.stdout(concat!(
                "guarded-update ",
                env!("CARGO_PKG_VERSION"),
                " (apt-executor)"
            ));
            #[cfg(all(feature = "apt-remote", not(feature = "apt-executor")))]
            out.stdout(concat!(
                "guarded-update ",
                env!("CARGO_PKG_VERSION"),
                " (apt-remote)"
            ));
            #[cfg(not(feature = "apt-remote"))]
            out.stdout(concat!(
                "guarded-update ",
                env!("CARGO_PKG_VERSION"),
                " (apt-agent)"
            ));
            ExitCode::SUCCESS
        }
        ["--help"] | [] => {
            #[cfg(feature = "apt-executor")]
            out.stdout("Executor build: broker --config PATH --requests PATH --responses PATH; validate-execution --input PATH --key PATH --journal PATH. Privileged updates require the installed root adapter, exact dashboard approval, fresh signed claim and local transaction checks.");
            out.stdout("APT build: guarded-update propose\nRead-only simulation using cached indexes. Installation is unavailable.");
            #[cfg(feature = "apt-remote")]
            out.stdout("Remote build: guarded-update sync --config /absolute/path/remote.toml\nReports proposals and verifies polled approvals. No installation.");
            ExitCode::SUCCESS
        }
        ["propose"] if cfg!(target_os = "linux") => {
            match proposal(&SystemRunner::new(Duration::from_secs(120)))
                .and_then(|p| serde_json::to_string_pretty(&p).map_err(|e| e.to_string()))
            {
                Ok(json) => {
                    out.stdout(&json);
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    out.stdout(&e);
                    ExitCode::from(1)
                }
            }
        }
        ["propose"] => {
            out.stdout("APT proposals require Linux; nothing was executed.");
            ExitCode::from(2)
        }
        _ => {
            out.stdout("Unsupported APT-agent command; nothing was executed. Use --help.");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dependency_annotations_do_not_change_transaction_versions() {
        let text = "1 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\nInst fixture [1] (2 Synthetic:stable [armhf]) [dependent:armhf on fixture:armhf] [dependent:armhf ]\nConf fixture (2 Synthetic:stable [armhf]) []\n";
        let changes = parse_simulation(text).unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].installed.as_deref(), Some("1"));
        assert_eq!(changes[0].target.as_deref(), Some("2"));
        assert_eq!(
            changes[0].source_description.as_deref(),
            Some("Synthetic:stable [armhf]")
        );
        assert!(parse_simulation(&text.replace("[dependent:armhf ]", "[bad;command]")).is_err());
    }
    #[test]
    fn configuration_version_must_match_the_proposed_target() {
        let prefix = "1 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\nInst foo [1] (2 Debian [armhf])\n";
        for conf in ["Conf foo garbage\n", "Conf foo (3 Debian [armhf])\n"] {
            assert!(parse_simulation(&format!("{prefix}{conf}")).is_err());
        }
    }

    #[test]
    fn empty_transaction_is_explicit_and_malformed_transactions_fail_closed() {
        let summary = "0 upgraded, 0 newly installed, 0 to remove and 3 not upgraded.\n";
        assert!(parse_simulation(summary).unwrap().is_empty());
        for input in [
            "1 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n",
            "1 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\nInst foo [1] (2 Debian [armhf])\n",
            "0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\nConf orphan (2 Debian [armhf])\n",
            "0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\nE: broken cache\n",
            "0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\nRemv --bad [1]\n",
        ] {
            assert!(parse_simulation(input).is_err(), "{input}");
        }
    }

    #[test]
    fn failed_simulation_produces_no_proposal() {
        struct Fake;
        impl Runner for Fake {
            fn run(
                &self,
                program: &str,
                _: &[&str],
                _: &[(&str, &str)],
            ) -> Result<crate::exec::CmdOutput, String> {
                Ok(crate::exec::CmdOutput {
                    code: Some(if program.ends_with("apt-mark") {
                        0
                    } else {
                        100
                    }),
                    stdout: String::new(),
                    stderr: "private diagnostics".into(),
                })
            }
        }
        let error = proposal(&Fake).err().unwrap();
        assert!(error.contains("simulation failed"));
        assert!(!error.contains("private diagnostics"));
    }

    #[test]
    fn explicitly_held_package_cannot_be_proposed() {
        struct Fake;
        impl Runner for Fake {
            fn run(
                &self,
                program: &str,
                args: &[&str],
                env: &[(&str, &str)],
            ) -> Result<crate::exec::CmdOutput, String> {
                assert_eq!(env, &[("LC_ALL", "C"), ("LANG", "C")]);
                let stdout = if program == "/usr/bin/apt-mark" {
                    assert_eq!(args, &["showhold"]);
                    "foo:armhf\n"
                } else {
                    assert_eq!(program, "/usr/bin/apt-get");
                    assert!(args.contains(&"--simulate"));
                    "1 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\nInst foo [1] (2 Debian:stable [armhf])\nConf foo (2 Debian:stable [armhf])\n"
                };
                Ok(crate::exec::CmdOutput {
                    code: Some(0),
                    stdout: stdout.into(),
                    stderr: String::new(),
                })
            }
        }
        assert!(proposal(&Fake).is_err());
    }

    #[test]
    fn missing_transaction_summary_is_not_an_empty_success() {
        assert!(parse_simulation("unsupported output\n").is_err());
    }

    #[test]
    fn proposal_keeps_versions_dependencies_architecture_and_removals() {
        let text = "Reading package lists...\n1 upgraded, 1 newly installed, 1 to remove and 0 not upgraded.\nInst libfoo:armhf [1.0-1] (1.0-2 Debian:stable [armhf])\nInst new-dep (2.0 Debian:stable [armhf])\nRemv old-dep [0.9]\nConf libfoo:armhf (1.0-2 Debian:stable [armhf])\nConf new-dep (2.0 Debian:stable [armhf])\n";
        let changes = parse_simulation(text).unwrap();
        assert_eq!(changes.len(), 3);
        assert_eq!(changes[0].package, "libfoo:armhf");
        assert_eq!(changes[0].installed.as_deref(), Some("1.0-1"));
        assert_eq!(changes[0].target.as_deref(), Some("1.0-2"));
        assert_eq!(changes[1].installed, None);
        assert_eq!(changes[2].operation, Operation::Remove);
    }
}
