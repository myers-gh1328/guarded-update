//! The nightly run's schedule (ADR-0001 D1): a per-user launchd job that
//! setup installs, replaces or removes. Linux timers come later.

use std::path::{Path, PathBuf};

use crate::exec::Runner;

pub const LABEL: &str = "io.github.myers-gh1328.guarded-update";
/// The name the job had before the project moved; setup removes it.
pub const OLD_LABEL: &str = "io.github.aegir-tech.guarded-update";

/// When the run starts each night, or not at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum When {
    At(u8, u8),
    Off,
}

/// Reads `off` or a 24-hour `H:MM` / `HH:MM` time.
pub fn parse(text: &str) -> Option<When> {
    let text = text.trim();
    if text.eq_ignore_ascii_case("off") {
        return Some(When::Off);
    }
    let (h, m) = text.split_once(':')?;
    if h.is_empty() || h.len() > 2 || m.len() != 2 {
        return None;
    }
    let (h, m): (u8, u8) = (h.parse().ok()?, m.parse().ok()?);
    (h < 24 && m < 60).then_some(When::At(h, m))
}

/// The form saved in the config.
pub fn format(when: When) -> String {
    match when {
        When::At(h, m) => format!("{h:02}:{m:02}"),
        When::Off => "off".into(),
    }
}

/// For people: `3:00 am`.
pub fn describe(when: When) -> String {
    match when {
        When::At(h, m) => {
            let half = if h < 12 { "am" } else { "pm" };
            let h12 = match h % 12 {
                0 => 12,
                h => h,
            };
            format!("{h12}:{m:02} {half}")
        }
        When::Off => "not scheduled".into(),
    }
}

/// What the job runs.
pub struct Job {
    pub exe: PathBuf,
    /// Arguments after the program, starting with `run`.
    pub args: Vec<String>,
    /// stdout and stderr of the job.
    pub log: PathBuf,
    pub path_env: String,
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn string(text: &str) -> String {
    format!("<string>{}</string>", escape(text))
}

/// The launchd property list. A run missed while the Mac slept starts
/// when it wakes.
pub fn plist(job: &Job, hour: u8, minute: u8) -> String {
    let mut args = vec![string(&job.exe.to_string_lossy())];
    args.extend(job.args.iter().map(|a| string(a)));
    let log = string(&job.log.to_string_lossy());
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	{label}
	<key>ProgramArguments</key>
	<array>
		{args}
	</array>
	<key>EnvironmentVariables</key>
	<dict>
		<key>PATH</key>
		{path}
	</dict>
	<key>StartCalendarInterval</key>
	<dict>
		<key>Hour</key>
		<integer>{hour}</integer>
		<key>Minute</key>
		<integer>{minute}</integer>
	</dict>
	<key>StandardOutPath</key>
	{log}
	<key>StandardErrorPath</key>
	{log}
	<key>ProcessType</key>
	<string>Background</string>
</dict>
</plist>
"#,
        label = string(LABEL),
        args = args.join("\n\t\t"),
        path = string(&job.path_env),
    )
}

pub fn plist_path(home: &Path) -> PathBuf {
    home.join("Library/LaunchAgents")
        .join(format!("{LABEL}.plist"))
}

/// PATH for the job: Homebrew and `~/.local/bin` first, then the system.
pub fn path_env(home: &Path) -> String {
    [
        "/opt/homebrew/bin".to_string(),
        "/opt/homebrew/sbin".to_string(),
        home.join(".local/bin").to_string_lossy().into_owned(),
        "/usr/local/bin".to_string(),
        "/usr/bin".to_string(),
        "/bin".to_string(),
        "/usr/sbin".to_string(),
        "/sbin".to_string(),
    ]
    .join(":")
}

/// A binary inside a build folder (`target/`) goes away with `cargo
/// clean`, so the job uses a copy in `~/.local/bin`.
pub fn needs_copy(exe: &Path) -> bool {
    exe.components().any(|c| c.as_os_str() == "target")
}

/// Copies the running binary to `~/.local/bin/guarded-update`.
pub fn copy_binary(exe: &Path, home: &Path) -> Result<PathBuf, String> {
    let dir = home.join(".local/bin");
    let dest = dir.join("guarded-update");
    let tmp = dir.join(".guarded-update.tmp");
    let fail = |e: std::io::Error| format!("cannot copy the program to {}: {e}", dest.display());
    std::fs::create_dir_all(&dir).map_err(fail)?;
    std::fs::copy(exe, &tmp).map_err(fail)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755)).map_err(fail)?;
    }
    std::fs::rename(&tmp, &dest).map_err(fail)?;
    Ok(dest)
}

fn launchctl(runner: &dyn Runner, args: &[&str]) -> Result<(), String> {
    match runner.run("launchctl", args, &[]) {
        Ok(out) if out.success() => Ok(()),
        Ok(out) => Err(format!(
            "`launchctl {}` failed: {}",
            args.join(" "),
            out.stderr.trim()
        )),
        Err(e) => Err(e),
    }
}

/// Installs, replaces or removes the job, then checks launchd has it.
pub fn apply(
    when: When,
    job: &Job,
    home: &Path,
    uid: &str,
    runner: &dyn Runner,
) -> Result<(), String> {
    let path = plist_path(home);
    let target = format!("gui/{uid}/{LABEL}");
    // Not loaded is fine; this makes running setup again safe.
    let _ = runner.run(
        "launchctl",
        &["bootout", &format!("gui/{uid}/{OLD_LABEL}")],
        &[],
    );
    let old = home.join(format!("Library/LaunchAgents/{OLD_LABEL}.plist"));
    match std::fs::remove_file(&old) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            return Err(format!("cannot remove {}: {e}", old.display()));
        }
        _ => {}
    }
    let _ = runner.run("launchctl", &["bootout", &target], &[]);
    let When::At(hour, minute) = when else {
        return match std::fs::remove_file(&path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                Err(format!("cannot remove {}: {e}", path.display()))
            }
            _ => Ok(()),
        };
    };
    if let Some(dir) = job.log.parent() {
        std::fs::create_dir_all(dir)
            .map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    }
    let dir = path.parent().expect("plist path has a folder");
    std::fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    let tmp = path.with_extension("plist.tmp");
    std::fs::write(&tmp, plist(job, hour, minute))
        .and_then(|()| std::fs::rename(&tmp, &path))
        .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    let path_text = path.to_string_lossy();
    match runner.run("plutil", &["-lint", &path_text], &[]) {
        Ok(out) if out.success() => {}
        Ok(out) => {
            return Err(format!(
                "the schedule file is invalid: {}",
                out.stdout.trim()
            ));
        }
        Err(e) => return Err(e),
    }
    launchctl(runner, &["bootstrap", &format!("gui/{uid}"), &path_text])?;
    launchctl(runner, &["print", &target])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::CmdOutput;
    use std::cell::RefCell;

    #[test]
    fn times_are_read_written_and_described() {
        assert_eq!(parse("3:00"), Some(When::At(3, 0)));
        assert_eq!(parse(" 23:30 "), Some(When::At(23, 30)));
        assert_eq!(parse("OFF"), Some(When::Off));
        for bad in ["24:00", "3:60", "3", "3:0", "abc", "", "003:00"] {
            assert_eq!(parse(bad), None, "{bad}");
        }
        assert_eq!(format(When::At(3, 0)), "03:00");
        assert_eq!(format(When::Off), "off");
        assert_eq!(describe(When::At(3, 0)), "3:00 am");
        assert_eq!(describe(When::At(0, 15)), "12:15 am");
        assert_eq!(describe(When::At(13, 5)), "1:05 pm");
    }

    fn job() -> Job {
        Job {
            exe: "/Users/a b/.local/bin/guarded-update".into(),
            args: vec!["run".into(), "--config".into(), "/c/R&D <x>.toml".into()],
            log: "/s/logs/launchd.log".into(),
            path_env: "/opt/homebrew/bin:/usr/bin".into(),
        }
    }

    #[test]
    fn the_plist_runs_the_job_at_the_time_with_escaped_paths() {
        let text = plist(&job(), 3, 5);
        assert!(text.contains(&format!("<string>{LABEL}</string>")));
        assert!(text.contains("<string>/Users/a b/.local/bin/guarded-update</string>"));
        assert!(text.contains("<string>/c/R&amp;D &lt;x&gt;.toml</string>"));
        assert!(text.contains("<key>Hour</key>\n\t\t<integer>3</integer>"));
        assert!(text.contains("<key>Minute</key>\n\t\t<integer>5</integer>"));
        assert!(text.contains("<string>/s/logs/launchd.log</string>"));
        assert!(text.contains("<string>/opt/homebrew/bin:/usr/bin</string>"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn plutil_accepts_the_plist() {
        let path = home("lint").with_extension("plist");
        std::fs::write(&path, plist(&job(), 23, 30)).unwrap();
        let out = std::process::Command::new("/usr/bin/plutil")
            .args(["-lint", path.to_str().unwrap()])
            .output()
            .unwrap();
        let _ = std::fs::remove_file(&path);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stdout)
        );
    }

    #[test]
    fn a_binary_in_a_build_folder_is_copied() {
        assert!(needs_copy(Path::new(
            "/x/repo/target/release/guarded-update"
        )));
        assert!(!needs_copy(Path::new("/x/.local/bin/guarded-update")));
        assert!(
            path_env(Path::new("/h"))
                .contains("/opt/homebrew/bin:/opt/homebrew/sbin:/h/.local/bin:")
        );
    }

    struct Calls(RefCell<Vec<String>>);
    impl Runner for Calls {
        fn run(
            &self,
            program: &str,
            args: &[&str],
            _: &[(&str, &str)],
        ) -> Result<CmdOutput, String> {
            self.0
                .borrow_mut()
                .push(format!("{program} {}", args.join(" ")));
            Ok(CmdOutput {
                code: Some(0),
                stdout: String::new(),
                stderr: String::new(),
            })
        }
    }

    fn home(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("gu-schedule-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn installing_replaces_the_job_and_checks_launchd_has_it() {
        let home = home("install");
        let job = Job {
            log: home.join("state/logs/launchd.log"),
            ..job()
        };
        // A job saved under the old name goes, so there are never two.
        let old = home.join(format!("Library/LaunchAgents/{OLD_LABEL}.plist"));
        std::fs::create_dir_all(old.parent().unwrap()).unwrap();
        std::fs::write(&old, "old").unwrap();
        let runner = Calls(RefCell::default());
        apply(When::At(3, 0), &job, &home, "501", &runner).unwrap();
        assert!(!old.exists(), "the old job's file is removed");
        let path = plist_path(&home);
        assert!(
            std::fs::read_to_string(&path)
                .unwrap()
                .contains("<integer>3</integer>")
        );
        assert!(
            home.join("state/logs").is_dir(),
            "launchd needs the log folder"
        );
        let p = path.display();
        assert_eq!(
            *runner.0.borrow(),
            [
                format!("launchctl bootout gui/501/{OLD_LABEL}"),
                format!("launchctl bootout gui/501/{LABEL}"),
                format!("plutil -lint {p}"),
                format!("launchctl bootstrap gui/501 {p}"),
                format!("launchctl print gui/501/{LABEL}"),
            ]
        );
        let runner = Calls(RefCell::default());
        apply(When::Off, &job, &home, "501", &runner).unwrap();
        assert!(!path.exists());
        assert_eq!(
            *runner.0.borrow(),
            [
                format!("launchctl bootout gui/501/{OLD_LABEL}"),
                format!("launchctl bootout gui/501/{LABEL}")
            ]
        );
        // Turning off what was never on is fine too.
        apply(When::Off, &job, &home, "501", &runner).unwrap();
        let _ = std::fs::remove_dir_all(&home);
    }
}
