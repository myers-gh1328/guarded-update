//! Child processes: every call has a timeout (R14), and children never
//! receive environment variables whose names look secret (ADR-0001 D15).

use std::io::Read;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CmdOutput {
    /// `None` when the process was killed by a signal.
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl CmdOutput {
    pub fn success(&self) -> bool {
        self.code == Some(0)
    }
}

/// Runs external commands. Providers take this trait so tests can use a
/// fake.
pub trait Runner {
    fn run(&self, program: &str, args: &[&str], env: &[(&str, &str)]) -> Result<CmdOutput, String>;

    /// Applies the configured per-command timeout.
    fn set_timeout(&self, _timeout: Duration) {}
}

/// Set on every Homebrew call for the whole run (ADR-0001 D1).
pub const HOMEBREW_ENV: &[(&str, &str)] = &[
    ("HOMEBREW_NO_AUTO_UPDATE", "1"),
    ("HOMEBREW_NO_INSTALL_CLEANUP", "1"),
    ("HOMEBREW_NO_ENV_HINTS", "1"),
    ("HOMEBREW_NO_ANALYTICS", "1"),
    ("HOMEBREW_NO_COLOR", "1"),
];

const SECRET_NAME_PARTS: &[&str] = &[
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "API_KEY",
    "APIKEY",
    "PRIVATE_KEY",
    "CREDENTIAL",
    "AUTH",
];

/// Drops variables whose names look like they hold secrets.
pub fn filtered_env<I: IntoIterator<Item = (String, String)>>(vars: I) -> Vec<(String, String)> {
    vars.into_iter()
        .filter(|(name, _)| {
            let upper = name.to_ascii_uppercase();
            !SECRET_NAME_PARTS.iter().any(|part| upper.contains(part))
        })
        .collect()
}

fn reader<R: Read + Send + 'static>(stream: Option<R>) -> thread::JoinHandle<String> {
    thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut stream) = stream {
            let _ = stream.read_to_end(&mut buf);
        }
        String::from_utf8_lossy(&buf).into_owned()
    })
}

/// Kills the child's whole process group, so grandchildren holding the
/// output pipes die too.
fn kill_tree(child: &mut std::process::Child) {
    #[cfg(unix)]
    {
        let _ = Command::new("kill")
            .args(["-KILL", &format!("-{}", child.id())])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    let _ = child.kill();
    let _ = child.wait();
}

pub struct SystemRunner {
    pub timeout: std::cell::Cell<Duration>,
}

impl SystemRunner {
    pub fn new(timeout: Duration) -> Self {
        Self {
            timeout: std::cell::Cell::new(timeout),
        }
    }
}

impl Runner for SystemRunner {
    fn set_timeout(&self, timeout: Duration) {
        self.timeout.set(timeout);
    }

    fn run(&self, program: &str, args: &[&str], env: &[(&str, &str)]) -> Result<CmdOutput, String> {
        self.run_input(program, args, env, None)
    }
}

impl SystemRunner {
    /// Runs a command, optionally writing `input` to its stdin.
    pub fn run_input(
        &self,
        program: &str,
        args: &[&str],
        env: &[(&str, &str)],
        input: Option<&str>,
    ) -> Result<CmdOutput, String> {
        let shown = std::iter::once(program)
            .chain(args.iter().copied())
            .collect::<Vec<_>>()
            .join(" ");
        let mut command = Command::new(program);
        command
            .args(args)
            .env_clear()
            .envs(filtered_env(std::env::vars()))
            .envs(env.iter().copied())
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        let mut child = command
            .spawn()
            .map_err(|e| format!("cannot start `{shown}`: {e}"))?;
        if let (Some(text), Some(mut stdin)) = (input, child.stdin.take()) {
            use std::io::Write;
            // Dropping stdin afterwards closes it so the child sees EOF.
            if let Err(e) = stdin.write_all(text.as_bytes()) {
                kill_tree(&mut child);
                return Err(format!("writing to `{program}`: {e}"));
            }
        }
        let stdout = reader(child.stdout.take());
        let stderr = reader(child.stderr.take());
        let started = Instant::now();
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if started.elapsed() >= self.timeout.get() => {
                    kill_tree(&mut child);
                    let _ = (stdout.join(), stderr.join());
                    return Err(format!(
                        "`{shown}` timed out after {}s and was killed",
                        self.timeout.get().as_secs_f32()
                    ));
                }
                Ok(None) => thread::sleep(Duration::from_millis(25)),
                Err(e) => {
                    kill_tree(&mut child);
                    return Err(format!("waiting for `{shown}`: {e}"));
                }
            }
        };
        Ok(CmdOutput {
            code: status.code(),
            stdout: stdout.join().unwrap_or_default(),
            stderr: stderr.join().unwrap_or_default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn runner(ms: u64) -> SystemRunner {
        SystemRunner::new(Duration::from_millis(ms))
    }

    #[test]
    fn captures_stdout_stderr_and_exit_code() {
        let out = runner(5000)
            .run("sh", &["-c", "echo out; echo err >&2; exit 3"], &[])
            .unwrap();
        assert_eq!(out.code, Some(3));
        assert_eq!(out.stdout, "out\n");
        assert_eq!(out.stderr, "err\n");
        assert!(!out.success());
    }

    #[test]
    fn passes_extra_environment() {
        let out = runner(5000)
            .run(
                "sh",
                &["-c", "printf %s \"$GU_TEST_VAR\""],
                &[("GU_TEST_VAR", "yes")],
            )
            .unwrap();
        assert_eq!(out.stdout, "yes");
    }

    #[test]
    fn writes_input_to_stdin_without_putting_it_in_arguments() {
        let out = runner(5000)
            .run_input("cat", &[], &[], Some("hidden-value\n"))
            .unwrap();
        assert_eq!(out.stdout, "hidden-value\n");
    }

    #[test]
    fn kills_a_command_that_overruns_its_timeout() {
        let started = Instant::now();
        let err = runner(200).run("sleep", &["5"], &[]).unwrap_err();
        assert!(err.contains("timed out"), "{err}");
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn missing_program_is_an_error() {
        let err = runner(1000)
            .run("gu-definitely-not-a-program", &[], &[])
            .unwrap_err();
        assert!(err.contains("gu-definitely-not-a-program"));
    }

    #[test]
    fn secret_looking_variables_are_dropped() {
        let vars = vec![
            ("PATH".to_string(), "/bin".to_string()),
            ("HOME".to_string(), "/h".to_string()),
            ("SLACK_BOT_TOKEN".to_string(), "x".to_string()),
            ("GITHUB_TOKEN".to_string(), "x".to_string()),
            ("db_password".to_string(), "x".to_string()),
            ("OPENAI_API_KEY".to_string(), "x".to_string()),
        ];
        let kept: Vec<String> = filtered_env(vars).into_iter().map(|(k, _)| k).collect();
        assert_eq!(kept, vec!["PATH".to_string(), "HOME".to_string()]);
    }
}
