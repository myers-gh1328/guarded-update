//! Fixed, bounded system tools; diagnostics never contain raw command output.
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub trait Tools: Sync {
    fn text(&self, program: &str, args: &[&str], limit: usize) -> Result<String, String>;
    fn sha256(&self, bytes: &[u8]) -> Result<String, String>;
}

pub struct SystemTools;
impl SystemTools {
    pub fn run(
        &self,
        program: &str,
        args: &[&str],
        input: &[u8],
        limit: usize,
    ) -> Result<Vec<u8>, String> {
        self.run_with_timeout(program, args, input, limit, Duration::from_secs(120))
    }
    pub(super) fn run_with_timeout(
        &self,
        program: &str,
        args: &[&str],
        input: &[u8],
        limit: usize,
        timeout: Duration,
    ) -> Result<Vec<u8>, String> {
        let mut command = Command::new(program);
        command
            .args(args)
            .env_clear()
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .env("LC_ALL", "C")
            .env("HOMEBREW_NO_AUTO_UPDATE", "1")
            .env("HOMEBREW_NO_ANALYTICS", "1")
            .env("HOMEBREW_NO_ENV_HINTS", "1")
            .env("HOMEBREW_NO_INSTALL_CLEANUP", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        if let Some(home) = std::env::var_os("HOME") {
            command.env("HOME", home);
        }
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        let mut child = command
            .spawn()
            .map_err(|_| "Required system tool unavailable".to_owned())?;
        let stdout = child.stdout.take().ok_or("Tool output unavailable")?;
        let reader = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            stdout
                .take((limit + 1) as u64)
                .read_to_end(&mut bytes)
                .map(|_| bytes)
        });
        let mut stdin = child.stdin.take().ok_or("Tool input unavailable")?;
        let input = input.to_vec();
        let writer = std::thread::spawn(move || stdin.write_all(&input));
        let start = Instant::now();
        let mut exit_success = None;
        let success = loop {
            match child.try_wait() {
                Ok(Some(status)) => exit_success = Some(status.success()),
                Ok(None) => {}
                Err(_) => exit_success = Some(false),
            }
            if let Some(success) = exit_success
                && reader.is_finished()
                && writer.is_finished()
            {
                break success;
            }
            if start.elapsed() >= timeout {
                #[cfg(unix)]
                {
                    let _ = Command::new("/bin/kill")
                        .args(["-KILL", &format!("-{}", child.id())])
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .status();
                }
                let _ = child.kill();
                let _ = child.wait();
                // Never join an abandoned pipe: a daemon may have changed
                // its group. Detached readers remain memory-bounded.
                if !reader.is_finished() || !writer.is_finished() {
                    return Err("System tool deadline exceeded".into());
                }
                break false;
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let written = writer.join().map_err(|_| "Tool input unavailable")?;
        let bytes = reader
            .join()
            .map_err(|_| "Tool output unavailable")?
            .map_err(|_| "Tool output unavailable")?;
        if !success || written.is_err() || bytes.len() > limit {
            return Err("System tool failed, timed out or exceeded output limit".into());
        }
        Ok(bytes)
    }
}
impl Tools for SystemTools {
    fn text(&self, program: &str, args: &[&str], limit: usize) -> Result<String, String> {
        String::from_utf8(self.run(program, args, &[], limit)?)
            .map_err(|_| "Tool output is not UTF-8".into())
    }
    fn sha256(&self, bytes: &[u8]) -> Result<String, String> {
        let output = self.run("/usr/bin/openssl", &["dgst", "-sha256", "-hex"], bytes, 256)?;
        let text = String::from_utf8(output).map_err(|_| "Digest unavailable")?;
        let digest = text.split_whitespace().last().ok_or("Digest unavailable")?;
        if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("Digest unavailable".into());
        }
        Ok(digest.to_lowercase())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn output_is_bounded_and_secret_environment_is_absent() {
        assert!(
            SystemTools
                .run("/bin/sh", &["-c", "printf oversized"], &[], 2)
                .is_err()
        );
        let output = SystemTools.run("/usr/bin/env", &[], &[], 4096).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(!text.contains("TOKEN="));
        assert!(text.contains("HOMEBREW_NO_AUTO_UPDATE=1"));
    }
    #[test]
    fn inherited_output_pipe_cannot_outlive_tool_deadline() {
        let start = Instant::now();
        let result = SystemTools.run_with_timeout(
            "/bin/sh",
            &["-c", "sleep 5 & exit 0"],
            &[],
            128,
            Duration::from_millis(100),
        );
        assert!(result.is_err());
        assert!(start.elapsed() < Duration::from_secs(2));
    }
}
