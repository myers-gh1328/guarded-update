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
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore]
    #[allow(clippy::disallowed_methods)] // Dedicated fixture control pipe, not a log.
    fn hosted_fd_reporter_parent_admission() {
        assert_eq!(
            std::env::var("GUARDED_UPDATE_NATIVE_EXEC_PARENT_PROOF")
                .ok()
                .as_deref(),
            Some("1")
        );
        let program = "import sys\nsys.path.insert(0,'/usr/local/libexec/command-center-inventory-refresh')\nfrom inventory_refresh_reporter_parent import ReporterParent\nowner=ReporterParent.fixed()\ntry:\n owner.verify();owner.clock();owner.verify()\nfinally:owner.close()\nsys.stdout.buffer.write(b'PARENT_OK\\n')";
        let result = SystemTools
            .run_with_timeout(
                "/usr/bin/python3",
                &["-I", "-B", "-S", "-c", program],
                &[],
                64,
                Duration::from_secs(10),
            )
            .unwrap();
        assert_eq!(result, b"PARENT_OK\n");
        super::super::reporter_barrier::handshake(
            &std::io::stdin(),
            &std::io::stderr(),
            Instant::now() + Duration::from_secs(10),
        )
        .unwrap();
    }
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore]
    fn held_fd_exec_child() {
        use std::os::unix::fs::MetadataExt;
        let value = std::env::var("EXEC_IDENTITY").unwrap();
        let parts: Vec<u64> = value.split(',').map(|part| part.parse().unwrap()).collect();
        assert_eq!(parts.len(), 7, "synthetic_stage_fields");
        assert_eq!(
            u64::from(std::process::id()),
            parts[0],
            "synthetic_stage_pid"
        );
        let stat = std::fs::read_to_string("/proc/self/stat").unwrap();
        let fields: Vec<&str> = stat
            .rsplit_once(") ")
            .unwrap()
            .1
            .split_whitespace()
            .collect();
        assert_eq!(
            fields[19].parse::<u64>().unwrap(),
            parts[1],
            "synthetic_stage_start"
        );
        let exe = std::fs::metadata("/proc/self/exe").unwrap();
        assert_eq!(
            (exe.dev(), exe.ino()),
            (parts[2], parts[3]),
            "synthetic_stage_exe"
        );
        let lock = std::fs::metadata(format!("/proc/self/fd/{}", parts[4])).unwrap();
        assert_eq!(
            (lock.dev(), lock.ino()),
            (parts[5], parts[6]),
            "synthetic_stage_lock"
        );
        let descriptors: Vec<_> = std::fs::read_dir("/proc/self/fd")
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        for descriptor in descriptors {
            match std::fs::metadata(&descriptor) {
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => panic!("descriptor metadata unavailable: {error}"),
            }
            let fd: u64 = descriptor
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .parse()
                .unwrap();
            assert!(
                [0, 1, 2, parts[4]].contains(&fd),
                "synthetic_stage_extra_fd"
            );
        }
        let contender = "import fcntl,os,sys\nf=os.open(sys.argv[1],os.O_RDONLY)\ntry:fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)\nexcept BlockingIOError:os.write(1,b'contended');sys.exit(0)\nsys.exit(1)";
        let result = SystemTools.run(
            "/usr/bin/python3",
            &[
                "-I",
                "-B",
                "-S",
                "-c",
                contender,
                &std::env::var("EXEC_LOCK_PATH").unwrap(),
            ],
            &[],
            32,
        );
        assert_eq!(result.unwrap(), b"contended", "synthetic_stage_contention");
    }

    #[cfg(target_os = "linux")]
    fn held_fd_test_output(raw: &[u8]) -> bool {
        let Ok(text) = std::str::from_utf8(raw) else {
            return false;
        };
        let lines: Vec<&str> = text.lines().filter(|line| !line.is_empty()).collect();
        if lines.len() != 3
            || lines[0] != "running 1 test"
            || lines[1] != "test inventory::process::tests::held_fd_exec_child ... ok"
        {
            return false;
        }
        let Some(tail) =
            lines[2].strip_prefix("test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; ")
        else {
            return false;
        };
        let Some((count, duration)) = tail.split_once(" filtered out; finished in ") else {
            return false;
        };
        !count.is_empty()
            && count.bytes().all(|byte| byte.is_ascii_digit())
            && duration.strip_suffix('s').is_some_and(|value| {
                !value.is_empty()
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || byte == b'.')
            })
    }

    #[cfg(target_os = "linux")]
    fn held_fd_stage(raw: &[u8], output: &[u8]) -> &'static str {
        let stage = match raw {
            b"Synthetic held-fd exec stage=setup\n" => "setup",
            b"Synthetic held-fd exec stage=ancestry\n" => "ancestry",
            b"Synthetic held-fd exec stage=source\n" => "source",
            b"Synthetic held-fd exec stage=lock\n" => "lock",
            b"Synthetic held-fd exec stage=exec\n" => "exec",
            _ => "unknown",
        };
        if stage != "unknown" {
            return stage;
        }
        for (marker, label) in [
            (b"synthetic_stage_fields".as_slice(), "fields"),
            (b"synthetic_stage_pid".as_slice(), "pid"),
            (b"synthetic_stage_start".as_slice(), "start"),
            (b"synthetic_stage_exe".as_slice(), "exe"),
            (b"synthetic_stage_lock".as_slice(), "lock_identity"),
            (b"synthetic_stage_extra_fd".as_slice(), "extra_fd"),
            (b"synthetic_stage_contention".as_slice(), "contention"),
        ] {
            if output.windows(marker.len()).any(|window| window == marker) {
                return label;
            }
        }
        if output
            .windows(b"running 1 test".len())
            .any(|window| window == b"running 1 test")
        {
            "child_test"
        } else {
            "pre_exec_unknown"
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn held_fd_exec_requires_one_named_test() {
        assert!(!held_fd_test_output(b"running 0 tests\n\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out; finished in 0.00s\n"));
        assert!(held_fd_test_output(b"running 1 test\ntest inventory::process::tests::held_fd_exec_child ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out; finished in 0.00s\n"));
        assert_eq!(
            held_fd_stage(b"token=synthetic-secret\n", b""),
            "pre_exec_unknown"
        );
        assert_eq!(
            held_fd_stage(b"", b"panic synthetic_stage_extra_fd token=secret"),
            "extra_fd"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    // A deadline leaves child ownership unknown; never wait without a bound.
    #[allow(clippy::zombie_processes)]
    fn held_fd_exec_preserves_reporter_identity_and_lifetime_lock() {
        let mut child = Command::new("/usr/bin/python3")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LC_ALL", "C")
            .args([
                "-I",
                "-B",
                "-S",
                concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/tests/inventory_reporter_exec_identity.py"
                ),
            ])
            .arg(std::env::current_exe().unwrap())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();
        let reader = std::thread::spawn(move || {
            use std::io::Read;
            let mut data = Vec::new();
            stdout.take(2049).read_to_end(&mut data).map(|_| data)
        });
        let errors = std::thread::spawn(move || {
            use std::io::Read;
            let mut data = Vec::new();
            stderr.take(513).read_to_end(&mut data).map(|_| data)
        });
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut status = None;
        loop {
            if status.is_none() {
                status = child.try_wait().unwrap();
            }
            if let Some(status) = status
                && reader.is_finished()
                && errors.is_finished()
            {
                let output = reader.join().unwrap().unwrap();
                let error_output = errors.join().unwrap().unwrap();
                if !status.success() {
                    panic!(
                        "Synthetic held-fd exec stage={}",
                        held_fd_stage(&error_output, &output)
                    );
                }
                assert!(
                    error_output.is_empty() && output.len() <= 2048 && held_fd_test_output(&output)
                );
                break;
            }
            assert!(Instant::now() < deadline, "fixture child exit unknown");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    #[ignore]
    fn maintenance_inheritance_child() {
        let value = std::env::var("INVENTORY_LOCK_FIXTURE").unwrap();
        let parts: Vec<&str> = value.split(',').collect();
        assert_eq!(parts.len(), 4);
        let program = "import os,select,sys\nfd,ready,control=map(int,sys.argv[1:])\npid=os.fork()\nif pid==0:\n os.close(0);os.close(1);os.close(2)\n s=os.fstat(fd);os.write(ready,('%d:%d\\n'%(s.st_dev,s.st_ino)).encode())\n if select.select([control],[],[],8)[0]: os.read(control,1)\n os._exit(0)\n";
        SystemTools
            .run(
                "/usr/bin/python3",
                &[
                    "-I", "-B", "-S", "-c", program, parts[0], parts[1], parts[2],
                ],
                &[],
                32,
            )
            .unwrap();
        use std::io::Read;
        use std::os::fd::FromRawFd;
        let fd: i32 = parts[3].parse().unwrap();
        let mut input = unsafe { std::fs::File::from_raw_fd(fd) };
        let mut byte = [0];
        input.read_exact(&mut byte).unwrap();
        assert_eq!(byte, [b'x']);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn maintenance_lock_survives_reporter_and_system_tools_exec() {
        let mut child = Command::new("/usr/bin/python3")
            .args([
                "-I",
                "-B",
                "-S",
                concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/tests/inventory_maintenance_exec_fixture.py"
                ),
            ])
            .arg(std::env::current_exe().unwrap())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            assert!(Instant::now() < deadline, "fixture child exit unknown");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
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
