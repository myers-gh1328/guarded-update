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
    fn held_fd_exec_child() {
        use std::os::unix::fs::MetadataExt;
        let value = std::env::var("EXEC_IDENTITY").unwrap();
        let parts: Vec<u64> = value.split(',').map(|part| part.parse().unwrap()).collect();
        assert_eq!(parts.len(), 7);
        assert_eq!(u64::from(std::process::id()), parts[0]);
        let stat = std::fs::read_to_string("/proc/self/stat").unwrap();
        let fields: Vec<&str> = stat
            .rsplit_once(") ")
            .unwrap()
            .1
            .split_whitespace()
            .collect();
        assert_eq!(fields[19].parse::<u64>().unwrap(), parts[1]);
        let exe = std::fs::metadata("/proc/self/exe").unwrap();
        assert_eq!((exe.dev(), exe.ino()), (parts[2], parts[3]));
        let lock = std::fs::metadata(format!("/proc/self/fd/{}", parts[4])).unwrap();
        assert_eq!((lock.dev(), lock.ino()), (parts[5], parts[6]));
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
            assert!([0, 1, 2, parts[4]].contains(&fd));
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
        assert_eq!(result.unwrap(), b"contended");
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
    #[test]
    fn held_fd_exec_requires_one_named_test() {
        assert!(!held_fd_test_output(b"running 0 tests\n\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out; finished in 0.00s\n"));
        assert!(held_fd_test_output(b"running 1 test\ntest inventory::process::tests::held_fd_exec_child ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out; finished in 0.00s\n"));
    }

    #[cfg(target_os = "linux")]
    #[test]
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
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let reader = std::thread::spawn(move || {
            use std::io::Read;
            let mut data = Vec::new();
            stdout.take(2049).read_to_end(&mut data).map(|_| data)
        });
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut status = None;
        loop {
            if status.is_none() {
                status = child.try_wait().unwrap();
            }
            if status.is_some() && reader.is_finished() {
                assert!(status.unwrap().success());
                let output = reader.join().unwrap().unwrap();
                assert!(output.len() <= 2048 && held_fd_test_output(&output));
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
