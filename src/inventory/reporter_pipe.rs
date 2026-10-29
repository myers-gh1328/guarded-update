//! Real test-only pipes. No process ownership or production witness.
//! Instant bounds awake time only, not the boot-relative lease. Constructor
//! failures and implicit Drop never establish successful closure or cleanup.

use std::io::{Read, Write};
use std::os::fd::{AsFd, AsRawFd, IntoRawFd, RawFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::process::{ChildStdin, ChildStdout};
use std::time::{Duration, Instant};

unsafe extern "C" {
    fn fcntl(fd: i32, cmd: i32, ...) -> i32;
    fn close(fd: i32) -> i32;
}
const GET: i32 = 3;
const SET: i32 = 4;
#[cfg(target_os = "linux")]
const NONBLOCK: i32 = 0x800;
#[cfg(target_os = "macos")]
const NONBLOCK: i32 = 0x4;
const LIMIT: usize = 256 * 1024;
const ERROR: &str = "Private reporter pipe unavailable";
type Result<T> = std::result::Result<T, &'static str>;

fn flags(fd: RawFd) -> Result<i32> {
    // SAFETY: F_GETFL reads flags from a borrowed live descriptor, with no pointer argument.
    let value = unsafe { fcntl(fd, GET) };
    if value < 0 { Err(ERROR) } else { Ok(value) }
}
fn identity<T: AsFd + AsRawFd>(pipe: &T, access: i32, nonblocking: bool) -> Result<(u64, u64)> {
    let file = std::fs::File::from(pipe.as_fd().try_clone_to_owned().map_err(|_| ERROR)?);
    let metadata = file.metadata().map_err(|_| ERROR)?;
    let mode = flags(pipe.as_raw_fd())?;
    if !metadata.file_type().is_fifo()
        || mode & 3 != access
        || (nonblocking && mode & NONBLOCK == 0)
    {
        return Err(ERROR);
    }
    Ok((metadata.dev(), metadata.ino()))
}
fn nonblock(fd: RawFd) -> Result<()> {
    let mode = flags(fd)?;
    // SAFETY: F_SETFL sets only the inherited status flags plus O_NONBLOCK on this owned pipe.
    if unsafe { fcntl(fd, SET, mode | NONBLOCK) } < 0 {
        Err(ERROR)
    } else {
        Ok(())
    }
}

struct PipePair {
    input: Option<ChildStdin>,
    output: Option<ChildStdout>,
    input_id: (u64, u64),
    output_id: (u64, u64),
    deadline: Instant,
    pending: Vec<u8>,
    failed: bool,
}
impl PipePair {
    fn new(input: ChildStdin, output: ChildStdout, deadline: Instant) -> Result<Self> {
        let input_id = identity(&input, 1, false)?;
        let output_id = identity(&output, 0, false)?;
        if input_id == output_id || Instant::now() >= deadline {
            return Err(ERROR);
        }
        nonblock(input.as_raw_fd())?;
        nonblock(output.as_raw_fd())?;
        let pair = Self {
            input: Some(input),
            output: Some(output),
            input_id,
            output_id,
            deadline,
            pending: Vec::new(),
            failed: false,
        };
        pair.verify()?;
        Ok(pair)
    }
    fn verify(&self) -> Result<()> {
        if self.failed || Instant::now() >= self.deadline {
            return Err(ERROR);
        }
        let input = self.input.as_ref().ok_or(ERROR)?;
        let output = self.output.as_ref().ok_or(ERROR)?;
        if identity(input, 1, true)? != self.input_id
            || identity(output, 0, true)? != self.output_id
            || Instant::now() >= self.deadline
        {
            return Err(ERROR);
        }
        Ok(())
    }
    fn pause(&self) -> Result<()> {
        self.verify()?;
        let remaining = self
            .deadline
            .checked_duration_since(Instant::now())
            .ok_or(ERROR)?;
        std::thread::sleep(remaining.min(Duration::from_millis(2)));
        self.verify()
    }
    fn write_frame(&mut self, raw: &[u8]) -> Result<()> {
        let result = self.write_inner(raw);
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    fn write_inner(&mut self, raw: &[u8]) -> Result<()> {
        if raw.is_empty()
            || raw.len() > LIMIT
            || raw.last() != Some(&b'\n')
            || raw[..raw.len() - 1].contains(&b'\n')
        {
            return Err(ERROR);
        }
        let mut offset = 0;
        while offset < raw.len() {
            self.verify()?;
            match self.input.as_mut().ok_or(ERROR)?.write(&raw[offset..]) {
                Ok(0) => return Err(ERROR),
                Ok(n) => offset += n,
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                    ) =>
                {
                    self.pause()?
                }
                Err(_) => return Err(ERROR),
            }
            self.verify()?;
        }
        Ok(())
    }
    fn read_frame(&mut self) -> Result<Vec<u8>> {
        let result = self.read_inner();
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    fn read_inner(&mut self) -> Result<Vec<u8>> {
        loop {
            self.verify()?;
            if let Some(index) = self.pending.iter().position(|b| *b == b'\n') {
                if index + 1 > LIMIT {
                    return Err(ERROR);
                }
                let rest = self.pending.split_off(index + 1);
                let frame = std::mem::replace(&mut self.pending, rest);
                self.verify()?;
                return Ok(frame);
            }
            if self.pending.len() >= LIMIT {
                return Err(ERROR);
            }
            let mut buffer = [0u8; 65536];
            let max = buffer.len().min(LIMIT - self.pending.len());
            match self.output.as_mut().ok_or(ERROR)?.read(&mut buffer[..max]) {
                Ok(0) => return Err(ERROR),
                Ok(n) => self.pending.extend_from_slice(&buffer[..n]),
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                    ) =>
                {
                    self.pause()?
                }
                Err(_) => return Err(ERROR),
            }
            self.verify()?;
        }
    }
    fn close(self) -> Result<()> {
        self.close_with(|fd| {
            // SAFETY: ownership was transferred exactly once; failed close is never retried.
            unsafe { close(fd) == 0 }
        })
    }
    fn close_with(mut self, mut retire: impl FnMut(RawFd) -> bool) -> Result<()> {
        let mut uncertain = false;
        if let Some(input) = self.input.take() {
            let valid = identity(&input, 1, true).is_ok_and(|value| value == self.input_id);
            let fd = input.into_raw_fd();
            if valid {
                if !retire(fd) {
                    uncertain = true;
                }
            } else {
                uncertain = true;
            }
        }
        if let Some(output) = self.output.take() {
            let valid = identity(&output, 0, true).is_ok_and(|value| value == self.output_id);
            let fd = output.into_raw_fd();
            if valid {
                if !retire(fd) {
                    uncertain = true;
                }
            } else {
                uncertain = true;
            }
        }
        if uncertain { Err(ERROR) } else { Ok(()) }
    }
}

#[cfg(test)]
mod tests {
    use super::{NONBLOCK, PipePair, SET, flags};
    use std::os::fd::AsRawFd;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    #[test]
    fn real_child_pipe_roundtrip_closes_both_owned_ends() {
        let mut child = Command::new("/usr/bin/python3")
            .args(["-I", "-c", "import sys; x=sys.stdin.buffer.readline(); sys.stdout.buffer.write(x[:2]); sys.stdout.buffer.flush(); sys.stdout.buffer.write(x[2:]); sys.stdout.buffer.flush()"])
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();
        let mut pair = PipePair::new(
            child.stdin.take().unwrap(),
            child.stdout.take().unwrap(),
            Instant::now() + Duration::from_secs(3),
        )
        .unwrap();
        pair.write_frame(b"{\"x\":1}\n").unwrap();
        assert_eq!(pair.read_frame().unwrap(), b"{\"x\":1}\n");
        pair.close().unwrap();
        assert!(child.wait().unwrap().success());
    }

    #[test]
    fn large_frame_crosses_pipe_capacity_without_blocking() {
        let mut child=Command::new("/usr/bin/python3").args(["-I","-c","import sys; x=sys.stdin.buffer.readline(); sys.stdout.buffer.write(str(len(x)).encode()+b'\\n'); sys.stdout.buffer.flush()"])
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();
        let mut pair = PipePair::new(
            child.stdin.take().unwrap(),
            child.stdout.take().unwrap(),
            Instant::now() + Duration::from_secs(3),
        )
        .unwrap();
        let mut frame = vec![b'x'; 256 * 1024 - 1];
        frame.push(b'\n');
        pair.write_frame(&frame).unwrap();
        assert_eq!(pair.read_frame().unwrap(), b"262144\n");
        pair.close().unwrap();
        assert!(child.wait().unwrap().success());
    }

    #[test]
    fn write_deadline_expires_when_child_never_reads() {
        let mut child = Command::new("/usr/bin/python3")
            .args(["-I", "-c", "import time; time.sleep(0.2)"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut pair = PipePair::new(
            child.stdin.take().unwrap(),
            child.stdout.take().unwrap(),
            Instant::now() + Duration::from_millis(80),
        )
        .unwrap();
        let mut frame = vec![b'x'; 256 * 1024 - 1];
        frame.push(b'\n');
        assert!(pair.write_frame(&frame).is_err());
        assert!(pair.read_frame().is_err());
        pair.close().unwrap();
        assert!(child.wait().unwrap().success());
    }

    #[test]
    fn close_failure_does_not_skip_the_other_close() {
        let mut child = Command::new("/usr/bin/python3")
            .args(["-I", "-c", "pass"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let pair = PipePair::new(
            child.stdin.take().unwrap(),
            child.stdout.take().unwrap(),
            Instant::now() + Duration::from_secs(3),
        )
        .unwrap();
        let mut calls = 0;
        let result = pair.close_with(|fd| {
            calls += 1;
            // SAFETY: the callback consumes each passed owned descriptor once.
            let closed = unsafe { super::close(fd) } == 0;
            closed && calls != 1
        });
        assert!(result.is_err());
        assert_eq!(calls, 2);
        assert!(child.wait().unwrap().success());
    }

    #[test]
    fn held_open_partial_frame_times_out_and_poison_is_absorbing() {
        let mut child = Command::new("/usr/bin/python3")
            .args(["-I", "-c", "import sys,time; sys.stdout.buffer.write(b'{'); sys.stdout.buffer.flush(); time.sleep(0.2)"])
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();
        let mut pair = PipePair::new(
            child.stdin.take().unwrap(),
            child.stdout.take().unwrap(),
            Instant::now() + Duration::from_millis(80),
        )
        .unwrap();
        assert!(pair.read_frame().is_err());
        assert!(pair.write_frame(b"{}\n").is_err());
        pair.close().unwrap();
        assert!(child.wait().unwrap().success());
    }

    #[test]
    fn eof_and_partial_frame_never_return_valid_data() {
        for source in ["pass", "import sys; sys.stdout.buffer.write(b'{')"] {
            let mut child = Command::new("/usr/bin/python3")
                .args(["-I", "-c", source])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let mut pair = PipePair::new(
                child.stdin.take().unwrap(),
                child.stdout.take().unwrap(),
                Instant::now() + Duration::from_secs(3),
            )
            .unwrap();
            assert!(pair.read_frame().is_err());
            pair.close().unwrap();
            assert!(child.wait().unwrap().success());
        }
    }

    #[test]
    fn flag_tamper_poison_and_uncertain_close_still_closes_other_endpoint() {
        let mut child = Command::new("/usr/bin/python3")
            .args(["-I", "-c", "import time; time.sleep(0.2)"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut pair = PipePair::new(
            child.stdin.take().unwrap(),
            child.stdout.take().unwrap(),
            Instant::now() + Duration::from_secs(3),
        )
        .unwrap();
        let input = pair.input.as_ref().unwrap().as_raw_fd();
        let output = pair.output.as_ref().unwrap().as_raw_fd();
        let original = flags(input).unwrap();
        // SAFETY: this test changes flags on the still-owned pipe descriptor.
        assert_eq!(unsafe { super::fcntl(input, SET, original & !NONBLOCK) }, 0);
        assert!(pair.write_frame(b"{}\n").is_err());
        assert!(pair.close().is_err());
        assert!(flags(output).is_err());
        // The deliberately uncertain descriptor was preserved, so the fixture explicitly retires it.
        assert!(flags(input).is_ok());
        // SAFETY: the test retains the deliberately preserved original descriptor exactly once.
        assert_eq!(unsafe { super::close(input) }, 0);
        assert!(child.wait().unwrap().success());
    }

    #[test]
    fn multiple_frames_remain_separate_and_invalid_write_poisons() {
        let mut child = Command::new("/usr/bin/python3")
            .args([
                "-I",
                "-c",
                "import sys; sys.stdout.buffer.write(b'{}\\n[]\\n'); sys.stdout.buffer.flush()",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut pair = PipePair::new(
            child.stdin.take().unwrap(),
            child.stdout.take().unwrap(),
            Instant::now() + Duration::from_secs(3),
        )
        .unwrap();
        assert_eq!(pair.read_frame().unwrap(), b"{}\n");
        assert_eq!(pair.read_frame().unwrap(), b"[]\n");
        assert!(pair.write_frame(b"{}\n{}\n").is_err());
        assert!(pair.read_frame().is_err());
        pair.close().unwrap();
        assert!(child.wait().unwrap().success());
    }

    #[test]
    fn oversize_output_is_rejected_without_returning_a_prefix() {
        let mut child=Command::new("/usr/bin/python3").args(["-I","-c","import sys; sys.stdout.buffer.write(b'x'*(256*1024+1)+b'\\n'); sys.stdout.buffer.flush()"])
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();
        let mut pair = PipePair::new(
            child.stdin.take().unwrap(),
            child.stdout.take().unwrap(),
            Instant::now() + Duration::from_secs(3),
        )
        .unwrap();
        assert!(pair.read_frame().is_err());
        pair.close().unwrap();
        let _status = child.wait().unwrap();
    }

    #[test]
    fn broken_pipe_does_not_terminate_test_process() {
        const FLAG: &str = "GUARDED_UPDATE_TEST_BROKEN_PIPE";
        if std::env::var_os(FLAG).is_none() {
            let result = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "inventory::reporter_pipe::tests::broken_pipe_does_not_terminate_test_process",
                ])
                .env(FLAG, "1")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .unwrap();
            assert!(result.success());
            return;
        }
        let mut child = Command::new("/usr/bin/python3")
            .args(["-I", "-c", "pass"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let input = child.stdin.take().unwrap();
        let output = child.stdout.take().unwrap();
        assert!(child.wait().unwrap().success());
        let mut pair =
            PipePair::new(input, output, Instant::now() + Duration::from_secs(3)).unwrap();
        assert!(pair.write_frame(b"{}\n").is_err());
        pair.close().unwrap();
    }
}
