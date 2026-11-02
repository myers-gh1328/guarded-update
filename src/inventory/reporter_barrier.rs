//! Hosted-only control pipe; it grants no process-set or completion authority.
use std::io::{Read, Write};
use std::os::fd::{AsFd, AsRawFd, IntoRawFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
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
const ERROR: &str = "Private barrier unavailable";
#[cfg(test)]
thread_local! {
    static FAULT: std::cell::Cell<u8> = const { std::cell::Cell::new(0) };
    static CLOSES: std::cell::Cell<u8> = const { std::cell::Cell::new(0) };
}
fn clone_output<W: AsFd>(output: &W) -> Result<std::fs::File, &'static str> {
    #[cfg(test)]
    if FAULT.get() == 1 {
        return Err(ERROR);
    }
    output
        .as_fd()
        .try_clone_to_owned()
        .map(std::fs::File::from)
        .map_err(|_| ERROR)
}
fn set_phase(fd: i32, value: i32, restoring: bool) -> Result<(), &'static str> {
    #[cfg(test)]
    if FAULT.get() == if restoring { 3 } else { 2 } {
        return Err(ERROR);
    }
    let _ = restoring;
    set(fd, value)
}
fn checked_close(fd: i32) -> Result<(), &'static str> {
    let result = unsafe { close(fd) };
    #[cfg(test)]
    {
        CLOSES.set(CLOSES.get() + 1);
        if FAULT.get() == 4 {
            return Err(ERROR);
        }
    }
    if result < 0 { Err(ERROR) } else { Ok(()) }
}
fn flags(fd: i32) -> Result<i32, &'static str> {
    let n = unsafe { fcntl(fd, GET) };
    if n < 0 { Err(ERROR) } else { Ok(n) }
}
fn set(fd: i32, value: i32) -> Result<(), &'static str> {
    if unsafe { fcntl(fd, SET, value) } < 0 {
        Err(ERROR)
    } else {
        Ok(())
    }
}
fn ident(file: &std::fs::File, access: i32) -> Result<(u64, u64, i32), &'static str> {
    let m = file.metadata().map_err(|_| ERROR)?;
    let f = flags(file.as_raw_fd())?;
    if !m.file_type().is_fifo() || f & 3 != access {
        return Err(ERROR);
    }
    Ok((m.dev(), m.ino(), f))
}

// The caller must guarantee exclusive use of both shared open-file descriptions
// through flag restoration. This sampled awake-time deadline is not BOOTTIME.
pub(super) fn handshake<R: AsFd, W: AsFd>(
    source_input: &R,
    source_output: &W,
    deadline: Instant,
) -> Result<(), &'static str> {
    handshake_outcome(source_input, source_output, deadline, Outcome::Accepted)
}

#[derive(Clone, Copy)]
pub(super) enum Outcome {
    Accepted,
    Epoch,
    Floor,
    Replay,
    Lost,
}

pub(super) fn handshake_outcome<R: AsFd, W: AsFd>(
    source_input: &R,
    source_output: &W,
    deadline: Instant,
    outcome: Outcome,
) -> Result<(), &'static str> {
    // These are fixture assertions, not Root acceptance or authority.
    let expected: &[u8] = match outcome {
        Outcome::Accepted => b"ACK-1\n",
        Outcome::Epoch => b"EPC-1\n",
        Outcome::Floor => b"FLR-1\n",
        Outcome::Replay => b"RPL-1\n",
        Outcome::Lost => b"",
    };
    let mut input = None;
    let mut output = None;
    let mut originals = None;
    let result = (|| {
        input = Some(std::fs::File::from(
            source_input
                .as_fd()
                .try_clone_to_owned()
                .map_err(|_| ERROR)?,
        ));
        output = Some(clone_output(source_output)?);
        let a = ident(input.as_ref().ok_or(ERROR)?, 0)?;
        let b = ident(output.as_ref().ok_or(ERROR)?, 1)?;
        if a.0 == b.0 && a.1 == b.1 || Instant::now() >= deadline {
            return Err(ERROR);
        }
        originals = Some((a, b));
        set_phase(
            input.as_ref().ok_or(ERROR)?.as_raw_fd(),
            a.2 | NONBLOCK,
            false,
        )?;
        set_phase(
            output.as_ref().ok_or(ERROR)?.as_raw_fd(),
            b.2 | NONBLOCK,
            false,
        )?;
        let verify = |input: &std::fs::File, output: &std::fs::File| -> Result<(), &'static str> {
            if ident(input, 0).map(|v| (v.0, v.1, v.2 & (3 | NONBLOCK)))?
                != (a.0, a.1, (a.2 | NONBLOCK) & (3 | NONBLOCK))
                || ident(output, 1).map(|v| (v.0, v.1, v.2 & (3 | NONBLOCK)))?
                    != (b.0, b.1, (b.2 | NONBLOCK) & (3 | NONBLOCK))
                || Instant::now() >= deadline
            {
                Err(ERROR)
            } else {
                Ok(())
            }
        };
        let reader = input.as_mut().ok_or(ERROR)?;
        let writer = output.as_mut().ok_or(ERROR)?;
        let marker = b"INVENTORY-BARRIER-1\n";
        let mut offset = 0;
        while offset < marker.len() {
            verify(reader, writer)?;
            match writer.write(&marker[offset..]) {
                Ok(0) => return Err(ERROR),
                Ok(n) => offset += n,
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                    ) =>
                {
                    std::thread::sleep(Duration::from_millis(1))
                }
                Err(_) => return Err(ERROR),
            }
            verify(reader, writer)?;
        }
        let mut ack = Vec::new();
        let mut buf = [0; 32];
        loop {
            verify(reader, writer)?;
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    ack.extend_from_slice(&buf[..n]);
                    if ack.len() > 6 {
                        return Err(ERROR);
                    }
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                    ) =>
                {
                    std::thread::sleep(Duration::from_millis(1))
                }
                Err(_) => return Err(ERROR),
            }
            verify(reader, writer)?;
        }
        verify(reader, writer)?;
        if ack != expected {
            return Err(ERROR);
        }
        Ok(())
    })();
    let mut failed = result.is_err();
    if let Some((a, b)) = originals {
        for (file, expected) in [(input.as_ref(), a), (output.as_ref(), b)] {
            if let Some(file) = file {
                if ident(file, expected.2 & 3).map(|v| (v.0, v.1)) != Ok((expected.0, expected.1))
                    || set_phase(file.as_raw_fd(), expected.2, true).is_err()
                {
                    failed = true
                }
                if ident(file, expected.2 & 3).map(|v| (v.0, v.1, v.2 & (3 | NONBLOCK)))
                    != Ok((expected.0, expected.1, expected.2 & (3 | NONBLOCK)))
                {
                    failed = true
                }
            }
        }
    }
    for file in [input.take(), output.take()].into_iter().flatten() {
        if checked_close(file.into_raw_fd()).is_err() {
            failed = true
        }
    }
    if Instant::now() >= deadline {
        failed = true
    }
    if failed { Err(ERROR) } else { Ok(()) }
}

#[cfg(test)]
mod tests {
    #[test]
    fn acquisition_setup_restore_and_close_faults_are_absorbing() {
        use std::os::fd::AsRawFd;
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};
        for fault in 1..=4 {
            let mut child = Command::new("/usr/bin/python3")
                .args(["-I", "-B", "-S", "-c", "import sys; sys.stdin.buffer.readline(); sys.stdout.buffer.write(b'ACK-1\\n'); sys.stdout.buffer.flush()"])
                .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();
            let reader = child.stdout.take().unwrap();
            let writer = child.stdin.take().unwrap();
            let read_flags = super::flags(reader.as_raw_fd()).unwrap();
            let write_flags = super::flags(writer.as_raw_fd()).unwrap();
            super::CLOSES.set(0);
            super::FAULT.set(fault);
            assert!(
                super::handshake(&reader, &writer, Instant::now() + Duration::from_secs(2))
                    .is_err()
            );
            assert_eq!(super::CLOSES.get(), if fault == 1 { 1 } else { 2 });
            super::FAULT.set(0);
            super::set(reader.as_raw_fd(), read_flags).unwrap();
            super::set(writer.as_raw_fd(), write_flags).unwrap();
            drop(writer);
            let _ = child.wait().unwrap();
        }
    }

    #[test]
    fn rejects_bad_extra_and_held_open_ack_and_restores_flags() {
        use std::os::fd::AsRawFd;
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};
        for payload in ["BAD\\n", "ACK-1\\nX", "ACK-1\\n"] {
            let code = format!(
                "import sys,time; sys.stdin.buffer.readline(); sys.stdout.buffer.write(b'{payload}'); sys.stdout.buffer.flush(); time.sleep(.25)"
            );
            let mut child = Command::new("/usr/bin/python3")
                .args(["-I", "-B", "-S", "-c", &code])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            let reader = child.stdout.as_ref().unwrap();
            let writer = child.stdin.as_ref().unwrap();
            let original_read = super::flags(reader.as_raw_fd()).unwrap();
            let original_write = super::flags(writer.as_raw_fd()).unwrap();
            assert!(
                super::handshake(reader, writer, Instant::now() + Duration::from_millis(100))
                    .is_err()
            );
            assert_eq!(
                super::flags(reader.as_raw_fd()).unwrap() & super::NONBLOCK,
                original_read & super::NONBLOCK
            );
            assert_eq!(
                super::flags(writer.as_raw_fd()).unwrap() & super::NONBLOCK,
                original_write & super::NONBLOCK
            );
            drop(child.stdin.take());
            assert!(child.wait().unwrap().success());
        }
    }

    #[test]
    fn closed_peer_does_not_kill_child() {
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};
        if std::env::var_os("BARRIER_CLOSED_PEER_TEST").is_some() {
            let mut peer = Command::new("/usr/bin/python3")
                .args(["-I", "-B", "-S", "-c", "pass"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            let writer = peer.stdin.take().unwrap();
            let reader = peer.stdout.take().unwrap();
            assert!(peer.wait().unwrap().success());
            assert!(
                super::handshake(&reader, &writer, Instant::now() + Duration::from_secs(2))
                    .is_err()
            );
            return;
        }
        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "inventory::reporter_barrier::tests::closed_peer_does_not_kill_child",
            ])
            .env("BARRIER_CLOSED_PEER_TEST", "1")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success());
    }

    #[test]
    fn actual_pipe_marker_and_exact_ack() {
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};
        let mut child=Command::new("/usr/bin/python3")
            .args(["-I","-B","-S","-c","import sys; assert sys.stdin.buffer.readline()==b'INVENTORY-BARRIER-1\\n'; sys.stdout.buffer.write(b'ACK-1\\n'); sys.stdout.buffer.flush()"])
            .stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
        super::handshake(
            child.stdout.as_ref().unwrap(),
            child.stdin.as_ref().unwrap(),
            Instant::now() + Duration::from_secs(3),
        )
        .unwrap();
        drop(child.stdin.take());
        assert!(child.wait().unwrap().success());
    }

    #[test]
    fn lost_reply_requires_clean_eof_after_marker() {
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};
        for (payload, accepted) in [("", true), ("x", false)] {
            let program = format!(
                "import sys; assert sys.stdin.buffer.readline()==b'INVENTORY-BARRIER-1\\n'; sys.stdout.buffer.write(b'{payload}'); sys.stdout.buffer.flush()"
            );
            let mut child = Command::new("/usr/bin/python3")
                .args(["-I", "-B", "-S", "-c", &program])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            let result = super::handshake_outcome(
                child.stdout.as_ref().unwrap(),
                child.stdin.as_ref().unwrap(),
                Instant::now() + Duration::from_secs(3),
                super::Outcome::Lost,
            );
            assert_eq!(result.is_ok(), accepted);
            drop(child.stdin.take());
            assert!(child.wait().unwrap().success());
        }
    }

    #[test]
    fn fixture_rejection_responses_must_match_the_specific_outcome() {
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};
        for (outcome, payload, accepted) in [
            (super::Outcome::Epoch, "EPC-1\\n", true),
            (super::Outcome::Floor, "FLR-1\\n", true),
            (super::Outcome::Replay, "RPL-1\\n", true),
            (super::Outcome::Epoch, "FLR-1\\n", false),
        ] {
            let program = format!(
                "import sys; assert sys.stdin.buffer.readline()==b'INVENTORY-BARRIER-1\\n'; sys.stdout.buffer.write(b'{payload}'); sys.stdout.buffer.flush()"
            );
            let mut child = Command::new("/usr/bin/python3")
                .args(["-I", "-B", "-S", "-c", &program])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            let result = super::handshake_outcome(
                child.stdout.as_ref().unwrap(),
                child.stdin.as_ref().unwrap(),
                Instant::now() + Duration::from_secs(3),
                outcome,
            );
            assert_eq!(result.is_ok(), accepted);
            drop(child.stdin.take());
            assert!(child.wait().unwrap().success());
        }
    }
}
