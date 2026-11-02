//! Hosted fixture clock without subprocesses; no completion authority.
// Procfs and host administration are trusted; ancestry checks are sampled,
// not an atomic namespace or physical process-set witness.
fn boot_id(raw: &[u8]) -> Result<String, &'static str> {
    if raw.len() != 37
        || raw[36] != b'\n'
        || !raw[..36].iter().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                *b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(b)
            }
        })
    {
        return Err("Native fixture clock unavailable");
    }
    Ok(std::str::from_utf8(&raw[..36])
        .map_err(|_| "Native fixture clock unavailable")?
        .to_owned())
}
fn millis(seconds: i64, nanos: i64) -> Result<u64, &'static str> {
    if seconds < 0 || !(0..1_000_000_000).contains(&nanos) {
        return Err("Native fixture clock unavailable");
    }
    u64::try_from(seconds)
        .map_err(|_| "Native fixture clock unavailable")?
        .checked_mul(1000)
        .and_then(|value| value.checked_add(nanos as u64 / 1_000_000))
        .ok_or("Native fixture clock unavailable")
}
#[cfg(all(
    target_os = "linux",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
thread_local! {
    static FAULT: std::cell::Cell<u8> = const { std::cell::Cell::new(0) };
    static CLOSES: std::cell::Cell<u8> = const { std::cell::Cell::new(0) };
}
#[cfg(all(
    target_os = "linux",
    any(target_arch = "aarch64", target_arch = "x86_64")
))]
pub(super) fn snapshot(
    deadline: std::time::Instant,
) -> Result<super::requests::Clock, &'static str> {
    use std::io::Read;
    use std::os::fd::IntoRawFd;
    use std::os::unix::fs::MetadataExt;
    use std::time::{Instant, SystemTime, UNIX_EPOCH};
    const ERROR: &str = "Native fixture clock unavailable";
    #[repr(C)]
    struct Timespec {
        sec: i64,
        nsec: i64,
    }
    unsafe extern "C" {
        fn clock_gettime(id: i32, value: *mut Timespec) -> i32;
        fn close(fd: i32) -> i32;
    }
    let mut held = Vec::<std::fs::File>::new();
    let result = (|| {
        if Instant::now() >= deadline {
            return Err(ERROR);
        }
        held.push(std::fs::File::open("/").map_err(|_| ERROR)?);
        let root = held[0].metadata().map_err(|_| ERROR)?;
        if !root.is_dir() || root.uid() != 0 || root.mode() & 0o022 != 0 {
            return Err(ERROR);
        }
        let names: [&[u8]; 5] = [b"proc\0", b"sys\0", b"kernel\0", b"random\0", b"boot_id\0"];
        for (index, name) in names.iter().enumerate() {
            if Instant::now() >= deadline {
                return Err(ERROR);
            }
            let file = super::reporter_status::open_child(&held[index], name, index < 4)
                .map_err(|_| ERROR)?;
            held.push(file);
            let meta = held[index + 1].metadata().map_err(|_| ERROR)?;
            if meta.uid() != 0
                || meta.mode() & 0o022 != 0
                || (index < 4 && !meta.is_dir())
                || (index == 4 && !meta.is_file())
            {
                return Err(ERROR);
            }
            if index > 0 && meta.dev() != held[1].metadata().map_err(|_| ERROR)?.dev() {
                return Err(ERROR);
            }
        }
        if FAULT.get() == 1 {
            return Err(ERROR);
        }
        let mut raw = Vec::new();
        held[5]
            .by_ref()
            .take(38)
            .read_to_end(&mut raw)
            .map_err(|_| ERROR)?;
        let boot_id = boot_id(&raw)?;
        for (index, name) in names.iter().enumerate() {
            if Instant::now() >= deadline {
                return Err(ERROR);
            }
            let other = super::reporter_status::open_child(&held[index], name, index < 4)
                .map_err(|_| ERROR)?;
            held.push(other);
            let a = held[index + 1].metadata().map_err(|_| ERROR)?;
            let b = held.last().ok_or(ERROR)?.metadata().map_err(|_| ERROR)?;
            if (a.dev(), a.ino(), a.mode(), a.uid(), a.gid())
                != (b.dev(), b.ino(), b.mode(), b.uid(), b.gid())
            {
                return Err(ERROR);
            }
        }
        let mut ts = Timespec { sec: 0, nsec: 0 };
        // SAFETY: 64-bit Linux CLOCK_BOOTTIME (7) writes one valid timespec.
        if unsafe { clock_gettime(7, &mut ts) } != 0 {
            return Err(ERROR);
        }
        let unix_ms = u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| ERROR)?
                .as_millis(),
        )
        .map_err(|_| ERROR)?;
        let clock = super::requests::Clock {
            boot_id,
            boottime_ms: millis(ts.sec, ts.nsec)?,
            unix_ms,
        };
        clock.validate().map_err(|_| ERROR)?;
        if Instant::now() >= deadline {
            return Err(ERROR);
        }
        Ok(clock)
    })();
    let mut failed = false;
    for file in held.into_iter().rev() {
        // SAFETY: every descriptor was opened in this call and is consumed once.
        let result = unsafe { close(file.into_raw_fd()) };
        CLOSES.set(CLOSES.get() + 1);
        if result < 0 || FAULT.get() == 2 {
            failed = true;
        }
    }
    if failed || Instant::now() >= deadline {
        return Err(ERROR);
    }
    result
}

#[cfg(test)]
mod tests {
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    #[test]
    fn read_and_close_uncertainty_fail_and_attempt_all_closes() {
        use std::time::{Duration, Instant};
        for fault in [1, 2] {
            super::CLOSES.set(0);
            super::FAULT.set(fault);
            assert!(super::snapshot(Instant::now() + Duration::from_secs(3)).is_err());
            assert_eq!(super::CLOSES.get(), if fault == 1 { 6 } else { 11 });
            super::FAULT.set(0);
        }
    }
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    #[test]
    fn real_fixed_sample_agrees_with_native_clock() {
        use std::time::{Duration, Instant};
        let before = super::super::clock::snapshot().unwrap();
        let direct = super::snapshot(Instant::now() + Duration::from_secs(3)).unwrap();
        let after = super::super::clock::snapshot().unwrap();
        assert_eq!(before.boot_id, direct.boot_id);
        assert_eq!(after.boot_id, direct.boot_id);
        assert!(
            before.boottime_ms <= direct.boottime_ms && direct.boottime_ms <= after.boottime_ms
        );
    }
    #[test]
    fn boot_id_requires_exact_canonical_line() {
        let good = b"01234567-89ab-cdef-0123-456789abcdef\n";
        assert_eq!(
            super::boot_id(good).unwrap(),
            "01234567-89ab-cdef-0123-456789abcdef"
        );
        for invalid in [
            b"01234567-89ab-cdef-0123-456789abcdeF\n".as_slice(),
            b"01234567-89ab-cdef-0123-456789abcdef",
            b"01234567-89ab-cdef-0123-456789abcdef\nx",
            b"x",
        ] {
            assert!(super::boot_id(invalid).is_err());
        }
    }
    #[test]
    fn timespec_rejects_bad_and_overflow_values() {
        assert_eq!(super::millis(3, 999_999_999).unwrap(), 3999);
        for (seconds, nanos) in [(-1, 0), (0, -1), (0, 1_000_000_000), (i64::MAX, 0)] {
            assert!(super::millis(seconds, nanos).is_err());
        }
    }
}
