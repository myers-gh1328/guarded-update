//! Native boot-relative request timing; wall time never supplies monotonic proof.
use super::requests::Clock;

fn sample(boot_id: &str, boottime_ms: u64, unix_ms: u128) -> Result<Clock, String> {
    let clock = Clock {
        boot_id: boot_id.trim().to_ascii_lowercase(),
        boottime_ms,
        unix_ms: u64::try_from(unix_ms).map_err(|_| "Native request clock overflow")?,
    };
    clock.validate()?;
    Ok(clock)
}

pub fn snapshot() -> Result<Clock, String> {
    #[cfg(target_os = "macos")]
    {
        use super::process::{SystemTools, Tools};
        // Apple's clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW), including sleep.
        // https://github.com/apple-oss-distributions/Libc/blob/main/include/_time.h
        unsafe extern "C" {
            fn clock_gettime_nsec_np(clock: std::ffi::c_uint) -> u64;
        }
        let boot = SystemTools.text("/usr/sbin/sysctl", &["-n", "kern.bootsessionuuid"], 128)?;
        // SAFETY: clock ID 4 is the platform's documented MONOTONIC_RAW enum;
        // this function accepts no pointer or caller-owned memory.
        let nanos = unsafe { clock_gettime_nsec_np(4) };
        if nanos == 0 {
            return Err("Native request clock unavailable".into());
        }
        let unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "Native wall clock unavailable")?
            .as_millis();
        sample(&boot, nanos / 1_000_000, unix)
    }
    #[cfg(target_os = "linux")]
    {
        // The approved Linux helper profile already requires system Python3.
        // Its native CLOCK_BOOTTIME binding avoids 32-bit time_t/time64 ABI
        // differences across glibc and static musl ARM builds. Isolated mode,
        // fixed source and cleared environment prohibit caller code/import paths.
        let bytes = super::process::SystemTools.run_with_timeout(
            "/usr/bin/python3",
            &["-I", "-c", "import pathlib,time; print(pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()); print(time.clock_gettime_ns(time.CLOCK_BOOTTIME)//1000000); print(time.time_ns()//1000000)"],
            &[],
            256,
            std::time::Duration::from_secs(5),
        )?;
        parse_linux(&bytes)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    Err("Native request clock unavailable".into())
}

#[cfg(any(target_os = "linux", test))]
fn parse_linux(bytes: &[u8]) -> Result<Clock, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "Native request clock invalid")?;
    let rows: Vec<_> = text.lines().collect();
    if rows.len() != 3
        || rows[1].is_empty()
        || rows[2].is_empty()
        || !rows[1].bytes().all(|v| v.is_ascii_digit())
        || !rows[2].bytes().all(|v| v.is_ascii_digit())
    {
        return Err("Native request clock invalid".into());
    }
    sample(
        rows[0],
        rows[1]
            .parse()
            .map_err(|_| "Native request clock invalid")?,
        rows[2]
            .parse()
            .map_err(|_| "Native request clock invalid")?,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn malformed_clock_data_never_supplies_proof() {
        for bytes in [
            b"not-a-boot\n1\n2".as_slice(),
            b"00000000-0000-4000-8000-000000000001\n-1\n2",
            b"00000000-0000-4000-8000-000000000001\n1\n2\nextra",
            b"00000000-0000-4000-8000-000000000001\n9007199254740992\n2",
        ] {
            assert!(parse_linux(bytes).is_err());
        }
        let valid = parse_linux(b"00000000-0000-4000-8000-000000000001\n1001\n2002\n").unwrap();
        assert_eq!(valid.boottime_ms, 1001);
        assert_eq!(valid.unix_ms, 2002);
    }
    #[test]
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn native_clock_retains_boot_identity_and_monotonic_order() {
        let first = snapshot().unwrap();
        let second = snapshot().unwrap();
        assert!(
            first.boot_id == second.boot_id,
            "Native boot identity changed"
        );
        assert!(second.boottime_ms >= first.boottime_ms);
        assert!(first.unix_ms > 0);
        assert_eq!(first.boot_id.len(), 36);
    }
}
