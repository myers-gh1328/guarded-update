//! Native read-only Linux inventory. Cached policy is not refresh evidence.
use super::process::Tools;
use serde_json::{Value, json};

fn package_id(value: &str) -> bool {
    let mut parts = value.split(':');
    let Some(base) = parts.next() else {
        return false;
    };
    let valid = |s: &str| {
        !s.is_empty()
            && s.len() <= 256
            && (s.as_bytes()[0].is_ascii_lowercase() || s.as_bytes()[0].is_ascii_digit())
            && s.bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"+.-".contains(&c))
    };
    valid(base) && parts.next().is_none_or(valid) && parts.next().is_none()
}
fn installed(text: &str) -> Result<Vec<Value>, String> {
    let mut rows = std::collections::BTreeMap::new();
    for line in text.lines().filter(|line| !line.is_empty()) {
        let fields: Vec<_> = line.split('\t').collect();
        if fields.len() != 4 {
            return Err("Malformed installed inventory".into());
        }
        if fields[0] != "installed" {
            continue;
        }
        if !package_id(fields[1])
            || fields[2].is_empty()
            || fields[2].len() > 256
            || fields[2].bytes().any(|c| c.is_ascii_control())
            || fields[3].is_empty()
            || fields[3].len() > 64
            || !fields[3]
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-')
        {
            return Err("Malformed installed package identity".into());
        }
        let value = json!({"packageId":fields[1],"name":fields[1].split(':').next().unwrap(),"installedVersion":fields[2],"architecture":fields[3]});
        let key = (fields[1].to_owned(), fields[3].to_owned());
        if rows.get(&key).is_some_and(|old| old != &value) {
            return Err("Conflicting installed inventory".into());
        }
        rows.insert(key, value);
        if rows.len() > 20000 {
            return Err("Installed inventory exceeds package limit".into());
        }
    }
    Ok(rows.into_values().collect())
}

#[derive(Default)]
struct Policy {
    version: Option<String>,
    repository: bool,
}
fn policy(text: &str) -> std::collections::BTreeMap<String, Policy> {
    let mut result = std::collections::BTreeMap::new();
    let mut package = None;
    let mut table_version = None;
    for line in text.lines() {
        if let Some(header) = line.strip_suffix(':').filter(|header| package_id(header)) {
            result.insert(header.to_owned(), Policy::default());
            package = Some(header.to_owned());
            table_version = None;
            continue;
        }
        let Some(entry) = package.as_ref().and_then(|name| result.get_mut(name)) else {
            continue;
        };
        let trimmed = line.trim();
        if let Some(candidate) = trimmed.strip_prefix("Candidate:") {
            let candidate = candidate.trim();
            entry.version =
                (candidate != "(none)" && !candidate.is_empty() && candidate.len() <= 256)
                    .then(|| candidate.to_owned());
            continue;
        }
        let mut fields: Vec<_> = trimmed.split_whitespace().collect();
        if fields.first() == Some(&"***") {
            fields.remove(0);
        }
        if fields.len() == 2 && fields[1].parse::<i32>().is_ok() {
            table_version = Some(fields[0].to_owned());
        } else if fields.len() >= 3
            && fields[0].parse::<i32>().is_ok()
            && fields.last() == Some(&"Packages")
            && entry.version.is_some()
            && table_version == entry.version
        {
            entry.repository = true;
        }
    }
    result
}

const APPS: &[&str] = &[
    "cups",
    "samba",
    "wsdd",
    "avahi-daemon",
    "vector",
    "tailscale",
    "nginx",
    "apache2",
    "postgresql",
    "mariadb-server",
    "redis-server",
    "docker.io",
    "docker-ce",
    "mosquitto",
    "grafana",
    "rustdesk",
];
fn system_text(path: &std::path::Path, limit: usize) -> Result<String, String> {
    use std::io::Read;
    let file = std::fs::File::open(path).map_err(|_| "System inventory metadata unavailable")?;
    let metadata = file
        .metadata()
        .map_err(|_| "System inventory metadata unavailable")?;
    if !metadata.is_file() || metadata.len() > limit as u64 {
        return Err("System inventory metadata exceeds limit".into());
    }
    let mut bytes = Vec::new();
    file.take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "System inventory metadata unavailable")?;
    if bytes.len() > limit {
        return Err("System inventory metadata exceeds limit".into());
    }
    String::from_utf8(bytes).map_err(|_| "System inventory metadata is not UTF-8".into())
}
fn os_release(text: &str) -> (String, String) {
    let values = text
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(k, v)| (k, v.trim().trim_matches('"').trim_matches('\'')))
        .collect::<std::collections::BTreeMap<_, _>>();
    let platform = match values.get("ID").copied() {
        Some("debian") => "Debian",
        Some("raspbian") => "Raspberry Pi OS",
        Some("ubuntu") => "Ubuntu",
        _ => "Linux",
    };
    (
        platform.into(),
        values
            .get("PRETTY_NAME")
            .copied()
            .unwrap_or("Linux (OS version unavailable)")
            .chars()
            .take(255)
            .collect(),
    )
}
fn visible_launcher(text: &str) -> bool {
    let mut active = false;
    let mut values = std::collections::BTreeMap::new();
    for line in text.lines() {
        if line.starts_with('[') {
            active = line.trim() == "[Desktop Entry]";
        } else if active && let Some((key, value)) = line.split_once('=') {
            values.insert(key.trim(), value.trim());
        }
    }
    values.get("Type") == Some(&"Application")
        && !["NoDisplay", "Hidden", "Terminal"].iter().any(|key| {
            values
                .get(key)
                .is_some_and(|v| v.eq_ignore_ascii_case("true"))
        })
}
fn desktop_owners(
    text: &str,
    visible: &std::collections::BTreeSet<String>,
) -> std::collections::BTreeSet<String> {
    let mut result = std::collections::BTreeSet::new();
    for line in text.lines() {
        if let Some((owners, path)) = line.split_once(": ")
            && visible.contains(path)
        {
            for owner in owners.split(", ").filter(|name| package_id(name)) {
                result.insert(owner.split(':').next().unwrap().to_owned());
            }
        }
    }
    result
}
fn desktop_evidence(path: &std::path::Path) -> (std::collections::BTreeSet<String>, bool) {
    let mut visible = std::collections::BTreeSet::new();
    let Ok(directory) = std::fs::read_dir(path) else {
        return (visible, false);
    };
    let mut complete = true;
    let mut bytes = 0;
    for (index, entry) in directory.enumerate() {
        if index >= 10000 {
            complete = false;
            break;
        }
        let Ok(entry) = entry else {
            complete = false;
            continue;
        };
        if entry.path().extension().is_none_or(|e| e != "desktop") {
            continue;
        }
        let metadata = std::fs::symlink_metadata(entry.path());
        if !metadata.is_ok_and(|m| m.is_file()) {
            complete = false;
            continue;
        }
        let Ok(text) = system_text(&entry.path(), 16384) else {
            complete = false;
            continue;
        };
        bytes += text.len();
        if bytes > 16 * 1024 * 1024 {
            complete = false;
            break;
        }
        if visible_launcher(&text) {
            visible.insert(entry.path().to_string_lossy().into_owned());
        }
    }
    (visible, complete)
}
fn oldest_index() -> Option<String> {
    let directory = std::fs::read_dir("/var/lib/apt/lists").ok()?;
    let mut oldest = None;
    for (index, entry) in directory.enumerate() {
        if index >= 20000 {
            return None;
        }
        let entry = entry.ok()?;
        if !entry.file_name().to_string_lossy().contains("_Packages") {
            continue;
        }
        let metadata = std::fs::symlink_metadata(entry.path()).ok()?;
        if !metadata.is_file() {
            continue;
        }
        let secs = metadata
            .modified()
            .ok()?
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_secs();
        oldest = Some(oldest.map_or(secs, |v: u64| v.min(secs)));
    }
    oldest
        .filter(|v| *v <= i64::MAX as u64)
        .map(|v| crate::timefmt::rfc3339(v as i64))
}
pub fn collect(tools: &impl Tools, report_id: &str, now: &str) -> Result<Value, String> {
    let hostname = tools.text("/bin/hostname", &[], 4096)?.trim().to_owned();
    let architecture = tools
        .text("/usr/bin/uname", &["-m"], 4096)?
        .trim()
        .to_owned();
    let (platform, version) = os_release(
        &system_text(std::path::Path::new("/etc/os-release"), 16384).unwrap_or_default(),
    );
    let mut scan = json!({"schemaVersion":1,"scanId":report_id,"startedAt":now,"completedAt":now,"status":"partial","reachable":true,"inventoryComplete":false,
      "machine":{"hostname":hostname,"platform":platform,"osVersion":version,"architecture":architecture},"packages":[],"errors":[],"aptIndexOldestAt":oldest_index(),"applicationIdentification":"partial","coverage":[
        "Read-only dpkg/APT package inventory in the dedicated reporting account context.",
        "APT indexes are never refreshed; cached candidates and holds are observations, not verified repository refresh evidence. Update status remains Unknown.",
        "Other package managers, manual/portable installations and inaccessible per-user software are not collected.",
        "OS/security update assessment, CVEs, application health, service state and logs are not collected."]});
    let records=tools.text("/usr/bin/dpkg-query",&["--show","--showformat=${db:Status-Status}\\t${binary:Package}\\t${Version}\\t${Architecture}\\n"],8*1024*1024).and_then(|text|installed(&text));
    let Ok(mut rows) = records else {
        scan["errors"] = json!([
            "Installed dpkg inventory unavailable or malformed; previous complete inventory must be retained."
        ]);
        scan["completedAt"] = json!(crate::timefmt::rfc3339(crate::timefmt::now_secs()));
        return Ok(scan);
    };
    scan["inventoryComplete"] = json!(true);
    let (visible, desktops_complete) =
        desktop_evidence(std::path::Path::new("/usr/share/applications"));
    let owners = tools.text(
        "/usr/bin/dpkg-query",
        &["--search", "/usr/share/applications/*.desktop"],
        1024 * 1024,
    );
    let launchers = owners
        .as_ref()
        .map(|text| desktop_owners(text, &visible))
        .unwrap_or_default();
    if owners.is_ok() && desktops_complete {
        scan["applicationIdentification"] = json!("available");
    } else {
        scan["coverage"].as_array_mut().unwrap().push(json!("Graphical application identification is partial: launcher files or ownership evidence were unavailable, unreadable or exceeded collection limits."));
    }
    let held = tools
        .text(
            "/usr/bin/apt-mark",
            &[
                "-o",
                "Dir::Cache::pkgcache=",
                "-o",
                "Dir::Cache::srcpkgcache=",
                "showhold",
            ],
            1024 * 1024,
        )
        .ok()
        .map(|text| {
            text.lines()
                .filter(|name| package_id(name))
                .map(str::to_owned)
                .collect::<std::collections::BTreeSet<_>>()
        });
    let mut policies = std::collections::BTreeMap::new();
    let started = std::time::Instant::now();
    let mut policy_failed = false;
    for batch in rows.chunks(300) {
        if started.elapsed() > std::time::Duration::from_secs(60) {
            policy_failed = true;
            break;
        }
        let mut args = vec![
            "-o",
            "Dir::Cache::pkgcache=",
            "-o",
            "Dir::Cache::srcpkgcache=",
            "policy",
        ];
        args.extend(batch.iter().filter_map(|row| row["packageId"].as_str()));
        match tools.text("/usr/bin/apt-cache", &args, 16 * 1024 * 1024) {
            Ok(text) => policies.extend(policy(&text)),
            Err(_) => {
                policy_failed = true;
                break;
            }
        }
    }
    if policy_failed {
        scan["errors"].as_array_mut().unwrap().push(json!(
            "Cached APT policy unavailable or bounded collection deadline reached."
        ));
    }
    let native = tools
        .text("/usr/bin/dpkg", &["--print-architecture"], 128)
        .ok()
        .map(|v| v.trim().to_owned());
    for row in &mut rows {
        let id = row["packageId"].as_str().unwrap().to_owned();
        let name = row["name"].as_str().unwrap().to_owned();
        let candidate = policies
            .get(&id)
            .or_else(|| {
                (native.as_deref() == row["architecture"].as_str())
                    .then(|| policies.get(&name))
                    .flatten()
            })
            .filter(|v| v.repository)
            .and_then(|v| v.version.as_ref());
        let is_held = held
            .as_ref()
            .map(|set| set.contains(&id) || set.contains(&name));
        row["provider"] = json!("APT");
        row["scope"] = json!("machine");
        row["publisher"] = Value::Null;
        row["latestVersion"] = json!(candidate);
        row["reliableMatch"] = json!(false);
        row["upgradeAvailable"] = json!(false);
        row["held"] = json!(is_held);
        row["applicationEvidence"] = json!(if launchers.contains(&name) {
            Some("Owns a visible graphical application launcher.".to_owned())
        } else if APPS.contains(&name.as_str()) {
            Some(format!("Recognized server application: {name}."))
        } else {
            None
        });
        row["note"] = json!(if is_held == Some(true) {
            "APT hold observed. Cached candidate is unverified; update status remains Unknown."
        } else {
            "Cached candidate is unverified; no metadata refresh performed and update status remains Unknown."
        });
    }
    scan["packages"] = json!(rows);
    scan["status"] = json!(if scan["errors"].as_array().unwrap().is_empty() {
        "complete"
    } else {
        "partial"
    });
    scan["completedAt"] = json!(crate::timefmt::rfc3339(crate::timefmt::now_secs()));
    Ok(scan)
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fake {
        installed_available: bool,
    }
    impl Tools for Fake {
        fn text(&self, program: &str, args: &[&str], _: usize) -> Result<String, String> {
            assert!(
                !args
                    .iter()
                    .any(|arg| matches!(*arg, "update" | "upgrade" | "install"))
            );
            match (program,args) {
                ("/bin/hostname",[]) => Ok("synthetic.test".into()),
                ("/usr/bin/uname",["-m"]) => Ok("armv6l".into()),
                ("/usr/bin/dpkg-query",["--show",_]) if self.installed_available => Ok("installed\tcups\t1\tarmhf\ninstalled\tlibcups2\t1\tarmhf\n".into()),
                ("/usr/bin/apt-cache",_) => Ok("cups:\n  Candidate: 2\n     2 500\n        500 https://synthetic.invalid stable/main armhf Packages\n".into()),
                ("/usr/bin/apt-mark",_) => Ok("cups\n".into()),
                _ => Err("synthetic unavailable".into()),
            }
        }
        fn sha256(&self, _: &[u8]) -> Result<String, String> {
            Ok("a".repeat(64))
        }
    }
    #[test]
    fn application_coverage_is_partial_for_missing_or_oversized_desktop_evidence() {
        let root = std::env::temp_dir().join(format!("inventory-desktop-{}", std::process::id()));
        assert!(!desktop_evidence(&root).1);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(
            root.join("valid.desktop"),
            "[Desktop Entry]\nType=Application\n",
        )
        .unwrap();
        assert!(desktop_evidence(&root).1);
        std::fs::write(root.join("oversized.desktop"), "x".repeat(16385)).unwrap();
        assert!(!desktop_evidence(&root).1);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn collection_keeps_installed_inventory_and_reports_cached_hold_without_false_currency() {
        let scan = collect(
            &Fake {
                installed_available: true,
            },
            "synthetic-report",
            "2026-01-01T00:00:00Z",
        )
        .unwrap();
        assert_eq!(scan["inventoryComplete"], true);
        let rows = scan["packages"].as_array().unwrap();
        let cups = rows.iter().find(|v| v["packageId"] == "cups").unwrap();
        assert_eq!(cups["latestVersion"], "2");
        assert_eq!(cups["reliableMatch"], false);
        assert_eq!(cups["held"], true);
        assert!(cups["applicationEvidence"].is_string());
        assert_eq!(
            rows.iter().find(|v| v["packageId"] == "libcups2").unwrap()["applicationEvidence"],
            Value::Null
        );
        assert!(!scan.to_string().contains("synthetic.invalid"));
        let failed = collect(
            &Fake {
                installed_available: false,
            },
            "synthetic-report",
            "2026-01-01T00:00:00Z",
        )
        .unwrap();
        assert_eq!(failed["inventoryComplete"], false);
        assert_eq!(failed["status"], "partial");
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn native_linux_inventory_matches_dpkg_without_refresh_or_installation() {
        if std::env::var_os("GUARDED_UPDATE_NATIVE_INVENTORY_TEST").is_none() {
            return;
        }
        let tools = crate::inventory::process::SystemTools;
        let expected=installed(&tools.text("/usr/bin/dpkg-query", &["--show","--showformat=${db:Status-Status}\\t${binary:Package}\\t${Version}\\t${Architecture}\\n"],8*1024*1024).unwrap()).unwrap();
        let now = crate::timefmt::rfc3339(crate::timefmt::now_secs());
        let scan = collect(&tools, "synthetic-ci-report", &now).unwrap();
        assert_eq!(scan["inventoryComplete"], true);
        let rows = scan["packages"].as_array().unwrap();
        assert_eq!(rows.len(), expected.len());
        for (actual, expected) in rows.iter().zip(expected.iter()) {
            for key in ["packageId", "installedVersion", "architecture"] {
                assert_eq!(actual[key], expected[key]);
            }
            assert_eq!(actual["reliableMatch"], false);
        }
    }
    #[test]
    fn policy_requires_repository_backing_and_does_not_retain_repository_urls() {
        let policies = policy(
            "test:\n  Installed: 1\n  Candidate: 2\n  Version table:\n     2 500\n        500 https://synthetic.invalid/debian stable/main armhf Packages\n *** 1 100\n        100 /var/lib/dpkg/status\nlocal:\n  Candidate: 3\n *** 3 100\n        100 /var/lib/dpkg/status\n",
        );
        assert_eq!(policies["test"].version.as_deref(), Some("2"));
        assert!(policies["test"].repository);
        assert!(!policies["local"].repository);
    }
    #[test]
    fn installed_rows_keep_multiarch_and_reject_malformed_identity() {
        let rows = installed("installed\tlibtest:armhf\t1:2.0-1\tarmhf\nconfig-files\tremoved\t1\tall\ninstalled\tlibtest:arm64\t2\tarm64\n").unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().any(|row| row["packageId"] == "libtest:armhf"));
        assert!(rows.iter().any(|row| row["architecture"] == "arm64"));
        assert!(installed("installed\tbroken\n").is_err());
        assert!(installed("installed\t--bad\t1\tall\n").is_err());
    }
}
