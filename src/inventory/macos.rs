use super::process::Tools;
use serde_json::{Value, json};

const SERVER_APPS: &[&str] = &[
    "cups",
    "samba",
    "wsdd",
    "avahi",
    "vector",
    "tailscale",
    "nginx",
    "postgresql",
    "mariadb",
    "redis",
    "docker",
    "mosquitto",
    "grafana",
    "prometheus",
];

fn brew_rows(text: &str, kind: &str, architecture: &str, outdated: &Value) -> Vec<Value> {
    text.lines().filter_map(|line| {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 2 { return None; }
        let name = fields[0];
        let installed = fields[fields.len()-1];
        let latest = outdated[if kind == "formula" {"formulae"} else {"casks"}].as_array()
            .and_then(|items| items.iter().find(|item| item["name"] == name && item["installed_versions"].as_array().is_some_and(|versions| versions.iter().any(|v| v == installed))))
            .and_then(|item| item["current_version"].as_str()).filter(|latest| *latest != installed);
        Some(json!({"packageId":format!("{kind}:{name}"),"name":name,"publisher":null,
            "installedVersion":installed,"architecture":architecture,
            "provider":if kind=="formula" {"Homebrew formula"} else {"Homebrew cask"},
            "scope":"machine","latestVersion":latest,"reliableMatch":latest.is_some(),
            "upgradeAvailable":latest.is_some(),
            "applicationEvidence":if kind=="cask" {Some("Installed Homebrew cask.".to_owned())} else if SERVER_APPS.contains(&name.to_ascii_lowercase().as_str()) {Some(format!("Recognized server application: {name}."))} else {None},
            "note":if latest.is_some() {"Homebrew cached metadata reports a newer version."} else {"No matching newer version reported; current status is unverified."}}))
    }).collect()
}

pub fn collect(tools: &impl Tools, report_id: &str, now: &str) -> Result<Value, String> {
    let hostname = tools.text("/bin/hostname", &[], 4096)?.trim().to_owned();
    let architecture = tools
        .text("/usr/bin/uname", &["-m"], 4096)?
        .trim()
        .to_owned();
    let version = tools
        .text("/usr/bin/sw_vers", &["-productVersion"], 4096)
        .unwrap_or_else(|_| "version unavailable".into());
    let mut scan = json!({"schemaVersion":1,"scanId":report_id,"startedAt":now,"completedAt":now,
        "status":"partial","reachable":true,"inventoryComplete":false,
        "machine":{"hostname":hostname,"platform":"macOS","osVersion":format!("macOS {}",version.trim()),"architecture":architecture},
        "packages":[],"errors":[],"aptIndexOldestAt":null,"coverage":[
            "Read-only System Information and cached Homebrew inventory in the reporting account context.",
            "Other users' applications, manual and portable installations may be inaccessible or missed.",
            "Homebrew metadata is not refreshed by collection; absence of an upgrade does not prove current status.",
            "macOS system updates, CVEs, service health and logs are not collected; macOS updates are never applied."]});
    let mut packages = Vec::new();
    match tools
        .text(
            "/usr/sbin/system_profiler",
            &["SPApplicationsDataType", "-json"],
            32 * 1024 * 1024,
        )
        .and_then(|text| {
            serde_json::from_str::<Value>(&text)
                .map_err(|_| "malformed application inventory".into())
        }) {
        Ok(data) if data["SPApplicationsDataType"].is_array() => {
            scan["inventoryComplete"] = json!(true);
            let mut seen = std::collections::BTreeSet::new();
            for app in data["SPApplicationsDataType"].as_array().unwrap() {
                let (Some(name), Some(version)) = (app["_name"].as_str(), app["version"].as_str())
                else {
                    continue;
                };
                if name.trim().is_empty() || version.trim().is_empty() {
                    continue;
                }
                let path = app["path"].as_str().unwrap_or(name);
                if !seen.insert(path.to_lowercase()) {
                    continue;
                }
                let identity = tools.sha256(path.as_bytes())?;
                let evidence = if path.starts_with('/')
                    && !path.starts_with("/System/")
                    && !path.starts_with("/usr/")
                {
                    Some("Third-party application reported by macOS System Information.")
                } else {
                    None
                };
                packages.push(json!({"packageId":format!("app:{identity}"),"name":name,"publisher":app["obtained_from"].as_str(),
                    "installedVersion":version,"architecture":architecture,"provider":"macOS application",
                    "scope":if path.starts_with("/Users/") {"user"} else {"machine"},
                    "applicationEvidence":evidence,
                    "latestVersion":null,"reliableMatch":false,"upgradeAvailable":false,
                    "note":"Installed version observed; no reliable latest-version comparison source."}));
            }
        }
        _ => scan["errors"].as_array_mut().unwrap().push(json!(
            "System Information application inventory unavailable or malformed."
        )),
    }
    let brew = ["/opt/homebrew/bin/brew", "/usr/local/bin/brew"]
        .into_iter()
        .find(|path| tools.text(path, &["--version"], 4096).is_ok());
    if let Some(brew) = brew {
        let outdated = tools
            .text(brew, &["outdated", "--json=v2"], 8 * 1024 * 1024)
            .and_then(|text| {
                serde_json::from_str::<Value>(&text)
                    .map_err(|_| "malformed Homebrew metadata".into())
            })
            .unwrap_or(Value::Null);
        if outdated.is_null() {
            scan["coverage"]
                .as_array_mut()
                .unwrap()
                .push(json!("Homebrew latest-version comparison unavailable."));
        }
        for kind in ["formula", "cask"] {
            match tools.text(
                brew,
                &["list", "--versions", &format!("--{kind}")],
                8 * 1024 * 1024,
            ) {
                Ok(text) => packages.extend(brew_rows(&text, kind, &architecture, &outdated)),
                Err(_) => scan["errors"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!(format!("Homebrew {kind} inventory unavailable."))),
            }
        }
    } else {
        scan["coverage"]
            .as_array_mut()
            .unwrap()
            .push(json!("Homebrew unavailable to the reporting account."));
        scan["errors"].as_array_mut().unwrap().push(json!(
            "Homebrew inventory unavailable; previous complete inventory must be retained."
        ));
    }
    let complete =
        scan["errors"].as_array().unwrap().is_empty() && scan["inventoryComplete"] == true;
    scan["inventoryComplete"] = json!(complete);
    scan["applicationIdentification"] = json!(if complete { "available" } else { "partial" });
    scan["status"] = json!(if scan["errors"].as_array().unwrap().is_empty() {
        "complete"
    } else {
        "partial"
    });
    scan["packages"] = json!(packages);
    scan["completedAt"] = json!(crate::timefmt::rfc3339(crate::timefmt::now_secs()));
    Ok(scan)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    struct Fake {
        fail_apps: bool,
        fail_brew: bool,
    }
    impl Tools for Fake {
        fn text(&self, program: &str, args: &[&str], _: usize) -> Result<String, String> {
            assert!(
                !args
                    .iter()
                    .any(|arg| matches!(*arg, "upgrade" | "update" | "install"))
            );
            if program.ends_with("/brew") && self.fail_brew {
                return Err("synthetic Homebrew unavailable".into());
            }
            match (program,args) {
                ("/bin/hostname",_)=>Ok("synthetic.test".into()),
                ("/usr/bin/uname",_)=>Ok("arm64".into()),
                ("/usr/bin/sw_vers",_)=>Ok("15.0".into()),
                ("/usr/sbin/system_profiler",_) if !self.fail_apps=>Ok(json!({"SPApplicationsDataType":[{"_name":"App","version":"1","path":"/Users/example/Applications/App.app"},{"_name":"App","version":"1","path":"/Users/example/Applications/App.app"}]}).to_string()),
                ("/opt/homebrew/bin/brew",["--version"])=>Ok("Homebrew synthetic".into()),
                ("/opt/homebrew/bin/brew",["outdated","--json=v2"])=>Ok("{\"formulae\":[],\"casks\":[]}".into()),
                ("/opt/homebrew/bin/brew",["list","--versions","--formula"])=>Ok("tool 1".into()),
                ("/opt/homebrew/bin/brew",["list","--versions","--cask"])=>Ok(String::new()),
                _=>Err("synthetic unavailable".into())
            }
        }
        fn sha256(&self, _: &[u8]) -> Result<String, String> {
            Ok("a".repeat(64))
        }
    }
    #[test]
    fn native_collection_deduplicates_user_apps_and_retains_brew_after_profiler_failure() {
        let scan = collect(
            &Fake {
                fail_apps: false,
                fail_brew: false,
            },
            "id",
            "2026-01-01T00:00:00Z",
        )
        .unwrap();
        assert_eq!(scan["packages"].as_array().unwrap().len(), 2);
        assert_eq!(scan["packages"][0]["scope"], "user");
        assert!(scan["packages"][0]["applicationEvidence"].is_string());
        assert_eq!(scan["applicationIdentification"], "available");
        assert_eq!(scan["packages"][1]["latestVersion"], Value::Null);
        let partial = collect(
            &Fake {
                fail_apps: true,
                fail_brew: false,
            },
            "id",
            "2026-01-01T00:00:00Z",
        )
        .unwrap();
        assert_eq!(partial["inventoryComplete"], false);
        assert_eq!(partial["status"], "partial");
        assert_eq!(partial["packages"][0]["provider"], "Homebrew formula");
        let unavailable = collect(
            &Fake {
                fail_apps: false,
                fail_brew: true,
            },
            "id",
            "2026-01-01T00:00:00Z",
        )
        .unwrap();
        assert_eq!(unavailable["inventoryComplete"], false);
        assert_eq!(unavailable["status"], "partial");
        assert_eq!(unavailable["applicationIdentification"], "partial");
    }
    #[test]
    fn cached_brew_only_marks_explicit_matching_outdated_versions() {
        let outdated = json!({"formulae":[{"name":"alpha","installed_versions":["1"],"current_version":"2"}],"casks":[]});
        let rows = brew_rows("alpha 1\nbeta 3\nalpha 0\n", "formula", "arm64", &outdated);
        assert_eq!(rows[0]["latestVersion"], "2");
        assert_eq!(rows[1]["latestVersion"], serde_json::Value::Null);
        assert_eq!(rows[2]["latestVersion"], serde_json::Value::Null);
        assert_eq!(rows[1]["reliableMatch"], false);
        let casks = brew_rows("browser 1", "cask", "arm64", &outdated);
        assert!(casks[0]["applicationEvidence"].is_string());
        let formulae = brew_rows("nginx 1\nlibrary 1", "formula", "arm64", &outdated);
        assert!(formulae[0]["applicationEvidence"].is_string());
        assert_eq!(formulae[1]["applicationEvidence"], Value::Null);
    }
}
