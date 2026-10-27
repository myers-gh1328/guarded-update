//! Native read-only preparation. Snapshot equality is a drift gate, never an execution grant.
use super::process::Tools;
pub fn package_name(text: &str) -> bool {
    let parts = text.split('/').collect::<Vec<_>>();
    text.len() <= 256
        && matches!(parts.len(), 1 | 3)
        && parts.iter().all(|part| {
            !part.is_empty()
                && part.as_bytes()[0].is_ascii_alphanumeric()
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"@+_.-".contains(&b))
        })
}
fn digest(value: &Value) -> Value {
    value
        .as_str()
        .filter(|hash| hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()))
        .map(|hash| json!(hash.to_lowercase()))
        .unwrap_or(Value::Null)
}
use serde_json::{Value, json};

pub fn prepare(
    provider: &str,
    selected: Option<&[String]>,
    info: &Value,
    outdated: &Value,
    state: &str,
    metadata: &str,
) -> Result<Value, String> {
    let kind = match provider {
        "homebrew_formula" => "formulae",
        "homebrew_cask" => "casks",
        _ => return Err("Unsupported native provider".into()),
    };
    let inventory = info[kind]
        .as_array()
        .ok_or("Homebrew inventory malformed")?;
    let candidates = outdated[kind]
        .as_array()
        .ok_or("Homebrew outdated metadata unavailable")?;
    if inventory.len() > 10000 || candidates.len() > 5000 {
        return Err("Homebrew preparation exceeds package budget".into());
    }
    let mut changes = Vec::new();
    let mut exclusions = Vec::new();
    let mut observed = std::collections::BTreeSet::new();
    for candidate in candidates {
        let name = candidate["name"]
            .as_str()
            .ok_or("Homebrew candidate identity missing")?;
        if !package_name(name) {
            return Err("Homebrew candidate identity invalid".into());
        }
        if selected.is_some_and(|items| !items.iter().any(|item| item == name)) {
            continue;
        }
        if !observed.insert(name) {
            return Err("Duplicate Homebrew candidate identity".into());
        }
        let installed = inventory
            .iter()
            .find(|item| item["name"] == name || item["token"] == name || item["full_name"] == name)
            .ok_or("Homebrew candidate not in installed inventory")?;
        let pinned = installed["pinned"] == true || candidate["pinned"] == true;
        if pinned {
            exclusions.push(json!({"package_id":name,"reason":"pinned"}));
            continue;
        }
        let versions = candidate["installed_versions"]
            .as_array()
            .ok_or("Homebrew installed version missing")?;
        if versions.len() != 1 {
            exclusions.push(json!({"package_id":name,"reason":"multiple_installed_versions"}));
            continue;
        }
        let Some(from) = versions[0].as_str() else {
            return Err("Homebrew installed version malformed".into());
        };
        let Some(target) = candidate["current_version"]
            .as_str()
            .filter(|v| !v.is_empty())
        else {
            return Err("Homebrew target version missing".into());
        };
        let actual = if kind == "formulae" {
            installed["installed"].as_array().and_then(|items| {
                if items.len() == 1 {
                    items[0]["version"].as_str()
                } else {
                    None
                }
            })
        } else {
            installed["installed"].as_str()
        };
        if actual != Some(from) {
            exclusions.push(json!({"package_id":name,"reason":"installed_state_drift"}));
            continue;
        }
        let recipe = digest(&installed["ruby_source_checksum"]["sha256"]);
        let artifacts = if kind == "formulae" {
            let mut hashes = serde_json::Map::new();
            if let Some(files) = installed["bottle"]["stable"]["files"].as_object() {
                for (tag, artifact) in files {
                    if package_name(tag) {
                        hashes.insert(tag.clone(), digest(&artifact["sha256"]));
                    }
                }
            }
            Value::Object(hashes)
        } else {
            json!({"sha256":digest(&installed["sha256"])})
        };
        changes.push(json!({"package_id":name,"installed_version":from,"target_version":target,
            "native_constraints":{"recipe_sha256":recipe,"artifact_candidates":artifacts,"dependencies":installed["dependencies"],
            "cask_privileges_unverified":kind=="casks"}}));
    }
    if selected.is_some_and(|items| {
        items.is_empty()
            || items.len() > 5000
            || items.iter().any(|item| !observed.contains(item.as_str()))
    }) {
        return Err("Selected Homebrew package is missing or not currently outdated".into());
    }
    Ok(
        json!({"schema_version":2,"kind":"provider-preparation","provider":provider,
        "selection":{"mode":if selected.is_some(){"selected"}else{"all_eligible"},"packages":selected},
        "context":{"scope":"user","user_id":null},"changes":changes,"exclusions":exclusions,
        "state_sha256":state,"metadata_sha256":metadata,"execution_supported":false,
        "limitations":["Cached metadata only; a newer recipe may exist upstream.",
            "Artifact candidates are provider metadata, not downloaded or verified archives.",
            "Dependency closure, exact frozen recipe execution and cask administrator requirements are unverified.",
            "Snapshot drift validation does not authorize installation; centrally approved execution is unavailable."]}),
    )
}

pub fn snapshot(
    tools: &impl Tools,
    provider: &str,
    selected: Option<&[String]>,
) -> Result<Value, String> {
    if !cfg!(target_os = "macos") {
        return Err("Homebrew native preparation requires macOS".into());
    }
    let brew = ["/opt/homebrew/bin/brew", "/usr/local/bin/brew"]
        .into_iter()
        .find(|path| tools.text(path, &["--version"], 4096).is_ok())
        .ok_or("Homebrew unavailable")?;
    let state = tools.text(
        brew,
        &["info", "--json=v2", "--installed"],
        16 * 1024 * 1024,
    )?;
    let metadata = tools.text(brew, &["outdated", "--json=v2"], 8 * 1024 * 1024)?;
    let inventory: Value =
        serde_json::from_str(&state).map_err(|_| "Homebrew inventory malformed")?;
    let outdated: Value =
        serde_json::from_str(&metadata).map_err(|_| "Homebrew metadata malformed")?;
    // Hash canonical JSON, preserving every installed object and metadata field.
    let mut prepared = prepare(
        provider,
        selected,
        &inventory,
        &outdated,
        &tools.sha256(inventory.to_string().as_bytes())?,
        &tools.sha256(outdated.to_string().as_bytes())?,
    )?;
    let uid = tools.text("/usr/bin/id", &["-u"], 64)?;
    let uid = uid.trim();
    if uid.is_empty() || !uid.bytes().all(|b| b.is_ascii_digit()) {
        return Err("Homebrew account context unavailable".into());
    }
    prepared["context"]["user_id"] = json!(format!("uid:{uid}"));
    let now = crate::timefmt::now_secs();
    prepared["generated_at"] = json!(crate::timefmt::rfc3339(now));
    prepared["expires_at"] = json!(crate::timefmt::rfc3339(now + 900));
    prepared["generated_at_unix"] = json!(now);
    prepared["expires_at_unix"] = json!(now + 900);
    Ok(prepared)
}

pub fn verify(original: &Value, current: &Value) -> Result<(), String> {
    verify_at(original, current, crate::timefmt::now_secs().max(0) as u64)
}
fn verify_at(original: &Value, current: &Value, now: u64) -> Result<(), String> {
    let generated = original["generated_at_unix"]
        .as_u64()
        .ok_or("Preparation timestamp missing")?;
    let expires = original["expires_at_unix"]
        .as_u64()
        .ok_or("Preparation expiry missing")?;
    if generated > now
        || expires <= now
        || expires
            .checked_sub(generated)
            .is_none_or(|ttl| ttl == 0 || ttl > 900)
        || original["generated_at"] != crate::timefmt::rfc3339(generated as i64)
        || original["expires_at"] != crate::timefmt::rfc3339(expires as i64)
    {
        return Err("Homebrew preparation expired or timestamp invalid; prepare again".into());
    }
    if original["kind"] != "provider-preparation"
        || original["schema_version"] != 2
        || original["execution_supported"] != false
        || [
            "provider",
            "selection",
            "state_sha256",
            "metadata_sha256",
            "changes",
            "exclusions",
        ]
        .iter()
        .any(|field| original[*field] != current[*field])
    {
        return Err(
            "Homebrew preparation drift detected; collect a new preparation before review".into(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    #[test]
    fn recipe_or_installed_state_drift_invalidates_preparation() {
        let original = json!({"schema_version":2,"kind":"provider-preparation","execution_supported":false,"state_sha256":"old","metadata_sha256":"old",
            "generated_at_unix":100,"expires_at_unix":1000,"generated_at":crate::timefmt::rfc3339(100),"expires_at":crate::timefmt::rfc3339(1000)});
        assert!(verify_at(&original, &original, 200).is_ok());
        assert!(verify_at(&original, &original, 1000).is_err());
        assert!(verify_at(&original, &original, 99).is_err());
        for field in ["state_sha256", "metadata_sha256", "changes", "provider"] {
            let mut changed = original.clone();
            changed[field] = json!("new");
            assert!(verify_at(&original, &changed, 200).is_err());
        }
    }
    #[test]
    fn all_eligible_respects_pins_and_never_enables_execution() {
        let info = json!({"formulae":[{"name":"alpha","full_name":"alpha","pinned":false,"installed":[{"version":"1"}],"versions":{"stable":"2"}},
            {"name":"held","pinned":true,"installed":[{"version":"1"}],"versions":{"stable":"2"}}],"casks":[]});
        let old = json!({"formulae":[{"name":"alpha","installed_versions":["1"],"current_version":"2"},{"name":"held","installed_versions":["1"],"current_version":"2"}],"casks":[]});
        let result = prepare("homebrew_formula", None, &info, &old, "state", "metadata").unwrap();
        assert_eq!(result["changes"].as_array().unwrap().len(), 1);
        assert_eq!(result["exclusions"][0]["reason"], "pinned");
        assert_eq!(result["execution_supported"], false);
        assert!(
            prepare(
                "homebrew_formula",
                Some(&["missing".into()]),
                &info,
                &old,
                "state",
                "metadata"
            )
            .is_err()
        );
    }
    #[test]
    fn native_names_and_candidate_pins_are_respected() {
        for name in [
            "node@24",
            "claude-code@latest",
            "owner/tap/node@24",
            "libc++",
        ] {
            assert!(package_name(name));
        }
        for name in ["--help", "a/b", "owner/../tool", "x;touch", "a\nb"] {
            assert!(!package_name(name));
        }
        let info =
            json!({"formulae":[{"name":"node@24","pinned":false,"installed":[{"version":"1"}]}]});
        let outdated = json!({"formulae":[{"name":"node@24","pinned":true,"installed_versions":["1"],"current_version":"2"}]});
        let result = prepare("homebrew_formula", None, &info, &outdated, "s", "m").unwrap();
        assert_eq!(result["changes"].as_array().unwrap().len(), 0);
        assert_eq!(result["exclusions"][0]["reason"], "pinned");
    }
}
