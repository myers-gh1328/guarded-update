//! Safety checks that run before an `auto` update is installed, without
//! any AI (ADR-0001 D8): wait some days after a version first appears,
//! hold big version jumps, and hold when the release notes use warning
//! words. Each check can only hold an update, never release one.

use std::cmp::Ordering;

use serde_json::Value;

use crate::config::Screening;
use crate::model::{Change, Update};
use crate::providers::homebrew::strip_revision;
use crate::version;

const DAY_SECS: u64 = 24 * 60 * 60;

/// Release notes for one update, or why there are none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Notes {
    Found(String),
    Missing(String),
    /// Some releases in the range could not be read; says which. Holds.
    Incomplete(String),
}

/// Days still to wait, or `None` when the wait is over.
pub fn days_left(first_seen: u64, now: u64, wait_days: u32) -> Option<u64> {
    let due = first_seen + u64::from(wait_days) * DAY_SECS;
    (now < due).then(|| (due - now).div_ceil(DAY_SECS))
}

/// 2.x -> 3.0, or 0.21 -> 0.22 while still below 1.0. Calendar versions
/// (a first number of 1900 or more) change every year, so they never
/// count.
pub fn big_jump(installed: &str, available: &str) -> bool {
    let (Some((a, _)), Some((b, _))) = (
        version::parse(strip_revision(installed)),
        version::parse(strip_revision(available)),
    ) else {
        return false;
    };
    if a[0] >= 1900 || b[0] >= 1900 {
        return false;
    }
    if a[0] == 0 && b[0] == 0 {
        return a.get(1) != b.get(1);
    }
    a[0] != b[0]
}

/// The first warning word in the notes, with the line it is on.
pub fn warning(text: &str, words: &[String]) -> Option<(String, String)> {
    for line in text.lines() {
        let lower = line.to_lowercase();
        for word in words {
            if lower.contains(&word.to_lowercase()) {
                return Some((word.clone(), line.trim().to_string()));
            }
        }
    }
    None
}

/// `owner/repo` from the first GitHub URL in the list.
pub fn github_repo(urls: &[&str]) -> Option<String> {
    urls.iter().find_map(|url| {
        let rest = url
            .strip_prefix("https://github.com/")
            .or_else(|| url.strip_prefix("http://github.com/"))?;
        let mut parts = rest.split('/');
        let owner = parts.next().filter(|s| !s.is_empty())?;
        let repo = parts.next().filter(|s| !s.is_empty())?;
        let repo = repo.strip_suffix(".git").unwrap_or(repo);
        Some(format!("{owner}/{repo}"))
    })
}

/// The version inside a release tag: `v1.2.3`, `1.2.3`, `node-v1.2.3`.
fn tag_version(tag: &str) -> Option<&str> {
    let start = tag.find(|c: char| c.is_ascii_digit())?;
    Some(&tag[start..])
}

/// GitHub releases, page by page (`fetch_page(1)` is the newest), until
/// a page has no release newer than `installed` or a page is short.
/// Releases are listed by date, so an old branch's fix can sit among
/// new ones; a whole page past `installed` is the sign to stop. `false`
/// when the pages ran out first or a later page failed.
pub fn collect_releases(
    installed: &str,
    per_page: usize,
    max_pages: u32,
    fetch_page: &mut dyn FnMut(u32) -> Result<Value, String>,
) -> Result<(Vec<Value>, bool), String> {
    let installed = strip_revision(installed);
    let mut all = Vec::new();
    for n in 1..=max_pages {
        let page = match fetch_page(n) {
            Ok(page) => page.as_array().cloned().unwrap_or_default(),
            Err(e) if n == 1 => return Err(e),
            Err(_) => return Ok((all, false)),
        };
        let short = page.len() < per_page;
        let newer = page.iter().any(|r| {
            r["tag_name"]
                .as_str()
                .and_then(tag_version)
                .is_some_and(|v| version::compare(v, installed) == Some(Ordering::Greater))
        });
        all.extend(page);
        if short || !newer {
            return Ok((all, true));
        }
    }
    Ok((all, false))
}

/// Joined notes of every stable release newer than `installed` and up
/// to `available`, newest first. `None` when no release matches.
pub fn notes_between(releases: &Value, installed: &str, available: &str) -> Option<String> {
    let installed = strip_revision(installed);
    let available = strip_revision(available);
    let mut found: Vec<(String, String)> = releases
        .as_array()?
        .iter()
        .filter(|r| r["draft"] != true && r["prerelease"] != true)
        .filter_map(|r| {
            let tag = r["tag_name"].as_str()?;
            let v = tag_version(tag)?;
            let newer = version::compare(v, installed) == Some(Ordering::Greater);
            let in_range = version::compare(v, available) != Some(Ordering::Greater);
            (newer && in_range).then(|| {
                (
                    v.to_string(),
                    format!("{tag}\n{}", r["body"].as_str().unwrap_or("")),
                )
            })
        })
        .collect();
    if found.is_empty() {
        return None;
    }
    found.sort_by(|a, b| version::compare(&b.0, &a.0).unwrap_or(Ordering::Equal));
    Some(
        found
            .into_iter()
            .map(|(_, text)| text)
            .collect::<Vec<_>>()
            .join("\n\n"),
    )
}

/// Why the checks hold this update; empty when they allow it. `notes` is
/// asked for only when the other checks pass, to spare the GitHub API.
/// `ai` reads the notes last, when they were found and nothing else held
/// the update; it returns a reason to hold.
pub fn holds(
    update: &Update,
    rules: &Screening,
    first_seen: u64,
    now: u64,
    notes: &mut dyn FnMut() -> Notes,
    ai: &mut dyn FnMut(&str) -> Option<String>,
) -> Vec<String> {
    let mut reasons = Vec::new();
    if let Some(days) = days_left(first_seen, now, rules.wait_days) {
        reasons.push(format!(
            "waiting {days} more day{} after {} first appeared",
            if days == 1 { "" } else { "s" },
            update.available
        ));
    }
    if rules.hold_major
        && update.change == Change::Version
        && big_jump(&update.installed, &update.available)
    {
        reasons.push(format!(
            "big version jump {} -> {}",
            update.installed, update.available
        ));
    }
    // A rebuild ships the same upstream release, so there are no new notes.
    let reads_notes = rules.hold_words || rules.ai.url.is_some();
    if reasons.is_empty() && reads_notes && update.change == Change::Version {
        match notes() {
            Notes::Found(text) => {
                if rules.hold_words
                    && let Some((word, line)) = warning(&text, &rules.words)
                {
                    reasons.push(format!("release notes say \"{word}\": {line}"));
                } else if rules.ai.url.is_some() {
                    reasons.extend(ai(&text));
                }
            }
            // The rules cannot vouch for notes nobody read.
            Notes::Incomplete(why) => reasons.push(why),
            Notes::Missing(_) => {}
        }
    }
    reasons
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Action, Source};
    use serde_json::json;

    fn update(installed: &str, available: &str, change: Change) -> Update {
        Update {
            source: Source::HomebrewFormula,
            name: "x".into(),
            installed: installed.into(),
            available: available.into(),
            change,
            action: Action::Update,
            note: None,
        }
    }

    #[test]
    fn the_wait_counts_from_first_sight() {
        assert_eq!(days_left(0, DAY_SECS / 2, 2), Some(2));
        assert_eq!(days_left(0, DAY_SECS + 1, 2), Some(1));
        assert_eq!(days_left(0, 2 * DAY_SECS, 2), None);
        assert_eq!(days_left(100, 100, 0), None, "0 days means no wait");
    }

    #[test]
    fn big_jumps_are_major_changes_or_minor_ones_below_1_0() {
        assert!(big_jump("2.9.1", "3.0.0"));
        assert!(!big_jump("14.4.0_1", "14.5.0"));
        assert!(big_jump("v0.21.6", "v0.22.0"));
        assert!(!big_jump("v0.21.5", "v0.21.6"));
        assert!(!big_jump("2025.12.1", "2026.1.0"), "calendar versions");
        assert!(!big_jump("abc", "3.0"));
    }

    #[test]
    fn warning_words_match_case_insensitively_and_quote_the_line() {
        let words: Vec<String> = ["breaking", "removed"].map(String::from).to_vec();
        let text = "## Fixes\n- faster start\n- BREAKING: config moved to ~/.x\n";
        assert_eq!(
            warning(text, &words),
            Some((
                "breaking".to_string(),
                "- BREAKING: config moved to ~/.x".to_string()
            ))
        );
        assert_eq!(warning("all good", &words), None);
        let long = format!("- removed {}", "y".repeat(300));
        assert_eq!(warning(&long, &words).unwrap().1, long, "the whole line");
    }

    #[test]
    fn incomplete_notes_hold_without_asking_the_ai() {
        let mut with_ai = Screening::default();
        with_ai.ai.url = Some("http://h/v1".into());
        let mut partial = || Notes::Incomplete("only the newest 1000 releases were read".into());
        let r = holds(
            &update("1.0", "1.1", Change::Version),
            &with_ai,
            0,
            10 * DAY_SECS,
            &mut partial,
            &mut |_| panic!("not asked"),
        );
        assert_eq!(r, ["only the newest 1000 releases were read"]);
    }

    fn page(tags: &[(&str, bool)]) -> Value {
        Value::Array(
            tags.iter()
                .map(|(t, pre)| json!({"tag_name": t, "body": "", "prerelease": pre}))
                .collect(),
        )
    }

    #[test]
    fn releases_are_fetched_until_a_page_has_nothing_newer() {
        // Page size 3. Page 2 is all prereleases and a backport, yet still
        // newer than 1.0.25; page 3 reaches the installed version.
        let pages = [
            page(&[("v1.0.95", false), ("v1.0.95-1", true), ("v1.0.94", false)]),
            page(&[("v1.0.60-0", true), ("v0.9.9", false), ("v1.0.50-2", true)]),
            page(&[("v1.0.26", false), ("v1.0.25", false), ("v1.0.24", false)]),
            page(&[("v1.0.1", false), ("v1.0.0", false), ("v0.1", false)]),
        ];
        let mut asked = Vec::new();
        let (all, complete) = collect_releases("1.0.25", 3, 10, &mut |n| {
            asked.push(n);
            Ok(pages[n as usize - 1].clone())
        })
        .unwrap();
        assert!(complete);
        assert_eq!(asked, [1, 2, 3, 4], "page 3 still had 1.0.26");
        assert_eq!(all.len(), 12);
        // Out of pages before reaching it: incomplete.
        let (_, complete) =
            collect_releases("1.0.25", 3, 2, &mut |n| Ok(pages[n as usize - 1].clone())).unwrap();
        assert!(!complete);
        // A short page is the last one.
        let (_, complete) =
            collect_releases("1.0.0", 3, 10, &mut |_| Ok(page(&[("v1.0.1", false)]))).unwrap();
        assert!(complete);
        // The first page failing is an error; a later one makes it incomplete.
        assert!(collect_releases("1.0.25", 3, 10, &mut |_| Err("down".into())).is_err());
        let (_, complete) = collect_releases("1.0.25", 3, 10, &mut |n| {
            if n == 1 {
                Ok(pages[0].clone())
            } else {
                Err("rate limited".into())
            }
        })
        .unwrap();
        assert!(!complete);
    }

    #[test]
    fn github_repos_come_from_homepage_or_source_urls() {
        assert_eq!(
            github_repo(&[
                "https://example.org",
                "https://github.com/acme/tool/archive/refs/tags/v1.0.tar.gz"
            ]),
            Some("acme/tool".into())
        );
        assert_eq!(
            github_repo(&["https://github.com/acme/tool.git"]),
            Some("acme/tool".into())
        );
        assert_eq!(github_repo(&["https://gitlab.com/a/b"]), None);
    }

    #[test]
    fn notes_cover_every_release_in_the_range() {
        let releases = json!([
            {"tag_name": "v1.3.0", "body": "three", "draft": false, "prerelease": false},
            {"tag_name": "v1.2.1", "body": "two-one", "draft": false, "prerelease": false},
            {"tag_name": "v1.2.0", "body": "two", "draft": false, "prerelease": false},
            {"tag_name": "v1.2.2-rc1", "body": "rc", "draft": false, "prerelease": true},
            {"tag_name": "v1.1.0", "body": "one", "draft": false, "prerelease": false}
        ]);
        let notes = notes_between(&releases, "1.1.0_2", "1.2.1").unwrap();
        assert!(notes.starts_with("v1.2.1\ntwo-one"), "{notes}");
        assert!(notes.contains("v1.2.0\ntwo"));
        for left_out in ["v1.3.0", "v1.1.0", "rc1"] {
            assert!(!notes.contains(left_out), "{notes}");
        }
        assert_eq!(notes_between(&releases, "1.3.0", "1.3.0"), None);
    }

    fn rule_holds(
        update: &Update,
        rules: &Screening,
        first_seen: u64,
        now: u64,
        notes: &mut dyn FnMut() -> Notes,
    ) -> Vec<String> {
        holds(update, rules, first_seen, now, notes, &mut |_| {
            panic!("the AI is off by default")
        })
    }

    #[test]
    fn the_ai_reads_notes_only_after_every_rule_passed() {
        let mut with_ai = Screening::default();
        with_ai.ai.url = Some("http://h/v1".into());
        let now = 10 * DAY_SECS;
        let mut asked = Vec::new();
        let mut ai = |notes: &str| {
            asked.push(notes.to_string());
            Some("AI check: risky".to_string())
        };
        let mut plain = || Notes::Found("Faster startup".into());
        let r = holds(
            &update("1.0", "1.1", Change::Version),
            &with_ai,
            0,
            now,
            &mut plain,
            &mut ai,
        );
        assert_eq!(r, ["AI check: risky"]);
        let mut worded = || Notes::Found("Removed a flag".into());
        let r = holds(
            &update("1.0", "1.1", Change::Version),
            &with_ai,
            0,
            now,
            &mut worded,
            &mut ai,
        );
        assert_eq!(
            r,
            ["release notes say \"removed\": Removed a flag"],
            "a rule hold needs no AI"
        );
        let mut none = || Notes::Missing("none".into());
        let r = holds(
            &update("1.0", "1.1", Change::Version),
            &with_ai,
            0,
            now,
            &mut none,
            &mut ai,
        );
        assert!(r.is_empty(), "no notes: nothing for the AI to read");
        // Words off, AI on: the AI still reads the notes.
        with_ai.hold_words = false;
        let r = holds(
            &update("1.0", "1.1", Change::Version),
            &with_ai,
            0,
            now,
            &mut worded,
            &mut ai,
        );
        assert_eq!(r, ["AI check: risky"]);
        assert_eq!(asked, ["Faster startup", "Removed a flag"]);
    }

    fn rules() -> Screening {
        Screening::default()
    }

    #[test]
    fn rules_hold_and_explain_why() {
        let now = 10 * DAY_SECS;
        let mut no_notes = || Notes::Missing("none".into());
        let fresh = rule_holds(
            &update("1.0", "1.1", Change::Version),
            &rules(),
            now - DAY_SECS,
            now,
            &mut no_notes,
        );
        assert_eq!(fresh, ["waiting 1 more day after 1.1 first appeared"]);
        let major = rule_holds(
            &update("1.0", "2.0", Change::Version),
            &rules(),
            0,
            now,
            &mut no_notes,
        );
        assert_eq!(major, ["big version jump 1.0 -> 2.0"]);
        let mut breaking = || Notes::Found("Removed the old API".into());
        let worded = rule_holds(
            &update("1.0", "1.1", Change::Version),
            &rules(),
            0,
            now,
            &mut breaking,
        );
        assert_eq!(
            worded,
            ["release notes say \"removed\": Removed the old API"]
        );
        assert!(
            rule_holds(
                &update("1.0", "1.1", Change::Version),
                &rules(),
                0,
                now,
                &mut no_notes
            )
            .is_empty(),
            "no notes found: the rule passes"
        );
    }

    #[test]
    fn notes_are_not_fetched_when_another_rule_already_rule_holds() {
        let mut fetched = false;
        let mut notes = || {
            fetched = true;
            Notes::Found("breaking".into())
        };
        let r = rule_holds(
            &update("1.0", "2.0", Change::Version),
            &rules(),
            0,
            10 * DAY_SECS,
            &mut notes,
        );
        assert_eq!(r.len(), 1);
        assert!(!fetched);
    }

    #[test]
    fn rebuilds_skip_the_release_notes() {
        let mut fetched = false;
        let mut notes = || {
            fetched = true;
            Notes::Found("breaking".into())
        };
        let r = rule_holds(
            &update("1.0", "1.0_1", Change::Rebuild),
            &rules(),
            0,
            10 * DAY_SECS,
            &mut notes,
        );
        assert!(r.is_empty() && !fetched);
    }

    #[test]
    fn each_rule_can_be_turned_off() {
        let off = Screening {
            wait_days: 0,
            hold_major: false,
            hold_words: false,
            ..Screening::default()
        };
        let mut breaking = || Notes::Found("breaking".into());
        assert!(
            rule_holds(
                &update("1.0", "2.0", Change::Version),
                &off,
                0,
                0,
                &mut breaking
            )
            .is_empty()
        );
    }
}
