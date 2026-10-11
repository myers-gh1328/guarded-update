//! Version comparison without a crate: dotted numbers, an optional `v`
//! prefix, and a pre-release suffix that sorts before its release.

use std::cmp::Ordering;

/// `v1.2.3-rc1` -> `([1, 2, 3], true)`. `None` when there is no leading
/// number.
pub fn parse(text: &str) -> Option<(Vec<u64>, bool)> {
    let text = text.trim();
    let text = text.strip_prefix(['v', 'V']).unwrap_or(text);
    let end = text
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(text.len());
    let numbers: Vec<u64> = text[..end]
        .split('.')
        .filter(|p| !p.is_empty())
        .map(str::parse)
        .collect::<Result<_, _>>()
        .ok()?;
    if numbers.is_empty() {
        return None;
    }
    Some((numbers, end < text.len()))
}

/// Compares two versions; `None` if either cannot be read.
pub fn compare(a: &str, b: &str) -> Option<Ordering> {
    let (a_nums, a_pre) = parse(a)?;
    let (b_nums, b_pre) = parse(b)?;
    for i in 0..a_nums.len().max(b_nums.len()) {
        let x = a_nums.get(i).copied().unwrap_or(0);
        let y = b_nums.get(i).copied().unwrap_or(0);
        if x != y {
            return Some(x.cmp(&y));
        }
    }
    // Same numbers: a release is newer than its pre-release.
    Some(b_pre.cmp(&a_pre))
}

#[cfg(test)]
mod tests {
    use super::*;
    use Ordering::*;

    #[test]
    fn parses_numbers_prefix_and_prerelease() {
        assert_eq!(parse("v0.21.6"), Some((vec![0, 21, 6], false)));
        assert_eq!(parse("1.0.0rc1"), Some((vec![1, 0, 0], true)));
        assert_eq!(parse("2.1.13_1"), Some((vec![2, 1, 13], true)));
        assert_eq!(parse("27.0"), Some((vec![27, 0], false)));
        assert_eq!(parse("latest"), None);
    }

    #[test]
    fn compares_numerically_with_padding() {
        assert_eq!(compare("0.7.6", "0.7.10"), Some(Less));
        assert_eq!(compare("v1.2", "1.2.0"), Some(Equal));
        assert_eq!(compare("1.3", "1.2.9"), Some(Greater));
        assert_eq!(compare("v2026.9.24", "v0.21.6"), Some(Greater));
    }

    #[test]
    fn prerelease_sorts_before_its_release() {
        assert_eq!(compare("1.0.0rc1", "1.0.0"), Some(Less));
        assert_eq!(compare("1.0.0", "1.0.0-beta"), Some(Greater));
        assert_eq!(compare("1.0.1-beta", "1.0.0"), Some(Greater));
    }

    #[test]
    fn unreadable_versions_do_not_compare() {
        assert_eq!(compare("abc", "1.0"), None);
    }
}
