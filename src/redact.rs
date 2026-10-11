//! The redaction layer: every string that leaves the process (stdout,
//! stderr, logs, history, and later the model prompt and Slack) passes
//! through [`Redactor::redact`].

use std::fmt;
use std::path::PathBuf;

pub const MASK: &str = "[REDACTED]";

/// Masks secret-shaped values and exact matches of known secret values.
pub struct Redactor {
    literals: Vec<String>,
}

// Manual Debug: never print the secret values themselves.
impl fmt::Debug for Redactor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Redactor {{ {} literal values }}", self.literals.len())
    }
}

impl Redactor {
    /// A redactor with pattern rules only.
    pub fn patterns_only() -> Self {
        Self {
            literals: Vec::new(),
        }
    }

    /// Adds exact secret values. Values shorter than 6 characters are
    /// ignored because masking them would destroy ordinary text.
    pub fn with_values<I: IntoIterator<Item = String>>(values: I) -> Self {
        let mut literals: Vec<String> = values
            .into_iter()
            .filter(|v| v.chars().count() >= MIN_LITERAL_LEN)
            .collect();
        // Longest first, so a value containing another is masked whole.
        literals.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
        literals.dedup();
        Self { literals }
    }

    /// Reads each referenced secret file and masks its values: the whole
    /// trimmed content, each line, and the value side of `KEY=value` lines.
    pub fn from_secret_files(paths: &[PathBuf]) -> Result<Self, String> {
        let mut values = Vec::new();
        for path in paths {
            let content = std::fs::read_to_string(path)
                .map_err(|e| format!("cannot read secret file {}: {}", path.display(), e.kind()))?;
            values.extend(secret_values(&content));
        }
        Ok(Self::with_values(values))
    }

    pub fn redact(&self, text: &str) -> String {
        let mut owned = text.to_string();
        for literal in &self.literals {
            if owned.contains(literal.as_str()) {
                owned = owned.replace(literal.as_str(), MASK);
            }
        }
        redact_patterns(&owned)
    }
}

const MIN_LITERAL_LEN: usize = 6;
const MIN_PREFIXED_TOKEN_LEN: usize = 16;
const MIN_BEARER_LEN: usize = 8;

const TOKEN_PREFIXES: &[&str] = &[
    "xoxb-",
    "xoxp-",
    "xoxa-",
    "xoxr-",
    "xoxs-",
    "xapp-",
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "github_pat_",
    "glpat-",
    "sk-",
    "AKIA",
];

const SECRET_KEY_WORDS: &[&str] = &[
    "token",
    "secret",
    "password",
    "passwd",
    "api_key",
    "apikey",
    "api-key",
    "private_key",
    "credential",
];

/// Keys that name a secret's location or size, not the secret itself.
const NON_SECRET_KEY_SUFFIXES: &[&str] = &["file", "path", "dir", "count", "tokens", "_name"];

fn secret_values(content: &str) -> Vec<String> {
    let mut values = vec![content.trim().to_string()];
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        values.push(line.to_string());
        let line = line.strip_prefix("export ").unwrap_or(line);
        if let Some((_, value)) = line.split_once(['=', ':']) {
            let value = value
                .trim()
                .trim_end_matches(',')
                .trim_matches(|c| c == '"' || c == '\'');
            values.push(value.to_string());
        }
    }
    values
}

fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

fn run_end(bytes: &[u8], start: usize) -> usize {
    let mut end = start;
    while end < bytes.len() && is_token_byte(bytes[end]) {
        end += 1;
    }
    end
}

fn skip_spaces(bytes: &[u8], mut i: usize) -> usize {
    while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t') {
        i += 1;
    }
    i
}

fn redact_patterns(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let at_boundary = i == 0 || !is_token_byte(bytes[i - 1]);
        if !at_boundary || !is_token_byte(bytes[i]) {
            out.push(bytes[i]);
            i += 1;
            continue;
        }
        let end = run_end(bytes, i);
        if let Some((value_start, value_end)) =
            bearer_value(bytes, i, end).or_else(|| assignment_value(bytes, i, end))
        {
            out.extend_from_slice(&bytes[i..value_start]);
            out.extend_from_slice(MASK.as_bytes());
            i = value_end;
            continue;
        }
        let word = &text[i..end];
        if end - i >= MIN_PREFIXED_TOKEN_LEN && TOKEN_PREFIXES.iter().any(|p| word.starts_with(p)) {
            out.extend_from_slice(MASK.as_bytes());
        } else {
            out.extend_from_slice(&bytes[i..end]);
        }
        i = end;
    }
    // Only whole runs of the input or ASCII masks were copied, so the
    // result is valid UTF-8.
    String::from_utf8(out).unwrap_or_default()
}

/// `Bearer <value>`: returns the value's byte range.
fn bearer_value(bytes: &[u8], start: usize, end: usize) -> Option<(usize, usize)> {
    if !bytes[start..end].eq_ignore_ascii_case(b"bearer") {
        return None;
    }
    let value_start = skip_spaces(bytes, end);
    if value_start == end {
        return None;
    }
    let value_end = run_end(bytes, value_start);
    (value_end - value_start >= MIN_BEARER_LEN).then_some((value_start, value_end))
}

/// `<secret-named key> = value` or `"key": "value"`: returns the value's
/// byte range.
fn assignment_value(bytes: &[u8], start: usize, end: usize) -> Option<(usize, usize)> {
    let key = String::from_utf8_lossy(&bytes[start..end]).to_ascii_lowercase();
    if !SECRET_KEY_WORDS.iter().any(|w| key.contains(w))
        || NON_SECRET_KEY_SUFFIXES.iter().any(|s| key.ends_with(s))
    {
        return None;
    }
    let mut i = end;
    if i < bytes.len() && (bytes[i] == b'"' || bytes[i] == b'\'') {
        i += 1;
    }
    i = skip_spaces(bytes, i);
    if i >= bytes.len() || (bytes[i] != b'=' && bytes[i] != b':') {
        return None;
    }
    i = skip_spaces(bytes, i + 1);
    let quote = match bytes.get(i) {
        Some(q @ (b'"' | b'\'')) => {
            i += 1;
            Some(*q)
        }
        _ => None,
    };
    let value_start = i;
    let mut value_end = i;
    while value_end < bytes.len() {
        let b = bytes[value_end];
        let stop = match quote {
            Some(q) => b == q,
            None => {
                b.is_ascii_whitespace() || matches!(b, b',' | b'}' | b';' | b'&' | b'"' | b'\'')
            }
        };
        if stop {
            break;
        }
        value_end += 1;
    }
    let value = &bytes[value_start..value_end];
    let short_number = value.len() < 12 && value.iter().all(u8::is_ascii_digit);
    let already_masked = value == MASK.as_bytes();
    let is_path = value.first() == Some(&b'/') || value.first() == Some(&b'~');
    if value.is_empty() || short_number || already_masked || is_path {
        return None;
    }
    Some((value_start, value_end))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r() -> Redactor {
        Redactor::patterns_only()
    }

    #[test]
    fn masks_known_token_prefixes() {
        let fake_slack = format!("xoxb-{}", "1234567890-abcdefghij");
        let fake_github = format!("ghp_{}", "A1b2C3d4E5f6G7h8I9j0K1l2");
        let out = r().redact(&format!("slack {fake_slack} gh {fake_github} end"));
        assert_eq!(out, format!("slack {MASK} gh {MASK} end"));
    }

    #[test]
    fn leaves_short_prefix_lookalikes_alone() {
        assert_eq!(r().redact("pip install sk-learn"), "pip install sk-learn");
        assert_eq!(r().redact("task-xoxb"), "task-xoxb");
    }

    #[test]
    fn masks_bearer_tokens() {
        assert_eq!(
            r().redact("Authorization: Bearer abcdefgh12345678"),
            format!("Authorization: Bearer {MASK}")
        );
    }

    #[test]
    fn masks_secret_named_assignments() {
        assert_eq!(
            r().redact("SLACK_BOT_TOKEN=abc123xyz other=1"),
            format!("SLACK_BOT_TOKEN={MASK} other=1")
        );
        assert_eq!(
            r().redact(r#"{"password": "hunter22", "user": "me"}"#),
            format!(r#"{{"password": "{MASK}", "user": "me"}}"#)
        );
        assert_eq!(
            r().redact("api_key: 'zzzzzz' done"),
            format!("api_key: '{MASK}' done")
        );
    }

    #[test]
    fn keeps_paths_counts_and_small_numbers_next_to_secret_words() {
        assert_eq!(
            r().redact("token_file=/etc/x max_tokens=4096"),
            "token_file=/etc/x max_tokens=4096"
        );
        assert_eq!(r().redact("secret_path: /a/b"), "secret_path: /a/b");
    }

    #[test]
    fn masks_exact_literal_values_anywhere() {
        let red = Redactor::with_values(vec!["s3cr3t-value".to_string(), "abc".to_string()]);
        assert_eq!(
            red.redact("prefix s3cr3t-value suffixs3cr3t-value abc"),
            format!("prefix {MASK} suffix{MASK} abc")
        );
    }

    #[test]
    fn reads_values_from_secret_files() {
        let dir = std::env::temp_dir().join(format!("gu-redact-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let env = dir.join("secrets.env");
        std::fs::write(
            &env,
            "# comment\nexport API_THING=\"value-one-123\"\nPLAIN=value-two-456\n",
        )
        .unwrap();
        let single = dir.join("token");
        std::fs::write(&single, "single-file-token-789\n").unwrap();

        let red = Redactor::from_secret_files(&[env, single]).unwrap();
        let out = red.redact("a value-one-123 b value-two-456 c single-file-token-789");
        assert_eq!(out, format!("a {MASK} b {MASK} c {MASK}"));
        assert!(!format!("{red:?}").contains("value-one"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn missing_secret_file_is_an_error_without_contents() {
        let err =
            Redactor::from_secret_files(&[PathBuf::from("/nonexistent/gu-secret")]).unwrap_err();
        assert!(err.contains("/nonexistent/gu-secret"));
    }
}
