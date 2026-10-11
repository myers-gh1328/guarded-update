//! The only output path. Everything printed or logged is redacted here
//! first; `clippy.toml` forbids printing anywhere else.

#![allow(clippy::disallowed_macros, clippy::disallowed_methods)]

use std::cell::RefCell;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
#[cfg(test)]
use std::rc::Rc;

use serde_json::{Map, Value};

use crate::redact::Redactor;
use crate::timefmt;

pub const SERVICE: &str = "guarded-update";

#[cfg(test)]
pub type Buffer = Rc<RefCell<Vec<u8>>>;

enum Sink {
    Std,
    #[cfg(test)]
    Buffer(Buffer),
}

pub struct Output {
    redactor: Redactor,
    sink: Sink,
    log: Option<RefCell<File>>,
    #[cfg(test)]
    log_buffer: Option<Buffer>,
}

impl Output {
    pub fn new(redactor: Redactor) -> Self {
        Self {
            redactor,
            sink: Sink::Std,
            log: None,
            #[cfg(test)]
            log_buffer: None,
        }
    }

    /// Replaces the redactor once secret files are known.
    pub fn set_redactor(&mut self, redactor: Redactor) {
        self.redactor = redactor;
    }

    /// Appends JSON-lines logs to `path`, creating it with mode 0600.
    pub fn open_log(&mut self, path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create log directory {}: {e}", parent.display()))?;
        }
        let mut options = OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options
            .open(path)
            .map_err(|e| format!("cannot open log file {}: {e}", path.display()))?;
        self.log = Some(RefCell::new(file));
        Ok(())
    }

    pub fn stdout(&self, text: &str) {
        let line = self.redactor.redact(text);
        match &self.sink {
            Sink::Std => println!("{line}"),
            #[cfg(test)]
            Sink::Buffer(buf) => writeln!(buf.borrow_mut(), "{line}").unwrap_or(()),
        }
    }

    /// One full-screen frame for the setup checklist: redacted, written
    /// without a trailing newline, and flushed.
    pub fn frame(&self, text: &str) {
        let frame = self.redactor.redact(text);
        match &self.sink {
            Sink::Std => {
                let mut out = std::io::stdout().lock();
                let _ = out.write_all(frame.as_bytes());
                let _ = out.flush();
            }
            #[cfg(test)]
            Sink::Buffer(buf) => buf.borrow_mut().extend_from_slice(frame.as_bytes()),
        }
    }

    /// Whether a person is at a terminal on both ends.
    pub fn interactive(&self) -> bool {
        use std::io::IsTerminal;
        matches!(self.sink, Sink::Std)
            && std::io::stdin().is_terminal()
            && std::io::stdout().is_terminal()
    }

    pub fn stderr(&self, text: &str) {
        let line = self.redactor.redact(text);
        match &self.sink {
            Sink::Std => eprintln!("{line}"),
            #[cfg(test)]
            Sink::Buffer(buf) => writeln!(buf.borrow_mut(), "{line}").unwrap_or(()),
        }
    }

    /// Writes one JSON log line: `ts`, `level`, `service`, `event`, then
    /// `fields`. The serialized line is redacted before it is written.
    pub fn log(&self, level: &str, event: &str, fields: Map<String, Value>) {
        let mut record = Map::new();
        record.insert(
            "ts".into(),
            Value::from(timefmt::rfc3339(timefmt::now_secs())),
        );
        record.insert("level".into(), Value::from(level));
        record.insert("service".into(), Value::from(SERVICE));
        record.insert("event".into(), Value::from(event));
        for (key, value) in fields {
            // Redact before serializing too: JSON escaping can split a
            // secret that contains quotes or backslashes.
            record
                .entry(key)
                .or_insert_with(|| self.redact_value(value));
        }
        let line = self.redactor.redact(&Value::Object(record).to_string());
        if let Some(file) = &self.log {
            // Logging must never stop a run; a failed write is dropped.
            let _ = writeln!(file.borrow_mut(), "{line}");
        }
        #[cfg(test)]
        if let Some(buf) = &self.log_buffer {
            let _ = writeln!(buf.borrow_mut(), "{line}");
        }
    }

    /// Redacts every string inside a JSON value.
    pub fn redact_value(&self, value: Value) -> Value {
        match value {
            Value::String(text) => Value::String(self.redactor.redact(&text)),
            Value::Array(items) => {
                Value::Array(items.into_iter().map(|v| self.redact_value(v)).collect())
            }
            Value::Object(map) => Value::Object(
                map.into_iter()
                    .map(|(k, v)| (k, self.redact_value(v)))
                    .collect(),
            ),
            other => other,
        }
    }

    #[cfg(test)]
    pub fn for_test(redactor: Redactor) -> (Self, Buffer, Buffer) {
        let out = Rc::new(RefCell::new(Vec::new()));
        let log = Rc::new(RefCell::new(Vec::new()));
        (
            Self {
                redactor,
                sink: Sink::Buffer(out.clone()),
                log: None,
                log_buffer: Some(log.clone()),
            },
            out,
            log,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn text(buf: &Rc<RefCell<Vec<u8>>>) -> String {
        String::from_utf8(buf.borrow().clone()).unwrap()
    }

    #[test]
    fn stdout_and_stderr_are_redacted() {
        let red = Redactor::with_values(vec!["very-secret-1".to_string()]);
        let (out, buf, _) = Output::for_test(red);
        out.stdout("hello very-secret-1");
        out.stderr("err very-secret-1");
        assert_eq!(text(&buf), "hello [REDACTED]\nerr [REDACTED]\n");
    }

    #[test]
    fn log_lines_are_json_with_service_label_and_redacted() {
        let red = Redactor::with_values(vec!["very-secret-1".to_string()]);
        let (out, _, log) = Output::for_test(red);
        let mut fields = Map::new();
        fields.insert("detail".into(), json!("saw very-secret-1"));
        out.log("info", "detect_done", fields);
        let line = text(&log);
        assert!(line.ends_with('\n'));
        let v: Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(v["service"], SERVICE);
        assert_eq!(v["level"], "info");
        assert_eq!(v["event"], "detect_done");
        assert_eq!(v["detail"], "saw [REDACTED]");
        assert!(v["ts"].as_str().unwrap().ends_with('Z'));
    }

    #[test]
    fn secrets_with_json_special_characters_do_not_leak_through_escaping() {
        let secret = r#"pa"ss\word-9"#.to_string();
        let red = Redactor::with_values(vec![secret.clone()]);
        let (out, _, log) = Output::for_test(red);
        let mut fields = Map::new();
        fields.insert("nested".into(), json!({"list": [format!("x {secret} y")]}));
        out.log("info", "e", fields);
        let line = text(&log);
        let v: Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(v["nested"]["list"][0], "x [REDACTED] y");
    }

    #[cfg(unix)]
    #[test]
    fn log_file_is_created_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("gu-out-{}", std::process::id()));
        let path = dir.join("logs/gu.jsonl");
        let mut out = Output::new(Redactor::patterns_only());
        out.open_log(&path).unwrap();
        out.log("info", "x", Map::new());
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert!(
            std::fs::read_to_string(&path)
                .unwrap()
                .contains("\"event\":\"x\"")
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
