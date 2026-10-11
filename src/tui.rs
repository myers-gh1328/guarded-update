//! The setup checklist: every package on one of four pages, one policy
//! per package, changed with single keys. `Checklist` is pure (keys in,
//! text out) so it is tested without a terminal; `Terminal` only puts the
//! tty in raw mode, reads keys and draws frames through `Output`.

use std::fs::File;
use std::io::Read;
use std::process::{Command, Stdio};

use crate::output::Output;

pub const POLICIES: [&str; 3] = ["auto", "alert", "ignore"];

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Row {
    pub name: String,
    pub installed: String,
    /// The waiting update, e.g. `24.21.0_2 rebuild`.
    pub update: Option<String>,
    /// Shown when nothing restarts, e.g. `runs as root`.
    pub note: String,
    pub services: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Page {
    pub title: &'static str,
    pub note: &'static str,
    /// Information only: policies cannot be changed here.
    pub fixed: bool,
    pub rows: Vec<Row>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    Left,
    Right,
    Up,
    Down,
    Char(char),
    Backspace,
    /// Esc pressed on its own.
    Escape,
    Enter,
    /// Ctrl-C: leave without saving.
    Quit,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Continue,
    Done,
    Cancel,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checklist {
    pub pages: Vec<Page>,
    pub default: &'static str,
    /// Per page and row: a policy that differs from the default.
    choices: Vec<Vec<Option<&'static str>>>,
    page: usize,
    cur: usize,
    top: usize,
}

const HELP: &str =
    "←→ or 1-4 page · ↑↓ move · a/l/i set auto/alert/ignore · d default · Enter done · Ctrl-C quit";

impl Checklist {
    /// `existing` gives each package's current policy, if it has one.
    pub fn new(
        pages: Vec<Page>,
        default: &'static str,
        existing: &dyn Fn(&str) -> Option<&'static str>,
    ) -> Self {
        let choices = pages
            .iter()
            .map(|p| {
                p.rows
                    .iter()
                    .map(|r| existing(&r.name).filter(|pol| !p.fixed && *pol != default))
                    .collect()
            })
            .collect();
        let mut list = Self {
            pages,
            default,
            choices,
            page: 0,
            cur: 0,
            top: 0,
        };
        // Open on the first page that has anything on it.
        list.page = list
            .pages
            .iter()
            .position(|p| !p.rows.is_empty())
            .unwrap_or(0);
        list
    }

    /// Packages whose policy differs from the default, in page order.
    pub fn exceptions(&self) -> Vec<(String, &'static str)> {
        let mut out = Vec::new();
        for (page, choices) in self.pages.iter().zip(&self.choices) {
            for (row, choice) in page.rows.iter().zip(choices) {
                if let Some(policy) = choice {
                    out.push((row.name.clone(), *policy));
                }
            }
        }
        out
    }

    /// Every package that appears on a page that can be changed.
    pub fn names(&self) -> Vec<&str> {
        self.pages
            .iter()
            .filter(|p| !p.fixed)
            .flat_map(|p| p.rows.iter().map(|r| r.name.as_str()))
            .collect()
    }

    pub fn policy(&self, page: usize, row: usize) -> &'static str {
        if self.pages[page].fixed {
            "manual"
        } else {
            self.choices[page][row].unwrap_or(self.default)
        }
    }

    /// Sets one package's policy; `None` page means search every page.
    pub fn set(&mut self, name: &str, policy: &'static str) -> bool {
        for (p, page) in self.pages.iter().enumerate() {
            if page.fixed {
                continue;
            }
            if let Some(r) = page.rows.iter().position(|row| row.name == name) {
                self.choices[p][r] = (policy != self.default).then_some(policy);
                return true;
            }
        }
        false
    }

    fn cycle_default(&mut self) {
        let next = POLICIES
            .iter()
            .position(|p| *p == self.default)
            .map_or(0, |i| (i + 1) % POLICIES.len());
        self.set_default(POLICIES[next]);
    }

    /// Changes the default; packages already set to it follow it.
    pub fn set_default(&mut self, default: &'static str) {
        self.default = default;
        for choice in self.choices.iter_mut().flatten() {
            if *choice == Some(default) {
                *choice = None;
            }
        }
    }

    fn go_to_page(&mut self, page: usize) {
        self.page = page;
        self.cur = 0;
        self.top = 0;
    }

    /// Applies one key. `view` is how many rows fit on screen.
    pub fn key(&mut self, key: Key, view: usize) -> Outcome {
        let pages = self.pages.len();
        let rows = self.pages[self.page].rows.len();
        match key {
            Key::Right => self.go_to_page((self.page + 1) % pages),
            Key::Left => self.go_to_page((self.page + pages - 1) % pages),
            Key::Char(c @ '1'..='9') => {
                let n = c as usize - '1' as usize;
                if n < pages {
                    self.go_to_page(n);
                }
            }
            Key::Down => self.cur = (self.cur + 1).min(rows.saturating_sub(1)),
            Key::Up => self.cur = self.cur.saturating_sub(1),
            Key::Char(c @ ('a' | 'l' | 'i')) if rows > 0 && !self.pages[self.page].fixed => {
                let policy = match c {
                    'a' => "auto",
                    'l' => "alert",
                    _ => "ignore",
                };
                self.choices[self.page][self.cur] = (policy != self.default).then_some(policy);
            }
            Key::Char('d') => self.cycle_default(),
            Key::Enter => return Outcome::Done,
            Key::Quit => return Outcome::Cancel,
            _ => {}
        }
        let view = view.max(1);
        if self.cur < self.top {
            self.top = self.cur;
        }
        if self.cur >= self.top + view {
            self.top = self.cur + 1 - view;
        }
        Outcome::Continue
    }

    /// One screen of text, `view` rows of packages tall.
    pub fn render(&self, view: usize, cols: usize, color: bool) -> String {
        let paint = |code: &str, text: &str| {
            if color {
                format!("\x1b[{code}m{text}\x1b[0m")
            } else {
                text.to_string()
            }
        };
        let dim = |t: &str| paint("2", t);
        let total: usize = self.pages.iter().map(|p| p.rows.len()).sum();
        let waiting: usize = self
            .pages
            .iter()
            .map(|p| p.rows.iter().filter(|r| r.update.is_some()).count())
            .sum();
        let mut lines = vec![
            format!(
                "{}  {}{}",
                paint("1", "Your packages"),
                dim(&format!(
                    "{total} packages · {waiting} updates waiting · default "
                )),
                paint("33", self.default)
            ),
            String::new(),
        ];
        let tabs: Vec<String> = self
            .pages
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let tab = format!(" {} {} {} ", i + 1, p.title, p.rows.len());
                if i == self.page {
                    paint("7", &tab)
                } else {
                    tab
                }
            })
            .collect();
        lines.push(tabs.join(" "));
        let page = &self.pages[self.page];
        lines.push(dim(page.note));
        let view = view.max(1);
        lines.push(if self.top > 0 {
            dim(&format!("     ↑ {} more", self.top))
        } else {
            String::new()
        });
        let end = page.rows.len().min(self.top + view);
        for (i, row) in page.rows.iter().enumerate().take(end).skip(self.top) {
            let own = !page.fixed && self.choices[self.page][i].is_some();
            let policy = format!(
                "{}{}",
                self.policy(self.page, i),
                if own { "*" } else { "" }
            );
            let policy = format!("{policy:<8}");
            let policy = if page.fixed {
                paint("31", &policy)
            } else if own {
                paint("33", &policy)
            } else {
                policy
            };
            let update = match &row.update {
                Some(u) => paint("32", &format!("→ {u:<18}")),
                None => dim(&format!("{:<20}", "up to date")),
            };
            let impact = match row.services.len() {
                0 => dim(&row.note),
                1 => paint("36", "1 service"),
                n => paint("36", &format!("{n} services")),
            };
            let marker = if i == self.cur { "›" } else { " " };
            lines.push(format!(
                " {marker} {:<24} {policy} {} {update} {impact}",
                row.name,
                dim(&format!("{:<11}", row.installed))
            ));
        }
        for _ in end.saturating_sub(self.top)..view {
            lines.push(String::new());
        }
        lines.push(if page.rows.len() > end {
            dim(&format!("     ↓ {} more", page.rows.len() - end))
        } else {
            String::new()
        });
        lines.push(dim(&"─".repeat(60)));
        if let Some(row) = page.rows.get(self.cur) {
            let update = row
                .update
                .as_ref()
                .map_or_else(|| dim("up to date"), |u| paint("32", &format!("→ {u}")));
            lines.push(format!(
                "{}  {}  {update}",
                paint("1", &row.name),
                row.installed
            ));
            lines.push(if page.fixed {
                format!("manual: {}; you update it yourself", row.note)
            } else if self.choices[self.page][self.cur].is_some() {
                format!(
                    "{}: set here (* = differs from the default)",
                    self.policy(self.page, self.cur)
                )
            } else {
                format!("{}: the default", self.default)
            });
            lines.push(match row.services.len() {
                0 => dim("restarts nothing"),
                n => {
                    let shown: Vec<&str> =
                        row.services.iter().take(3).map(String::as_str).collect();
                    let more = if n > 3 {
                        format!(" +{} more", n - 3)
                    } else {
                        String::new()
                    };
                    format!("{} {}{}", dim("restarts:"), shown.join(", "), dim(&more))
                }
            });
        } else {
            lines.push(dim("Nothing on this page."));
            lines.push(String::new());
            lines.push(String::new());
        }
        lines.push(String::new());
        lines.push(dim(HELP));
        if page.fixed {
            lines.push(dim("This page is information only."));
        }
        lines
            .iter()
            .map(|l| fit(l, cols))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

/// Lines a frame needs besides the package rows.
pub const CHROME_LINES: usize = 15;

/// Decodes one key from raw terminal bytes. Arrow keys come as
/// `ESC [ X` or, in application-cursor mode, `ESC O X`. Letters are taken
/// as typed, so a stray byte from a split escape sequence (`O`, `A`, `D`)
/// is never mistaken for a command.
pub fn decode(bytes: &[u8]) -> Key {
    match bytes {
        [0x1b, b'[' | b'O', b'A', ..] => Key::Up,
        [0x1b, b'[' | b'O', b'B', ..] => Key::Down,
        [0x1b, b'[' | b'O', b'C', ..] => Key::Right,
        [0x1b, b'[' | b'O', b'D', ..] => Key::Left,
        [0x1b] => Key::Escape,
        [0x1b, ..] => Key::Other,
        [b'\r' | b'\n', ..] => Key::Enter,
        [0x03, ..] => Key::Quit,
        [0x7f | 0x08, ..] => Key::Backspace,
        [b'\t', ..] => Key::Right,
        [c, ..] if c.is_ascii_graphic() || *c == b' ' => Key::Char(*c as char),
        _ => Key::Other,
    }
}

/// Cuts a line to `cols` visible characters, skipping colour codes when
/// counting. `0` means no limit.
pub fn fit(line: &str, cols: usize) -> String {
    if cols == 0 {
        return line.to_string();
    }
    let mut out = String::new();
    let mut visible = 0;
    let mut chars = line.chars().peekable();
    let mut cut = false;
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            out.push(c);
            for d in chars.by_ref() {
                out.push(d);
                if d.is_ascii_alphabetic() {
                    break;
                }
            }
            continue;
        }
        if visible == cols {
            cut = true;
            continue;
        }
        out.push(c);
        visible += 1;
    }
    if cut && out.contains('\x1b') {
        out.push_str("\x1b[0m");
    }
    out
}

/// The controlling terminal in raw mode. Dropping it restores the
/// previous settings, so early returns and panics leave the shell usable.
pub struct Terminal {
    tty: File,
    saved: String,
}

fn stty(tty: &File, args: &[&str]) -> Option<String> {
    let out = Command::new("/bin/stty")
        .env_clear()
        .args(args)
        .stdin(Stdio::from(tty.try_clone().ok()?))
        .stderr(Stdio::null())
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

impl Terminal {
    /// `None` when there is no usable terminal.
    pub fn open() -> Option<Self> {
        let tty = File::options()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .ok()?;
        let saved = stty(&tty, &["-g"])?;
        // Reads wait at most 0.2 s, so a lone Esc can be told apart from
        // the start of an arrow key.
        stty(&tty, &["raw", "-echo", "min", "0", "time", "2"])?;
        Some(Self { tty, saved })
    }

    /// Rows of packages that fit, leaving room for the rest of the
    /// frame, and the window width.
    pub fn size(&self) -> (usize, usize) {
        let size = stty(&self.tty, &["size"]).unwrap_or_default();
        let mut parts = size.split_whitespace().map(|n| n.parse::<usize>().ok());
        let rows = parts.next().flatten().unwrap_or(24);
        let cols = parts.next().flatten().unwrap_or(80);
        (rows.saturating_sub(CHROME_LINES).clamp(3, 30), cols)
    }

    pub fn read_key(&mut self) -> Key {
        let mut buf = [0u8; 8];
        let mut n = loop {
            match self.tty.read(&mut buf) {
                Err(_) => return Key::Quit,
                Ok(0) => continue,
                Ok(n) => break n,
            }
        };
        // An escape sequence can arrive split across reads (over SSH or
        // under load); collect the rest before decoding. Nothing more
        // within two short waits means Esc on its own.
        let mut waits = 0;
        while buf[0] == 0x1b && n < 3 && waits < 2 {
            match self.tty.read(&mut buf[n..]) {
                Err(_) => break,
                Ok(0) => waits += 1,
                Ok(more) => n += more,
            }
        }
        decode(&buf[..n])
    }

    /// A line typed without echo; `None` on Ctrl-C or end of input.
    pub fn read_hidden_line(&mut self) -> Option<String> {
        let mut line = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            match self.tty.read(&mut byte) {
                Err(_) => return None,
                Ok(0) => continue,
                Ok(_) => match byte[0] {
                    b'\r' | b'\n' => break,
                    0x03 | 0x04 => return None,
                    0x7f | 0x08 => {
                        line.pop();
                    }
                    b if b >= 0x20 => line.push(b),
                    _ => {}
                },
            }
        }
        Some(String::from_utf8_lossy(&line).into_owned())
    }

    pub fn draw(&self, out: &Output, frame: &str) {
        // Raw mode does not turn \n into a carriage return.
        out.frame(&format!(
            "\x1b[H\x1b[2J\x1b[?25l{}",
            frame.replace('\n', "\r\n")
        ));
    }
}

impl Drop for Terminal {
    fn drop(&mut self) {
        use std::io::Write;
        // Show the cursor again even if the checklist panicked.
        let _ = self.tty.write_all(b"\x1b[?25h");
        let _ = stty(&self.tty, &[&self.saved]);
    }
}

/// Runs the checklist on the terminal. `None` when cancelled.
pub fn run(list: &mut Checklist, term: &mut Terminal, out: &Output) -> Option<()> {
    // The alternate screen keeps the answers above it intact.
    out.frame("\x1b[?1049h");
    let outcome = loop {
        let (view, cols) = term.size();
        term.draw(out, &list.render(view, cols, true));
        match list.key(term.read_key(), view) {
            Outcome::Continue => {}
            done => break done,
        }
    };
    out.frame("\x1b[H\x1b[2J\x1b[?25h\x1b[?1049l");
    (outcome == Outcome::Done).then_some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(name: &str, update: Option<&str>, services: usize) -> Row {
        Row {
            name: name.into(),
            installed: "1.0".into(),
            update: update.map(str::to_string),
            note: String::new(),
            services: (0..services).map(|i| format!("svc{i}")).collect(),
        }
    }

    fn sample() -> Checklist {
        let pages = vec![
            Page {
                title: "Restarts services",
                note: "",
                fixed: false,
                rows: vec![
                    row("node@24", Some("24.2"), 9),
                    row("node", None, 3),
                    row("restic", None, 2),
                ],
            },
            Page {
                title: "Apps",
                note: "",
                fixed: false,
                rows: vec![row("copilot-cli", None, 0)],
            },
            Page {
                title: "Tools",
                note: "",
                fixed: false,
                rows: (0..12)
                    .map(|i| row(&format!("tool{i:02}"), None, 0))
                    .collect(),
            },
            Page {
                title: "By hand",
                note: "",
                fixed: true,
                rows: vec![row("ollama", Some("0.40.2"), 1)],
            },
        ];
        Checklist::new(pages, "auto", &|name| (name == "restic").then_some("alert"))
    }

    #[test]
    fn keys_change_the_row_under_the_cursor() {
        let mut c = sample();
        assert_eq!(
            c.exceptions(),
            [("restic".to_string(), "alert")],
            "existing policy loaded"
        );
        c.key(Key::Char('l'), 10);
        c.key(Key::Down, 10);
        c.key(Key::Char('i'), 10);
        c.key(Key::Down, 10);
        c.key(Key::Char('a'), 10);
        assert_eq!(
            c.exceptions(),
            [
                ("node@24".to_string(), "alert"),
                ("node".to_string(), "ignore")
            ],
            "setting the default clears the exception"
        );
    }

    #[test]
    fn the_by_hand_page_cannot_be_changed() {
        let mut c = sample();
        c.key(Key::Char('4'), 10);
        c.key(Key::Char('l'), 10);
        assert!(c.exceptions().iter().all(|(n, _)| n != "ollama"));
        assert_eq!(c.policy(3, 0), "manual");
        assert!(!c.names().contains(&"ollama"));
        assert!(c.render(10, 0, false).contains("information only"));
    }

    #[test]
    fn long_pages_scroll_inside_the_view() {
        let mut c = sample();
        c.key(Key::Char('3'), 5);
        for _ in 0..7 {
            c.key(Key::Down, 5);
        }
        let screen = c.render(5, 0, false);
        assert!(screen.contains("↑ 3 more"), "{screen}");
        assert!(screen.contains("↓ 4 more"), "{screen}");
        assert!(screen.contains("› tool07"), "{screen}");
        assert!(!screen.contains("tool02"), "{screen}");
    }

    #[test]
    fn changing_the_default_drops_choices_that_now_match_it() {
        let mut c = sample();
        c.key(Key::Char('d'), 10);
        assert_eq!(c.default, "alert");
        assert!(c.exceptions().is_empty(), "restic now follows the default");
        assert!(c.set("node", "auto"));
        assert_eq!(c.exceptions(), [("node".to_string(), "auto")]);
        assert!(!c.set("ollama", "auto"), "by-hand packages cannot be set");
    }

    #[test]
    fn pages_wrap_and_enter_or_ctrl_c_finish() {
        let mut c = sample();
        c.key(Key::Left, 10);
        assert!(c.render(10, 0, false).contains("information only"));
        c.key(Key::Right, 10);
        assert!(c.render(10, 0, false).contains("› node@24"));
        assert_eq!(c.key(Key::Enter, 10), Outcome::Done);
        assert_eq!(c.key(Key::Quit, 10), Outcome::Cancel);
    }

    #[test]
    fn the_detail_panel_names_the_services() {
        let c = sample();
        let screen = c.render(10, 0, false);
        assert!(
            screen.contains("restarts: svc0, svc1, svc2 +6 more"),
            "{screen}"
        );
        assert!(screen.contains("→ 24.2"), "{screen}");
        assert!(!screen.contains('\x1b'), "no colour codes when off");
    }

    #[test]
    fn raw_bytes_decode_to_keys() {
        assert_eq!(decode(b"\x1b[A"), Key::Up);
        assert_eq!(decode(b"\x1b[C"), Key::Right);
        assert_eq!(decode(b"\x1bOA"), Key::Up, "application cursor mode");
        assert_eq!(decode(b"\x1bOD"), Key::Left);
        assert_eq!(decode(b"\r"), Key::Enter);
        assert_eq!(decode(&[3]), Key::Quit);
        assert_eq!(decode(b"l"), Key::Char('l'));
        assert_eq!(decode(b"\x1b"), Key::Escape);
        assert_eq!(decode(b"\x1b["), Key::Other);
    }

    #[test]
    fn pieces_of_an_arrow_key_never_change_a_setting() {
        let mut c = sample();
        for piece in [&b"["[..], b"A", b"O", b"D"] {
            c.key(decode(piece), 10);
        }
        assert_eq!(c.default, "auto");
        assert_eq!(c.exceptions(), [("restic".to_string(), "alert")]);
    }

    #[test]
    fn every_line_fits_the_window() {
        let c = sample();
        for color in [false, true] {
            let screen = c.render(5, 40, color);
            for line in screen.lines() {
                let plain = fit(line, 0);
                let visible: String = {
                    let mut out = String::new();
                    let mut skip = false;
                    for ch in plain.chars() {
                        if ch == '\x1b' {
                            skip = true;
                        } else if skip {
                            skip = !ch.is_ascii_alphabetic();
                        } else {
                            out.push(ch);
                        }
                    }
                    out
                };
                assert!(visible.chars().count() <= 40, "{visible:?}");
            }
        }
        assert_eq!(fit("\x1b[1mabcdef\x1b[0m", 3), "\x1b[1mabc\x1b[0m\x1b[0m");
    }
}
