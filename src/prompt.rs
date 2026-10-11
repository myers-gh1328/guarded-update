//! How one setup question looks and answers at a terminal: a bold title,
//! one line of explanation, the options, and a hint line. Once answered,
//! the question is erased and replaced by one `✓ Title  answer` line.
//! Pure functions here; `setup::StdPrompter` draws them.

use crate::tui::{Key, fit};

/// Width of the title column in answered lines and the settings menu.
pub const LABEL_WIDTH: usize = 31;

/// A question's title and its one line of explanation, from text whose
/// first line is the title.
pub fn split(question: &str) -> (&str, &str) {
    question.split_once('\n').unwrap_or((question, ""))
}

fn paint(color: bool, code: &str, text: &str) -> String {
    if color {
        format!("\x1b[{code}m{text}\x1b[0m")
    } else {
        text.to_string()
    }
}

/// The highlighted row: white text on a dark grey bar, readable on light
/// and dark terminals; plain text keeps its `›` marker.
const SELECTED: &str = "97;48;5;238";

fn head(question: &str, color: bool) -> Vec<String> {
    let (title, detail) = split(question);
    let mut lines = vec![paint(color, "1", title)];
    // Each explanation line is its own screen line, so erasing counts right.
    lines.extend(detail.lines().map(|l| paint(color, "2", l)));
    lines.push(String::new());
    lines
}

fn finish(mut lines: Vec<String>, hint: &str, cols: usize, color: bool) -> Vec<String> {
    lines.push(String::new());
    lines.push(paint(color, "2", hint));
    lines.iter().map(|l| fit(l, cols)).collect()
}

/// A pick-one question with row `cur` highlighted.
pub fn choice(
    question: &str,
    options: &[(&str, &str)],
    cur: usize,
    default: usize,
    cols: usize,
    color: bool,
) -> Vec<String> {
    let mut lines = head(question, color);
    let width = options
        .iter()
        .map(|(n, _)| n.chars().count())
        .max()
        .unwrap_or(0);
    let rows: Vec<String> = options
        .iter()
        .enumerate()
        .map(|(i, (name, help))| {
            let pad = " ".repeat(width - name.chars().count());
            format!(" {}  {name}{pad}   {help}", i + 1)
                .trim_end()
                .to_string()
        })
        .collect();
    // Every bar is as wide as the widest row.
    let bar = rows.iter().map(|r| r.chars().count()).max().unwrap_or(0) + 1;
    for (i, row) in rows.into_iter().enumerate() {
        lines.push(if i != cur {
            format!(" {row}")
        } else if color {
            let pad = " ".repeat(bar - row.chars().count());
            format!(
                "{}{}",
                paint(true, "32;1", "›"),
                paint(true, SELECTED, &format!("{row}{pad}"))
            )
        } else {
            format!("›{row}")
        });
    }
    let n = options.len();
    let hint = format!(
        "↑↓ or 1-{n} · Enter picks {}",
        options
            .get(default.min(n.saturating_sub(1)))
            .map_or("", |o| o.0)
    );
    finish(lines, &hint, cols, color)
}

fn button(label: &str, on: bool, color: bool) -> String {
    if on {
        paint(color, SELECTED, &format!(" {label} "))
    } else {
        format!(" {label} ")
    }
}

/// The last question of setup: the title and both buttons on one line.
pub fn save(question: &str, save: bool, cols: usize, color: bool) -> Vec<String> {
    let line = format!(
        "{}   {}  {}",
        paint(color, "1", question),
        button("Save", save, color),
        button("Don't save", !save, color)
    );
    finish(
        vec![line],
        "Enter saves · n leaves without saving",
        cols,
        color,
    )[..]
        .iter()
        .filter(|l| !l.is_empty())
        .cloned()
        .collect()
}

/// A yes/no question with `yes` highlighted or not.
pub fn yes_no(question: &str, yes: bool, default: bool, cols: usize, color: bool) -> Vec<String> {
    let mut lines = head(question, color);
    lines.push(format!(
        "  {}  {}",
        button("Yes", yes, color),
        button("No", !yes, color)
    ));
    let hint = format!(
        "y / n · ←→ · Enter picks {}",
        if default { "Yes" } else { "No" }
    );
    finish(lines, &hint, cols, color)
}

/// A text answer being edited, the cursor at its end.
pub fn text(question: &str, value: &str, original: &str, cols: usize, color: bool) -> Vec<String> {
    let mut lines = head(question, color);
    lines.push(format!("  {} {value}▌", paint(color, "32;1", "›")));
    let hint = if original.is_empty() {
        "Type it, then Enter · Esc goes back"
    } else {
        "Edit, or Enter to keep it · Esc goes back"
    };
    finish(lines, hint, cols, color)
}

/// A hidden answer such as an API key; nothing typed is drawn.
pub fn secret(question: &str, cols: usize, color: bool) -> Vec<String> {
    let mut lines = head(question, color);
    lines.push("  › (hidden while you type or paste)".into());
    finish(lines, "Enter when done", cols, color)
}

/// What stays on screen once a question is answered.
pub fn answered(title: &str, value: &str, color: bool) -> String {
    format!("{} {title:<26}  {value}", paint(color, "32", "✓"))
}

/// A part of a question that failed, lined up with answered lines.
pub fn failed(title: &str, why: &str, color: bool) -> String {
    format!("{} {title}: {why}", paint(color, "31", "✗"))
}

/// One key in a pick-one question: arrows move, a number picks, Enter
/// takes the highlighted row, Ctrl-C cancels.
pub fn choice_key(key: Key, cur: &mut usize, n: usize) -> Option<Result<usize, ()>> {
    match key {
        Key::Up | Key::Left => *cur = cur.checked_sub(1).unwrap_or(n - 1),
        Key::Down | Key::Right => *cur = (*cur + 1) % n,
        Key::Enter => return Some(Ok(*cur)),
        Key::Quit => return Some(Err(())),
        Key::Char(c) => {
            let d = c.to_digit(10)? as usize;
            return (1..=n).contains(&d).then_some(Ok(d - 1));
        }
        _ => {}
    }
    None
}

/// One key in a yes/no question.
pub fn yes_no_key(key: Key, yes: &mut bool) -> Option<Result<bool, ()>> {
    match key {
        Key::Char('y' | 'Y') => Some(Ok(true)),
        Key::Char('n' | 'N') => Some(Ok(false)),
        Key::Left | Key::Right | Key::Up | Key::Down => {
            *yes = !*yes;
            None
        }
        Key::Enter => Some(Ok(*yes)),
        Key::Quit => Some(Err(())),
        _ => None,
    }
}

/// One key while typing: `Some(Ok)` when done, `Some(Err)` on Ctrl-C.
/// Esc puts the original value back and leaves.
pub fn edit_key(key: Key, value: &mut String, original: &str) -> Option<Result<(), ()>> {
    match key {
        Key::Enter => Some(Ok(())),
        Key::Quit => Some(Err(())),
        Key::Escape => {
            *value = original.to_string();
            Some(Ok(()))
        }
        Key::Backspace => {
            value.pop();
            None
        }
        Key::Char(c) => {
            value.push(c);
            None
        }
        _ => None,
    }
}

/// Moves the cursor back over a drawn block and clears it.
pub fn erase(lines: usize) -> String {
    match lines {
        0 => String::new(),
        1 => "\r\x1b[J".into(),
        n => format!("\r\x1b[{}A\x1b[J", n - 1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OPTIONS: [(&str, &str); 3] = [
        ("auto", "Update after the safety checks"),
        ("alert", "Tell me; change nothing"),
        ("ignore", "Neither update nor report"),
    ];

    #[test]
    fn a_choice_has_a_title_aligned_options_and_a_hint() {
        let lines = choice(
            "Updates by default\nWhat happens to an update.",
            &OPTIONS,
            1,
            0,
            80,
            false,
        );
        assert_eq!(
            lines,
            [
                "Updates by default",
                "What happens to an update.",
                "",
                "  1  auto     Update after the safety checks",
                "› 2  alert    Tell me; change nothing",
                "  3  ignore   Neither update nor report",
                "",
                "↑↓ or 1-3 · Enter picks auto",
            ]
        );
        let narrow = choice("T", &OPTIONS, 0, 0, 12, false);
        assert!(narrow.iter().all(|l| l.chars().count() <= 12), "{narrow:?}");
    }

    #[test]
    fn each_explanation_line_is_its_own_screen_line() {
        let lines = choice(
            "AI check\nOptional.\nOllama has no chat model.",
            &OPTIONS,
            0,
            0,
            80,
            false,
        );
        assert_eq!(
            &lines[..4],
            ["AI check", "Optional.", "Ollama has no chat model.", ""]
        );
        assert!(lines.iter().all(|l| !l.contains('\n')));
    }

    #[test]
    fn arrows_move_numbers_pick_and_enter_takes_the_highlight() {
        let mut cur = 0;
        assert_eq!(choice_key(Key::Up, &mut cur, 3), None);
        assert_eq!(cur, 2, "wraps");
        assert_eq!(choice_key(Key::Down, &mut cur, 3), None);
        assert_eq!(cur, 0);
        assert_eq!(choice_key(Key::Enter, &mut cur, 3), Some(Ok(0)));
        assert_eq!(choice_key(Key::Char('3'), &mut cur, 3), Some(Ok(2)));
        assert_eq!(choice_key(Key::Char('4'), &mut cur, 3), None);
        assert_eq!(choice_key(Key::Quit, &mut cur, 3), Some(Err(())));
    }

    #[test]
    fn yes_no_takes_one_key_or_arrows_and_enter() {
        let mut yes = true;
        assert_eq!(yes_no_key(Key::Char('n'), &mut yes), Some(Ok(false)));
        assert_eq!(yes_no_key(Key::Right, &mut yes), None);
        assert_eq!(yes_no_key(Key::Enter, &mut yes), Some(Ok(false)));
        let lines = yes_no("Hermes Agent releases\nCheck?", true, true, 80, false);
        assert_eq!(lines[3], "   Yes    No ");
        assert_eq!(lines[5], "y / n · ←→ · Enter picks Yes");
    }

    #[test]
    fn the_saved_value_is_edited_in_place_and_esc_puts_it_back() {
        let original = "http://old/v1";
        let mut value = original.to_string();
        assert_eq!(
            text("Address", &value, original, 80, false)[2],
            "  › http://old/v1▌"
        );
        assert_eq!(edit_key(Key::Backspace, &mut value, original), None);
        assert_eq!(edit_key(Key::Char('2'), &mut value, original), None);
        assert_eq!(value, "http://old/v2");
        assert_eq!(edit_key(Key::Escape, &mut value, original), Some(Ok(())));
        assert_eq!(value, original, "Esc goes back to the saved value");
        assert_eq!(edit_key(Key::Enter, &mut value, original), Some(Ok(())));
        assert!(text("Address", "", "", 80, false)[4].starts_with("Type it"));
    }

    #[test]
    fn save_shows_both_buttons_on_the_question_line() {
        assert_eq!(
            save("Save these settings?", true, 80, false),
            [
                "Save these settings?    Save    Don't save ",
                "Enter saves · n leaves without saving"
            ]
        );
    }

    #[test]
    fn answered_lines_line_up() {
        assert_eq!(
            answered("Updates by default", "auto", false),
            "✓ Updates by default          auto"
        );
        assert_eq!(
            answered("Nightly run", "3:00 am", false).find("3:00"),
            answered("Updates by default", "auto", false).find("auto")
        );
        assert_eq!(erase(1), "\r\x1b[J");
        assert_eq!(erase(8), "\r\x1b[7A\x1b[J");
    }
}
