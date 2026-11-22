//! Home / username / tmpdir paths.
//!
//! Collapse the personal prefix of a home path to `~` (or `<HOME_N>`). Spans
//! cover only the prefix: the tail is ordinary text, so its separators, line
//! numbers, and extension survive, and other detectors still see it (a digest
//! is kept, a token redacted). The captured username becomes a registered
//! identity. System paths are never matched here, so they're kept for free.

use std::sync::LazyLock;

use regex::Regex;

use super::{Action, Candidate};

/// `/Users/<u>` (macOS) and `/home/<u>` (Linux). Group 1 = username.
static UNIX_HOME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?:/Users/|/home/)([^/\s'"]+)"#).unwrap());

/// `/root` — root's home, collapsed to `~` but not enrolled as a
/// bare-redactable username.
static ROOT_HOME: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"/root").unwrap());

/// `C:\Users\<u>` and `C:\Documents and Settings\<u>` (Windows).
static WIN_HOME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)[a-z]:\\(?:Users|Documents and Settings)\\([^\\/\s'"]+)"#).unwrap()
});

/// macOS per-user temp dir: `/var/folders/<xx>/<yyyy…>/T` → `<TMPDIR>`.
static MACOS_TMPDIR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"/var/folders/[^/\s'"]+/[^/\s'"]+/T\b"#).unwrap());

/// Segments directly under `/Users` that are system folders, not user homes.
const NON_USER_HOMES: &[&str] = &["Shared"];

pub fn detect(line: &str, out: &mut Vec<Candidate>) {
    for caps in UNIX_HOME.captures_iter(line) {
        let m = caps.get(0).unwrap();
        let user = caps.get(1).unwrap().as_str();
        if NON_USER_HOMES.contains(&user) {
            continue;
        }
        let subtype = if m.as_str().starts_with("/Users/") {
            "macos_home"
        } else {
            "linux_home"
        };
        out.push(home(m.start(), m.end(), subtype, user, true));
    }

    for m in ROOT_HOME.find_iter(line) {
        // Reject `/rootfs` and friends.
        if !home_boundary(line, m.end()) {
            continue;
        }
        out.push(home(m.start(), m.end(), "root_home", "root", false));
    }

    for caps in WIN_HOME.captures_iter(line) {
        let m = caps.get(0).unwrap();
        let user = caps.get(1).unwrap().as_str();
        out.push(home(m.start(), m.end(), "windows_home", user, true));
    }

    for m in MACOS_TMPDIR.find_iter(line) {
        out.push(Candidate {
            start: m.start(),
            end: m.end(),
            subtype: Some("macos_tmpdir"),
            action: Action::Tmpdir,
            rank: 0,
        });
    }
}

/// Collapse a literal `$HOME` prefix (from the local-identity signal) to `~`,
/// registering its owner. Catches non-standard homes the structural matchers
/// miss; for a standard `/Users/<u>` home it just overlaps the structural match
/// and the resolver dedups.
pub fn detect_home_dir(line: &str, home_dir: &str, owner: &str, out: &mut Vec<Candidate>) {
    if home_dir.is_empty() {
        return;
    }
    let mut from = 0;
    while let Some(rel) = line[from..].find(home_dir) {
        let start = from + rel;
        let end = start + home_dir.len();
        // The prefix must end at a name boundary, so $HOME=/Users/dp doesn't
        // swallow /Users/dpepper.
        if home_boundary(line, end) {
            out.push(home(start, end, "home_env", owner, true));
        }
        from = end;
    }
}

fn home(
    start: usize,
    end: usize,
    subtype: &'static str,
    user: &str,
    bare_eligible: bool,
) -> Candidate {
    Candidate {
        start,
        end,
        subtype: Some(subtype),
        action: Action::Home {
            user: user.to_string(),
            bare_eligible,
        },
        rank: 0,
    }
}

/// True if the char at `pos` ends a directory name (so a `$HOME` prefix match is
/// a whole segment, not a prefix of a longer name). A path separator is fine; an
/// alphanumeric / `_` / `-` / `.` means we're mid-name.
fn home_boundary(line: &str, pos: usize) -> bool {
    match line[pos..].chars().next() {
        None => true,
        Some(c) => !(c.is_alphanumeric() || c == '_' || c == '-' || c == '.'),
    }
}
