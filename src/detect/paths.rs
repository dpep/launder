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

/// A username path segment: stops at separators, quotes, and the punctuation
/// that wraps or lists paths (`PATH=…:…`, `(…)`).
const NAME: &str = r#"[^/\\\s'"`:;,|()\[\]{}<>]+"#;

/// `/Users/<u>` (macOS) and `/home/<u>` (Linux). Group 1 = username.
static UNIX_HOME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(&format!("(?:/Users/|/home/)({NAME})")).unwrap());

/// `/root` — root's home, collapsed to `~` but not enrolled as a
/// bare-redactable username.
static ROOT_HOME: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"/root").unwrap());

/// `C:\Users\<u>` and `C:\Documents and Settings\<u>` (Windows).
static WIN_HOME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r"(?i)[a-z]:\\(?:Users|Documents and Settings)\\({NAME})"
    ))
    .unwrap()
});

/// macOS per-user temp dir: `[/private]/var/folders/<xx>/<yyyy…>/T` → `<TMPDIR>`.
static MACOS_TMPDIR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?:/private)?/var/folders/[^/\s'"]+/[^/\s'"]+/T\b"#).unwrap());

/// pytest's per-user temp root, `pytest-of-<u>`. Group 1 = username.
static PYTEST_OF: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(&format!("/pytest-of-({NAME})")).unwrap());

/// Home-directory names that are system or CI accounts, not people: macOS
/// `/Users/Shared`, and the GitHub Actions runner's `/home/runner`, `/Users/runner`.
const NON_USER_HOMES: &[&str] = &["Shared", "runner"];

pub fn detect(line: &str, out: &mut Vec<Candidate>) {
    for caps in UNIX_HOME.captures_iter(line) {
        let m = caps.get(0).unwrap();
        let user = caps.get(1).unwrap();
        if NON_USER_HOMES.contains(&user.as_str()) {
            continue;
        }
        // Nested in a longer path (a backup, a container root): keep the
        // location, scrub only the owner.
        if nested(line, m.start()) {
            out.push(path_user(
                user.start(),
                user.end(),
                "nested_home",
                user.as_str(),
            ));
            continue;
        }
        let subtype = if m.as_str().starts_with("/Users/") {
            "macos_home"
        } else {
            "linux_home"
        };
        out.push(home(m.start(), m.end(), subtype, user.as_str(), true));
    }

    for m in ROOT_HOME.find_iter(line) {
        // Reject `/rootfs` and a `root` segment inside another path.
        if nested(line, m.start()) || !home_boundary(line, m.end()) {
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

    for caps in PYTEST_OF.captures_iter(line) {
        let user = caps.get(1).unwrap();
        out.push(path_user(
            user.start(),
            user.end(),
            "pytest_user",
            user.as_str(),
        ));
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
    while let Some(rel) = memchr::memmem::find(&line.as_bytes()[from..], home_dir.as_bytes()) {
        let start = from + rel;
        let end = start + home_dir.len();
        // The prefix must end at a name boundary, so $HOME=/Users/dp doesn't
        // swallow /Users/dpepper.
        if !nested(line, start) && home_boundary(line, end) {
            out.push(home(start, end, "home_env", owner, true));
        }
        from = end;
    }
}

fn path_user(start: usize, end: usize, subtype: &'static str, user: &str) -> Candidate {
    Candidate {
        start,
        end,
        subtype: Some(subtype),
        action: Action::PathUser {
            user: user.to_string(),
        },
        rank: 0,
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

/// True if the path starting at `pos` continues a longer path or name, so it
/// isn't a home directory itself (`/srv/root`, `/mnt/backup/home/u`).
fn nested(line: &str, pos: usize) -> bool {
    line[..pos]
        .chars()
        .next_back()
        .is_some_and(|c| c.is_alphanumeric() || "_-./~\\".contains(c))
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
