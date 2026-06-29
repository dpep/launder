//! Pillar 1 — home / username / tmpdir paths (§5).
//!
//! Collapse the personal prefix of a home path to `~` (or `<HOME_N>`) while
//! preserving the relative tail, separators, line numbers, and extension. The
//! captured username becomes a registered identity. System paths are never
//! matched here, so they're kept for free.

use std::sync::LazyLock;

use regex::Regex;

use super::{Action, Candidate, Kind};

/// `/Users/<u>/…` (macOS) and `/home/<u>/…` (Linux). Group 1 = username,
/// group 2 = the tail (leading separator onward, possibly empty).
static UNIX_HOME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?:/Users/|/home/)([^/\s'"]+)([^\s'"]*)"#).unwrap());

/// `/root` and its tail — root's home, collapsed to `~` but not enrolled as a
/// bare-redactable username.
static ROOT_HOME: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"/root(/[^\s'"]*)?"#).unwrap());

/// `C:\Users\<u>\…` and `C:\Documents and Settings\<u>\…` (Windows).
static WIN_HOME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)[a-z]:\\(?:Users|Documents and Settings)\\([^\\/\s'"]+)([^\s'"]*)"#).unwrap()
});

/// macOS per-user temp: `/var/folders/<xx>/<yyyy…>/T/…` → `<TMPDIR>` + tail.
static MACOS_TMPDIR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"/var/folders/[^/\s'"]+/[^/\s'"]+/T([^\s'"]*)"#).unwrap());

/// Segments directly under `/Users` that are system folders, not user homes.
const NON_USER_HOMES: &[&str] = &["Shared"];

pub fn detect(line: &str, out: &mut Vec<Candidate>) {
    for caps in UNIX_HOME.captures_iter(line) {
        let m = caps.get(0).unwrap();
        let user = caps.get(1).unwrap().as_str();
        if NON_USER_HOMES.contains(&user) {
            continue;
        }
        let tail = caps.get(2).map_or("", |t| t.as_str()).to_string();
        let subtype = if m.as_str().starts_with("/Users/") {
            "macos_home"
        } else {
            "linux_home"
        };
        out.push(Candidate {
            start: m.start(),
            end: m.end(),
            kind: Kind::Home,
            subtype: Some(subtype),
            action: Action::Home {
                user: user.to_string(),
                bare_eligible: true,
                tail,
            },
            rank: 0,
        });
    }

    for caps in ROOT_HOME.captures_iter(line) {
        let m = caps.get(0).unwrap();
        // Reject `/rootfs` and friends: the char after must be a real boundary.
        if !boundary_after(line, m.end()) {
            continue;
        }
        let tail = caps.get(1).map_or("", |t| t.as_str()).to_string();
        out.push(Candidate {
            start: m.start(),
            end: m.end(),
            kind: Kind::Home,
            subtype: Some("root_home"),
            action: Action::Home {
                user: "root".to_string(),
                bare_eligible: false,
                tail,
            },
            rank: 0,
        });
    }

    for caps in WIN_HOME.captures_iter(line) {
        let m = caps.get(0).unwrap();
        let user = caps.get(1).unwrap().as_str();
        let tail = caps.get(2).map_or("", |t| t.as_str()).to_string();
        out.push(Candidate {
            start: m.start(),
            end: m.end(),
            kind: Kind::Home,
            subtype: Some("windows_home"),
            action: Action::Home {
                user: user.to_string(),
                bare_eligible: true,
                tail,
            },
            rank: 0,
        });
    }

    for caps in MACOS_TMPDIR.captures_iter(line) {
        let m = caps.get(0).unwrap();
        let tail = caps.get(1).map_or("", |t| t.as_str()).to_string();
        out.push(Candidate {
            start: m.start(),
            end: m.end(),
            kind: Kind::Tmpdir,
            subtype: Some("macos_tmpdir"),
            action: Action::Tmpdir { tail },
            rank: 0,
        });
    }
}

/// True if the byte at `pos` ends the path: end-of-line or a non-path char.
fn boundary_after(line: &str, pos: usize) -> bool {
    match line[pos..].chars().next() {
        None => true,
        Some(c) => !(c.is_alphanumeric() || c == '_' || c == '/'),
    }
}
