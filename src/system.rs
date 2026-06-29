//! `--system` precision layer (§5). Turns structural guesses into exact,
//! exhaustive identity detection using local sources only — `$HOME` / `$USER` /
//! `$LOGNAME`, `/etc/passwd`, and the machine hostname. Fully offline: it
//! touches the system but never the network.

use std::env;
use std::fs;
use std::process::Command;

#[derive(Debug, Clone, Default)]
pub struct SystemInfo {
    /// The primary identity, pinned to index 1 (`~` / `<USER_1>`).
    pub primary_user: Option<String>,
    /// Other local users (from `/etc/passwd`), for bare-name coverage.
    pub users: Vec<String>,
    /// Hostnames to scrub verbatim (the machine's own name).
    pub hostnames: Vec<String>,
}

/// Gather identity info from the local environment. Never fails: missing
/// sources just yield less precision.
pub fn detect() -> SystemInfo {
    let primary_user = env::var("USER")
        .ok()
        .or_else(|| env::var("LOGNAME").ok())
        .filter(|s| !s.is_empty());

    let mut users = passwd_users();
    if let Some(primary) = &primary_user {
        users.retain(|u| u != primary);
    }

    let hostnames = hostname().into_iter().collect();

    SystemInfo {
        primary_user,
        users,
        hostnames,
    }
}

/// Real (non-system) login names from `/etc/passwd`, by UID threshold.
fn passwd_users() -> Vec<String> {
    let Ok(body) = fs::read_to_string("/etc/passwd") else {
        return Vec::new();
    };
    // macOS real users start at uid 500, Linux at 1000; 500 covers both.
    const MIN_UID: u32 = 500;
    let mut users = Vec::new();
    for line in body.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() < 6 {
            continue;
        }
        let (name, uid) = (fields[0], fields[2]);
        if let Ok(uid) = uid.parse::<u32>()
            && uid >= MIN_UID
            && name != "nobody"
            && !users.iter().any(|u| u == name)
        {
            users.push(name.to_string());
        }
    }
    users
}

/// The machine's hostname, both fully-qualified and short forms.
fn hostname() -> Vec<String> {
    let out = Command::new("hostname").output().ok();
    let raw = out
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty());
    let mut names = Vec::new();
    if let Some(full) = raw {
        if let Some(short) = full.split('.').next()
            && short != full
            && !short.is_empty()
        {
            names.push(short.to_string());
        }
        names.push(full);
    }
    names
}
