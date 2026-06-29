//! Local-identity **signal** (offline, on by default).
//!
//! Reads `$USER` / `$LOGNAME` / `$HOME` and the machine hostname and offers them
//! as a *watchlist* of known-identifying tokens — things to look out for and
//! scrub on sight. It deliberately does **not** pin an identity or impose
//! ordering: numbering still follows first-seen order from the log itself, so a
//! trace pulled from a remote machine launders just as well as a local one. If
//! a watchlist token never appears, it has no effect. Fully offline — touches
//! the system, never the network.

use std::env;
use std::process::Command;

#[derive(Debug, Clone, Default)]
pub struct SystemInfo {
    /// Usernames to watch for (`$USER` / `$LOGNAME` / `$HOME`'s owner).
    pub usernames: Vec<String>,
    /// The literal `$HOME` prefix, collapsed to `~` even when non-standard.
    pub home: Option<String>,
    /// Hostnames to scrub verbatim (the machine's own name).
    pub hostnames: Vec<String>,
}

/// Gather identity signal from the local environment. Never fails: missing
/// sources just yield less signal.
pub fn detect() -> SystemInfo {
    let home = env::var("HOME").ok().filter(|s| !s.is_empty());

    let mut usernames: Vec<String> = Vec::new();
    let home_owner = home
        .as_deref()
        .and_then(|h| h.rsplit(['/', '\\']).next())
        .map(str::to_string);
    for cand in [env::var("USER").ok(), env::var("LOGNAME").ok(), home_owner] {
        if let Some(name) = cand.filter(|s| !s.is_empty())
            && !usernames.contains(&name)
        {
            usernames.push(name);
        }
    }

    SystemInfo {
        usernames,
        home,
        hostnames: hostname(),
    }
}

/// The machine's hostname, both fully-qualified and short forms.
fn hostname() -> Vec<String> {
    let out = Command::new("hostname").output().ok();
    let raw = out
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty() && s != "localhost");
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
