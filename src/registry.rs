//! Per-run placeholder registry.
//!
//! Maps each distinct `(type, value)` to a stable placeholder for the life of
//! one run, so a repeated value reuses its number ("user X did A then B" stays
//! linkable). Identities (usernames / home dirs) share a single index space:
//! the primary user renders as `~` / `<USER_1>`, additional homes as
//! `<HOME_2>` / `<USER_2>`, …
//!
//! The registry lives in memory and is discarded at exit. **No file is ever
//! written** — a persisted map would be a re-identification key.

use std::collections::HashMap;

use crate::detect::Label;

#[derive(Debug, Default)]
pub struct Registry {
    counters: HashMap<Label, usize>,
    values: HashMap<(Label, String), String>,
    /// Username identities in first-seen order; index = position + 1.
    identities: Vec<String>,
    ident_index: HashMap<String, usize>,
    /// Identities eligible for standalone-username redaction.
    bare_users: Vec<String>,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    /// The placeholder for a numbered value, assigning the next index on first
    /// sight and reusing it thereafter.
    pub fn placeholder(&mut self, label: Label, value: &str) -> String {
        let key = (label, value.to_string());
        if let Some(p) = self.values.get(&key) {
            return p.clone();
        }
        let n = self.counters.entry(label).or_insert(0);
        *n += 1;
        let placeholder = format!("<{}_{}>", label.as_str(), n);
        self.values.insert(key, placeholder.clone());
        placeholder
    }

    /// Register a username identity (idempotent), returning its 1-based index.
    pub fn identity_index(&mut self, user: &str) -> usize {
        if let Some(&i) = self.ident_index.get(user) {
            return i;
        }
        self.identities.push(user.to_string());
        let index = self.identities.len();
        self.ident_index.insert(user.to_string(), index);
        index
    }

    /// Register a home owner and return its rendered prefix: `~` for the primary
    /// identity, `<HOME_N>` for the rest. `bare_eligible` enrolls the username
    /// for standalone redaction.
    pub fn home_prefix(&mut self, user: &str, bare_eligible: bool) -> String {
        let index = self.identity_index(user);
        if bare_eligible {
            self.enroll_bare(user);
        }
        if index == 1 {
            "~".to_string()
        } else {
            format!("<HOME_{index}>")
        }
    }

    /// Register a username a path proves and return its `<USER_N>`, enrolling
    /// it for standalone redaction like a home owner.
    pub fn path_user(&mut self, user: &str) -> String {
        self.enroll_bare(user);
        self.user_placeholder(user)
    }

    /// The `<USER_N>` placeholder for an identity, registering it if needed.
    pub fn user_placeholder(&mut self, user: &str) -> String {
        let index = self.identity_index(user);
        format!("<USER_{index}>")
    }

    /// Enroll a username for standalone (bare) redaction if it is long enough
    /// not to collide with prose.
    pub fn enroll_bare(&mut self, user: &str) {
        const MIN_BARE_LEN: usize = 4;
        if user.len() >= MIN_BARE_LEN && !self.bare_users.iter().any(|u| u == user) {
            self.bare_users.push(user.to_string());
        }
    }

    /// Usernames currently eligible for standalone redaction.
    pub fn bare_users(&self) -> &[String] {
        &self.bare_users
    }
}
