//! Per-line pipeline (§6): detect → resolve → assign → emit.
//!
//! The engine owns the run-lifetime [`Registry`] and the small amount of
//! cross-line state (the PEM private-key block). Identities discovered from a
//! home path are registered before standalone-username (bare) detection runs,
//! so `user=<name>` on the same line still maps.

use crate::config::{Config, TypeGroup};
use crate::detect::{self, Action, Candidate, Kind, resolve};
use crate::registry::Registry;

/// One detected, replaced region — the engine's resolved unit of work.
#[derive(Debug, Clone)]
pub struct Finding {
    pub kind: Kind,
    pub subtype: Option<&'static str>,
    pub line: usize,
    pub col: usize,
    pub len: usize,
    pub replacement: String,
    /// The raw matched text. Emitted only per the §7 rules (never for secrets).
    pub original: String,
    /// Byte span within the source line (internal; not serialized).
    byte_start: usize,
    byte_end: usize,
}

/// The outcome of laundering one input line.
pub struct LineResult {
    /// The laundered line, or `None` when the line is fully suppressed
    /// (private-key body).
    pub output: Option<String>,
    pub findings: Vec<Finding>,
}

pub struct Engine {
    reg: Registry,
    cfg: Config,
    line_no: usize,
    in_private_key: bool,
    extra_hosts: Vec<String>,
}

impl Engine {
    pub fn new(cfg: Config) -> Self {
        let mut reg = Registry::new();
        let mut extra_hosts = Vec::new();
        if let Some(sys) = &cfg.system {
            // Pin the primary identity to index 1 (`~` / <USER_1>).
            if let Some(user) = &sys.primary_user {
                reg.identity_index(user);
                reg.enroll_bare(user);
            }
            for user in &sys.users {
                reg.identity_index(user);
                reg.enroll_bare(user);
            }
            extra_hosts = sys.hostnames.clone();
        }
        Engine {
            reg,
            cfg,
            line_no: 0,
            in_private_key: false,
            extra_hosts,
        }
    }

    pub fn process_line(&mut self, line: &str) -> LineResult {
        self.line_no += 1;
        let secrets_on = self.cfg.enabled(TypeGroup::Secret);

        // PEM private-key blocks span lines; collapse the whole block to one
        // <PRIVATE_KEY> placeholder.
        if secrets_on {
            if self.in_private_key {
                return self.continue_private_key(line);
            }
            if detect::secrets::is_private_key_begin(line) {
                return self.begin_private_key(line);
            }
        }

        // Phase A: every enabled detector except bare-username.
        let mut candidates = Vec::new();
        if self.cfg.enabled(TypeGroup::Path) {
            detect::paths::detect(line, &mut candidates);
        }
        if secrets_on {
            detect::secrets::detect(line, &mut candidates);
        }
        // Diagnostic-ID preservation always runs (it only ever keeps text).
        detect::ids::detect(line, &mut candidates);
        if self.cfg.enabled(TypeGroup::Email) {
            detect::net::email(line, &mut candidates);
        }
        if self.cfg.enabled(TypeGroup::Ip) {
            detect::net::ip(line, self.cfg.keep_private_ips, &mut candidates);
        }
        if self.cfg.enabled(TypeGroup::Host) {
            detect::net::host(line, &self.extra_hosts, &mut candidates);
        }
        if self.cfg.enabled(TypeGroup::Mac) {
            detect::net::mac(line, &mut candidates);
        }

        let resolved = resolve(candidates);
        let covered: Vec<(usize, usize)> = resolved.iter().map(|c| (c.start, c.end)).collect();

        // Assign placeholders in first-seen (left-to-right) order. Home spans
        // register identities here, before bare-username detection.
        let mut findings: Vec<Finding> = resolved
            .iter()
            .filter(|c| c.kind != Kind::Keep)
            .map(|c| self.assign(line, c))
            .collect();

        // Phase B: standalone usernames, over regions nothing else claimed.
        if self.cfg.enabled(TypeGroup::User) {
            let bare = self.detect_bare_users(line, &covered);
            for c in resolve(bare) {
                findings.push(self.assign(line, &c));
            }
        }

        findings.sort_by_key(|f| f.byte_start);
        let output = render(line, &findings);
        LineResult {
            output: Some(output),
            findings,
        }
    }

    /// Turn a resolved candidate into a finding with its concrete replacement.
    fn assign(&mut self, line: &str, c: &Candidate) -> Finding {
        let original = line[c.start..c.end].to_string();
        let replacement = match &c.action {
            Action::Number { ptype, value } => self.reg.placeholder(*ptype, value),
            Action::Home {
                user,
                bare_eligible,
                tail,
            } => format!("{}{}", self.reg.home_prefix(user, *bare_eligible), tail),
            Action::Tmpdir { tail } => format!("<TMPDIR>{tail}"),
            Action::BareUser { user } => self.reg.user_placeholder(user),
            Action::Fixed(text) => text.to_string(),
            Action::Keep => original.clone(),
        };
        Finding {
            kind: c.kind,
            subtype: c.subtype,
            line: self.line_no,
            col: line[..c.start].chars().count() + 1,
            len: original.chars().count(),
            replacement,
            original,
            byte_start: c.start,
            byte_end: c.end,
        }
    }

    /// Find standalone occurrences of registered usernames outside `covered`.
    fn detect_bare_users(&self, line: &str, covered: &[(usize, usize)]) -> Vec<Candidate> {
        let mut out = Vec::new();
        for user in self.reg.bare_users() {
            for (start, end) in bare_occurrences(line, user) {
                let overlaps = covered.iter().any(|&(s, e)| start < e && s < end);
                if overlaps {
                    continue;
                }
                out.push(Candidate {
                    start,
                    end,
                    kind: Kind::User,
                    subtype: None,
                    action: Action::BareUser { user: user.clone() },
                    rank: 0,
                });
            }
        }
        out
    }

    fn begin_private_key(&mut self, line: &str) -> LineResult {
        let begin = line.find("-----BEGIN").unwrap();
        let prefix = &line[..begin];
        // A single-line key carries its own END marker after the BEGIN header.
        let after_begin = begin + "-----BEGIN".len();
        if let Some(end_rel) = line[after_begin..].find("-----END") {
            let end_marker = "PRIVATE KEY-----";
            let end_at = after_begin + end_rel;
            let after = line[end_at..]
                .find(end_marker)
                .map(|i| &line[end_at + i + end_marker.len()..])
                .unwrap_or("");
            let output = format!("{prefix}<PRIVATE_KEY>{after}");
            let finding = self.private_key_finding(begin, line);
            return LineResult {
                output: Some(output),
                findings: vec![finding],
            };
        }
        self.in_private_key = true;
        let finding = self.private_key_finding(begin, line);
        LineResult {
            output: Some(format!("{prefix}<PRIVATE_KEY>")),
            findings: vec![finding],
        }
    }

    fn continue_private_key(&mut self, line: &str) -> LineResult {
        if detect::secrets::is_private_key_end(line) {
            self.in_private_key = false;
            let after = line
                .find("PRIVATE KEY-----")
                .map(|i| &line[i + "PRIVATE KEY-----".len()..])
                .unwrap_or("");
            let output = if after.trim().is_empty() {
                None
            } else {
                Some(after.to_string())
            };
            return LineResult {
                output,
                findings: vec![],
            };
        }
        // Body line: suppress entirely.
        LineResult {
            output: None,
            findings: vec![],
        }
    }

    fn private_key_finding(&self, col_byte: usize, line: &str) -> Finding {
        Finding {
            kind: Kind::Secret,
            subtype: Some("private_key"),
            line: self.line_no,
            col: line[..col_byte].chars().count() + 1,
            len: line[col_byte..].chars().count(),
            replacement: "<PRIVATE_KEY>".to_string(),
            original: String::new(),
            byte_start: col_byte,
            byte_end: line.len(),
        }
    }
}

/// Rebuild a line, substituting each finding's byte span with its replacement.
/// Findings arrive sorted by `byte_start` and are non-overlapping.
fn render(line: &str, findings: &[Finding]) -> String {
    if findings.is_empty() {
        return line.to_string();
    }
    let mut out = String::with_capacity(line.len());
    let mut prev = 0;
    for f in findings {
        if f.byte_start < prev {
            continue; // defensive: skip any overlap
        }
        out.push_str(&line[prev..f.byte_start]);
        out.push_str(&f.replacement);
        prev = f.byte_end;
    }
    out.push_str(&line[prev..]);
    out
}

/// Standalone occurrences of `user`: word-boundary delimited, where a word char
/// is alphanumeric or underscore.
fn bare_occurrences(line: &str, user: &str) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    if user.is_empty() {
        return out;
    }
    let bytes = line.as_bytes();
    let mut from = 0;
    while let Some(rel) = line[from..].find(user) {
        let start = from + rel;
        let end = start + user.len();
        let before_ok = start == 0 || !is_word_byte(bytes[start - 1]);
        let after_ok = end >= bytes.len() || !is_word_byte(bytes[end]);
        if before_ok && after_ok {
            out.push((start, end));
        }
        from = end;
    }
    out
}

fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}
