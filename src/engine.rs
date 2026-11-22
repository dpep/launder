//! Per-line pipeline: detect → resolve → assign → emit.
//!
//! The engine owns the run-lifetime [`Registry`] and the small amount of
//! cross-line state (the PEM private-key block). Identities discovered from a
//! home path are registered before standalone-username (bare) detection runs,
//! so `user=<name>` on the same line still maps.

use crate::config::Config;
use crate::detect::literal::{Boundary, Term};
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
    /// The raw matched text. Never emitted for secrets.
    pub original: String,
    /// Byte span within the source line (internal; not serialized).
    byte_start: usize,
    byte_end: usize,
}

/// The outcome of laundering one input line.
pub struct LineResult {
    /// 1-based input line number, counted across all inputs.
    pub line: usize,
    /// The laundered line, or `None` when the line is fully suppressed
    /// (private-key body).
    pub output: Option<String>,
    pub findings: Vec<Finding>,
}

pub struct Engine {
    reg: Registry,
    cfg: Config,
    line_no: usize,
    /// An open PEM private-key block: body lines suppressed so far.
    open_key: Option<usize>,
    /// Literal `$HOME` prefix and its owner, for collapsing non-standard homes.
    home: Option<(String, String)>,
    /// The machine's own hostnames.
    machine: Vec<Term>,
    watch: Vec<Term>,
    keep: Vec<Term>,
    /// Searchers for the registry's bare usernames, in the same order.
    bare: Vec<Term>,
}

impl Engine {
    pub fn new(cfg: Config) -> Self {
        let mut reg = Registry::new();
        // Signal, not pinning: enroll the tokens to watch for, but assign no
        // identity index up front — numbering follows first-seen order from
        // the log, so a remote machine's trace is unaffected by local names.
        for user in &cfg.watchlist.usernames {
            reg.enroll_bare(user);
        }
        let home = cfg.watchlist.home.as_ref().and_then(|h| {
            let owner = h.rsplit(['/', '\\']).next().filter(|s| !s.is_empty())?;
            Some((h.clone(), owner.to_string()))
        });
        let terms = |list: &[String], make: fn(&str) -> Option<Term>| {
            list.iter().filter_map(|t| make(t)).collect::<Vec<_>>()
        };
        Engine {
            machine: terms(&cfg.watchlist.hostnames, |t| Term::new(t, Boundary::Host)),
            watch: terms(&cfg.watch, Term::user),
            keep: terms(&cfg.keep, Term::user),
            bare: Vec::new(),
            reg,
            cfg,
            line_no: 0,
            open_key: None,
            home,
        }
    }

    pub fn process_line(&mut self, line: &str) -> LineResult {
        self.line_no += 1;
        let secrets_on = self.cfg.enabled(Kind::Secret);

        // PEM private-key blocks span lines; collapse the whole block to one
        // <PRIVATE_KEY> placeholder.
        if secrets_on && self.open_key.is_some() {
            return self.continue_private_key(line);
        }

        // Phase A: every enabled detector except bare-username.
        // Detectors read the escape-blanked view; replacements index `line`.
        let view = detect::detection_view(line);
        let text = view.as_ref();
        // Literal terms match case-insensitively; ASCII lowering keeps offsets.
        let lower = text.to_ascii_lowercase();
        let mut candidates = Vec::new();
        if secrets_on && let Some((start, end, continues)) = detect::secrets::private_key(text) {
            self.open_key = continues.then_some(0);
            candidates.push(Candidate {
                start,
                end,
                subtype: Some("private_key"),
                action: Action::FixedSecret("<PRIVATE_KEY>"),
                rank: u8::MAX,
            });
        }
        // Path detection always runs: the identities it finds feed bare-username
        // matching even when paths themselves are left alone.
        let mut paths = Vec::new();
        detect::paths::detect(text, &mut paths);
        if let Some((prefix, owner)) = &self.home {
            detect::paths::detect_home_dir(text, prefix, owner, &mut paths);
        }
        if self.cfg.enabled(Kind::Path) {
            candidates.append(&mut paths);
        } else {
            self.learn_identities(paths);
        }
        // The secrets detector also finds logins (URL, curl, .netrc): users.
        if secrets_on || self.cfg.enabled(Kind::User) {
            detect::secrets::detect(text, &mut candidates);
        }
        // Diagnostic-ID preservation always runs (it only ever keeps text).
        detect::ids::detect(text, &mut candidates);
        if self.cfg.enabled(Kind::Email) {
            detect::net::email(text, &mut candidates);
        }
        if self.cfg.enabled(Kind::Ip) {
            detect::net::ip(text, self.cfg.keep_private_ips, &mut candidates);
        }
        if self.cfg.enabled(Kind::Host) {
            detect::net::host(text, &lower, &self.machine, &mut candidates);
        }
        if self.cfg.enabled(Kind::Mac) {
            detect::net::mac(text, &mut candidates);
        }

        detect::literal::watch(&self.watch, &lower, &mut candidates);

        // --only / --except judge each span by what it scrubs, whichever
        // detector found it.
        let kept = self.kept_spans(&lower);
        candidates.retain(|c| c.kind().is_none_or(|k| self.cfg.enabled(k)) && !is_kept(c, &kept));
        let resolved = resolve(candidates);
        let covered: Vec<(usize, usize)> = resolved.iter().map(|c| (c.start, c.end)).collect();

        // Assign placeholders in first-seen (left-to-right) order. Home spans
        // register identities here, before bare-username detection.
        let mut findings: Vec<Finding> = resolved
            .iter()
            .filter_map(|c| self.assign(line, c))
            .collect();

        // Phase B: standalone usernames, over regions nothing else claimed.
        if self.cfg.enabled(Kind::User) {
            let mut bare = self.detect_bare_users(&lower, &covered);
            bare.retain(|c| !is_kept(c, &kept));
            for c in resolve(bare) {
                findings.extend(self.assign(line, &c));
            }
        }

        findings.sort_by_key(|f| f.byte_start);
        set_columns(line, &mut findings);
        let output = render(line, &findings);
        LineResult {
            line: self.line_no,
            output: Some(output),
            findings,
        }
    }

    /// Mark the end of one input source (a file, or stdin at EOF). A private-key
    /// block never spans sources: an open one is closed here, returning how
    /// many body lines it suppressed so the caller can warn.
    pub fn end_input(&mut self) -> Option<usize> {
        self.open_key.take()
    }

    /// Turn a resolved candidate into a finding with its concrete replacement.
    /// A kept ID yields no finding: its text passes through as is.
    fn assign(&mut self, line: &str, c: &Candidate) -> Option<Finding> {
        let kind = c.kind()?;
        let original = line[c.start..c.end].to_string();
        let replacement = match &c.action {
            Action::Number { label, value } => self.reg.placeholder(*label, value),
            Action::Home {
                user,
                bare_eligible,
            } => self.reg.home_prefix(user, *bare_eligible),
            Action::Tmpdir => "<TMPDIR>".to_string(),
            Action::PathUser { user } | Action::BareUser { user } => self.reg.proven_user(user),
            Action::FixedSecret(text) => text.to_string(),
            Action::Keep => return None,
        };
        Some(Finding {
            kind,
            subtype: c.subtype,
            line: self.line_no,
            col: 0, // set by `set_columns`
            len: original.chars().count(),
            replacement,
            original,
            byte_start: c.start,
            byte_end: c.end,
        })
    }

    /// Register the identities path candidates reveal without replacing them,
    /// in first-seen order.
    fn learn_identities(&mut self, mut paths: Vec<Candidate>) {
        paths.sort_by_key(|c| c.start);
        for c in paths {
            match c.action {
                Action::Home {
                    user,
                    bare_eligible,
                } => {
                    self.reg.home_prefix(&user, bare_eligible);
                }
                Action::PathUser { user } => {
                    self.reg.proven_user(&user);
                }
                _ => {}
            }
        }
    }

    /// Find standalone occurrences of registered usernames outside `covered`
    /// (resolved spans, sorted by start).
    fn detect_bare_users(&mut self, lower: &str, covered: &[(usize, usize)]) -> Vec<Candidate> {
        // The registry only appends, so build searchers for the new names.
        let users = self.reg.bare_users();
        for user in &users[self.bare.len()..] {
            self.bare
                .push(Term::new(user, Boundary::Word).expect("enrolled names are non-empty"));
        }
        let mut out = Vec::new();
        for (user, term) in users.iter().zip(&self.bare) {
            for (start, end) in term.spans(lower.as_bytes()) {
                // `covered` is sorted and disjoint: only the last span starting
                // before `end` can overlap.
                let i = covered.partition_point(|&(s, _)| s < end);
                if i > 0 && covered[i - 1].1 > start {
                    continue;
                }
                out.push(Candidate {
                    start,
                    end,
                    subtype: None,
                    action: Action::BareUser { user: user.clone() },
                    rank: 0,
                });
            }
        }
        out
    }

    /// Spans of `--keep` terms, which nothing but a secret may replace.
    fn kept_spans(&self, lower: &str) -> Vec<(usize, usize)> {
        self.keep
            .iter()
            .flat_map(|t| t.spans(lower.as_bytes()))
            .collect()
    }

    fn continue_private_key(&mut self, line: &str) -> LineResult {
        if let Some(after) = detect::secrets::private_key_end(line) {
            self.open_key = None;
            let output = if after.trim().is_empty() {
                None
            } else {
                Some(after.to_string())
            };
            return LineResult {
                line: self.line_no,
                output,
                findings: vec![],
            };
        }
        // Body line: suppress entirely.
        if let Some(n) = &mut self.open_key {
            *n += 1;
        }
        LineResult {
            line: self.line_no,
            output: None,
            findings: vec![],
        }
    }
}

/// Fill each finding's 1-based char column in one pass over the line, so a
/// line with many findings stays linear. Findings must be sorted by start.
fn set_columns(line: &str, findings: &mut [Finding]) {
    let (mut byte, mut col) = (0, 1);
    for f in findings {
        col += line[byte..f.byte_start].chars().count();
        byte = f.byte_start;
        f.col = col;
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
        out.push_str(&line[prev..f.byte_start]);
        out.push_str(&f.replacement);
        prev = f.byte_end;
    }
    out.push_str(&line[prev..]);
    out
}

/// A scrub that lies within a `--keep` span. A secret is never kept, and a
/// wider match that merely contains the term (an email at a kept domain) is
/// still scrubbed.
fn is_kept(c: &Candidate, kept: &[(usize, usize)]) -> bool {
    c.kind().is_some_and(|k| !k.is_secret())
        && kept.iter().any(|&(s, e)| s <= c.start && c.end <= e)
}
