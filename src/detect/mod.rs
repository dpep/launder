//! Detector core: candidate spans, the placeholder vocabulary, and the
//! precedence-based overlap resolution.
//!
//! Each detector reads a line and emits [`Candidate`] spans. They run
//! independently and may overlap; [`resolve`] reduces them to a non-overlapping
//! set by precedence. Numbering is assigned later, in the engine, so it follows
//! first-seen order across the whole stream.

use std::borrow::Cow;
use std::collections::BTreeMap;

pub mod ids;
pub mod literal;
pub mod net;
pub mod paths;
pub mod secrets;

/// The line as detectors see it: ANSI CSI sequences (`\e[31m`) blanked to
/// spaces, since the final letter would otherwise defeat a `\b` on the token
/// after it. Same byte length, so spans still index the original line.
pub fn detection_view(line: &str) -> Cow<'_, str> {
    if !line.contains('\x1b') {
        return Cow::Borrowed(line);
    }
    let mut bytes = line.as_bytes().to_vec();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != 0x1b || bytes.get(i + 1) != Some(&b'[') {
            i += 1;
            continue;
        }
        let mut end = i + 2;
        while end < bytes.len() && (0x20..=0x3f).contains(&bytes[end]) {
            end += 1;
        }
        if end < bytes.len() && (0x40..=0x7e).contains(&bytes[end]) {
            end += 1;
        }
        bytes[i..end].fill(b' ');
        i = end;
    }
    // Only ASCII bytes were rewritten, so UTF-8 validity is unchanged.
    Cow::Owned(String::from_utf8(bytes).expect("ASCII-only rewrite"))
}

/// A detected region of a line and what to do with it.
#[derive(Debug, Clone)]
pub struct Candidate {
    /// Byte range within the line.
    pub start: usize,
    pub end: usize,
    /// Finer-grained label for findings (e.g. `github`, `jwt`, `macos_home`).
    pub subtype: Option<&'static str>,
    pub action: Action,
    /// Tiebreak within the same kind: higher wins (e.g. jwt over auth-bearer).
    pub rank: u8,
}

impl Candidate {
    pub fn width(&self) -> usize {
        self.end - self.start
    }

    /// What this span scrubs; `None` for a diagnostic ID kept verbatim.
    pub fn kind(&self) -> Option<Kind> {
        match &self.action {
            Action::Number { label, .. } => Some(label.kind()),
            Action::Home { .. } | Action::Tmpdir | Action::PathUser { .. } => Some(Kind::Path),
            Action::BareUser { .. } => Some(Kind::User),
            Action::FixedSecret(_) => Some(Kind::Secret),
            Action::Keep => None,
        }
    }

    /// Overlap precedence: higher wins.
    fn precedence(&self) -> u8 {
        match self.kind() {
            Some(Kind::Secret) => 100,
            // Path spans are only personal prefixes (home, tmpdir), so they can
            // outrank a kept ID that happens to fall on a hex-looking segment.
            Some(Kind::Path) => 90,
            // A kept ID blocks every other detector.
            None => 80,
            Some(Kind::Email) => 60,
            Some(Kind::Ip) => 50,
            Some(Kind::Host) => 40,
            Some(Kind::Mac) => 30,
            Some(Kind::Term) => 20,
            Some(Kind::User) => 10,
        }
    }
}

/// A scrub type: the finding `type`, and what `--only` / `--except` name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    Path,
    Secret,
    Email,
    Ip,
    Host,
    Mac,
    User,
    Term,
}

impl Kind {
    pub const ALL: [Kind; 8] = [
        Kind::Path,
        Kind::Secret,
        Kind::Email,
        Kind::Ip,
        Kind::Host,
        Kind::Mac,
        Kind::User,
        Kind::Term,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Path => "path",
            Kind::Secret => "secret",
            Kind::Email => "email",
            Kind::Ip => "ip",
            Kind::Host => "host",
            Kind::Mac => "mac",
            Kind::User => "user",
            Kind::Term => "term",
        }
    }

    /// Secrets never reveal their original value, in any mode.
    pub fn is_secret(self) -> bool {
        matches!(self, Kind::Secret)
    }
}

/// What replaces a span. Numbering happens in the engine via the registry.
#[derive(Debug, Clone)]
pub enum Action {
    /// A numbered placeholder for a distinct value: `<EMAIL_1>`, `<TOKEN_2>`…
    Number { label: Label, value: String },
    /// A home-dir prefix → `~` / `<HOME_N>`, registering `user` as an identity.
    /// `bare_eligible` controls whether the username is also scrubbed standalone.
    Home { user: String, bare_eligible: bool },
    /// The macOS per-user temp dir → `<TMPDIR>`.
    Tmpdir,
    /// A username that a path's shape proves (`pytest-of-<u>`, a nested home)
    /// → `<USER_N>`, registering and enrolling it like a home owner.
    PathUser { user: String },
    /// A username outside a path → `<USER_N>`: a standalone occurrence of a
    /// known identity, or a credential's login (`alice` in `alice:pw@host`).
    BareUser { user: String },
    /// An unnumbered secret placeholder: `<PRIVATE_KEY>`.
    FixedSecret(&'static str),
    /// Preserve the original text; the span only blocks weaker detectors.
    Keep,
}

/// Numbered placeholder names. Each counts from 1 independently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Label {
    Token,
    Jwt,
    Secret,
    Password,
    Email,
    Ip,
    Host,
    Mac,
    /// A `--watch` term that is not a domain.
    Term,
}

impl Label {
    pub fn as_str(self) -> &'static str {
        match self {
            Label::Token => "TOKEN",
            Label::Jwt => "JWT",
            Label::Secret => "SECRET",
            Label::Password => "PASSWORD",
            Label::Email => "EMAIL",
            Label::Ip => "IP",
            Label::Host => "HOST",
            Label::Mac => "MAC",
            Label::Term => "TERM",
        }
    }

    pub fn kind(self) -> Kind {
        match self {
            Label::Token | Label::Jwt | Label::Secret | Label::Password => Kind::Secret,
            Label::Email => Kind::Email,
            Label::Ip => Kind::Ip,
            Label::Host => Kind::Host,
            Label::Mac => Kind::Mac,
            Label::Term => Kind::Term,
        }
    }
}

/// Resolve overlapping candidates to a non-overlapping set by precedence.
///
/// Greedy weighted-interval selection: sort by precedence, then rank, then
/// length (longest-first within a detector), then position; accept a candidate
/// only if it doesn't overlap one already accepted. The result is sorted by
/// start offset, ready for left-to-right assignment.
///
/// A kept ID strictly inside a wider scrub span yields to it first: a hex run
/// in `ops@cafebabe.io` is part of the address, not a digest. A keep as wide
/// as the span still wins.
pub fn resolve(candidates: Vec<Candidate>) -> Vec<Candidate> {
    let mut candidates = drop_keeps_inside_scrubs(candidates);
    candidates.sort_by(|a, b| {
        b.precedence()
            .cmp(&a.precedence())
            .then(b.rank.cmp(&a.rank))
            .then(b.width().cmp(&a.width()))
            .then(a.start.cmp(&b.start))
    });

    // Accepted spans are disjoint, so only the one starting last before
    // `cand.end` can overlap it. Empty spans replace nothing and are dropped.
    let mut chosen: BTreeMap<usize, Candidate> = BTreeMap::new();
    for cand in candidates.into_iter().filter(|c| c.start < c.end) {
        let overlaps = chosen
            .range(..cand.end)
            .next_back()
            .is_some_and(|(_, c)| cand.start < c.end && c.start < cand.end);
        if !overlaps {
            chosen.insert(cand.start, cand);
        }
    }
    chosen.into_values().collect()
}

/// Drop each `Keep` that a wider scrub span contains.
fn drop_keeps_inside_scrubs(candidates: Vec<Candidate>) -> Vec<Candidate> {
    let mut scrubs: Vec<(usize, usize)> = candidates
        .iter()
        .filter(|c| c.kind().is_some())
        .map(|c| (c.start, c.end))
        .collect();
    if scrubs.is_empty() {
        return candidates;
    }
    scrubs.sort_unstable();
    // reach[i]: the furthest end among scrubs[..=i].
    let reach: Vec<usize> = scrubs
        .iter()
        .scan(0, |far, &(_, e)| {
            *far = (*far).max(e);
            Some(*far)
        })
        .collect();
    // The furthest end of any scrub starting before (or at) `pos`.
    let reach_from = |pos: usize, inclusive: bool| {
        let n = scrubs.partition_point(|&(s, _)| s < pos || (inclusive && s == pos));
        n.checked_sub(1).map_or(0, |i| reach[i])
    };
    candidates
        .into_iter()
        .filter(|c| {
            !matches!(c.action, Action::Keep)
                || !(reach_from(c.start, false) >= c.end || reach_from(c.start, true) > c.end)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The quadratic greedy scan `resolve` must agree with.
    fn resolve_naive(candidates: Vec<Candidate>) -> Vec<(usize, usize)> {
        let scrubs: Vec<(usize, usize)> = candidates
            .iter()
            .filter(|c| c.kind().is_some())
            .map(|c| (c.start, c.end))
            .collect();
        let mut candidates: Vec<Candidate> = candidates
            .into_iter()
            .filter(|c| {
                c.kind().is_some()
                    || !scrubs
                        .iter()
                        .any(|&(s, e)| s <= c.start && c.end <= e && e - s > c.width())
            })
            .collect();
        candidates.sort_by(|a, b| {
            b.precedence()
                .cmp(&a.precedence())
                .then(b.rank.cmp(&a.rank))
                .then(b.width().cmp(&a.width()))
                .then(a.start.cmp(&b.start))
        });
        let mut chosen: Vec<Candidate> = Vec::new();
        for cand in candidates {
            if !chosen
                .iter()
                .any(|c| cand.start < c.end && c.start < cand.end)
            {
                chosen.push(cand);
            }
        }
        let mut spans: Vec<_> = chosen.iter().map(|c| (c.start, c.end)).collect();
        spans.sort();
        spans
    }

    #[test]
    fn resolve_matches_naive_greedy() {
        let labels = [Label::Token, Label::Email, Label::Ip, Label::Host];
        let mut seed: u64 = 0x2545_f491_4f6c_dd1d;
        let mut next = |n: u64| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            (seed % n) as usize
        };
        for _ in 0..200 {
            let cands: Vec<Candidate> = (0..40)
                .map(|_| {
                    let start = next(100);
                    let action = match next(5) {
                        4 => Action::Keep,
                        i => Action::Number {
                            label: labels[i],
                            value: String::new(),
                        },
                    };
                    Candidate {
                        start,
                        end: start + 1 + next(15),
                        subtype: None,
                        action,
                        rank: next(2) as u8,
                    }
                })
                .collect();
            let fast: Vec<_> = resolve(cands.clone())
                .iter()
                .map(|c| (c.start, c.end))
                .collect();
            assert_eq!(fast, resolve_naive(cands));
        }
    }
}
