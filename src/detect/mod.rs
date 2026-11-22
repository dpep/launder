//! Detector core: candidate spans, the placeholder vocabulary, and the
//! precedence-based overlap resolution.
//!
//! Each detector reads a line and emits [`Candidate`] spans. They run
//! independently and may overlap; [`resolve`] reduces them to a non-overlapping
//! set by precedence. Numbering is assigned later, in the engine, so it follows
//! first-seen order across the whole stream.

use std::borrow::Cow;

pub mod ids;
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
            Action::Home { .. } | Action::Tmpdir { .. } => Some(Kind::Path),
            Action::BareUser { .. } => Some(Kind::User),
            Action::FixedSecret(_) => Some(Kind::Secret),
            Action::Keep => None,
        }
    }

    /// Overlap precedence: higher wins.
    fn precedence(&self) -> u8 {
        match self.kind() {
            Some(Kind::Secret) => 100,
            // A kept ID blocks every detector except a genuine secret.
            None => 90,
            Some(Kind::Path) => 70,
            Some(Kind::Email) => 60,
            Some(Kind::Ip) => 50,
            Some(Kind::Host) => 40,
            Some(Kind::Mac) => 30,
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
}

impl Kind {
    pub const ALL: [Kind; 7] = [
        Kind::Path,
        Kind::Secret,
        Kind::Email,
        Kind::Ip,
        Kind::Host,
        Kind::Mac,
        Kind::User,
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
    /// Home-dir collapse: register `user` as an identity, render prefix + tail.
    /// `bare_eligible` controls whether the username is also scrubbed standalone.
    Home {
        user: String,
        bare_eligible: bool,
        tail: String,
    },
    /// macOS per-user temp path → `<TMPDIR>` + tail.
    Tmpdir { tail: String },
    /// A standalone username occurrence → `<USER_N>` (identity already known).
    BareUser { user: String },
    /// An unnumbered secret placeholder: `<PASSWORD>`, `<PRIVATE_KEY>`.
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
    Email,
    Ip,
    Host,
    Mac,
}

impl Label {
    pub fn as_str(self) -> &'static str {
        match self {
            Label::Token => "TOKEN",
            Label::Jwt => "JWT",
            Label::Secret => "SECRET",
            Label::Email => "EMAIL",
            Label::Ip => "IP",
            Label::Host => "HOST",
            Label::Mac => "MAC",
        }
    }

    pub fn kind(self) -> Kind {
        match self {
            Label::Token | Label::Jwt | Label::Secret => Kind::Secret,
            Label::Email => Kind::Email,
            Label::Ip => Kind::Ip,
            Label::Host => Kind::Host,
            Label::Mac => Kind::Mac,
        }
    }
}

/// Resolve overlapping candidates to a non-overlapping set by precedence.
///
/// Greedy weighted-interval selection: sort by precedence, then rank, then
/// length (longest-first within a detector), then position; accept a candidate
/// only if it doesn't overlap one already accepted. The result is sorted by
/// start offset, ready for left-to-right assignment.
pub fn resolve(mut candidates: Vec<Candidate>) -> Vec<Candidate> {
    candidates.sort_by(|a, b| {
        b.precedence()
            .cmp(&a.precedence())
            .then(b.rank.cmp(&a.rank))
            .then(b.width().cmp(&a.width()))
            .then(a.start.cmp(&b.start))
    });

    let mut chosen: Vec<Candidate> = Vec::new();
    for cand in candidates {
        let overlaps = chosen
            .iter()
            .any(|c| cand.start < c.end && c.start < cand.end);
        if !overlaps {
            chosen.push(cand);
        }
    }

    chosen.sort_by_key(|c| c.start);
    chosen
}
