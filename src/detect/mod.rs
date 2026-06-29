//! Detector core: candidate spans, the placeholder vocabulary, and the
//! precedence-based overlap resolution (§6.3).
//!
//! Each detector reads a line and emits [`Candidate`] spans. They run
//! independently and may overlap; [`resolve`] reduces them to a non-overlapping
//! set by precedence. Numbering is assigned later, in the engine, so it follows
//! first-seen order across the whole stream.

pub mod ids;
pub mod net;
pub mod paths;
pub mod secrets;

/// A detected region of a line and what to do with it.
#[derive(Debug, Clone)]
pub struct Candidate {
    /// Byte range within the line.
    pub start: usize,
    pub end: usize,
    pub kind: Kind,
    /// Finer-grained label for findings (e.g. `github`, `jwt`, `macos_home`).
    pub subtype: Option<&'static str>,
    pub action: Action,
    /// Tiebreak within the same `kind`: higher wins (e.g. jwt over auth-bearer).
    pub rank: u8,
}

impl Candidate {
    pub fn width(&self) -> usize {
        self.end - self.start
    }
}

/// The broad category of a span. Drives precedence and the finding `type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    Secret,
    /// A diagnostic ID (UUID / git SHA) to preserve verbatim — never scrubbed.
    Keep,
    Home,
    Tmpdir,
    Email,
    Ip,
    Host,
    Mac,
    User,
}

impl Kind {
    /// The finding `type` string (§7).
    pub fn type_str(self) -> &'static str {
        match self {
            Kind::Secret => "secret",
            Kind::Keep => "keep",
            Kind::Home => "home",
            Kind::Tmpdir => "tmpdir",
            Kind::Email => "email",
            Kind::Ip => "ip",
            Kind::Host => "host",
            Kind::Mac => "mac",
            Kind::User => "user",
        }
    }

    /// Precedence for overlap resolution: higher wins (§6.3).
    fn precedence(self) -> u8 {
        match self {
            Kind::Secret => 100,
            Kind::Keep => 90,
            Kind::Home | Kind::Tmpdir => 70,
            Kind::Email => 60,
            Kind::Ip => 50,
            Kind::Host => 40,
            Kind::Mac => 30,
            Kind::User => 10,
        }
    }

    /// Secrets never reveal their original value, in any mode (§7).
    pub fn is_secret(self) -> bool {
        matches!(self, Kind::Secret)
    }
}

/// What replaces a span. Numbering happens in the engine via the registry.
#[derive(Debug, Clone)]
pub enum Action {
    /// A numbered placeholder for a distinct value: `<EMAIL_1>`, `<TOKEN_2>`…
    Number { ptype: PType, value: String },
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
    /// A fixed placeholder with no numbering: `<PASSWORD>`, `<PRIVATE_KEY>`.
    Fixed(&'static str),
    /// Preserve the original text; the span only blocks weaker detectors.
    Keep,
}

/// Numbered placeholder buckets. Each counts from 1 independently (§6.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PType {
    Token,
    Jwt,
    Secret,
    Email,
    Ip,
    Host,
    Mac,
}

impl PType {
    pub fn label(self) -> &'static str {
        match self {
            PType::Token => "TOKEN",
            PType::Jwt => "JWT",
            PType::Secret => "SECRET",
            PType::Email => "EMAIL",
            PType::Ip => "IP",
            PType::Host => "HOST",
            PType::Mac => "MAC",
        }
    }
}

/// Resolve overlapping candidates to a non-overlapping set by precedence (§6.3).
///
/// Greedy weighted-interval selection: sort by precedence, then rank, then
/// length (longest-first within a detector), then position; accept a candidate
/// only if it doesn't overlap one already accepted. The result is sorted by
/// start offset, ready for left-to-right assignment.
pub fn resolve(mut candidates: Vec<Candidate>) -> Vec<Candidate> {
    candidates.sort_by(|a, b| {
        b.kind
            .precedence()
            .cmp(&a.kind.precedence())
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
