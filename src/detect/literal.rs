//! Literal-term matching: usernames and hostnames from the watchlist, and the
//! user's `--watch` / `--keep` terms. Case-insensitive (see [`fold`]),
//! boundary-checked, one prebuilt searcher per term.

use std::collections::{BTreeMap, HashMap};

use memchr::memmem::Finder;

use super::{Action, Candidate, Label};

/// Exact, case-sensitive strings matched as whole words ([`Boundary::Word`]).
/// Looked up by length and hash rather than searched one by one, so a set
/// that grows with the input stays cheap per line.
#[derive(Debug)]
pub struct Exact<T> {
    by_len: BTreeMap<usize, HashMap<String, T>>,
}

impl<T> Default for Exact<T> {
    fn default() -> Self {
        Exact {
            by_len: BTreeMap::new(),
        }
    }
}

impl<T> Exact<T> {
    /// Add `s` unless already present; true if added.
    pub fn insert(&mut self, s: &str, value: T) -> bool {
        let set = self.by_len.entry(s.len()).or_default();
        if set.contains_key(s) {
            return false;
        }
        set.insert(s.to_string(), value);
        true
    }

    /// Every bounded occurrence in `text`, with its value, by start.
    pub fn find<'a>(&'a self, text: &str) -> Vec<(usize, usize, &'a T)> {
        let b = text.as_bytes();
        let word = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
        let mut out = Vec::new();
        for start in 0..b.len() {
            if (start > 0 && word(b[start - 1])) || !text.is_char_boundary(start) {
                continue;
            }
            for (&len, set) in &self.by_len {
                let end = start + len;
                if end > b.len() {
                    break;
                }
                if b.get(end).copied().is_some_and(word) || !text.is_char_boundary(end) {
                    continue;
                }
                if let Some(value) = set.get(&text[start..end]) {
                    out.push((start, end, value));
                }
            }
        }
        out
    }
}

/// `--watch` terms: a domain → `<HOST_N>` (each distinct host its own number),
/// any other term → `<TERM_N>`.
pub fn watch(watch: &[Term], lower: &str, out: &mut Vec<Candidate>) {
    for term in watch {
        let label = if term.is_domain() {
            Label::Host
        } else {
            Label::Term
        };
        for (start, end) in term.spans(lower.as_bytes()) {
            out.push(Candidate {
                start,
                end,
                subtype: Some("watch"),
                action: Action::Number {
                    label,
                    value: lower[start..end].to_string(),
                },
                rank: 0,
            });
        }
    }
}

/// Lowercase `s` without moving a byte: a char whose lowercase is a single
/// char of the same UTF-8 length folds (`Ë` → `ë`), any other is left as is
/// (`İ`, whose lowercase is longer), so spans in the result index `s`.
pub fn fold(s: &str) -> String {
    if s.is_ascii() {
        return s.to_ascii_lowercase();
    }
    s.chars()
        .map(|c| {
            let mut lower = c.to_lowercase();
            match (lower.next(), lower.next()) {
                (Some(l), None) if l.len_utf8() == c.len_utf8() => l,
                _ => c,
            }
        })
        .collect()
}

/// What may sit on either side of a match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Boundary {
    /// Not a word character (alphanumeric or `_`): usernames, plain terms.
    Word,
    /// Not alphanumeric, `-`, or `.`: a machine hostname.
    Host,
    /// A domain and any subdomain of it; the span grows left over the
    /// subdomain labels (`web-03.prod.acme.com` for `acme.com`).
    Domain,
}

#[derive(Debug, Clone)]
pub struct Term {
    finder: Finder<'static>,
    boundary: Boundary,
}

impl Term {
    /// `None` for an empty term.
    pub fn new(term: &str, boundary: Boundary) -> Option<Self> {
        let lower = fold(term.trim());
        (!lower.is_empty()).then(|| Term {
            finder: Finder::new(lower.as_bytes()).into_owned(),
            boundary,
        })
    }

    /// A user-supplied term: a domain when it is dot-separated labels of
    /// letters, digits, and `-`; else a word.
    pub fn user(term: &str) -> Option<Self> {
        let term = term.trim();
        let label =
            |l: &str| !l.is_empty() && l.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-');
        let boundary = if term.contains('.') && term.split('.').all(label) {
            Boundary::Domain
        } else {
            Boundary::Word
        };
        Term::new(term, boundary)
    }

    /// The term's length in bytes.
    pub fn width(&self) -> usize {
        self.finder.needle().len()
    }

    pub fn is_domain(&self) -> bool {
        self.boundary == Boundary::Domain
    }

    /// Byte spans of each match in `lower`, the [`fold`]ed line.
    pub fn spans(&self, lower: &[u8]) -> Vec<(usize, usize)> {
        let len = self.width();
        let mut out = Vec::new();
        for start in self.finder.find_iter(lower) {
            let end = start + len;
            if let Some(span) = self.bounded(lower, start, end) {
                // Matches are reported left to right and may overlap; keep
                // only disjoint ones.
                if out.last().is_none_or(|&(_, e)| span.0 >= e) {
                    out.push(span);
                }
            }
        }
        out
    }

    fn bounded(&self, b: &[u8], start: usize, end: usize) -> Option<(usize, usize)> {
        let before = start.checked_sub(1).map(|i| b[i]);
        let after = b.get(end).copied();
        let word = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
        match self.boundary {
            Boundary::Word => {
                (!before.is_some_and(word) && !after.is_some_and(word)).then_some((start, end))
            }
            Boundary::Host => {
                let host = |c: u8| c.is_ascii_alphanumeric() || c == b'-' || c == b'.';
                (!before.is_some_and(host) && !after.is_some_and(host)).then_some((start, end))
            }
            Boundary::Domain => {
                let label = |c: u8| c.is_ascii_alphanumeric() || c == b'-' || c == b'_';
                // A trailing dot ends a sentence; one before a label extends
                // the name into another domain (`acme.com.au`).
                let continues = after == Some(b'.') && b.get(end + 1).copied().is_some_and(label);
                if after.is_some_and(label) || continues || before.is_some_and(label) {
                    return None;
                }
                let mut s = start;
                if before == Some(b'.') {
                    while s > 0 && (label(b[s - 1]) || b[s - 1] == b'.') {
                        s -= 1;
                    }
                    while s < start && b[s] == b'.' {
                        s += 1;
                    }
                }
                Some((s, end))
            }
        }
    }
}
