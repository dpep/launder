//! Diagnostic-ID preservation (§5). UUIDs, git SHAs, and other hex digests are
//! diagnostic gold — they must survive laundering untouched. These emit
//! `Keep` spans that block weaker detectors (e.g. keyed-entropy) from claiming
//! them, while still yielding to a genuine `Secret` match.

use std::sync::LazyLock;

use regex::Regex;

use super::{Action, Candidate, Kind};

static UUID: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
        .unwrap()
});

/// A standalone hex run: git SHAs (7–40) and longer digests up to 64.
static HEX_DIGEST: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b[0-9a-fA-F]{7,64}\b").unwrap());

pub fn detect(line: &str, out: &mut Vec<Candidate>) {
    for m in UUID.find_iter(line) {
        out.push(keep(m.start(), m.end(), "uuid"));
    }
    for m in HEX_DIGEST.find_iter(line) {
        // A pure-digits run is a number, not a digest — let it be.
        if m.as_str().bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        out.push(keep(m.start(), m.end(), "hex"));
    }
}

pub fn is_uuid(s: &str) -> bool {
    UUID.is_match(s) && UUID.find(s).is_some_and(|m| m.as_str().len() == s.len())
}

fn keep(start: usize, end: usize, subtype: &'static str) -> Candidate {
    Candidate {
        start,
        end,
        kind: Kind::Keep,
        subtype: Some(subtype),
        action: Action::Keep,
        rank: 0,
    }
}
