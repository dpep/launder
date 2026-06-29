//! Round-out detectors (§5): email, IP, hostname, MAC.
//!
//! Asymmetric bias: keep loopback + RFC1918 IPs and only the conservative
//! `*.local/*.internal/*.corp` hostnames by default — over-scrubbing destroys a
//! trace's usefulness.

use std::sync::LazyLock;

use regex::Regex;

use super::{Action, Candidate, Kind, PType};

static EMAIL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b").unwrap());

static IPV4: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap());

/// IPv6: a full 8-group address or a `::`-compressed form. Deliberately does
/// not match 6-group MAC-shaped strings.
static IPV6: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}\b|(?:[0-9a-f]{1,4}:){1,7}:(?:[0-9a-f]{1,4}:?){0,6}",
    )
    .unwrap()
});

static MAC: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b").unwrap());

static INTERNAL_HOST: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?(?:\.[a-z0-9\-]+)*\.(?:local|internal|corp)\b",
    )
    .unwrap()
});

pub fn email(line: &str, out: &mut Vec<Candidate>) {
    for m in EMAIL.find_iter(line) {
        out.push(Candidate {
            start: m.start(),
            end: m.end(),
            kind: Kind::Email,
            subtype: None,
            action: Action::Number {
                ptype: PType::Email,
                value: m.as_str().to_ascii_lowercase(),
            },
            rank: 0,
        });
    }
}

pub fn ip(line: &str, keep_private: bool, out: &mut Vec<Candidate>) {
    for m in IPV4.find_iter(line) {
        let text = m.as_str();
        let Some(octets) = parse_ipv4(text) else {
            continue;
        };
        if keep_private && is_private_v4(octets) {
            continue;
        }
        out.push(ip_candidate(m.start(), m.end(), text));
    }
    for m in IPV6.find_iter(line) {
        let text = m.as_str();
        // A MAC is not an IPv6 address.
        if MAC.is_match(text) {
            continue;
        }
        if keep_private && is_private_v6(text) {
            continue;
        }
        out.push(ip_candidate(m.start(), m.end(), text));
    }
}

pub fn mac(line: &str, out: &mut Vec<Candidate>) {
    for m in MAC.find_iter(line) {
        out.push(Candidate {
            start: m.start(),
            end: m.end(),
            kind: Kind::Mac,
            subtype: None,
            action: Action::Number {
                ptype: PType::Mac,
                value: m.as_str().to_ascii_lowercase(),
            },
            rank: 0,
        });
    }
}

pub fn host(line: &str, extra: &[String], out: &mut Vec<Candidate>) {
    for m in INTERNAL_HOST.find_iter(line) {
        out.push(host_candidate(m.start(), m.end(), m.as_str(), "internal"));
    }
    // The machine's own hostname (from --system), matched verbatim.
    for name in extra {
        if name.is_empty() {
            continue;
        }
        let mut from = 0;
        while let Some(rel) = line[from..].find(name.as_str()) {
            let start = from + rel;
            let end = start + name.len();
            if is_token_boundary(line, start, end) {
                out.push(host_candidate(start, end, name, "machine"));
            }
            from = end;
        }
    }
}

fn ip_candidate(start: usize, end: usize, text: &str) -> Candidate {
    Candidate {
        start,
        end,
        kind: Kind::Ip,
        subtype: None,
        action: Action::Number {
            ptype: PType::Ip,
            value: text.to_ascii_lowercase(),
        },
        rank: 0,
    }
}

fn host_candidate(start: usize, end: usize, text: &str, subtype: &'static str) -> Candidate {
    Candidate {
        start,
        end,
        kind: Kind::Host,
        subtype: Some(subtype),
        action: Action::Number {
            ptype: PType::Host,
            value: text.to_ascii_lowercase(),
        },
        rank: 0,
    }
}

fn parse_ipv4(s: &str) -> Option<[u8; 4]> {
    let mut octets = [0u8; 4];
    let mut parts = s.split('.');
    for slot in &mut octets {
        *slot = parts.next()?.parse().ok()?;
    }
    if parts.next().is_some() {
        return None;
    }
    Some(octets)
}

fn is_private_v4(o: [u8; 4]) -> bool {
    matches!(
        o,
        [127, ..]                       // loopback
        | [10, ..]                      // 10/8
        | [192, 168, ..]                // 192.168/16
        | [169, 254, ..]                // link-local
        | [172, 16..=31, ..] // 172.16/12
    )
}

fn is_private_v6(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    lower == "::1"                          // loopback
        || lower.starts_with("fe80")        // link-local
        || lower.starts_with("fc")          // unique-local fc00::/7
        || lower.starts_with("fd")
}

fn is_token_boundary(line: &str, start: usize, end: usize) -> bool {
    let before = line[..start].chars().next_back();
    let after = line[end..].chars().next();
    let ok = |c: Option<char>| match c {
        None => true,
        Some(c) => !(c.is_alphanumeric() || c == '-' || c == '.'),
    };
    ok(before) && ok(after)
}
