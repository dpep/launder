//! Email, IP, hostname, and MAC detectors.
//!
//! Asymmetric bias: keep loopback + RFC1918 IPs and only the conservative
//! `*.local/*.internal/*.corp` hostnames by default — over-scrubbing destroys a
//! trace's usefulness.

use std::net::Ipv6Addr;
use std::sync::LazyLock;

use regex::Regex;

use super::{Action, Candidate, Label};

/// The local part may carry percent-escapes (`%6Aane`), and the `@` may be
/// URL-encoded (`%40`). Group 1 = local part, group 2 = domain.
static EMAIL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"((?:[A-Za-z0-9]|%[0-9A-Fa-f]{2})(?:[A-Za-z0-9._+\-]|%[0-9A-Fa-f]{2})*)(?:@|%40)([A-Za-z0-9.\-]+\.[A-Za-z]{2,})\b",
    )
    .unwrap()
});

static IPV4: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap());

/// IPv6 candidate shape only; [`ipv6_at`] decides. Loose on purpose: `::`
/// compression rules don't fit a regex, and `Ipv6Addr` parsing gets them right.
static IPV6: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:[0-9a-f]{0,4}:){2,7}(?:(?:[0-9]{1,3}\.){3}[0-9]{1,3}|[0-9a-f]{1,4})?")
        .unwrap()
});

static MAC: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b").unwrap());

/// A dotted name; [`is_internal`] decides whether it is an internal host.
static DOTTED_NAME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?(?:\.[a-z0-9\-]+)+").unwrap()
});

const INTERNAL_LABELS: &[&str] = &["local", "internal", "corp"];

/// Names that say "this was printed by a version banner", not an address.
const VERSION_WORDS: &[&str] = &["version", "ver"];

pub fn email(line: &str, out: &mut Vec<Candidate>) {
    for caps in EMAIL.captures_iter(line) {
        let m = caps.get(0).unwrap();
        let (local, domain) = (&caps[1], &caps[2]);
        // An scp-style remote (`git@host:org/repo`) names a host, not a person.
        if local == "git" && line[m.end()..].starts_with(':') {
            continue;
        }
        out.push(Candidate {
            start: m.start(),
            end: m.end(),
            subtype: None,
            action: Action::Number {
                label: Label::Email,
                // `%40` and `@` spellings share a placeholder.
                value: format!("{local}@{domain}").to_ascii_lowercase(),
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
        if (keep_private && is_private_v4(octets)) || is_version(line, m.start()) {
            continue;
        }
        out.push(ip_candidate(m.start(), m.end(), text));
    }
    for m in IPV6.find_iter(line) {
        let Some((end, addr)) = ipv6_at(line, m.start(), m.end()) else {
            continue;
        };
        if keep_private && is_private_v6(addr) {
            continue;
        }
        out.push(ip_candidate(m.start(), end, &line[m.start()..end]));
    }
}

pub fn mac(line: &str, out: &mut Vec<Candidate>) {
    for m in MAC.find_iter(line) {
        out.push(Candidate {
            start: m.start(),
            end: m.end(),
            subtype: None,
            action: Action::Number {
                label: Label::Mac,
                value: m.as_str().to_ascii_lowercase(),
            },
            rank: 0,
        });
    }
}

pub fn host(line: &str, extra: &[String], out: &mut Vec<Candidate>) {
    for m in DOTTED_NAME.find_iter(line) {
        // `.env.local` is a dotfile, not a host.
        if line[..m.start()].ends_with('.') || !is_internal(m.as_str()) {
            continue;
        }
        out.push(host_candidate(m.start(), m.end(), m.as_str(), "internal"));
    }
    // The machine's own hostname (from the watchlist), matched verbatim.
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
        subtype: None,
        action: Action::Number {
            label: Label::Ip,
            value: text.to_ascii_lowercase(),
        },
        rank: 0,
    }
}

fn host_candidate(start: usize, end: usize, text: &str, subtype: &'static str) -> Candidate {
    Candidate {
        start,
        end,
        subtype: Some(subtype),
        action: Action::Number {
            label: Label::Host,
            value: text.to_ascii_lowercase(),
        },
        rank: 0,
    }
}

/// An internal label ends the name (`db.internal`), or sits mid-name ahead of
/// a domain of two or more labels (`db.internal.acme.com`). A single label
/// after it is a file extension (`database.local.yml`).
fn is_internal(name: &str) -> bool {
    let labels: Vec<&str> = name.split('.').collect();
    let n = labels.len();
    labels[1..].iter().enumerate().any(|(i, l)| {
        let i = i + 1;
        INTERNAL_LABELS.iter().any(|w| l.eq_ignore_ascii_case(w))
            && (i == n - 1 || (i + 2 < n && labels[n - 1].bytes().all(|b| b.is_ascii_alphabetic())))
    })
}

/// A dotted quad that is a version: a product token (`Chrome/119.0.0.0`) or
/// after a version word (`version 1.2.3.4`, `Version: 1.2.3.4`).
fn is_version(line: &str, start: usize) -> bool {
    let before = &line[..start];
    if let Some(product) = before.strip_suffix('/') {
        return product.ends_with(|c: char| c.is_ascii_alphanumeric());
    }
    let word = before.trim_end_matches([' ', ':', '=']);
    if word.len() == before.len() {
        return false;
    }
    let word = word
        .rsplit(|c: char| !c.is_ascii_alphabetic())
        .next()
        .unwrap_or("");
    VERSION_WORDS.iter().any(|w| word.eq_ignore_ascii_case(w))
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

/// A real IPv6 address in `start..end`, returning the trimmed end. It must stand
/// alone (so `ActiveRecord::Base` and `Api::V1::Accounts` are not addresses),
/// have two or more hex groups (Ruby's `::Face` has one), and parse. A trailing
/// single `:` is punctuation: `2001:db8::1: refused`.
fn ipv6_at(line: &str, start: usize, mut end: usize) -> Option<(usize, Ipv6Addr)> {
    let b = line.as_bytes();
    let joins = |c: u8| c.is_ascii_alphanumeric() || c == b'_' || c == b':';
    if start > 0 && (joins(b[start - 1]) || b[start - 1] == b'.') {
        return None;
    }
    if end < b.len() && joins(b[end]) {
        return None;
    }
    if b[end - 1] == b':' && b[end - 2] != b':' {
        end -= 1;
    }
    let text = &line[start..end];
    if text.split(':').filter(|g| !g.is_empty()).count() < 2 {
        return None;
    }
    let addr: Ipv6Addr = text.parse().ok()?;
    (!addr.is_unspecified()).then_some((end, addr))
}

fn is_private_v6(a: Ipv6Addr) -> bool {
    let first = a.segments()[0];
    a.is_loopback()
        || first & 0xffc0 == 0xfe80 // link-local fe80::/10
        || first & 0xfe00 == 0xfc00 // unique-local fc00::/7
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
