//! Pillar 2 — secrets / tokens (§5). Highest stakes: bias toward over-detection.
//!
//! Two layers: high-precision known-prefix / structural credentials that are
//! always redacted, and contextual entropy that fires only on the value of a
//! suspicious key. Private-key blocks span lines and are handled by the engine.

use std::sync::LazyLock;

use regex::Regex;

use super::ids;
use super::{Action, Candidate, Kind, PType};

/// Known-prefix / structurally-shaped credentials. All map to `<TOKEN_N>`.
struct Prefix {
    re: Regex,
    subtype: &'static str,
}

static PREFIX_TOKENS: LazyLock<Vec<Prefix>> = LazyLock::new(|| {
    let p = |pat: &str, subtype| Prefix {
        re: Regex::new(pat).unwrap(),
        subtype,
    };
    vec![
        p(
            r"\b(?:gh[pousr]_[A-Za-z0-9]{16,}|github_pat_[A-Za-z0-9_]{20,})\b",
            "github",
        ),
        p(r"\bsk-[A-Za-z0-9]{20,}\b", "openai"),
        p(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b", "aws"),
        p(r"\bAIza[A-Za-z0-9_\-]{35}\b", "google"),
        p(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b", "slack"),
        p(r"\b(?:sk|pk|rk)_live_[A-Za-z0-9]{16,}\b", "stripe"),
        p(r"\bglpat-[A-Za-z0-9_\-]{20,}\b", "gitlab"),
        p(r"\bnpm_[A-Za-z0-9]{36}\b", "npm"),
        p(
            r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b",
            "sendgrid",
        ),
    ]
});

/// JWT: three base64url segments. → `<JWT_N>`.
static JWT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b").unwrap()
});

/// `Authorization:` header value (opaque token after an optional scheme word).
static AUTH_HEADER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\bAuthorization\s*:\s*(?:Bearer\s+|Basic\s+|Token\s+)?([A-Za-z0-9._\-+/=]+)")
        .unwrap()
});

/// Credentials in a URL / connection string: redact only the password.
static URL_CREDENTIAL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"[a-zA-Z][a-zA-Z0-9+.\-]*://[^:/@\s'"]+:([^@/\s'"]+)@"#).unwrap()
});

/// A suspicious key whose value should be entropy-checked (contextual scan).
static KEYED_VALUE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)\b(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret|auth[a-z]*)\b\s*[=:]\s*["']?([^\s,;"']+)"#,
    )
    .unwrap()
});

const KEYED_MIN_LEN: usize = 8;
const KEYED_MIN_ENTROPY: f64 = 3.0;

pub fn detect(line: &str, out: &mut Vec<Candidate>) {
    for prefix in PREFIX_TOKENS.iter() {
        for m in prefix.re.find_iter(line) {
            out.push(Candidate {
                start: m.start(),
                end: m.end(),
                kind: Kind::Secret,
                subtype: Some(prefix.subtype),
                action: Action::Number {
                    ptype: PType::Token,
                    value: m.as_str().to_string(),
                },
                rank: 50,
            });
        }
    }

    for m in JWT.find_iter(line) {
        out.push(Candidate {
            start: m.start(),
            end: m.end(),
            kind: Kind::Secret,
            subtype: Some("jwt"),
            action: Action::Number {
                ptype: PType::Jwt,
                value: m.as_str().to_string(),
            },
            rank: 60,
        });
    }

    for caps in AUTH_HEADER.captures_iter(line) {
        let tok = caps.get(1).unwrap();
        out.push(Candidate {
            start: tok.start(),
            end: tok.end(),
            kind: Kind::Secret,
            subtype: Some("authorization"),
            action: Action::Number {
                ptype: PType::Token,
                value: tok.as_str().to_string(),
            },
            rank: 30,
        });
    }

    for caps in URL_CREDENTIAL.captures_iter(line) {
        let pass = caps.get(1).unwrap();
        out.push(Candidate {
            start: pass.start(),
            end: pass.end(),
            kind: Kind::Secret,
            subtype: Some("url_credential"),
            action: Action::Fixed("<PASSWORD>"),
            rank: 40,
        });
    }

    for caps in KEYED_VALUE.captures_iter(line) {
        let val = caps.get(1).unwrap();
        let text = val.as_str();
        // Preserve diagnostic IDs even under a suspicious key (§5).
        if ids::is_uuid(text) {
            continue;
        }
        if text.chars().count() < KEYED_MIN_LEN || shannon_entropy(text) < KEYED_MIN_ENTROPY {
            continue;
        }
        out.push(Candidate {
            start: val.start(),
            end: val.end(),
            kind: Kind::Secret,
            subtype: Some("keyed_entropy"),
            action: Action::Number {
                ptype: PType::Secret,
                value: text.to_string(),
            },
            rank: 20,
        });
    }
}

/// True if `line` begins (or continues) a PEM private-key block.
pub fn is_private_key_begin(line: &str) -> bool {
    line.contains("-----BEGIN") && line.contains("PRIVATE KEY-----")
}

/// True if `line` ends a PEM private-key block.
pub fn is_private_key_end(line: &str) -> bool {
    line.contains("-----END") && line.contains("PRIVATE KEY-----")
}

/// Shannon entropy in bits per character.
fn shannon_entropy(s: &str) -> f64 {
    let mut counts = [0u32; 256];
    let mut total = 0u32;
    for b in s.bytes() {
        counts[b as usize] += 1;
        total += 1;
    }
    if total == 0 {
        return 0.0;
    }
    let total = total as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / total;
            -p * p.log2()
        })
        .sum()
}
