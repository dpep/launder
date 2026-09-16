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
    /// Reject all-lowercase matches: kebab-case names share the shape.
    needs_upper: bool,
}

static PREFIX_TOKENS: LazyLock<Vec<Prefix>> = LazyLock::new(|| {
    let p = |pat: &str, subtype| Prefix {
        re: Regex::new(pat).unwrap(),
        subtype,
        needs_upper: false,
    };
    vec![
        p(
            r"\b(?:gh[pousr]_[A-Za-z0-9]{16,}|github_pat_[A-Za-z0-9_]{20,})\b",
            "github",
        ),
        // OpenAI and Anthropic: `sk-…`, `sk-proj-…`, `sk-ant-api03-…`. The body
        // carries `-` and `_`, and may end in one, so there is no trailing `\b`.
        Prefix {
            needs_upper: true,
            ..p(r"\bsk-[A-Za-z0-9_\-]{20,}", "openai")
        },
        p(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b", "aws"),
        p(r"\bAIza[A-Za-z0-9_\-]{35}\b", "google"),
        p(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b", "slack"),
        p(r"\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b", "stripe"),
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

/// Credentials in a URL / connection string: redact only the password. The
/// user may be empty, as in `redis://:pass@host`.
static URL_CREDENTIAL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"[a-zA-Z][a-zA-Z0-9+.\-]*://[^:/@\s'"]*:([^@/\s'"]+)@"#).unwrap()
});

/// A suspicious key whose value should be entropy-checked (contextual scan).
/// The key may carry a prefix (`access_token`, `refreshToken`, `SECRET_KEY_BASE`)
/// and a closing quote (`"password"=>`, `"api_key":`), escaped or not
/// (`\"token\":`). A quoted key may be followed by a comma, as in a Rails SQL
/// bind `["token", "…"]`. Bare `key` is not a credential word: `sort_key`,
/// `cache_key` are not secrets, and `auth` is spelled out so `author` is not.
static KEYED_VALUE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)\b([a-z0-9_\-]*(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|master[_-]?key|secret[_-]?key[_-]?base|auth(?:orization|[_-]?key|[_-]?code)?))\b(?:\\*["']\s*,|\\*["']?\s*(?:=>|[=:]))\s*\\*["']?([^\s,;"']+)"#,
    )
    .unwrap()
});

/// Every `KEYED_VALUE` key contains one of these. The leading class in that
/// pattern defeats the regex crate's literal prefilter, so check these first.
/// A regex, not an ASCII scan, so case folding matches `KEYED_VALUE` exactly.
static KEYED_HINT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)pass|pwd|secret|token|key|auth").unwrap());

/// `Cookie:` / `Set-Cookie:` header; its `name=value` pairs are split below.
static COOKIE_HEADER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b(?:set-)?cookie\s*:(.*)").unwrap());

static COOKIE_PAIR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"([^=;\s]+)=([^;\s]+)").unwrap());

/// `Set-Cookie` attributes, which carry no secret.
const COOKIE_ATTRIBUTES: [&str; 5] = ["path", "domain", "expires", "max-age", "samesite"];

const KEYED_MIN_LEN: usize = 8;
const KEYED_MIN_ENTROPY: f64 = 3.0;

/// Cookie values are opaque session material, so there is no entropy gate —
/// only the length floor, which keeps preferences like `locale=en` readable.
fn cookies(line: &str, out: &mut Vec<Candidate>) {
    for caps in COOKIE_HEADER.captures_iter(line) {
        let header = caps.get(1).unwrap();
        for pair in COOKIE_PAIR.captures_iter(header.as_str()) {
            let (name, val) = (&pair[1], pair.get(2).unwrap());
            if val.len() < KEYED_MIN_LEN
                || is_redaction_marker(val.as_str())
                || COOKIE_ATTRIBUTES
                    .iter()
                    .any(|a| name.eq_ignore_ascii_case(a))
            {
                continue;
            }
            let start = header.start() + val.start();
            out.push(Candidate {
                start,
                end: start + val.len(),
                kind: Kind::Secret,
                subtype: Some("cookie"),
                action: Action::Number {
                    ptype: PType::Token,
                    value: val.as_str().to_string(),
                },
                rank: 30,
            });
        }
    }
}

pub fn detect(line: &str, out: &mut Vec<Candidate>) {
    cookies(line, out);
    for prefix in PREFIX_TOKENS.iter() {
        for m in prefix.re.find_iter(line) {
            if prefix.needs_upper && !m.as_str().bytes().any(|b| b.is_ascii_uppercase()) {
                continue;
            }
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

    if !KEYED_HINT.is_match(line) {
        return;
    }
    for caps in KEYED_VALUE.captures_iter(line) {
        let (key, val) = (&caps[1], caps.get(2).unwrap());
        // A trailing `\` escapes the closing quote, as in `\"api_key\":\"…\"`.
        let text = trim_unbalanced_closers(val.as_str().trim_end_matches('\\'));
        // Preserve diagnostic IDs even under a suspicious key (§5).
        if ids::is_uuid(text) || is_redaction_marker(text) || is_shell_cwd(key, text) {
            continue;
        }
        if text.chars().count() < KEYED_MIN_LEN || shannon_entropy(text) < KEYED_MIN_ENTROPY {
            continue;
        }
        out.push(Candidate {
            start: val.start(),
            end: val.start() + text.len(),
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

/// Drop closing brackets that end the value but opened outside it, as in
/// `(--token=abc)`. A bracket inside the value stays, so no tail can leak.
fn trim_unbalanced_closers(mut s: &str) -> &str {
    while let Some(close) = s.chars().last() {
        let open = match close {
            ')' => '(',
            ']' => '[',
            '}' => '{',
            _ => break,
        };
        if s.matches(close).count() <= s.matches(open).count() {
            break;
        }
        s = &s[..s.len() - 1];
    }
    s
}

/// The shell's `PWD=/…` / `OLDPWD=~/…`: a working directory, left for the path
/// rules. ODBC's `Pwd=` is a password and rarely starts with a path.
fn is_shell_cwd(key: &str, value: &str) -> bool {
    ["pwd", "oldpwd"]
        .iter()
        .any(|k| key.eq_ignore_ascii_case(k))
        && (value.starts_with('/') || value.starts_with('~'))
}

/// A value already redacted upstream: Rails' `[FILTERED]`, launder's `<SECRET_1>`.
fn is_redaction_marker(s: &str) -> bool {
    let inner = s
        .strip_prefix('[')
        .and_then(|r| r.strip_suffix(']'))
        .or_else(|| s.strip_prefix('<').and_then(|r| r.strip_suffix('>')));
    inner.is_some_and(|i| {
        !i.is_empty()
            && i.bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
    })
}

/// One rule for every armored private-key spelling — RSA, EC, DSA, OPENSSH,
/// PKCS#8's bare `PRIVATE KEY`, `ENCRYPTED PRIVATE KEY`, and OpenPGP's
/// `PGP PRIVATE KEY BLOCK` (the trailing " BLOCK" is why a literal
/// `"PRIVATE KEY-----"` suffix match used to miss it) — instead of one literal
/// per key type. A substring check also keeps `CERTIFICATE` and `PUBLIC KEY`
/// armor (including `PGP PUBLIC KEY BLOCK`) out, since those aren't secrets.
fn label_is_private_key(label: &str) -> bool {
    label.contains("PRIVATE KEY")
}

/// Find the next `-----BEGIN`/`-----END` armor tag at or after `from`: its
/// label text and the byte position just past the tag's closing dashes.
fn find_tag<'a>(line: &'a str, tag: &str, from: usize) -> Option<(usize, &'a str, usize)> {
    let tag_start = from + line[from..].find(tag)?;
    let label_start = tag_start + tag.len();
    let label_end = label_start + line[label_start..].find("-----")?;
    Some((tag_start, &line[label_start..label_end], label_end + 5))
}

/// A PEM private key that starts on `line`: the byte span to redact, and
/// whether the block continues onto the following lines.
///
/// A key inlined in a string (`"-----BEGIN …-----\nMIIE…"`) ends at its END
/// marker, or at the closing quote when truncated; everything around it is
/// still scanned. `"-----BEGIN …-----\n" \` carries no key material after the
/// escape, so it is a multi-line block like a bare header.
pub fn private_key(line: &str) -> Option<(usize, usize, bool)> {
    let (start, label, header_end) = find_tag(line, "-----BEGIN", 0)?;
    if !label_is_private_key(label) {
        return None;
    }
    let rest = &line[header_end..];
    if let Some((_, end_label, end_at)) = find_tag(rest, "-----END", 0)
        && label_is_private_key(end_label)
    {
        return Some((start, header_end + end_at, false));
    }
    let body = rest.trim_start_matches(['\\', 'r', 'n']);
    let escaped = rest.starts_with('\\') && body.len() < rest.len();
    if !escaped || !body.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '+' || c == '/') {
        return Some((start, line.len(), true));
    }
    let end = rest.find(['"', '\'']).map_or(line.len(), |q| {
        header_end + rest[..q].trim_end_matches('\\').len()
    });
    Some((start, end, false))
}

/// If `line` closes an open PEM private-key block, the text following the
/// closing tag (e.g. a trailing literal `\n` that belongs to the next
/// logical line).
pub fn private_key_end(line: &str) -> Option<&str> {
    let (_, label, end) = find_tag(line, "-----END", 0)?;
    label_is_private_key(label).then(|| &line[end..])
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
