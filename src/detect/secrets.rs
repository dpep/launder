//! Secrets / tokens. Highest stakes: bias toward over-detection.
//!
//! Two layers: high-precision known-prefix / structural credentials that are
//! always redacted, and a contextual check that fires only on the value of a
//! suspicious key. Private-key blocks span lines and are handled by the engine.

use std::cmp::Reverse;
use std::sync::LazyLock;

use regex::Regex;

use super::{Action, Candidate, Label};

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
        p(r"\bhf_[A-Za-z0-9]{30,}\b", "huggingface"),
        // A macaroon whose base64 always opens with `AgE`.
        p(r"\bpypi-AgE[A-Za-z0-9_\-]{50,}", "pypi"),
        p(r"\bdo[opr]_v1_[a-f0-9]{64}\b", "digitalocean"),
        p(r"\bshp(?:at|ss|ca|pa)_[a-fA-F0-9]{32}\b", "shopify"),
        p(r"\bkey-[0-9a-z]{32}\b", "mailgun"),
        p(r"\bSK[0-9a-f]{32}\b", "twilio"),
    ]
});

/// Webhook URLs whose path is the credential: everything after the fixed
/// prefix (group 1), IDs included.
static WEBHOOKS: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| {
    vec![
        (
            Regex::new(r"\bhooks\.slack\.com/(?:services|workflows|triggers)/([A-Za-z0-9_/\-]+)")
                .unwrap(),
            "slack_webhook",
        ),
        (
            Regex::new(r"\bdiscord(?:app)?\.com/api/webhooks/([0-9]+/[A-Za-z0-9_\-]+)").unwrap(),
            "discord_webhook",
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
/// user may be empty, as in `redis://:pass@host`. The password runs to the
/// last `@` of the authority, so an unencoded `@` in it can't leak its tail.
static URL_CREDENTIAL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"[a-zA-Z][a-zA-Z0-9+.\-]*://([^:/@\s'"]*):([^/?#\s'"]+)@"#).unwrap()
});

/// Login names that name a role, not a person: kept, since they identify no one.
const ROLE_USERS: [&str; 11] = [
    "postgres",
    "root",
    "admin",
    "user",
    "guest",
    "anonymous",
    "default",
    "token",
    "oauth2",
    "x-access-token",
    "x-oauth-basic",
];

/// A credential's login as an identity → `<USER_N>`. Short names share the
/// bare-username floor: too generic (`sa`, `app`, `git`) to identify anyone.
fn login(
    line: &str,
    (start, end): (usize, usize),
    subtype: &'static str,
    out: &mut Vec<Candidate>,
) {
    let name = &line[start..end];
    if name.len() < 4 || ROLE_USERS.iter().any(|r| name.eq_ignore_ascii_case(r)) {
        return;
    }
    out.push(Candidate {
        start,
        end,
        subtype: Some(subtype),
        action: Action::BareUser {
            user: name.to_string(),
        },
        rank: 0,
    });
}

/// A password in a credential's userinfo → `<PASSWORD_N>`.
fn userinfo_password(
    line: &str,
    (start, end): (usize, usize),
    subtype: &'static str,
    out: &mut Vec<Candidate>,
) {
    out.push(Candidate {
        start,
        end,
        subtype: Some(subtype),
        action: Action::Number {
            label: Label::Password,
            value: line[start..end].to_string(),
        },
        rank: 40,
    });
}

/// The scheme of a percent-encoded URL (`https%3A%2F%2F`), as in a
/// `redirect=` parameter. [`encoded_url_credential`] reads the authority.
static ENCODED_URL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b[a-z][a-z0-9+.\-]*%3a%2f%2f").unwrap());

/// Credentials in a percent-encoded URL, by the same rule as a plain one:
/// the authority ends at an encoded `/`, `?` or `#`, the password runs to its
/// last `%40`, and the user ends at the first `%3A`.
fn encoded_url_credential(line: &str, at: usize, out: &mut Vec<Candidate>) {
    let rest = &line[at..];
    let lower = rest.to_ascii_lowercase();
    let run = rest
        .find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '&' | '/' | '?' | '#'))
        .unwrap_or(rest.len());
    let authority = ["%2f", "%3f", "%23"]
        .iter()
        .filter_map(|t| lower[..run].find(t))
        .min()
        .unwrap_or(run);
    let Some(userinfo) = lower[..authority].rfind("%40") else {
        return;
    };
    let Some(colon) = lower[..userinfo].find("%3a") else {
        return;
    };
    if colon + 3 < userinfo {
        login(line, (at, at + colon), "url_credential", out);
        userinfo_password(line, (at + colon + 3, at + userinfo), "url_credential", out);
    }
}

/// `curl -u user:pass` / `--user user:pass`. Only after `curl`: elsewhere
/// `-u 1000:1000` is a uid:gid.
static CURL_USER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"\bcurl\b.*?\s(?:-u|--user)(?:\s+|=)['"]?([^\s:'"]+):([^\s'"]+)"#).unwrap()
});

/// A `.netrc` entry, and its `login` / `password` tokens.
static NETRC_LINE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*(?:machine\s+\S+|default)\s").unwrap());
static NETRC_TOKEN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(login|password)\s+(\S+)").unwrap());

/// The words that make a key a credential key. Bare `key` is not one:
/// `sort_key`, `cache_key` are not secrets, and `auth` is spelled out so
/// `author` is not.
const CREDENTIAL_WORDS: &str = r"password|passwd|passphrase|pass|pwd|secret|token|credentials?|signature|sig|session(?:[_-]?id)?|(?:api|access|account|private|master|encryption|signing)[_-]?key|secret[_-]?key[_-]?base|auth(?:orization|[_-]?key|[_-]?code)?";

/// A long CLI flag naming a credential, then its value after a space:
/// `--password X`, `--db-pass X`, `--api-key X`.
static CLI_FLAG: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:^|\s)(--(?:[a-z0-9]+-)*)(password|passwd|passphrase|pass|token|secret|api-?key)\s+")
        .unwrap()
});

/// `<password>…</password>`; the closing tag is checked to match.
static XML_ELEMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r"(?i)<(([a-z0-9_\-]*)({CREDENTIAL_WORDS}))>([^<]*)</([^>\s]*)>"
    ))
    .unwrap()
});

/// A suspicious key whose value should be checked (contextual scan).
/// The key may carry a prefix (`access_token`, `refreshToken`, `SECRET_KEY_BASE`)
/// and a closing quote (`"password"=>`, `"api_key":`), escaped or not
/// (`\"token\":`). A quoted key may be followed by a comma, as in a Rails SQL
/// bind `["token", "…"]`. The match ends where the value begins;
/// [`value_span`] reads the value.
static KEYED_VALUE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r#"(?i)\b(([a-z0-9_\-]*)({CREDENTIAL_WORDS}))\b(?:\\*["']\s*,|\\*["']?\s*(?:=>|[=:]|%3[ad]))\s*"#
    ))
    .unwrap()
});

/// Every `KEYED_VALUE` key contains one of these. The leading class in that
/// pattern defeats the regex crate's literal prefilter, so check these first.
/// A regex, not an ASCII scan, so case folding matches `KEYED_VALUE` exactly.
static KEYED_HINT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)pass|pwd|secret|token|cred|sig|session|key|auth").unwrap());

/// `Cookie:` / `Set-Cookie:` header, or the same as a quoted key
/// (`"cookie":"…"`); its `name=value` pairs are split below.
static COOKIE_HEADER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"(?i)\b(?:set-)?cookie\\*["']?\s*:\s*"#).unwrap());

static COOKIE_PAIR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"([^=;\s]+)=([^;\s]+)").unwrap());

/// `Set-Cookie` attributes, which carry no secret.
const COOKIE_ATTRIBUTES: [&str; 5] = ["path", "domain", "expires", "max-age", "samesite"];

const KEYED_MIN_LEN: usize = 8;

/// A value that reads as a name rather than a credential: words joined in one
/// case (`my_secret_name`, `deploy_token_v2`, `GITHUB_TOKEN`, `REDACTED`),
/// letter-only camel humps (`TokenProvider`), a date or duration, or a path
/// or reference (`/run/secrets/db`, `$VAR`, `{{tmpl}}`). A word after the
/// first may end in a short number; a longer digit run (`sess_5f4e3d…`), an
/// all-digit PIN, or a URL (which can carry a session) is not a name.
static IDENTIFIER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"^(?:[a-z]+(?:[_.\-](?:[a-z]+[0-9]{0,3}|[0-9]{1,3}))*",
        r"|[A-Z]+(?:_(?:[A-Z]+[0-9]{0,3}|[0-9]{1,3}))*",
        r"|[a-z]*(?:[A-Z][a-z]{2,})+",
        r"|[0-9\-:TZ.]*[\-:TZ.][0-9\-:TZ.]*",
        r"|[a-z0-9]+(?:/[a-z0-9_.\-]+)+",
        r"|[/.$%{].*)$",
    ))
    .unwrap()
});

fn is_identifier_shaped(s: &str) -> bool {
    IDENTIFIER.is_match(s)
}

/// Cookie values are opaque session material, so there is no shape gate —
/// only the length floor, which keeps preferences like `locale=en` readable.
fn cookies(line: &str, out: &mut Vec<Candidate>) {
    for m in COOKIE_HEADER.find_iter(line) {
        // A quoted value ends at its quote; a header runs to the end of the line.
        let quoted = line[m.end()..]
            .trim_start_matches('\\')
            .starts_with(['"', '\'']);
        let (start, end) = if quoted {
            value_span(line, m.end())
        } else {
            (m.end(), line.len())
        };
        let header = &line[start..end];
        for pair in COOKIE_PAIR.captures_iter(header) {
            let (name, val) = (&pair[1], pair.get(2).unwrap());
            if val.len() < KEYED_MIN_LEN
                || is_redaction_marker(val.as_str())
                || COOKIE_ATTRIBUTES
                    .iter()
                    .any(|a| name.eq_ignore_ascii_case(a))
            {
                continue;
            }
            let start = start + val.start();
            out.push(Candidate {
                start,
                end: start + val.len(),
                subtype: Some("cookie"),
                action: Action::Number {
                    label: Label::Token,
                    value: val.as_str().to_string(),
                },
                rank: 30,
            });
        }
    }
}

pub fn detect(line: &str, out: &mut Vec<Candidate>) {
    let from = out.len();
    scan(line, out);
    merge_overlaps(line, out, from);
}

/// Merge overlapping secrets in `out[from..]` into one span, labeled by its
/// highest-rank member, so a narrow match inside a wider one can't leave the
/// wider one's tail raw. Logins (`BareUser`) are left alone.
fn merge_overlaps(line: &str, out: &mut Vec<Candidate>, from: usize) {
    let (mut secrets, logins): (Vec<_>, Vec<_>) = out
        .drain(from..)
        .partition(|c| matches!(c.action, Action::Number { .. }));
    secrets.sort_by_key(|c| (c.start, Reverse(c.end)));
    for c in secrets {
        match out[from..].last_mut() {
            Some(last) if c.start < last.end => {
                let (start, end) = (last.start, last.end.max(c.end));
                if (c.rank, c.width()) > (last.rank, last.width()) {
                    *last = c;
                }
                last.start = start;
                last.end = end;
                if let Action::Number { value, .. } = &mut last.action {
                    *value = line[start..end].to_string();
                }
            }
            _ => out.push(c),
        }
    }
    out.extend(logins);
}

fn scan(line: &str, out: &mut Vec<Candidate>) {
    cookies(line, out);
    for prefix in PREFIX_TOKENS.iter() {
        for m in prefix.re.find_iter(line) {
            if prefix.needs_upper && !m.as_str().bytes().any(|b| b.is_ascii_uppercase()) {
                continue;
            }
            out.push(Candidate {
                start: m.start(),
                end: m.end(),
                subtype: Some(prefix.subtype),
                action: Action::Number {
                    label: Label::Token,
                    value: m.as_str().to_string(),
                },
                rank: 50,
            });
        }
    }
    if out.iter().any(|c| c.subtype == Some("aws")) {
        aws_secret_keys(line, out);
    }
    for (re, subtype) in WEBHOOKS.iter() {
        for caps in re.captures_iter(line) {
            let path = caps.get(1).unwrap();
            out.push(Candidate {
                start: path.start(),
                end: path.end(),
                subtype: Some(subtype),
                action: Action::Number {
                    label: Label::Token,
                    value: path.as_str().to_string(),
                },
                rank: 50,
            });
        }
    }

    for m in JWT.find_iter(line) {
        out.push(Candidate {
            start: m.start(),
            end: m.end(),
            subtype: Some("jwt"),
            action: Action::Number {
                label: Label::Jwt,
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
            subtype: Some("authorization"),
            action: Action::Number {
                label: Label::Token,
                value: tok.as_str().to_string(),
            },
            rank: 30,
        });
    }

    for (re, subtype) in [
        (&*URL_CREDENTIAL, "url_credential"),
        (&*CURL_USER, "curl_user"),
    ] {
        for caps in re.captures_iter(line) {
            let span = |i| {
                caps.get(i)
                    .map(|m: regex::Match| (m.start(), m.end()))
                    .unwrap()
            };
            login(line, span(1), subtype, out);
            userinfo_password(line, span(2), subtype, out);
        }
    }
    for m in ENCODED_URL.find_iter(line) {
        encoded_url_credential(line, m.end(), out);
    }

    if !KEYED_HINT.is_match(line) {
        return;
    }
    for caps in KEYED_VALUE.captures_iter(line) {
        let span = value_span(line, caps.get(0).unwrap().end());
        keyed(line, &caps[1], &caps[2], &caps[3], span, out);
    }
    for caps in CLI_FLAG.captures_iter(line) {
        let at = caps.get(0).unwrap().end();
        if !line[at..].starts_with('-') {
            let span = value_span(line, at);
            keyed(line, &caps[2], &caps[1], &caps[2], span, out);
        }
    }
    for caps in XML_ELEMENT.captures_iter(line) {
        let val = caps.get(4).unwrap();
        if caps[1] == caps[5] {
            keyed(
                line,
                &caps[1],
                &caps[2],
                &caps[3],
                (val.start(), val.end()),
                out,
            );
        }
    }
    if NETRC_LINE.is_match(line) {
        for caps in NETRC_TOKEN.captures_iter(line) {
            let val = caps.get(2).unwrap();
            if &caps[1] == "login" {
                login(line, (val.start(), val.end()), "netrc_login", out);
            } else {
                let span = value_span(line, val.start());
                keyed(line, "password", "", "password", span, out);
            }
        }
    }
}

static BASE64_RUN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[A-Za-z0-9/+]+").unwrap());

/// An AWS secret access key needs no key name when its access key ID shares
/// the line (CSV exports, pasted pairs): any standalone 40-char base64 run.
/// All-hex runs are git SHAs.
fn aws_secret_keys(line: &str, out: &mut Vec<Candidate>) {
    for m in BASE64_RUN.find_iter(line) {
        let s = m.as_str();
        if s.len() != 40 || s.bytes().all(|b| b.is_ascii_hexdigit()) {
            continue;
        }
        out.push(Candidate {
            start: m.start(),
            end: m.end(),
            subtype: Some("aws_secret"),
            action: Action::Number {
                label: Label::Secret,
                value: s.to_string(),
            },
            rank: 20,
        });
    }
}

/// Judge the value of a credential key at `start..end` and push it if it is
/// one. `prefix` and `word` split the key (`DB_` + `PASSWORD`).
fn keyed(
    line: &str,
    key: &str,
    prefix: &str,
    word: &str,
    (start, end): (usize, usize),
    out: &mut Vec<Candidate>,
) {
    let Some(gated) = shape_gated(prefix, word) else {
        return;
    };
    let text = &line[start..end];
    // A UUID or SHA here is a credential: many services issue them as tokens.
    if is_placeholder_value(text) || is_shell_cwd(key, text) {
        return;
    }
    if gated && (text.chars().count() < KEYED_MIN_LEN || is_identifier_shaped(text)) {
        return;
    }
    out.push(Candidate {
        start,
        end,
        subtype: Some("keyed_entropy"),
        action: Action::Number {
            label: Label::Secret,
            value: text.to_string(),
        },
        rank: 20,
    });
}

/// Whether a keyed value needs the shape gate, by the key's credential
/// word: a password is redacted whatever it looks like, but `token`, `secret`
/// and `key` also name non-secrets (`token_type=bearer`). `None`: not a key.
fn shape_gated(prefix: &str, word: &str) -> Option<bool> {
    let separated = prefix.is_empty()
        || prefix.ends_with(['_', '-'])
        || (prefix.ends_with(|c: char| c.is_ascii_lowercase())
            && word.starts_with(|c: char| c.is_ascii_uppercase()));
    match word.to_ascii_lowercase().as_str() {
        "password" | "passwd" | "passphrase" => Some(false),
        // A bare `pass` is as often a test tally (`pass: 12`); `bypass` is no key.
        "pass" if prefix.is_empty() => Some(true),
        "pass" => separated.then_some(false),
        // `OLDPWD` is the shell's, not a password.
        "pwd" => Some(!separated),
        _ => Some(true),
    }
}

/// A value that stands in for a secret rather than being one: empty, a
/// boolean or null, a mask of `*`, or a redaction marker.
fn is_placeholder_value(s: &str) -> bool {
    s.is_empty()
        || ["true", "false", "null", "nil", "none"]
            .iter()
            .any(|w| s.eq_ignore_ascii_case(w))
        || s.bytes().all(|b| b == b'*')
        || is_redaction_marker(s)
}

/// The value that starts at `at`. A quoted value runs to the closing quote at
/// the same escape depth (`"…"`, `\"…\"`), spaces and commas included; an
/// unclosed one is read as unquoted.
fn value_span(line: &str, at: usize) -> (usize, usize) {
    let rest = &line[at..];
    let escapes = rest.bytes().take_while(|&b| b == b'\\').count();
    if let Some(q @ (b'"' | b'\'')) = rest.as_bytes().get(escapes).copied() {
        let body = at + escapes + 1;
        if let Some(len) = closing_quote(&line[body..], &rest[..=escapes], q) {
            return (body + scheme_len(&line[body..body + len]), body + len);
        }
        return unquoted_span(line, body);
    }
    unquoted_span(line, at + scheme_len(rest))
}

/// An auth scheme before the credential (`Bearer …`), which stays readable.
static AUTH_SCHEME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^(?:bearer|basic|token)\s+").unwrap());

fn scheme_len(value: &str) -> usize {
    AUTH_SCHEME.find(value).map_or(0, |m| m.end())
}

/// Offset of `close` (the opening quote with its escapes) in `body`. A bare
/// quote must not itself be escaped.
fn closing_quote(body: &str, close: &str, q: u8) -> Option<usize> {
    if close.len() > 1 {
        return body.find(close);
    }
    let bytes = body.as_bytes();
    (0..bytes.len()).find(|&i| bytes[i] == q && (i == 0 || bytes[i - 1] != b'\\'))
}

/// An unquoted value: up to whitespace, `,`, `;` or a quote, and before the
/// next query parameter (`&name=`).
fn unquoted_span(line: &str, at: usize) -> (usize, usize) {
    let rest = &line[at..];
    let len = rest
        .find(|c: char| c.is_whitespace() || matches!(c, ',' | ';' | '"' | '\''))
        .unwrap_or(rest.len());
    let text = &rest[..query_param_end(&rest[..len])];
    // A trailing `\` escapes the closing quote, as in `\"api_key\":\"…\"`.
    let text = trim_unbalanced_closers(text.trim_end_matches('\\'));
    (at, at + text.len())
}

/// Where a value ends at a following query parameter, `&name=`. A bare `&` is
/// part of the value.
fn query_param_end(s: &str) -> usize {
    QUERY_PARAM.find(s).map_or(s.len(), |m| m.start())
}

/// `&name=`, or URL-encoded as `%26name%3D`.
static QUERY_PARAM: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)(?:&|%26)[a-z0-9_.\-]+(?:=|%3d)").unwrap());

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
