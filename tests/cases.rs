//! Gold acceptance cases. Each asserts the exact laundered output (and, where
//! it matters, the findings) for an `(input, flags)` pair. Determinism is part
//! of the contract: the same input always produces the same output.
//!
//! Tests drive the library directly (one `Engine` per run) rather than shelling
//! out — faster, deterministic, no permission prompts.

use launder::config::Config;
use launder::detect::Kind;
use launder::engine::{Engine, Finding};
use launder::watchlist::Watchlist;

/// Launder a whole multi-line input with the given config; return the joined
/// laundered text (suppressed lines dropped) and all findings.
fn launder(cfg: Config, input: &str) -> (String, Vec<Finding>) {
    let mut engine = Engine::new(cfg);
    let mut out = Vec::new();
    let mut findings = Vec::new();
    for line in input.lines() {
        let r = engine.process_line(line);
        if let Some(text) = r.output {
            out.push(text);
        }
        findings.extend(r.findings);
    }
    (out.join("\n"), findings)
}

/// Convenience: default config, single laundered string.
fn clean(input: &str) -> String {
    launder(Config::default(), input).0
}

/// Table-driven: every `(input, expected)` row gets a fresh engine; all
/// mismatches are reported together.
fn check(rows: &[(&str, &str)]) {
    let failures: Vec<String> = rows
        .iter()
        .filter_map(|&(input, expected)| {
            let got = clean(input);
            (got != expected).then(|| {
                format!("  input:    {input:?}\n  expected: {expected:?}\n  got:      {got:?}")
            })
        })
        .collect();
    assert!(
        failures.is_empty(),
        "{} row(s) failed:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

// Credential-shaped inputs are split with `concat!` so no literal token sits in
// the source for secret scanners and push protection to flag.

#[test]
fn token_after_ansi_escape_is_redacted() {
    check(&[
        (
            "\x1b[31mghp_Q7m2Xk9Lp4Rz8Wv1Tn\x1b[0m",
            "\x1b[31m<TOKEN_1>\x1b[0m",
        ),
        (
            "\x1b[1m\x1b[36mAuthorization: Bearer Zq8vN2kLp4RxQm7Tz9Lw\x1b[0m",
            "\x1b[1m\x1b[36mAuthorization: Bearer <TOKEN_1>\x1b[0m",
        ),
    ]);
}

#[test]
fn quoted_keys_are_redacted() {
    check(&[
        (
            concat!(r#"  Parameters: {"password"=>"Zq8vN2"#, r#"kLp4Rx"}"#),
            r#"  Parameters: {"password"=>"<SECRET_1>"}"#,
        ),
        (
            concat!(r#"{"api_key": "Qm7Tz9Lw"#, r#"2Xc4Vb6N"}"#),
            r#"{"api_key": "<SECRET_1>"}"#,
        ),
        // Already-redacted markers are not secrets.
        (
            r#"  Parameters: {"password"=>"[FILTERED]"}"#,
            r#"  Parameters: {"password"=>"[FILTERED]"}"#,
        ),
        ("password=<SECRET_1>", "password=<SECRET_1>"),
    ]);
}

#[test]
fn suffixed_and_env_key_names_are_redacted() {
    check(&[
        (
            concat!("access_token=Hk3Jd8Ws", "1Qz5Pm7R"),
            "access_token=<SECRET_1>",
        ),
        (
            concat!("auth_token: Hk3Jd8Ws", "1Qz5Pm7R"),
            "auth_token: <SECRET_1>",
        ),
        (
            concat!(r#"{"refreshToken":"Hk3Jd8Ws"#, r#"1Qz5Pm7R"}"#),
            r#"{"refreshToken":"<SECRET_1>"}"#,
        ),
        (
            concat!("SECRET_KEY_BASE=Hk3Jd8Ws", "1Qz5Pm7RaB9"),
            "SECRET_KEY_BASE=<SECRET_1>",
        ),
        (
            concat!("RAILS_MASTER_KEY=Hk3Jd8Ws", "1Qz5Pm7RaB9"),
            "RAILS_MASTER_KEY=<SECRET_1>",
        ),
        // `key` alone is not a credential word.
        ("sort_key=created_at_desc_Z9", "sort_key=created_at_desc_Z9"),
        (
            "cache_key=views/users/1-20260915",
            "cache_key=views/users/1-20260915",
        ),
    ]);
}

#[test]
fn keyed_value_keeps_trailing_close_paren() {
    check(&[
        (
            "CMD (backup.sh --token=Hk3Jd8Ws1Qz5Pm7R)",
            "CMD (backup.sh --token=<SECRET_1>)",
        ),
        // A paren inside the value must not split it and leak the tail.
        ("password=Zq8)vN2kLp4Rx", "password=<SECRET_1>"),
    ]);
}

#[test]
fn ruby_constants_are_not_ipv6() {
    check(&[
        (
            "Processing by Api::V1::AccountsController#show as HTML",
            "Processing by Api::V1::AccountsController#show as HTML",
        ),
        (
            "class User < ActiveRecord::Base",
            "class User < ActiveRecord::Base",
        ),
        (
            "in 'RSpec::Core::Configuration#load_spec_files'",
            "in 'RSpec::Core::Configuration#load_spec_files'",
        ),
        (
            "peer 2001:db8:85a3::8a2e:370:7334 connected",
            "peer <IP_1> connected",
        ),
        (
            "connect to 2001:db8::1: refused",
            "connect to <IP_1>: refused",
        ),
        (
            "listening on [::1]:3000 and fe80::1%en0",
            "listening on [::1]:3000 and fe80::1%en0",
        ),
        ("mac aa:bb:cc:dd:ee:ff", "mac <MAC_1>"),
    ]);
}

#[test]
fn url_credential_with_empty_user_redacts_password_only() {
    check(&[(
        "redis://:Zq8vN2kLp4Rx@cache.example.com:6379/0",
        "redis://:<PASSWORD_1>@cache.example.com:6379/0",
    )]);
}

#[test]
fn cookie_header_values_are_redacted() {
    check(&[
        (
            "Cookie: _app_session=Qm7Tz9Lw2Xc4Vb6NHk3Jd8Ws1Qz5Pm7R",
            "Cookie: _app_session=<TOKEN_1>",
        ),
        (
            "Set-Cookie: _app_session=Qm7Tz9Lw2Xc4Vb6NHk3Jd8Ws1Qz5Pm7R; path=/; HttpOnly",
            "Set-Cookie: _app_session=<TOKEN_1>; path=/; HttpOnly",
        ),
        (
            "Cookie: locale=en; _app_session=Qm7Tz9Lw2Xc4Vb6NHk3Jd8Ws1Qz5Pm7R",
            "Cookie: locale=en; _app_session=<TOKEN_1>",
        ),
        (
            "Set-Cookie: sid=Qm7Tz9Lw2Xc4Vb6N; Domain=app.example.com; Expires=Wed, 21 Oct 2026 07:28:00 GMT",
            "Set-Cookie: sid=<TOKEN_1>; Domain=app.example.com; Expires=Wed, 21 Oct 2026 07:28:00 GMT",
        ),
    ]);
}

#[test]
fn dashed_sk_prefix_keys_are_redacted() {
    check(&[
        (
            concat!(
                "key ",
                "sk-",
                "proj-",
                "Hk3Jd8Ws1Qz5Pm7R-aB9xLq2Vt6Nc_4Ym8Tz9Lw2Xc done"
            ),
            "key <TOKEN_1> done",
        ),
        (
            concat!(
                "key ",
                "sk-",
                "ant-",
                "api03-Hk3Jd8Ws1Qz5Pm7R-aB9xLq2Vt6Nc_4Ym8TzAA"
            ),
            "key <TOKEN_1>",
        ),
        (
            concat!("key ", "sk-", "svcacct-", "Hk3Jd8Ws1Qz5Pm7RaB9xLq2Vt6Nc"),
            "key <TOKEN_1>",
        ),
        // Kebab-case names are not keys.
        (
            "uses sk-learn-compatible-estimator-4",
            "uses sk-learn-compatible-estimator-4",
        ),
    ]);
}

#[test]
fn stripe_test_and_restricted_keys_are_redacted() {
    check(&[
        (
            concat!("sk_", "test_", "Hk3Jd8Ws1Qz5Pm7RaB9xLq2V"),
            "<TOKEN_1>",
        ),
        (
            concat!("rk_", "test_", "Hk3Jd8Ws1Qz5Pm7RaB9xLq2V"),
            "<TOKEN_1>",
        ),
        (
            concat!("rk_", "live_", "Hk3Jd8Ws1Qz5Pm7RaB9xLq2V"),
            "<TOKEN_1>",
        ),
        (
            concat!("pk_", "test_", "Hk3Jd8Ws1Qz5Pm7RaB9xLq2V"),
            "<TOKEN_1>",
        ),
    ]);
}

#[test]
fn json_escaped_keys_are_redacted() {
    check(&[
        (
            r#"  Parameters: {\"password\"=>\"Zq8vN2kLp4Rx\"}"#,
            r#"  Parameters: {\"password\"=>\"<SECRET_1>\"}"#,
        ),
        (
            r#"{"body":"{\"api_key\":\"Qm7Tz9Lw2Xc4Vb6N\"}"}"#,
            r#"{"body":"{\"api_key\":\"<SECRET_1>\"}"}"#,
        ),
        (
            r#"got "{\\\"token\\\":\\\"Hk3Jd8Ws1Qz5Pm7R\\\"}""#,
            r#"got "{\\\"token\\\":\\\"<SECRET_1>\\\"}""#,
        ),
    ]);
}

#[test]
fn rails_sql_bind_values_are_redacted() {
    check(&[
        (
            concat!(
                r#"  User Load (0.4ms)  SELECT "users".* FROM "users" WHERE "users"."token" = $1 LIMIT $2  [["token", "Hk3Jd8Ws"#,
                r#"1Qz5Pm7R"], ["LIMIT", 1]]"#
            ),
            r#"  User Load (0.4ms)  SELECT "users".* FROM "users" WHERE "users"."token" = $1 LIMIT $2  [["token", "<SECRET_1>"], ["LIMIT", 1]]"#,
        ),
        (
            concat!(
                r#"  Account Update (0.2ms)  UPDATE "accounts" SET "api_key" = $1 WHERE "accounts"."id" = $2  [["api_key", "Qm7Tz9Lw"#,
                r#"2Xc4Vb6N"], ["id", 7]]"#
            ),
            r#"  Account Update (0.2ms)  UPDATE "accounts" SET "api_key" = $1 WHERE "accounts"."id" = $2  [["api_key", "<SECRET_1>"], ["id", 7]]"#,
        ),
        // A credential word in prose followed by a comma is not a bind.
        (
            "invalid token, Christopher retried",
            "invalid token, Christopher retried",
        ),
    ]);
}

#[test]
fn private_key_in_escaped_json_string_is_redacted() {
    check(&[
        (
            concat!(
                r#"{"private_key":"-----BEGIN "#,
                "PRIVATE KEY",
                r#"-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END "#,
                "PRIVATE KEY",
                r#"-----\n","api_key":"Qm7Tz9Lw"#,
                r#"2Xc4Vb6N"}"#
            ),
            r#"{"private_key":"<PRIVATE_KEY>\n","api_key":"<SECRET_1>"}"#,
        ),
        (
            concat!(
                r#"{"api_key":"Qm7Tz9Lw"#,
                r#"2Xc4Vb6N","private_key":"-----BEGIN "#,
                "PRIVATE KEY",
                r#"-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END "#,
                "PRIVATE KEY",
                r#"-----\n"}"#
            ),
            r#"{"api_key":"<SECRET_1>","private_key":"<PRIVATE_KEY>\n"}"#,
        ),
        // Truncated: no END marker, but the escapes show the key is inline, so
        // the following lines must survive.
        (
            concat!(
                r#"{"private_key":"-----BEGIN "#,
                "PRIVATE KEY",
                r#"-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC"}"#,
                "\nCompleted 200 OK in 5ms"
            ),
            "{\"private_key\":\"<PRIVATE_KEY>\"}\nCompleted 200 OK in 5ms",
        ),
        // String concatenation: the key body is on the next lines, so the block
        // stays open until END.
        (
            concat!(
                r#"KEY = "-----BEGIN "#,
                "PRIVATE KEY",
                "-----\\n\" \\\n  \"MIIEvQIBADANBgkqhkiG9w0BAQEFAASC\\n\" \\\n  \"-----END ",
                "PRIVATE KEY",
                "-----\\n\"\nok"
            ),
            "KEY = \"<PRIVATE_KEY>\n\\n\"\nok",
        ),
    ]);
}

#[test]
fn author_is_not_an_auth_key() {
    check(&[
        ("author: Christopher Nolan", "author: Christopher Nolan"),
        (
            "authors=Christopher,Josephine",
            "authors=Christopher,Josephine",
        ),
        (concat!("auth=Hk3Jd8Ws", "1Qz5Pm7R"), "auth=<SECRET_1>"),
        (
            concat!("basic_auth=Hk3Jd8Ws", "1Qz5Pm7R"),
            "basic_auth=<SECRET_1>",
        ),
        (
            concat!("authkey: Hk3Jd8Ws", "1Qz5Pm7R"),
            "authkey: <SECRET_1>",
        ),
        (
            concat!("authorization=Hk3Jd8Ws", "1Qz5Pm7R"),
            "authorization=<SECRET_1>",
        ),
    ]);
}

#[test]
fn shell_pwd_is_a_path_not_a_password() {
    check(&[
        ("PWD=/Users/dpep/code/proj", "PWD=~/code/proj"),
        ("OLDPWD=/Users/dpep/code", "OLDPWD=~/code"),
        (
            "Server=db;Uid=sa;Pwd=Zq8vN2kLp4Rx;",
            "Server=db;Uid=sa;Pwd=<SECRET_1>;",
        ),
        ("DB_PWD=Zq8vN2kLp4Rx", "DB_PWD=<SECRET_1>"),
    ]);
}

#[test]
fn macos_home_collapses_keeping_tail_and_line_number() {
    assert_eq!(
        clean("/Users/dpep/code/proj/src/db.rs:42"),
        "~/code/proj/src/db.rs:42"
    );
}

#[test]
fn linux_home_collapses_toolchain_path() {
    assert_eq!(
        clean("/home/dpep/.rustup/toolchains/x/lib.rs"),
        "~/.rustup/toolchains/x/lib.rs"
    );
}

#[test]
fn windows_home_collapses_with_backslashes() {
    assert_eq!(clean(r"C:\Users\dpep\app\log.txt"), r"~\app\log.txt");
}

#[test]
fn two_distinct_home_users_get_distinct_identities() {
    let input = "/Users/alice/a.rs\nuser=alice\n/Users/robin/b.rs\nuser=robin";
    let (out, _) = launder(Config::default(), input);
    assert_eq!(out, "~/a.rs\nuser=<USER_1>\n<HOME_2>/b.rs\nuser=<USER_2>");
}

#[test]
fn system_paths_are_kept() {
    assert_eq!(clean("/usr/lib/libfoo.so"), "/usr/lib/libfoo.so");
}

#[test]
fn macos_tmpdir_collapses() {
    assert_eq!(
        clean("/var/folders/qx/abc123/T/tmp.log"),
        "<TMPDIR>/tmp.log"
    );
}

#[test]
fn jwt_in_authorization_header() {
    assert_eq!(
        clean("Authorization: Bearer eyJhbGciOiJI.aaa.bbb"),
        "Authorization: Bearer <JWT_1>"
    );
}

#[test]
fn repeated_token_reuses_placeholder() {
    assert_eq!(
        clean("ghp_AbCdEf0123456789 then ghp_AbCdEf0123456789"),
        "<TOKEN_1> then <TOKEN_1>"
    );
}

#[test]
fn url_credential_redacts_only_the_password() {
    assert_eq!(
        clean("postgres://app:s3cr3t@db:5432/x"),
        "postgres://app:<PASSWORD_1>@db:5432/x"
    );
}

#[test]
fn keyed_high_entropy_value_is_redacted() {
    assert_eq!(clean("password=Z9x!q2Lm8Vt0"), "password=<SECRET_1>");
}

#[test]
fn diagnostic_ids_are_preserved() {
    let input = "commit a1b2c3d4e5f6a7b8 req 550e8400-e29b-41d4-a716-446655440000";
    assert_eq!(clean(input), input);
}

#[test]
fn repeated_email_reuses_placeholder() {
    assert_eq!(
        clean("ops@dpep.io and ops@dpep.io"),
        "<EMAIL_1> and <EMAIL_1>"
    );
}

#[test]
fn public_ip_scrubbed_private_kept() {
    assert_eq!(clean("203.0.113.7 then 127.0.0.1"), "<IP_1> then 127.0.0.1");
}

#[test]
fn secrets_never_expose_original_even_with_flag() {
    let cfg = Config {
        with_originals: true,
        ..Config::default()
    };
    let (_, findings) = launder(cfg, "ghp_AbCdEf0123456789");
    let secret = findings.iter().find(|f| f.kind.is_secret()).unwrap();
    let json = launder::emit::finding_to_json(secret, true);
    assert!(
        json.get("original").is_none(),
        "secret leaked original: {json}"
    );
}

#[test]
fn non_secret_original_included_only_with_flag() {
    let (_, findings) = launder(Config::default(), "ops@dpep.io");
    let email = findings.iter().find(|f| f.kind == Kind::Email).unwrap();
    assert!(
        launder::emit::finding_to_json(email, false)
            .get("original")
            .is_none()
    );
    assert_eq!(
        launder::emit::finding_to_json(email, true)["original"],
        serde_json::json!("ops@dpep.io")
    );
}

#[test]
fn home_and_tmpdir_report_as_path() {
    let input = "/Users/dpep/a.rs /var/folders/xy/abc123/T/b.log";
    let (_, findings) = launder(Config::default(), input);
    let typed: Vec<_> = findings
        .iter()
        .map(|f| {
            let json = launder::emit::finding_to_json(f, false);
            (json["type"].clone(), json["subtype"].clone())
        })
        .collect();
    assert_eq!(
        typed,
        [
            (serde_json::json!("path"), serde_json::json!("macos_home")),
            (serde_json::json!("path"), serde_json::json!("macos_tmpdir")),
        ]
    );

    let mut report = launder::report::Report::new();
    report.record(&findings);
    assert_eq!(report.counts().get("path"), Some(&2));
}

#[test]
fn private_key_block_collapses() {
    let input =
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\nabcdef\n-----END RSA PRIVATE KEY-----";
    assert_eq!(clean(input), "<PRIVATE_KEY>");
}

// The armor label carries a trailing " BLOCK" that the other PEM labels don't,
// so a matcher tuned to "...PRIVATE KEY-----" misses it entirely.
#[test]
fn pgp_private_key_block_collapses() {
    let input = concat!(
        "-----BEGIN PGP ",
        "PRIVATE KEY",
        " BLOCK-----\n",
        "lQOYBAABCAD6xN2kj9",
        "\n-----END PGP ",
        "PRIVATE KEY",
        " BLOCK-----"
    );
    assert_eq!(clean(input), "<PRIVATE_KEY>");
}

/// Every armored private-key spelling collapses to one `<PRIVATE_KEY>`,
/// regardless of what sits between "BEGIN"/"END" and the closing dashes.
#[test]
fn every_private_key_armor_label_collapses() {
    for label in [
        "RSA PRIVATE KEY",
        "EC PRIVATE KEY",
        "DSA PRIVATE KEY",
        "OPENSSH PRIVATE KEY",
        "PRIVATE KEY", // PKCS#8, unencrypted
        "ENCRYPTED PRIVATE KEY",
        "PGP PRIVATE KEY BLOCK",
    ] {
        let input = format!("-----BEGIN {label}-----\nYWJjZGVm\n-----END {label}-----");
        assert_eq!(clean(&input), "<PRIVATE_KEY>", "label: {label}");
    }
}

/// Armor that is NOT a private key must pass through untouched — over-matching
/// (e.g. any `-----BEGIN`) would redact harmless public material.
#[test]
fn non_private_key_armor_is_not_redacted() {
    for label in [
        "CERTIFICATE",
        "CERTIFICATE REQUEST",
        "PUBLIC KEY",
        "RSA PUBLIC KEY",
        "PGP PUBLIC KEY BLOCK",
        "PGP SIGNATURE",
        "PGP MESSAGE",
    ] {
        let input = format!("-----BEGIN {label}-----\nYWJjZGVm\n-----END {label}-----");
        assert_eq!(clean(&input), input, "label: {label}");
    }
}

#[test]
fn dry_run_passes_through_unchanged() {
    // The engine still produces findings; the caller chooses to echo input.
    let (_, findings) = launder(Config::default(), "ops@dpep.io");
    assert_eq!(findings.len(), 1);
}

#[test]
fn only_filter_limits_types() {
    let cfg = Config {
        enabled: Config::resolve_types(Some("email"), None).unwrap(),
        ..Config::default()
    };
    // Email scrubbed, but the home path is left alone.
    assert_eq!(
        launder(cfg, "/Users/dpep/x ops@dpep.io").0,
        "/Users/dpep/x <EMAIL_1>"
    );
}

/// Config with a local-identity watchlist (what the CLI builds by default).
fn with_watchlist(usernames: &[&str], home: Option<&str>, hostnames: &[&str]) -> Config {
    Config {
        watchlist: Watchlist {
            usernames: usernames.iter().map(|s| s.to_string()).collect(),
            home: home.map(|s| s.to_string()),
            hostnames: hostnames.iter().map(|s| s.to_string()).collect(),
        },
        ..Config::default()
    }
}

#[test]
fn watchlist_catches_bare_username_and_hostname() {
    // The username appears with no home path to reveal it, and the hostname is
    // only known from the local environment.
    let cfg = with_watchlist(&["dpep"], Some("/Users/dpep"), &["my-host"]);
    let out = launder(cfg, "job by dpep on my-host\n/Users/dpep/x").0;
    assert_eq!(out, "job by <USER_1> on <HOST_1>\n~/x");
}

#[test]
fn watchlist_does_not_pin_local_identity() {
    // Local $USER is dpep, but the trace is from a remote machine about alice.
    // alice must still be the primary `~` — the watchlist imposes no ordering.
    let cfg = with_watchlist(&["dpep"], Some("/Users/dpep"), &["my-host"]);
    let out = launder(cfg, "/Users/alice/a.rs\nuser=alice").0;
    assert_eq!(out, "~/a.rs\nuser=<USER_1>");
}

#[test]
fn bare_username_guarded_by_length_and_boundary() {
    // `dpep` (>=4) maps; substring inside `dpepper` does not.
    assert_eq!(
        clean("/Users/dpep/x logged in as dpep on host dpepper"),
        "~/x logged in as <USER_1> on host dpepper"
    );
}

// --- paths / network / overlap lane ---

#[test]
fn home_prefix_collapses_independently_of_tail() {
    check(&[
        // A digest in the tail is kept and doesn't cancel the collapse.
        (
            "/Users/priya/.cargo/registry/src/index.crates.io-6f17d22bba15001f/tokio-1.35.1/src/a.rs:3:1",
            "~/.cargo/registry/src/index.crates.io-6f17d22bba15001f/tokio-1.35.1/src/a.rs:3:1",
        ),
        // A secret in the tail is redacted and the owner still collapses.
        (
            concat!(
                "open /Users/bob/ghp_",
                "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789/app.rb:12"
            ),
            "open ~/<TOKEN_1>/app.rb:12",
        ),
        (
            concat!(
                "open /home/bob/.config/x?token=Zx9Yw8Vu",
                "7Ts6Rq5Po4Nm3 ok"
            ),
            "open ~/.config/x?token=<SECRET_1> ok",
        ),
    ]);
}

#[test]
fn macos_tmpdir_via_private_symlink_collapses() {
    check(&[(
        "tmp_path = PosixPath('/private/var/folders/qx/abc123/T/test0')",
        "tmp_path = PosixPath('<TMPDIR>/test0')",
    )]);
}

#[test]
fn pytest_temp_dir_owner_is_an_identity() {
    check(&[
        (
            "/var/folders/qx/abc123/T/pytest-of-priya/pytest-3/test0 owner=priya",
            "<TMPDIR>/pytest-of-<USER_1>/pytest-3/test0 owner=<USER_1>",
        ),
        // Short names are scrubbed here too: the position proves the identity.
        (
            "/tmp/pytest-of-bob/pytest-1/x.py",
            "/tmp/pytest-of-<USER_1>/pytest-1/x.py",
        ),
        (
            "/Users/priya/a.py /tmp/pytest-of-priya/pytest-1",
            "~/a.py /tmp/pytest-of-<USER_1>/pytest-1",
        ),
    ]);
}

#[test]
fn home_prefix_needs_a_left_boundary() {
    check(&[
        // A `root` segment mid-path is not root's home.
        ("/srv/root/data", "/srv/root/data"),
        (
            "ls /var/lib/docker/merged/root/x",
            "ls /var/lib/docker/merged/root/x",
        ),
        ("cd /root/x && ls /root", "cd ~/x && ls ~"),
        // A home nested in another path keeps its location; only the owner goes.
        ("/mnt/backup/home/alice/x", "/mnt/backup/home/<USER_1>/x"),
        ("file:///Users/alice/a.txt", "file:///Users/<USER_1>/a.txt"),
        (
            "/mnt/backup/home/alice/x then /home/alice/y",
            "/mnt/backup/home/<USER_1>/x then ~/y",
        ),
        // Separators and punctuation end the username.
        ("PATH=/usr/bin:/home/alice/bin", "PATH=/usr/bin:~/bin"),
        ("PATH=/home/alice:/usr/bin", "PATH=~:/usr/bin"),
        ("(/Users/alice)", "(~)"),
    ]);
}

#[test]
fn identities_are_learned_with_path_disabled() {
    let only = |types: &str| Config {
        enabled: Config::resolve_types(Some(types), None).unwrap(),
        ..Config::default()
    };
    let except = |types: &str| Config {
        enabled: Config::resolve_types(None, Some(types)).unwrap(),
        ..Config::default()
    };
    assert_eq!(
        launder(only("user"), "/Users/priya/a.rs\nby priya").0,
        "/Users/<USER_1>/a.rs\nby <USER_1>"
    );
    assert_eq!(
        launder(except("path"), "/tmp/pytest-of-priya/x ops@dpep.io priya").0,
        "/tmp/pytest-of-<USER_1>/x <EMAIL_1> <USER_1>"
    );
}

#[test]
fn internal_host_label_must_end_the_name_or_mark_an_fqdn() {
    check(&[
        ("db-prod-01.internal", "<HOST_1>"),
        ("ip-10-0-3-17.ec2.internal:5432", "<HOST_1>:5432"),
        // Mid-name, followed by a domain: the whole FQDN is evidently internal.
        (
            "connect db-prod-01.internal.acme-corp.com:5432",
            "connect <HOST_1>:5432",
        ),
        // File names are not hosts.
        ("config/database.local.yml", "config/database.local.yml"),
        (
            "cp settings.local.json .env.local",
            "cp settings.local.json .env.local",
        ),
    ]);
}

#[test]
fn version_numbers_are_not_ips() {
    check(&[
        (
            "Mozilla/5.0 Chrome/119.0.0.0 Safari/537.36",
            "Mozilla/5.0 Chrome/119.0.0.0 Safari/537.36",
        ),
        ("version 1.2.3.4", "version 1.2.3.4"),
        ("Version: 1.2.3.4", "Version: 1.2.3.4"),
        // An address is still an address.
        ("ip=8.8.4.4 from 8.8.8.8", "ip=<IP_1> from <IP_2>"),
        ("http://8.8.8.8/x", "http://<IP_1>/x"),
    ]);
}

#[test]
fn scp_style_git_remote_is_not_an_email() {
    check(&[
        (
            concat!("git", "@github.com:org/repo.git"),
            concat!("git", "@github.com:org/repo.git"),
        ),
        (
            concat!("git", "@github.com: Permission denied (publickey)."),
            concat!("git", "@github.com: Permission denied (publickey)."),
        ),
        (
            concat!("git", "@git.corp:org/repo.git"),
            concat!("git", "@<HOST_1>:org/repo.git"),
        ),
        ("ops@dpep.io: bounced", "<EMAIL_1>: bounced"),
    ]);
}

#[test]
fn percent_encoded_emails_are_scrubbed_whole() {
    check(&[
        (
            "GET /users?email=maria.garcia%40gmail.com&limit=10",
            "GET /users?email=<EMAIL_1>&limit=10",
        ),
        (
            "maria.garcia%40gmail.com maria.garcia@gmail.com",
            "<EMAIL_1> <EMAIL_1>",
        ),
        ("mailto:%6Aane@customer.com", "mailto:<EMAIL_1>"),
        ("-bob@dpep.io", "-<EMAIL_1>"),
    ]);
}

// Secrets detection: credentials in URLs, keyed values, CLI and file forms.

#[test]
fn url_password_runs_to_the_last_at_before_the_host() {
    check(&[
        (
            concat!("postgres://app:p@s", "s@db1.example.com/app"),
            "postgres://app:<PASSWORD_1>@db1.example.com/app",
        ),
        // The authority ends at the path: a later `@` stays in the path.
        (
            concat!(
                "https://app:Zq8vN2",
                "kLp4Rx@registry.example.com/@babel/core"
            ),
            "https://app:<PASSWORD_1>@registry.example.com/@babel/core",
        ),
    ]);
}

#[test]
fn url_passwords_are_numbered_per_value() {
    check(&[(
        concat!(
            "redis://:Zq8vN2kLp4Rx@a.example.com ",
            "redis://:Hk3Jd8Ws1Qz5@b.example.com ",
            "redis://:Zq8vN2kLp4Rx@c.example.com"
        ),
        concat!(
            "redis://:<PASSWORD_1>@a.example.com ",
            "redis://:<PASSWORD_2>@b.example.com ",
            "redis://:<PASSWORD_1>@c.example.com"
        ),
    )]);
}

#[test]
fn url_username_is_an_identity() {
    check(&[
        (
            concat!("https://alice:Zq8vN2", "kLp4Rx@git.example.com/org/repo"),
            "https://<USER_1>:<PASSWORD_1>@git.example.com/org/repo",
        ),
        // Role accounts and very short names identify no one.
        (
            concat!("postgres://postgres:Zq8vN2", "kLp4Rx@db1.example.com/app"),
            "postgres://postgres:<PASSWORD_1>@db1.example.com/app",
        ),
        (
            concat!("amqp://sa:Zq8vN2", "kLp4Rx@mq.example.com"),
            "amqp://sa:<PASSWORD_1>@mq.example.com",
        ),
    ]);
}

#[test]
fn quoted_keyed_value_runs_to_its_closing_quote() {
    check(&[
        (
            r#"password: "correct horse battery staple""#,
            r#"password: "<SECRET_1>""#,
        ),
        (
            concat!(r#"{"password":"p@ss,wo"#, r#"rd;123","user":"bob"}"#),
            r#"{"password":"<SECRET_1>","user":"bob"}"#,
        ),
        (
            concat!("password = 'Zx9Yw8 Vu7Ts6", "Rq5Po4Nm3'"),
            "password = '<SECRET_1>'",
        ),
        // Escaped quotes inside JSON-in-JSON close at the same escape depth.
        (
            concat!(
                r#"{"msg":"{\"api_key\":\"Zx9Yw8 Vu7Ts6"#,
                r#"Rq5Po4Nm3\"}"}"#
            ),
            r#"{"msg":"{\"api_key\":\"<SECRET_1>\"}"}"#,
        ),
    ]);
}

#[test]
fn keyed_value_stops_at_the_next_query_parameter() {
    check(&[
        (
            concat!("GET /cb?access_token=Hk3Jd8Ws", "1Qz5Pm7R&state=xyz"),
            "GET /cb?access_token=<SECRET_1>&state=xyz",
        ),
        // An `&` not followed by `name=` belongs to the value.
        (
            concat!("password=Tr0ub4dor&3", "Zq8vN2"),
            "password=<SECRET_1>",
        ),
    ]);
}

#[test]
fn password_keys_redact_any_value() {
    check(&[
        ("password=hunter2", "password=<SECRET_1>"),
        ("password: hunter2hunter2", "password: <SECRET_1>"),
        (
            r#"{"password":"hunter2hunter2"}"#,
            r#"{"password":"<SECRET_1>"}"#,
        ),
        ("DB_PASSWORD=letmein1", "DB_PASSWORD=<SECRET_1>"),
        ("PGPASSWORD=hunter2", "PGPASSWORD=<SECRET_1>"),
        ("DB_PASS=letmein1", "DB_PASS=<SECRET_1>"),
        ("dbPass: letmein1", "dbPass: <SECRET_1>"),
        ("passwd=abc123", "passwd=<SECRET_1>"),
        ("passphrase: Tr0ub4dor&3", "passphrase: <SECRET_1>"),
        ("MYSQL_PWD=hunter2", "MYSQL_PWD=<SECRET_1>"),
        (
            "Server=db;Uid=sa;Pwd=hunter2;",
            "Server=db;Uid=sa;Pwd=<SECRET_1>;",
        ),
    ]);
}

#[test]
fn password_keys_keep_placeholder_values() {
    check(&[
        ("password=", "password="),
        (r#"{"password":""}"#, r#"{"password":""}"#),
        ("password: true", "password: true"),
        ("password=False", "password=False"),
        ("password: null", "password: null"),
        ("password=None", "password=None"),
        ("password: nil", "password: nil"),
        ("password=********", "password=********"),
        ("PWD=/srv/app", "PWD=/srv/app"),
    ]);
}

#[test]
fn ambiguous_pass_words_keep_the_entropy_gate() {
    check(&[
        // A bare `pass` is as often a test tally as a password.
        ("pass: 42 fail: 0", "pass: 42 fail: 0"),
        ("pass=12", "pass=12"),
        (concat!("pass=Hk3Jd8Ws", "1Qz5Pm7R"), "pass=<SECRET_1>"),
        // `pass` inside a word is no key at all.
        (
            "bypass=enabled compass=northwest",
            "bypass=enabled compass=northwest",
        ),
        ("token_type=bearer", "token_type=bearer"),
    ]);
}

#[test]
fn credential_key_names_are_redacted() {
    check(&[
        (
            concat!("credentials=Hk3Jd8Ws", "1Qz5Pm7R"),
            "credentials=<SECRET_1>",
        ),
        (
            concat!("client_secret: Hk3Jd8Ws", "1Qz5Pm7R"),
            "client_secret: <SECRET_1>",
        ),
        (
            concat!("encryption_key=Hk3Jd8Ws", "1Qz5Pm7R"),
            "encryption_key=<SECRET_1>",
        ),
        (
            concat!("signing_key=Hk3Jd8Ws", "1Qz5Pm7R"),
            "signing_key=<SECRET_1>",
        ),
        (
            concat!(
                "session_id=Hk3Jd8Ws",
                "1Qz5Pm7R sessionid=Qm7Tz9Lw",
                "2Xc4Vb6N"
            ),
            "session_id=<SECRET_1> sessionid=<SECRET_2>",
        ),
        (
            concat!("X-Session-Id: Hk3Jd8Ws", "1Qz5Pm7R"),
            "X-Session-Id: <SECRET_1>",
        ),
        // A signature outranks the hex-digest keep.
        (
            concat!(
                "/o?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=fe5f80f77d5fa3beca038a248ff027d0",
                "445342fe2855ddc963176630326f1024&X-Amz-Expires=300"
            ),
            "/o?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=<SECRET_1>&X-Amz-Expires=300",
        ),
        (
            concat!(
                "/c/b?sv=2021-08-06&sr=b&sig=Zx9Yw8Vu7Ts6",
                "Rq5Po4Nm3%2BAbCd%3D"
            ),
            "/c/b?sv=2021-08-06&sr=b&sig=<SECRET_1>",
        ),
        (
            concat!(
                "DefaultEndpointsProtocol=https;AccountName=acct;AccountKey=Zx9Yw8Vu7Ts6",
                "Rq5Po4Nm3==;EndpointSuffix=core.windows.net"
            ),
            "DefaultEndpointsProtocol=https;AccountName=acct;AccountKey=<SECRET_1>;EndpointSuffix=core.windows.net",
        ),
        (
            "secret_name=prod/db/credentials",
            "secret_name=prod/db/credentials",
        ),
    ]);
}

#[test]
fn uuid_under_a_credential_key_is_a_credential() {
    check(&[
        (
            concat!(
                "//registry.npmjs.org/:_authToken=0a1b2c3d-",
                "4e5f-4a7b-8c9d-0e1f2a3b4c5d"
            ),
            "//registry.npmjs.org/:_authToken=<SECRET_1>",
        ),
        (
            concat!("HEROKU_API_KEY=0a1b2c3d-", "4e5f-4a7b-8c9d-0e1f2a3b4c5d"),
            "HEROKU_API_KEY=<SECRET_1>",
        ),
        // A SHA-shaped token is still a token.
        (
            concat!("token=95f2a31c4e8b2d1f0a9e", "8d7c6b5a4f3e2d1c0b9a"),
            "token=<SECRET_1>",
        ),
        // Diagnostic IDs under ordinary keys survive.
        (
            "request_id=7f3c2b1a-0e9d-4c7b-a5f4-e3d2c1b0a9f8 trace_id=4bf92f3577b34da6a3ce929d0e0e4736",
            "request_id=7f3c2b1a-0e9d-4c7b-a5f4-e3d2c1b0a9f8 trace_id=4bf92f3577b34da6a3ce929d0e0e4736",
        ),
    ]);
}

#[test]
fn keyed_authorization_keeps_its_scheme() {
    check(&[
        (
            r#"{"authorization":"Bearer Zq8vN2kLp4RxQm7Tz9Lw"}"#,
            r#"{"authorization":"Bearer <SECRET_1>"}"#,
        ),
        (
            r#"{"Authorization": "Token Zq8vN2kLp4RxQm7Tz9Lw", "ok": true}"#,
            r#"{"Authorization": "Token <SECRET_1>", "ok": true}"#,
        ),
    ]);
}

#[test]
fn keyed_cookie_values_are_redacted() {
    check(&[
        (
            r#"{"cookie":"_gh_sess=Qm7Tz9Lw2Xc4Vb6NHk3Jd8Ws1Qz5Pm7R; locale=en","user":"bob"}"#,
            r#"{"cookie":"_gh_sess=<TOKEN_1>; locale=en","user":"bob"}"#,
        ),
        (
            r#"{"set-cookie": "sid=Qm7Tz9Lw2Xc4Vb6N; Path=/"}"#,
            r#"{"set-cookie": "sid=<TOKEN_1>; Path=/"}"#,
        ),
    ]);
}

#[test]
fn url_encoded_separators_are_keyed_values() {
    check(&[
        (
            concat!(
                "redirect=https%3A%2F%2Fx.io%2Fcb%3Faccess_token%3DZx9Yw8Vu7Ts6",
                "Rq5Po4Nm3"
            ),
            "redirect=https%3A%2F%2Fx.io%2Fcb%3Faccess_token%3D<SECRET_1>",
        ),
        (
            concat!("body: password%3dZx9Yw8Vu7Ts6", "Rq5Po4Nm3%26user%3Dbob"),
            "body: password%3d<SECRET_1>%26user%3Dbob",
        ),
        (
            concat!("api_key%3AZx9Yw8Vu7Ts6", "Rq5Po4Nm3"),
            "api_key%3A<SECRET_1>",
        ),
    ]);
}

#[test]
fn more_known_prefix_tokens_are_redacted() {
    check(&[
        (
            concat!("HF_TOKEN set: hf_AbCdEfGhIjKlMn", "OpQrStUvWxYz0123456789"),
            "HF_TOKEN set: <TOKEN_1>",
        ),
        (
            concat!(
                "upload with pypi-AgEIcHlwaS5vcmcCJDAwMDAw",
                "MDAwLTAwMDAtMDAwMC0wMDAwLTAwMDAwMDAwMDAwMAACKlszLCJhYmMiXQ"
            ),
            "upload with <TOKEN_1>",
        ),
        (
            concat!(
                "doctl auth dop_v1_0123456789abcdef0123456789abcdef",
                "0123456789abcdef0123456789abcdef"
            ),
            "doctl auth <TOKEN_1>",
        ),
        (
            concat!(
                "shpat_1a2b3c4d5e6f", "7a8b9c0d1e2f3a4b5c6d ",
                "shpss_1a2b3c4d5e6f", "7a8b9c0d1e2f3a4b5c6e ",
                "shpca_1a2b3c4d5e6f", "7a8b9c0d1e2f3a4b5c6f ",
                "shppa_1a2b3c4d5e6f", "7a8b9c0d1e2f3a4b5c60"
            ),
            "<TOKEN_1> <TOKEN_2> <TOKEN_3> <TOKEN_4>",
        ),
        (
            concat!("mailgun key-3ax6xnjp29jd6fds", "4gc373sgvjxteol0"),
            "mailgun <TOKEN_1>",
        ),
        (
            concat!("twilio SK0123456789abcdef", "0123456789abcdef"),
            "twilio <TOKEN_1>",
        ),
        // Look-alikes stay.
        (
            "key-value-store-abcdefghij hf_hub_download",
            "key-value-store-abcdefghij hf_hub_download",
        ),
    ]);
}

#[test]
fn webhook_urls_redact_their_secret_path() {
    check(&[
        (
            concat!(
                "webhook_url=https://hooks.slack.com/services/T0000",
                "0000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
            ),
            "webhook_url=https://hooks.slack.com/services/<TOKEN_1>",
        ),
        (
            concat!(
                "POST https://discord.com/api/webhooks/123456789012345678/AbCdEfGhIjKl",
                "MnOpQrStUvWxYz0123456789 failed"
            ),
            "POST https://discord.com/api/webhooks/<TOKEN_1> failed",
        ),
    ]);
}

#[test]
fn space_separated_cli_flags_are_keyed_values() {
    check(&[
        (
            "mysql --password hunter2 -h db",
            "mysql --password <SECRET_1> -h db",
        ),
        ("deploy --db-pass hunter2", "deploy --db-pass <SECRET_1>"),
        (
            concat!(
                "gh --token Zx9Yw8Vu7Ts6",
                "Rq5Po4Nm3 --api-key Hk3Jd8Ws",
                "1Qz5Pm7R"
            ),
            "gh --token <SECRET_1> --api-key <SECRET_2>",
        ),
        (
            concat!(r#"run --secret "Zx9Yw8 Vu7Ts6"#, r#"Rq5Po4Nm3" -v"#),
            r#"run --secret "<SECRET_1>" -v"#,
        ),
        // The flag's value is the next word, never the next flag or a file flag.
        ("cli --password --verbose", "cli --password --verbose"),
        (
            "cli --token-file /etc/app/token",
            "cli --token-file /etc/app/token",
        ),
        // `mysql -pX` is too ambiguous with other tools' short flags.
        ("mysql -phunter2 -u root", "mysql -phunter2 -u root"),
    ]);
}

#[test]
fn curl_user_credentials_are_redacted() {
    check(&[
        (
            "curl -u alice:hunter2 https://api.example.com/v1",
            "curl -u <USER_1>:<PASSWORD_1> https://api.example.com/v1",
        ),
        (
            "curl -s --user 'deploy-bot:hunter2' https://api.example.com",
            "curl -s --user '<USER_1>:<PASSWORD_1>' https://api.example.com",
        ),
        // Other tools' `-u uid:gid` is not a credential.
        ("docker run -u 1000:1000 app", "docker run -u 1000:1000 app"),
    ]);
}

#[test]
fn netrc_lines_redact_password_and_login() {
    check(&[
        (
            "machine api.example.com login alice password hunter2",
            "machine api.example.com login <USER_1> password <SECRET_1>",
        ),
        (
            "default login anonymous password ''",
            "default login anonymous password ''",
        ),
    ]);
}

#[test]
fn xml_credential_elements_are_redacted() {
    check(&[
        (
            "<password>hunter2</password>",
            "<password><SECRET_1></password>",
        ),
        (
            concat!("<db><apiToken>Zx9Yw8Vu7Ts6", "Rq5Po4Nm3</apiToken></db>"),
            "<db><apiToken><SECRET_1></apiToken></db>",
        ),
        ("<token>short</token>", "<token>short</token>"),
    ]);
}

#[test]
fn aws_secret_beside_its_access_key_id_is_redacted() {
    check(&[
        (
            concat!(
                "AKIAIOSFODNN7EXAMPLE,wJalrXUtnFEMI/K7MDENG/",
                "bPxRfiCYEXAMPLEKEY"
            ),
            "<TOKEN_1>,<SECRET_1>",
        ),
        (
            concat!(
                "zedd,,ASIAIOSFODNN7EXAMPLE,wJalrXUtnFEMI/K7MDENG/",
                "bPxRfiCYEXAMPLEKEY"
            ),
            "zedd,,<TOKEN_1>,<SECRET_1>",
        ),
        // A git SHA is hex, never an AWS secret.
        (
            concat!(
                "AKIAIOSFODNN7EXAMPLE at 95f2a31c4e8b2d1f0a9e",
                "8d7c6b5a4f3e2d1c0b9a"
            ),
            "<TOKEN_1> at 95f2a31c4e8b2d1f0a9e8d7c6b5a4f3e2d1c0b9a",
        ),
    ]);
}

#[test]
fn percent_encoded_url_credentials_are_redacted() {
    check(&[
        (
            concat!(
                "url=https%3A%2F%2Falice%3AZx9Yw8Vu7Ts6",
                "Rq5Po4Nm3%40db.example.com"
            ),
            "url=https%3A%2F%2F<USER_1>%3A<PASSWORD_1>%40db.example.com",
        ),
        // The password runs to the last `%40` of the authority.
        (
            concat!(
                "next=postgres%3a%2f%2fapp%3ap%40",
                "ss%40db.example.com%2Fapp%40x"
            ),
            "next=postgres%3a%2f%2fapp%3a<PASSWORD_1>%40db.example.com%2Fapp%40x",
        ),
        // No credentials, nothing to redact.
        (
            "next=https%3A%2F%2Fdb.example.com%2Fa%3Ab",
            "next=https%3A%2F%2Fdb.example.com%2Fa%3Ab",
        ),
    ]);
}
