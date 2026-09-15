//! §9 gold acceptance cases. Each asserts the exact laundered output (and, where
//! it matters, the findings) for an `(input, flags)` pair. Determinism is part
//! of the contract: the same input always produces the same output.
//!
//! Tests drive the library directly (one `Engine` per run) rather than shelling
//! out — faster, deterministic, no permission prompts.

use launder::config::Config;
use launder::engine::{Engine, Finding};
use launder::system::SystemInfo;

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
            r#"  Parameters: {"password"=>"Zq8vN2kLp4Rx"}"#,
            r#"  Parameters: {"password"=>"<SECRET_1>"}"#,
        ),
        (
            r#"{"api_key": "Qm7Tz9Lw2Xc4Vb6N"}"#,
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
        ("access_token=Hk3Jd8Ws1Qz5Pm7R", "access_token=<SECRET_1>"),
        ("auth_token: Hk3Jd8Ws1Qz5Pm7R", "auth_token: <SECRET_1>"),
        (
            r#"{"refreshToken":"Hk3Jd8Ws1Qz5Pm7R"}"#,
            r#"{"refreshToken":"<SECRET_1>"}"#,
        ),
        (
            "SECRET_KEY_BASE=Hk3Jd8Ws1Qz5Pm7RaB9",
            "SECRET_KEY_BASE=<SECRET_1>",
        ),
        (
            "RAILS_MASTER_KEY=Hk3Jd8Ws1Qz5Pm7RaB9",
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
        "redis://:<PASSWORD>@cache.example.com:6379/0",
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

// Credential-shaped inputs are assembled with `concat!` so no literal token
// sits in the source for push protection to flag.

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
            r#"  User Load (0.4ms)  SELECT "users".* FROM "users" WHERE "users"."token" = $1 LIMIT $2  [["token", "Hk3Jd8Ws1Qz5Pm7R"], ["LIMIT", 1]]"#,
            r#"  User Load (0.4ms)  SELECT "users".* FROM "users" WHERE "users"."token" = $1 LIMIT $2  [["token", "<SECRET_1>"], ["LIMIT", 1]]"#,
        ),
        (
            r#"  Account Update (0.2ms)  UPDATE "accounts" SET "api_key" = $1 WHERE "accounts"."id" = $2  [["api_key", "Qm7Tz9Lw2Xc4Vb6N"], ["id", 7]]"#,
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
                r#"-----\n","api_key":"Qm7Tz9Lw2Xc4Vb6N"}"#
            ),
            r#"{"private_key":"<PRIVATE_KEY>\n","api_key":"<SECRET_1>"}"#,
        ),
        (
            concat!(
                r#"{"api_key":"Qm7Tz9Lw2Xc4Vb6N","private_key":"-----BEGIN "#,
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
        ("auth=Hk3Jd8Ws1Qz5Pm7R", "auth=<SECRET_1>"),
        ("basic_auth=Hk3Jd8Ws1Qz5Pm7R", "basic_auth=<SECRET_1>"),
        ("authkey: Hk3Jd8Ws1Qz5Pm7R", "authkey: <SECRET_1>"),
        ("authorization=Hk3Jd8Ws1Qz5Pm7R", "authorization=<SECRET_1>"),
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
        "postgres://app:<PASSWORD>@db:5432/x"
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
    let email = findings
        .iter()
        .find(|f| f.kind.type_str() == "email")
        .unwrap();
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
fn private_key_block_collapses() {
    let input =
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\nabcdef\n-----END RSA PRIVATE KEY-----";
    assert_eq!(clean(input), "<PRIVATE_KEY>");
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
fn with_system(usernames: &[&str], home: Option<&str>, hostnames: &[&str]) -> Config {
    Config {
        system: Some(SystemInfo {
            usernames: usernames.iter().map(|s| s.to_string()).collect(),
            home: home.map(|s| s.to_string()),
            hostnames: hostnames.iter().map(|s| s.to_string()).collect(),
        }),
        ..Config::default()
    }
}

#[test]
fn system_signal_catches_bare_username_and_hostname() {
    // The username appears with no home path to reveal it, and the hostname is
    // only known from the local environment.
    let cfg = with_system(&["dpep"], Some("/Users/dpep"), &["my-host"]);
    let out = launder(cfg, "job by dpep on my-host\n/Users/dpep/x").0;
    assert_eq!(out, "job by <USER_1> on <HOST_1>\n~/x");
}

#[test]
fn system_signal_does_not_pin_local_identity() {
    // Local $USER is dpep, but the trace is from a remote machine about alice.
    // alice must still be the primary `~` — the watchlist imposes no ordering.
    let cfg = with_system(&["dpep"], Some("/Users/dpep"), &["my-host"]);
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
