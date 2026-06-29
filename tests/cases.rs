//! §9 gold acceptance cases. Each asserts the exact laundered output (and, where
//! it matters, the findings) for an `(input, flags)` pair. Determinism is part
//! of the contract: the same input always produces the same output.
//!
//! Tests drive the library directly (one `Engine` per run) rather than shelling
//! out — faster, deterministic, no permission prompts.

use launder::config::Config;
use launder::engine::{Engine, Finding};

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

#[test]
fn bare_username_guarded_by_length_and_boundary() {
    // `dpep` (>=4) maps; substring inside `dpepper` does not.
    assert_eq!(
        clean("/Users/dpep/x logged in as dpep on host dpepper"),
        "~/x logged in as <USER_1> on host dpepper"
    );
}
