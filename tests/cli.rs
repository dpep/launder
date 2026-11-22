//! Binary-level tests: behavior only the real process shows — streaming
//! timing, exit codes, help, completions. Everything else drives the library.

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

fn launder() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_launder"));
    cmd.env_remove("LAUNDER_WATCH");
    cmd
}

/// Write one line, keep stdin open, and require a line of output before EOF.
/// The bytes are identical either way; only the timing shows a buffered pipe.
fn first_line_before_eof(args: &[&str], input: &str) -> String {
    let mut child = launder()
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(input.as_bytes()).unwrap();
    stdin.flush().unwrap();

    let stdout = child.stdout.take().unwrap();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut line = String::new();
        BufReader::new(stdout).read_line(&mut line).unwrap();
        let _ = tx.send(line);
    });
    let got = rx.recv_timeout(Duration::from_secs(5));
    drop(stdin);
    let _ = child.kill();
    let _ = child.wait();
    got.expect("no output before EOF: stdout is not streaming")
}

#[test]
fn text_streams_before_eof() {
    let line = first_line_before_eof(&[], "mail ops@dpep.io\n");
    assert_eq!(line, "mail <EMAIL_1>\n");
}

#[test]
fn ndjson_streams_before_eof() {
    let line = first_line_before_eof(&["-J"], "mail ops@dpep.io\n");
    assert!(line.contains("<EMAIL_1>"), "{line}");
}

/// Run to completion over `input`; return (exit code, stdout, stderr).
fn run(args: &[&str], input: &[u8]) -> (i32, String, String) {
    let mut child = launder()
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    let out = child.wait_with_output().unwrap();
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8(out.stdout).unwrap(),
        String::from_utf8(out.stderr).unwrap(),
    )
}

#[test]
fn invalid_utf8_is_replaced_and_the_run_continues() {
    let (code, out, _) = run(&[], b"bad \xff byte ops@dpep.io\nnext alice@dpep.io\n");
    assert_eq!(code, 0);
    assert_eq!(out, "bad \u{FFFD} byte <EMAIL_1>\nnext <EMAIL_2>\n");
}

#[test]
fn check_exits_one_when_anything_was_scrubbed() {
    assert_eq!(run(&["--check"], b"mail ops@dpep.io\n").0, 1);
    assert_eq!(run(&["--check"], b"all clear\n").0, 0);
    // Without --check a scrub is still success, so `| pbcopy` is fine.
    assert_eq!(run(&[], b"mail ops@dpep.io\n").0, 0);
    assert_eq!(run(&["--check", "--bogus"], b"").0, 2);
    let (_, help, _) = run(&["--help"], b"");
    assert!(help.contains("Exit codes:"), "{help}");
}

#[test]
fn launder_watch_adds_to_watch_flags() {
    let mut child = launder()
        .env("LAUNDER_WATCH", "globex,initech")
        .args(["--watch", "acme"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"acme globex initech\n")
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        "<TERM_1> <TERM_2> <TERM_3>\n"
    );
}

/// A fresh scratch directory under the system temp dir, unique per test.
fn scratch(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("launder-cli-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn output_that_names_an_input_is_refused() {
    let dir = scratch("same");
    let log = dir.join("app.log");
    std::fs::write(&log, "mail ops@dpep.io\n").unwrap();
    let path = log.to_str().unwrap();
    // A second spelling of the same file must be caught too.
    let alias = dir.join(".").join("app.log");
    let (code, _, err) = run(&["-o", alias.to_str().unwrap(), path], b"");
    assert_eq!(code, 2);
    assert!(err.contains("is also an input"), "{err}");
    assert_eq!(std::fs::read_to_string(&log).unwrap(), "mail ops@dpep.io\n");
}

#[test]
fn unterminated_private_key_is_closed_at_each_file() {
    let dir = scratch("pem");
    let a = dir.join("a.log");
    let b = dir.join("b.log");
    std::fs::write(&a, "-----BEGIN RSA PRIVATE KEY-----\nMIIE\nabcd\n").unwrap();
    std::fs::write(&b, "mail ops@dpep.io\n").unwrap();
    let (code, out, err) = run(&[a.to_str().unwrap(), b.to_str().unwrap()], b"");
    assert_eq!(code, 0);
    assert_eq!(out, "<PRIVATE_KEY>\nmail <EMAIL_1>\n");
    assert_eq!(
        err,
        format!(
            "launder: unterminated private key in {}; 2 lines suppressed\n",
            a.display()
        )
    );
}
