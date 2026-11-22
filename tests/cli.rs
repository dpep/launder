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
fn completions_print_only_the_script() {
    // The Homebrew formula's invocation, verbatim.
    let (code, out, err) = run(&["--completions", "bash"], b"");
    assert_eq!((code, err.as_str()), (0, ""));
    assert!(out.contains("complete -F"), "{out}");

    let bare = |shell: Option<&str>| {
        let mut cmd = launder();
        cmd.arg("--completions");
        match shell {
            Some(s) => cmd.env("SHELL", s),
            None => cmd.env_remove("SHELL"),
        };
        cmd.output().unwrap()
    };
    let zsh = bare(Some("/bin/zsh"));
    assert!(zsh.status.success());
    assert!(String::from_utf8_lossy(&zsh.stdout).contains("compdef"));
    let unknown = bare(None);
    assert_eq!(unknown.status.code(), Some(2));
    assert!(unknown.stdout.is_empty());
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
fn output_that_is_redirected_stdin_is_refused() {
    let dir = scratch("same-stdin");
    let log = dir.join("app.log");
    std::fs::write(&log, "mail ops@dpep.io\n").unwrap();
    let out = launder()
        .args(["-o", log.to_str().unwrap()])
        .stdin(std::fs::File::open(&log).unwrap())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("is also an input"));
    assert_eq!(std::fs::read_to_string(&log).unwrap(), "mail ops@dpep.io\n");
}

#[test]
fn inputs_are_checked_before_the_output_is_created() {
    let dir = scratch("inputs-first");
    let log = dir.join("app.log");
    std::fs::write(&log, "mail ops@dpep.io\n").unwrap();
    let out = dir.join("out.log");
    std::fs::write(&out, "keep\n").unwrap();
    let missing = dir.join("missing.log");
    let (code, _, _) = run(
        &[
            "-o",
            out.to_str().unwrap(),
            log.to_str().unwrap(),
            missing.to_str().unwrap(),
        ],
        b"",
    );
    assert_eq!(code, 2);
    assert_eq!(std::fs::read_to_string(&out).unwrap(), "keep\n");

    // An output that is also a not-yet-existing input must not read itself.
    let fresh = dir.join("fresh.log");
    let fresh = fresh.to_str().unwrap();
    let (code, _, _) = run(&["-o", fresh, log.to_str().unwrap(), fresh], b"");
    assert_eq!(code, 2);
    assert!(!std::path::Path::new(fresh).exists());
}

#[test]
fn private_key_split_across_files_stays_suppressed() {
    let dir = scratch("pem");
    let a = dir.join("a.log");
    let b = dir.join("b.log");
    std::fs::write(&a, "start\n-----BEGIN RSA PRIVATE KEY-----\nMIIE\n").unwrap();
    std::fs::write(
        &b,
        "abcd\n-----END RSA PRIVATE KEY-----\nmail ops@dpep.io\n",
    )
    .unwrap();
    let (code, out, err) = run(&[a.to_str().unwrap(), b.to_str().unwrap()], b"");
    assert_eq!((code, err.as_str()), (0, ""));
    assert_eq!(out, "start\n<PRIVATE_KEY>\nmail <EMAIL_1>\n");
}

#[test]
fn unterminated_private_key_is_reported_at_end_of_input() {
    let dir = scratch("pem-open");
    let a = dir.join("a.log");
    let b = dir.join("b.log");
    std::fs::write(&a, "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n").unwrap();
    std::fs::write(&b, "abcd\n").unwrap();
    let (code, out, err) = run(&[a.to_str().unwrap(), b.to_str().unwrap()], b"");
    assert_eq!(code, 0);
    assert_eq!(out, "<PRIVATE_KEY>\n");
    assert_eq!(
        err,
        "launder: unterminated private key; 2 lines suppressed to the end of input\n"
    );
}

#[test]
fn watch_terms_split_on_commas_and_whitespace() {
    let mut cmd = launder();
    cmd.env("LAUNDER_WATCH", "globex initech")
        .args(["--watch", "acme, hooli"]);
    let out = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            child
                .stdin
                .take()
                .unwrap()
                .write_all(b"acme hooli globex initech\n")?;
            child.wait_with_output()
        })
        .unwrap();
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        "<TERM_1> <TERM_2> <TERM_3> <TERM_4>\n"
    );
}

#[test]
fn a_watch_term_with_nothing_to_match_is_an_error() {
    for term in [".", "", " ", ","] {
        let (code, out, err) = run(&["--watch", term], b"a.b\n");
        assert_eq!(code, 2, "--watch {term:?}");
        assert!(out.is_empty(), "--watch {term:?}: {out}");
        assert!(err.contains("--watch"), "--watch {term:?}: {err}");
    }
}

#[cfg(unix)]
#[test]
fn non_utf8_launder_watch_keeps_its_terms_and_warns() {
    use std::os::unix::ffi::OsStrExt;
    let out = launder()
        .env(
            "LAUNDER_WATCH",
            std::ffi::OsStr::from_bytes(b"acme,m\xfcller"),
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            child
                .stdin
                .take()
                .unwrap()
                .write_all(b"acme and m\xfcller\n")?;
            child.wait_with_output()
        })
        .unwrap();
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        "<TERM_1> and <TERM_2>\n"
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("LAUNDER_WATCH"));
}

#[test]
fn messages_show_the_home_dir_as_tilde() {
    let home = scratch("home-msg");
    let missing = home.join(".ssh").join("id_rsa");
    let out = launder().env("HOME", &home).arg(&missing).output().unwrap();
    let err = String::from_utf8(out.stderr).unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(err.contains("reading ~/.ssh/id_rsa"), "{err}");
    assert!(!err.contains(home.to_str().unwrap()), "{err}");
}

#[test]
fn dash_reads_stdin_among_files() {
    let dir = scratch("dash");
    let log = dir.join("app.log");
    std::fs::write(&log, "mail ops@dpep.io\n").unwrap();
    let (code, out, _) = run(&[log.to_str().unwrap(), "-"], b"next alice@dpep.io\n");
    assert_eq!(code, 0);
    assert_eq!(out, "mail <EMAIL_1>\nnext <EMAIL_2>\n");
}
