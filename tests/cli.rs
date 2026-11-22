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
