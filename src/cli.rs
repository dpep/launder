//! Command-line surface: wire cli → reader → engine → emitter.

use std::borrow::Cow;
use std::fs::File;
use std::io::{self, BufWriter, IsTerminal, Write};
use std::process::ExitCode;

use anyhow::Result;
use clap::{ArgGroup, CommandFactory, Parser};
use clap_complete::Shell;

use crate::config::{self, Config};
use crate::emit::{Emitter, Format};
use crate::engine::Engine;
use crate::input::{Input, LineReader};
use crate::report::Report;
use crate::watchlist::Watchlist;

const AFTER_HELP: &str = "\
Examples:
  myapp 2>&1 | launder | pbcopy       clean trace on the clipboard
  launder -n crash.log                preview what would change
  launder -r -o clean.log app.log     write a copy; summary on stderr
  launder --watch acme.com app.log    also scrub a company domain
  git diff | launder --check -n       fail a hook, showing what it found

Exit codes:
  0  success; with --check, nothing needed scrubbing
  1  --check only: something was scrubbed
  2  error (bad flag, unreadable file, ...)";

/// Scrub identifying paths, secrets, and contacts from logs and stack traces,
/// keeping everything a reader needs to help.
#[derive(Debug, Parser)]
#[command(name = "launder", version, about, after_help = AFTER_HELP)]
#[command(group(ArgGroup::new("structured").args(["json", "ndjson"])))]
struct Cli {
    /// Input files, read in order (stdin if none).
    files: Vec<String>,

    /// Show each replacement instead of the text (not for pasting: shows originals).
    #[arg(short = 'n', long = "dry-run", conflicts_with_all = ["json", "ndjson"])]
    dry_run: bool,

    /// JSON: {lines: [{line, text, findings}], summary}, written at EOF.
    #[arg(short = 'j', long = "json", conflicts_with = "ndjson")]
    json: bool,

    /// Like -j, streamed: one row per line, then a summary line.
    #[arg(short = 'J', long = "ndjson")]
    ndjson: bool,

    /// Add each finding's original text to -j/-J output (never a secret's).
    #[arg(long = "with-originals", requires = "structured")]
    with_originals: bool,

    /// Write output to FILE instead of stdout.
    #[arg(short = 'o', long = "output", value_name = "FILE")]
    output: Option<String>,

    /// Also print a summary of what changed to stderr.
    #[arg(short = 'r', long = "report")]
    report: bool,

    /// Exit 1 if anything was scrubbed, 0 if clean (for hooks and CI).
    #[arg(long = "check")]
    check: bool,

    /// Also scrub TERM, any case; a domain takes its subdomains (also $LAUNDER_WATCH).
    #[arg(long = "watch", value_name = "TERM", help_heading = "Scrubbing")]
    watch: Vec<String>,

    /// Never scrub TERM, e.g. a public host. Secrets are scrubbed regardless.
    #[arg(
        long = "keep",
        value_name = "TERM",
        value_delimiter = ',',
        help_heading = "Scrubbing"
    )]
    keep: Vec<String>,

    #[arg(
        long = "only",
        value_name = "TYPES",
        conflicts_with = "except",
        help_heading = "Scrubbing",
        help = format!("Scrub only these types: {}", config::kind_names())
    )]
    only: Option<String>,

    /// Scrub every type except these (same names as --only).
    #[arg(long = "except", value_name = "TYPES", help_heading = "Scrubbing")]
    except: Option<String>,

    /// Also scrub private and loopback IPs (kept by default).
    #[arg(long = "all-ips", help_heading = "Scrubbing")]
    all_ips: bool,

    /// Print a completion script for bash, zsh, fish, ... (default: $SHELL).
    #[arg(long = "completions", value_name = "SHELL", num_args = 0..=1, hide_possible_values = true)]
    completions: Option<Option<Shell>>,
}

pub fn run() -> ExitCode {
    let cli = Cli::parse();
    if let Some(shell) = cli.completions {
        return completions(shell);
    }
    // Bare `launder` at a terminal would wait forever for input.
    if cli.files.is_empty() && io::stdin().is_terminal() {
        let _ = Cli::command().write_help(&mut io::stderr());
        return ExitCode::from(2);
    }
    match execute(&cli) {
        Ok(scrubbed) if scrubbed && cli.check => ExitCode::from(1),
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("launder: {}", tilde(&format!("{e:#}")));
            ExitCode::from(2)
        }
    }
}

/// `msg` with `$HOME/` shown as `~/`: an error that echoes an input path
/// must not leak the home dir into a `2>&1 | pbcopy`.
fn tilde(msg: &str) -> String {
    match std::env::var("HOME") {
        Ok(home) if !home.trim_end_matches('/').is_empty() => {
            msg.replace(&format!("{}/", home.trim_end_matches('/')), "~/")
        }
        _ => msg.to_string(),
    }
}

/// Write the completion script — and nothing else — to stdout.
fn completions(shell: Option<Shell>) -> ExitCode {
    let Some(shell) = shell.or_else(Shell::from_env) else {
        eprintln!("launder: can't tell your shell from $SHELL; name it: --completions zsh");
        return ExitCode::from(2);
    };
    clap_complete::generate(shell, &mut Cli::command(), "launder", &mut io::stdout());
    ExitCode::SUCCESS
}

/// Launder the input; `Ok(true)` when anything was scrubbed.
fn execute(cli: &Cli) -> Result<bool> {
    let enabled = Config::resolve_types(cli.only.as_deref(), cli.except.as_deref())?;
    let cfg = Config {
        enabled,
        keep_private_ips: !cli.all_ips,
        with_originals: cli.with_originals,
        // Local identity ($USER / $HOME / hostname) is always used as signal —
        // a watchlist of known-identifying tokens, never pinned. Offline.
        watchlist: Watchlist::from_env(),
        watch: watch_terms(cli)?,
        keep: cli.keep.clone(),
    };
    let format = if cli.dry_run {
        Format::Preview
    } else if cli.json {
        Format::Json
    } else if cli.ndjson {
        Format::Ndjson
    } else {
        Format::Text
    };

    let mut reader = LineReader::new(&cli.files)?;
    let out = open_output(cli.output.as_deref(), &cli.files, reader.reads_stdin())?;
    let mut emitter = Emitter::new(out, format, cfg.with_originals);
    let mut engine = Engine::new(cfg);
    let mut report = Report::new();

    loop {
        if reader.would_block() {
            emitter.flush()?;
        }
        let line = match reader.read()? {
            None => break,
            Some(Input::Line(line)) => line,
            Some(Input::End(_)) => continue,
        };
        let result = engine.process_line(&line);
        report.record(&result.findings);
        emitter.line(&result)?;
    }
    if let Some(n) = engine.finish() {
        let lines = if n == 1 { "line" } else { "lines" };
        eprintln!("launder: unterminated private key; {n} {lines} suppressed to the end of input");
    }
    emitter.finish(&report)?;

    if cli.report {
        eprintln!("{}", report.render());
    }
    Ok(report.total() > 0)
}

/// `$LAUNDER_WATCH` (set once in a shell rc) plus the `--watch` values, each
/// split on commas and whitespace.
fn watch_terms(cli: &Cli) -> Result<Vec<String>> {
    let split = |s: &str| -> Vec<String> {
        s.split(|c: char| c == ',' || c.is_whitespace())
            .filter(|t| !t.is_empty())
            .map(str::to_string)
            .collect()
    };
    let env = std::env::var_os("LAUNDER_WATCH").unwrap_or_default();
    let env = env.to_str().map(Cow::Borrowed).unwrap_or_else(|| {
        // Lossy, like input lines, so a term still matches the text it names.
        eprintln!("launder: LAUNDER_WATCH is not valid UTF-8; reading it lossily");
        env.to_string_lossy()
    });
    let mut terms = split(&env);
    for value in &cli.watch {
        let found = split(value);
        if found.is_empty() {
            anyhow::bail!("--watch {value:?} names no term");
        }
        terms.extend(found);
    }
    if let Some(t) = terms.iter().find(|t| !t.chars().any(char::is_alphanumeric)) {
        anyhow::bail!("--watch {t:?} has nothing to match; name a word or domain");
    }
    Ok(terms)
}

fn open_output(path: Option<&str>, inputs: &[String], stdin: bool) -> Result<Box<dyn Write>> {
    match path {
        None | Some("-") => Ok(Box::new(BufWriter::new(io::stdout()))),
        Some(p) => {
            // Creating the output truncates it before the input is read.
            if let Some(input) = inputs.iter().find(|i| same_file(p, i)) {
                anyhow::bail!("-o {p} is also an input ({input}); write somewhere else");
            }
            if stdin && is_stdin(p) {
                anyhow::bail!("-o {p} is also an input (stdin); write somewhere else");
            }
            let f = File::create(p).map_err(|e| anyhow::anyhow!("writing {p}: {e}"))?;
            Ok(Box::new(BufWriter::new(f)))
        }
    }
}

/// Whether two paths name one existing file, through any alias or hard link.
#[cfg(unix)]
fn same_file(a: &str, b: &str) -> bool {
    use std::os::unix::fs::MetadataExt;
    match (std::fs::metadata(a), std::fs::metadata(b)) {
        (Ok(a), Ok(b)) => a.dev() == b.dev() && a.ino() == b.ino(),
        _ => false,
    }
}

/// Whether `path` is the file stdin is redirected from (`< path`).
#[cfg(unix)]
fn is_stdin(path: &str) -> bool {
    use std::os::fd::AsFd;
    use std::os::unix::fs::MetadataExt;
    let stdin = io::stdin().as_fd().try_clone_to_owned().map(File::from);
    match (std::fs::metadata(path), stdin.and_then(|f| f.metadata())) {
        (Ok(a), Ok(b)) => a.dev() == b.dev() && a.ino() == b.ino(),
        _ => false,
    }
}

#[cfg(not(unix))]
fn is_stdin(_path: &str) -> bool {
    false
}

#[cfg(not(unix))]
fn same_file(a: &str, b: &str) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every `launder …` in the --help examples still parses.
    #[test]
    fn help_examples_parse() {
        let examples = AFTER_HELP
            .split("Examples:\n")
            .nth(1)
            .and_then(|s| s.split("\n\n").next())
            .unwrap();
        let mut seen = 0;
        for line in examples.lines() {
            let command = line.trim().split("  ").next().unwrap();
            for stage in command.split('|').map(str::trim) {
                if stage.starts_with("launder") {
                    let args = stage.split_whitespace();
                    if let Err(e) = Cli::try_parse_from(args) {
                        panic!("example `{stage}` no longer parses: {e}");
                    }
                    seen += 1;
                }
            }
        }
        assert!(seen >= 4, "examples not found in AFTER_HELP");
    }

    #[test]
    fn completions_carry_each_shells_marker() {
        for (shell, marker) in [
            (Shell::Bash, "complete -F"),
            (Shell::Zsh, "compdef"),
            (Shell::Fish, "complete -c"),
        ] {
            let mut out = Vec::new();
            clap_complete::generate(shell, &mut Cli::command(), "launder", &mut out);
            let script = String::from_utf8(out).unwrap();
            assert!(script.contains(marker), "{shell}: missing {marker}");
        }
    }
}
