//! Command-line surface: wire cli → reader → engine → emitter.

use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::process::ExitCode;

use anyhow::Result;
use clap::{ArgGroup, Parser};

use crate::config::{self, Config};
use crate::emit::{Emitter, Format};
use crate::engine::Engine;
use crate::input::{Input, LineReader};
use crate::report::Report;
use crate::watchlist::Watchlist;

/// Scrub identifying paths, secrets, and contacts from logs and stack traces,
/// keeping everything a reader needs to help.
#[derive(Debug, Parser)]
#[command(name = "launder", version, about)]
#[command(group(ArgGroup::new("structured").args(["json", "ndjson"])))]
struct Cli {
    /// Input files (stdin if none).
    files: Vec<String>,

    /// Write laundered output to FILE (default: stdout).
    #[arg(short = 'o', long = "output", value_name = "FILE")]
    output: Option<String>,

    /// Scrub private / loopback IPs too (kept by default).
    #[arg(long = "all-ips")]
    all_ips: bool,

    #[arg(
        long = "only",
        value_name = "TYPES",
        conflicts_with = "except",
        help = format!("Only these types (comma list): {}",config::kind_names())
    )]
    only: Option<String>,

    /// Every type except these (comma list).
    #[arg(long = "except", value_name = "TYPES")]
    except: Option<String>,

    /// Print a summary of what changed (counts by type) to stderr.
    #[arg(short = 'r', long = "report")]
    report: bool,

    /// Preview each replacement instead of printing the text (shows originals).
    #[arg(short = 'n', long = "dry-run", conflicts_with_all = ["json", "ndjson"])]
    dry_run: bool,

    /// Pretty JSON: {lines: [{line, text, findings}], summary}, written at EOF.
    #[arg(short = 'j', long = "json", conflicts_with = "ndjson")]
    json: bool,

    /// Streaming JSON: one {line, text, findings} row per line, then a summary.
    #[arg(short = 'J', long = "ndjson")]
    ndjson: bool,

    /// Add each finding's original text to JSON (never for secrets).
    #[arg(long = "with-originals", requires = "structured")]
    with_originals: bool,
}

pub fn run() -> ExitCode {
    let cli = Cli::parse();
    match execute(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("launder: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn execute(cli: &Cli) -> Result<()> {
    let enabled = Config::resolve_types(cli.only.as_deref(), cli.except.as_deref())?;
    let cfg = Config {
        enabled,
        keep_private_ips: !cli.all_ips,
        with_originals: cli.with_originals,
        // Local identity ($USER / $HOME / hostname) is always used as signal —
        // a watchlist of known-identifying tokens, never pinned. Offline.
        watchlist: Watchlist::from_env(),
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

    let mut reader = LineReader::new(&cli.files);
    let out = open_output(cli.output.as_deref(), &cli.files)?;
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
            Some(Input::End(name)) => {
                if let Some(n) = engine.end_input() {
                    let lines = if n == 1 { "line" } else { "lines" };
                    eprintln!(
                        "launder: unterminated private key in {name}; {n} {lines} suppressed"
                    );
                }
                continue;
            }
        };
        let result = engine.process_line(&line);
        report.record(&result.findings);
        emitter.line(&result)?;
    }
    emitter.finish(&report)?;

    if cli.report {
        eprintln!("{}", report.render());
    }
    Ok(())
}

fn open_output(path: Option<&str>, inputs: &[String]) -> Result<Box<dyn Write>> {
    match path {
        None | Some("-") => Ok(Box::new(BufWriter::new(io::stdout()))),
        Some(p) => {
            // Creating the output truncates it before the input is read.
            if let Some(input) = inputs.iter().find(|i| same_file(p, i)) {
                anyhow::bail!("-o {p} is also an input ({input}); write somewhere else");
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

#[cfg(not(unix))]
fn same_file(a: &str, b: &str) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}
