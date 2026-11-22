//! Command-line surface: wire cli → reader → engine → emitter.

use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::process::ExitCode;

use anyhow::Result;
use clap::Parser;
use serde_json::json;

use crate::config::{self, Config};
use crate::emit;
use crate::engine::{Engine, Finding};
use crate::input::{Input, LineReader};
use crate::report::Report;
use crate::watchlist::Watchlist;

/// Scrub identifying paths, secrets, and contacts from logs and stack traces,
/// keeping everything a reader needs to help.
#[derive(Debug, Parser)]
#[command(name = "launder", version, about)]
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

    /// Detect and report, but pass input through unchanged.
    #[arg(short = 'n', long = "dry-run")]
    dry_run: bool,

    /// Buffered JSON: one object {laundered, findings, summary}.
    #[arg(short = 'j', long = "json", conflicts_with = "ndjson")]
    json: bool,

    /// Streaming NDJSON: one finding per line, as encountered.
    #[arg(short = 'J', long = "ndjson")]
    ndjson: bool,

    /// Include original values in JSON (never for secrets).
    #[arg(long = "with-originals")]
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

enum Mode {
    Text,
    Json,
    Ndjson,
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
    let mode = if cli.json {
        Mode::Json
    } else if cli.ndjson {
        Mode::Ndjson
    } else {
        Mode::Text
    };

    let mut engine = Engine::new(cfg.clone());
    let mut reader = LineReader::new(&cli.files);
    let mut out = open_output(cli.output.as_deref(), &cli.files)?;
    let mut report = Report::new();

    // Accumulators for buffered JSON mode.
    let mut laundered = String::new();
    let mut all_findings: Vec<Finding> = Vec::new();

    loop {
        if reader.would_block() {
            out.flush()?;
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

        match mode {
            Mode::Text => {
                if cli.dry_run {
                    writeln!(out, "{line}")?;
                } else if let Some(text) = &result.output {
                    writeln!(out, "{text}")?;
                }
            }
            Mode::Ndjson => {
                for f in &result.findings {
                    let value = emit::finding_to_json(f, cfg.with_originals);
                    writeln!(out, "{value}")?;
                }
            }
            Mode::Json => {
                if cli.dry_run {
                    laundered.push_str(&line);
                    laundered.push('\n');
                } else if let Some(text) = &result.output {
                    laundered.push_str(text);
                    laundered.push('\n');
                }
                all_findings.extend(result.findings);
            }
        }
    }

    if let Mode::Json = mode {
        let findings: Vec<_> = all_findings
            .iter()
            .map(|f| emit::finding_to_json(f, cfg.with_originals))
            .collect();
        let obj = json!({
            "laundered": laundered,
            "findings": findings,
            "summary": emit::summary_to_json(&report),
        });
        writeln!(out, "{obj}")?;
    }

    out.flush()?;

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
