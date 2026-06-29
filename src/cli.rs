//! Command-line surface (§4): wire cli → reader → engine → emitter.

use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::process::ExitCode;

use anyhow::Result;
use clap::Parser;
use serde_json::json;

use crate::config::Config;
use crate::emit;
use crate::engine::{Engine, Finding};
use crate::input::LineReader;
use crate::report::Report;
use crate::system;

/// Make logs pastesafe — scrub identifying paths, secrets, and contacts from
/// diagnostic output while keeping everything a reader needs to help.
#[derive(Debug, Parser)]
#[command(name = "launder", version, about)]
struct Cli {
    /// Input files (stdin if none).
    files: Vec<String>,

    /// Write laundered output to FILE (default: stdout).
    #[arg(short = 'o', long = "output", value_name = "FILE")]
    output: Option<String>,

    /// Use local identity sources ($HOME/$USER, /etc/passwd, hostname) for exact
    /// detection. Still fully offline.
    #[arg(long = "system")]
    system: bool,

    /// Keep OS paths (/usr, /bin, /etc, …). Default: on.
    #[arg(long = "keep-system", overrides_with = "no_keep_system")]
    keep_system: bool,

    /// Scrub system paths too.
    #[arg(long = "no-keep-system", overrides_with = "keep_system")]
    no_keep_system: bool,

    /// Keep loopback + RFC1918 IPs. Default: on.
    #[arg(long = "keep-private-ips", overrides_with = "all_ips")]
    keep_private_ips: bool,

    /// Scrub private / loopback IPs as well.
    #[arg(long = "all-ips", overrides_with = "keep_private_ips")]
    all_ips: bool,

    /// Only these types (comma list): path,secret,email,ip,host,mac,user.
    #[arg(long = "only", value_name = "TYPES", conflicts_with = "except")]
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
        keep_system: !cli.no_keep_system,
        keep_private_ips: !cli.all_ips,
        with_originals: cli.with_originals,
        system: if cli.system {
            Some(system::detect())
        } else {
            None
        },
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
    let mut out = open_output(cli.output.as_deref())?;
    let mut report = Report::new();

    // Accumulators for buffered JSON mode.
    let mut laundered = String::new();
    let mut all_findings: Vec<Finding> = Vec::new();

    while let Some(line) = reader.next_line()? {
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

fn open_output(path: Option<&str>) -> Result<Box<dyn Write>> {
    match path {
        None => Ok(Box::new(BufWriter::new(io::stdout()))),
        Some("-") => Ok(Box::new(BufWriter::new(io::stdout()))),
        Some(p) => {
            let f = File::create(p).map_err(|e| anyhow::anyhow!("writing {p}: {e}"))?;
            Ok(Box::new(BufWriter::new(f)))
        }
    }
}
