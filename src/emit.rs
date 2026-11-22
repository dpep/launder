//! Output writers — laundered text, the `--dry-run` preview, and JSON — and
//! the secret rule.
//!
//! **Hard rule (overrides `--with-originals`):** a secret's original text is
//! never written, in any format. [`revealable`] is the one place that decides.

use std::collections::BTreeMap;
use std::io::{self, Write};

use serde::Serialize;
use serde_json::Value;

use crate::detect::Kind;
use crate::engine::{Finding, LineResult};
use crate::report::Report;

/// What stdout carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// The laundered text.
    Text,
    /// One aligned line per replacement, instead of the text (`-n`).
    Preview,
    /// One pretty JSON document at EOF (`-j`).
    Json,
    /// One compact JSON row per line, then a summary line (`-J`).
    Ndjson,
}

/// A finding's original text, unless it is a secret.
pub fn revealable(f: &Finding) -> Option<&str> {
    (!f.kind.is_secret()).then_some(f.original.as_str())
}

/// One output line: its input line number, laundered text, and what changed.
#[derive(Debug, Serialize)]
struct Row {
    line: usize,
    text: String,
    findings: Vec<FindingOut>,
}

#[derive(Debug, Serialize)]
struct FindingOut {
    #[serde(rename = "type")]
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    subtype: Option<&'static str>,
    col: usize,
    len: usize,
    replacement: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    original: Option<String>,
}

impl FindingOut {
    fn new(f: &Finding, with_originals: bool) -> Self {
        FindingOut {
            kind: f.kind.as_str(),
            subtype: f.subtype,
            col: f.col,
            len: f.len,
            replacement: f.replacement.clone(),
            original: revealable(f).filter(|_| with_originals).map(str::to_string),
        }
    }
}

#[derive(Debug, Serialize)]
struct Summary<'a> {
    total: usize,
    by_type: &'a BTreeMap<&'static str, usize>,
}

/// Serialize one finding as it appears in a JSON row.
pub fn finding_to_json(f: &Finding, with_originals: bool) -> Value {
    serde_json::to_value(FindingOut::new(f, with_originals)).expect("plain data")
}

/// Writes each laundered line in the chosen format.
pub struct Emitter<W: Write> {
    out: W,
    format: Format,
    with_originals: bool,
    /// `-j` rows, held until [`Emitter::finish`].
    rows: Vec<Row>,
}

impl<W: Write> Emitter<W> {
    pub fn new(out: W, format: Format, with_originals: bool) -> Self {
        Emitter {
            out,
            format,
            with_originals,
            rows: Vec::new(),
        }
    }

    /// Emit one line. A suppressed line (private-key body) writes nothing.
    pub fn line(&mut self, r: &LineResult) -> io::Result<()> {
        match self.format {
            Format::Text => {
                if let Some(text) = &r.output {
                    writeln!(self.out, "{text}")?;
                }
            }
            Format::Preview => {
                for f in &r.findings {
                    writeln!(self.out, "{}", preview(f))?;
                }
            }
            Format::Json | Format::Ndjson => {
                let Some(text) = &r.output else {
                    return Ok(());
                };
                let row = Row {
                    line: r.line,
                    text: text.clone(),
                    findings: r
                        .findings
                        .iter()
                        .map(|f| FindingOut::new(f, self.with_originals))
                        .collect(),
                };
                if self.format == Format::Json {
                    self.rows.push(row);
                } else {
                    serde_json::to_writer(&mut self.out, &row)?;
                    writeln!(self.out)?;
                }
            }
        }
        Ok(())
    }

    pub fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }

    /// Write whatever closes the format (the `-j` document, the `-J` summary
    /// line) and flush.
    pub fn finish(mut self, report: &Report) -> io::Result<()> {
        let summary = Summary {
            total: report.total(),
            by_type: report.counts(),
        };
        match self.format {
            Format::Text | Format::Preview => {}
            Format::Json => {
                #[derive(Serialize)]
                struct Doc<'a> {
                    lines: Vec<Row>,
                    summary: Summary<'a>,
                }
                let doc = Doc {
                    lines: std::mem::take(&mut self.rows),
                    summary,
                };
                serde_json::to_writer_pretty(&mut self.out, &doc)?;
                writeln!(self.out)?;
            }
            Format::Ndjson => {
                #[derive(Serialize)]
                struct Tail<'a> {
                    summary: Summary<'a>,
                }
                serde_json::to_writer(&mut self.out, &Tail { summary })?;
                writeln!(self.out)?;
            }
        }
        self.out.flush()
    }
}

/// `12:5     email   ops@dpep.io → <EMAIL_1>`. A secret shows its subtype in
/// brackets, never its text.
fn preview(f: &Finding) -> String {
    let width = Kind::ALL
        .map(|k| k.as_str().len())
        .into_iter()
        .max()
        .unwrap_or(0);
    let shown = match revealable(f) {
        Some(original) => original.to_string(),
        None => format!("[{}]", f.subtype.unwrap_or(f.kind.as_str())),
    };
    format!(
        "{:<7}  {:<width$}  {shown} → {}",
        format!("{}:{}", f.line, f.col),
        f.kind.as_str(),
        f.replacement
    )
}
