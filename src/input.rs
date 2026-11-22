//! Streaming, line-oriented input over stdin and files. One line in
//! flight; works on `tail -f`. Files are read in order; stdin is used when no
//! files are given.

use std::fs::File;
use std::io::{self, BufRead, BufReader, Read};

use anyhow::{Context, Result};

/// What the reader yields: a line, or the end of one input source.
#[derive(Debug, PartialEq, Eq)]
pub enum Input {
    /// A line without its trailing newline.
    Line(String),
    /// A source is exhausted: a chance to flush before the next one blocks.
    End,
}

/// A source of lines: stdin or a sequence of files, read lazily.
pub struct LineReader {
    /// Sources not yet started, last first.
    sources: Vec<(String, Box<dyn Read>)>,
    current: Option<(String, BufReader<Box<dyn Read>>)>,
    /// Lines read from the current source.
    line: usize,
    reads_stdin: bool,
}

impl LineReader {
    /// Build a reader over `files` (`-` is stdin), or stdin if `files` is
    /// empty. Every file is opened up front, so a missing one fails before
    /// any output is made.
    pub fn new(files: &[String]) -> Result<Self> {
        let stdin = || -> (String, Box<dyn Read>) { ("stdin".into(), Box::new(io::stdin())) };
        let sources = if files.is_empty() {
            vec![stdin()]
        } else {
            files
                .iter()
                .rev()
                .map(|path| {
                    if path == "-" {
                        return Ok(stdin());
                    }
                    let f = File::open(path).with_context(|| format!("reading {path}"))?;
                    Ok((path.clone(), Box::new(f) as Box<dyn Read>))
                })
                .collect::<Result<_>>()?
        };
        Ok(LineReader {
            sources,
            current: None,
            line: 0,
            reads_stdin: files.is_empty() || files.iter().any(|f| f == "-"),
        })
    }

    /// Whether any input is stdin.
    pub fn reads_stdin(&self) -> bool {
        self.reads_stdin
    }

    /// True when no complete line is buffered, so the next read may block
    /// (a pipe from `tail -f`): flush pending output first.
    pub fn would_block(&self) -> bool {
        self.current
            .as_ref()
            .is_none_or(|(_, r)| memchr::memchr(b'\n', r.buffer()).is_none())
    }

    /// Where the last line read came from: `FILE:LINE`.
    pub fn position(&self) -> Option<String> {
        let (name, _) = self.current.as_ref()?;
        Some(format!("{name}:{}", self.line))
    }

    /// The next line or source boundary. `Ok(None)` once every source is done.
    pub fn read(&mut self) -> Result<Option<Input>> {
        if self.current.is_none() {
            let Some((name, source)) = self.sources.pop() else {
                return Ok(None);
            };
            self.current = Some((name, BufReader::new(source)));
            self.line = 0;
        }

        let (name, reader) = self.current.as_mut().unwrap();
        let mut buf = Vec::new();
        let n = reader
            .read_until(b'\n', &mut buf)
            .with_context(|| format!("reading {name}"))?;
        if n == 0 {
            self.current = None;
            return Ok(Some(Input::End));
        }
        self.line += 1;
        // Strip a single trailing \n (and \r) — restored by the caller.
        if buf.ends_with(b"\n") {
            buf.pop();
            if buf.ends_with(b"\r") {
                buf.pop();
            }
        }
        // Invalid UTF-8 becomes U+FFFD; the valid text around it is still
        // scanned, and no raw byte of unknown meaning reaches the output.
        let line = match String::from_utf8(buf) {
            Ok(s) => s,
            Err(e) => String::from_utf8_lossy(e.as_bytes()).into_owned(),
        };
        Ok(Some(Input::Line(line)))
    }
}
