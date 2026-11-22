//! Streaming, line-oriented input over stdin and files. One line in
//! flight; works on `tail -f`. Files are read in order; stdin is used when no
//! files are given.

use std::fs::File;
use std::io::{self, BufRead, BufReader, Read};

use anyhow::{Context, Result};

/// A source of lines: stdin or a sequence of files, read lazily.
pub struct LineReader {
    sources: Vec<Source>,
    current: Option<BufReader<Box<dyn Read>>>,
}

enum Source {
    Stdin,
    File(String),
}

impl LineReader {
    /// Build a reader over `files`, or stdin if `files` is empty.
    pub fn new(files: &[String]) -> Self {
        let sources = if files.is_empty() {
            vec![Source::Stdin]
        } else {
            files.iter().cloned().map(Source::File).collect()
        };
        LineReader {
            sources: sources.into_iter().rev().collect(),
            current: None,
        }
    }

    /// True when no complete line is buffered, so the next read may block
    /// (a pipe from `tail -f`): flush pending output first.
    pub fn would_block(&self) -> bool {
        self.current
            .as_ref()
            .is_none_or(|r| memchr::memchr(b'\n', r.buffer()).is_none())
    }

    /// Read the next line without its trailing newline. `Ok(None)` at EOF.
    pub fn next_line(&mut self) -> Result<Option<String>> {
        loop {
            if self.current.is_none() {
                match self.sources.pop() {
                    None => return Ok(None),
                    Some(Source::Stdin) => {
                        self.current = Some(BufReader::new(Box::new(io::stdin())));
                    }
                    Some(Source::File(path)) => {
                        let f = File::open(&path).with_context(|| format!("reading {path}"))?;
                        self.current = Some(BufReader::new(Box::new(f)));
                    }
                }
            }

            let reader = self.current.as_mut().unwrap();
            let mut buf = Vec::new();
            let n = reader
                .read_until(b'\n', &mut buf)
                .context("reading input")?;
            if n == 0 {
                self.current = None;
                continue;
            }
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
            return Ok(Some(line));
        }
    }
}
