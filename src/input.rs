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
    /// The named source is exhausted (`stdin` or the file path as given).
    End(String),
}

/// A source of lines: stdin or a sequence of files, read lazily.
pub struct LineReader {
    sources: Vec<String>,
    current: Option<(String, BufReader<Box<dyn Read>>)>,
    use_stdin: bool,
}

impl LineReader {
    /// Build a reader over `files`, or stdin if `files` is empty.
    pub fn new(files: &[String]) -> Self {
        LineReader {
            sources: files.iter().rev().cloned().collect(),
            current: None,
            use_stdin: files.is_empty(),
        }
    }

    /// True when no complete line is buffered, so the next read may block
    /// (a pipe from `tail -f`): flush pending output first.
    pub fn would_block(&self) -> bool {
        self.current
            .as_ref()
            .is_none_or(|(_, r)| memchr::memchr(b'\n', r.buffer()).is_none())
    }

    /// The next line or source boundary. `Ok(None)` once every source is done.
    pub fn read(&mut self) -> Result<Option<Input>> {
        if self.current.is_none() {
            let (name, source): (String, Box<dyn Read>) = if std::mem::take(&mut self.use_stdin) {
                ("stdin".into(), Box::new(io::stdin()))
            } else if let Some(path) = self.sources.pop() {
                let f = File::open(&path).with_context(|| format!("reading {path}"))?;
                (path, Box::new(f))
            } else {
                return Ok(None);
            };
            self.current = Some((name, BufReader::new(source)));
        }

        let (name, reader) = self.current.as_mut().unwrap();
        let mut buf = Vec::new();
        let n = reader
            .read_until(b'\n', &mut buf)
            .with_context(|| format!("reading {name}"))?;
        if n == 0 {
            let (name, _) = self.current.take().unwrap();
            return Ok(Some(Input::End(name)));
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
        Ok(Some(Input::Line(line)))
    }
}
