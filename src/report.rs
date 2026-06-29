//! `--report` summary (§6.6): counts by type, accumulated across the run and
//! written to stderr so it never pollutes the laundered stdout.

use std::collections::BTreeMap;

use crate::detect::Kind;
use crate::engine::Finding;

#[derive(Debug, Default)]
pub struct Report {
    counts: BTreeMap<&'static str, usize>,
    total: usize,
}

impl Report {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, findings: &[Finding]) {
        for f in findings {
            if f.kind == Kind::Keep {
                continue;
            }
            *self.counts.entry(f.kind.type_str()).or_insert(0) += 1;
            self.total += 1;
        }
    }

    pub fn counts(&self) -> &BTreeMap<&'static str, usize> {
        &self.counts
    }

    pub fn total(&self) -> usize {
        self.total
    }

    /// One line per type, plus a total. Empty when nothing changed.
    pub fn render(&self) -> String {
        if self.total == 0 {
            return "launder: nothing to scrub".to_string();
        }
        let mut lines = vec![format!("launder: {} replacement(s)", self.total)];
        for (kind, count) in &self.counts {
            lines.push(format!("  {kind}: {count}"));
        }
        lines.join("\n")
    }
}
