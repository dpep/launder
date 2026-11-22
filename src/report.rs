//! `--report` summary: counts by type, accumulated across the run and
//! written to stderr so it never pollutes the laundered stdout.

use std::collections::BTreeMap;

use crate::config;
use crate::detect::Kind;
use crate::engine::Finding;

#[derive(Debug, Default)]
pub struct Report {
    counts: BTreeMap<&'static str, usize>,
    /// Secrets by subtype (`github`, `jwt`, …): which kinds of credential.
    secrets: BTreeMap<&'static str, usize>,
    total: usize,
}

impl Report {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, findings: &[Finding]) {
        for f in findings {
            *self.counts.entry(f.kind.as_str()).or_insert(0) += 1;
            if f.kind.is_secret() {
                *self
                    .secrets
                    .entry(f.subtype.unwrap_or("other"))
                    .or_insert(0) += 1;
            }
            self.total += 1;
        }
    }

    pub fn counts(&self) -> &BTreeMap<&'static str, usize> {
        &self.counts
    }

    pub fn total(&self) -> usize {
        self.total
    }

    /// A total, then one aligned line per type; secrets list their subtypes.
    pub fn render(&self) -> String {
        if self.total == 0 {
            return "launder: nothing to scrub".to_string();
        }
        let noun = if self.total == 1 {
            "replacement"
        } else {
            "replacements"
        };
        let width = config::kind_width();
        let mut lines = vec![format!("launder: {} {noun}", self.total)];
        for (kind, count) in &self.counts {
            let mut line = format!("  {kind:<width$}  {count}");
            if *kind == Kind::Secret.as_str() {
                let parts: Vec<String> = self
                    .secrets
                    .iter()
                    .map(|(s, n)| format!("{s} {n}"))
                    .collect();
                line.push_str(&format!("  ({})", parts.join(", ")));
            }
            lines.push(line);
        }
        lines.join("\n")
    }
}
