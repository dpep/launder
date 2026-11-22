//! Resolved run configuration: the CLI flags reduced to the knobs the engine
//! and detectors actually read.

use std::collections::HashSet;

use anyhow::{Result, bail};

use crate::detect::Kind;
use crate::watchlist::Watchlist;

#[derive(Debug, Clone)]
pub struct Config {
    pub enabled: HashSet<Kind>,
    pub keep_private_ips: bool,
    pub with_originals: bool,
    pub watchlist: Watchlist,
    /// `--watch` terms: scrubbed on sight.
    pub watch: Vec<String>,
    /// `--keep` terms: never scrubbed, unless a secret.
    pub keep: Vec<String>,
}

impl Config {
    /// Resolve `--only` / `--except` into the active type set.
    pub fn resolve_types(only: Option<&str>, except: Option<&str>) -> Result<HashSet<Kind>> {
        if only.is_some() && except.is_some() {
            bail!("--only and --except are mutually exclusive");
        }
        if let Some(list) = only {
            return parse_kinds(list);
        }
        let mut all: HashSet<Kind> = Kind::ALL.into_iter().collect();
        if let Some(list) = except {
            for t in parse_kinds(list)? {
                all.remove(&t);
            }
        }
        Ok(all)
    }

    pub fn enabled(&self, kind: Kind) -> bool {
        self.enabled.contains(&kind)
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            enabled: Kind::ALL.into_iter().collect(),
            keep_private_ips: true,
            with_originals: false,
            watchlist: Watchlist::default(),
            watch: Vec::new(),
            keep: Vec::new(),
        }
    }
}

/// The types `--only` / `--except` name. Not `term`: only `--watch` makes
/// one, and a named term is scrubbed whatever the filter says.
fn filterable() -> impl Iterator<Item = Kind> {
    Kind::ALL.into_iter().filter(|&k| k != Kind::Term)
}

/// The `--only` / `--except` vocabulary, comma-separated: `path,secret,…`.
pub fn kind_names() -> String {
    filterable().map(Kind::as_str).collect::<Vec<_>>().join(",")
}

/// The longest type name, for aligning human-readable columns.
pub fn kind_width() -> usize {
    Kind::ALL
        .map(|k| k.as_str().len())
        .into_iter()
        .max()
        .unwrap_or(0)
}

fn parse_kinds(list: &str) -> Result<HashSet<Kind>> {
    list.split(',')
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .map(|s| match filterable().find(|k| k.as_str() == s) {
            Some(kind) => Ok(kind),
            None => bail!("unknown type: {s} (want {})", kind_names()),
        })
        .collect()
}
