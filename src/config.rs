//! Resolved run configuration: the CLI flags reduced to the knobs the engine
//! and detectors actually read.

use std::collections::HashSet;

use anyhow::{Result, bail};

use crate::system::SystemInfo;

/// A scrub category, toggled by `--only` / `--except` (§4). `Keep`
/// (diagnostic-ID preservation) is not a scrub type and is always on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TypeGroup {
    Path,
    Secret,
    Email,
    Ip,
    Host,
    Mac,
    User,
}

impl TypeGroup {
    const ALL: [TypeGroup; 7] = [
        TypeGroup::Path,
        TypeGroup::Secret,
        TypeGroup::Email,
        TypeGroup::Ip,
        TypeGroup::Host,
        TypeGroup::Mac,
        TypeGroup::User,
    ];

    fn parse(s: &str) -> Result<TypeGroup> {
        Ok(match s.trim().to_ascii_lowercase().as_str() {
            "path" => TypeGroup::Path,
            "secret" => TypeGroup::Secret,
            "email" => TypeGroup::Email,
            "ip" => TypeGroup::Ip,
            "host" => TypeGroup::Host,
            "mac" => TypeGroup::Mac,
            "user" => TypeGroup::User,
            other => bail!("unknown type: {other} (want path,secret,email,ip,host,mac,user)"),
        })
    }

    fn parse_list(s: &str) -> Result<HashSet<TypeGroup>> {
        s.split(',')
            .filter(|p| !p.trim().is_empty())
            .map(TypeGroup::parse)
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub enabled: HashSet<TypeGroup>,
    pub keep_system: bool,
    pub keep_private_ips: bool,
    pub with_originals: bool,
    pub system: Option<SystemInfo>,
}

impl Config {
    /// Resolve `--only` / `--except` into the active type set.
    pub fn resolve_types(only: Option<&str>, except: Option<&str>) -> Result<HashSet<TypeGroup>> {
        if only.is_some() && except.is_some() {
            bail!("--only and --except are mutually exclusive");
        }
        if let Some(list) = only {
            return TypeGroup::parse_list(list);
        }
        let mut all: HashSet<TypeGroup> = TypeGroup::ALL.into_iter().collect();
        if let Some(list) = except {
            for t in TypeGroup::parse_list(list)? {
                all.remove(&t);
            }
        }
        Ok(all)
    }

    pub fn enabled(&self, group: TypeGroup) -> bool {
        self.enabled.contains(&group)
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            enabled: TypeGroup::ALL.into_iter().collect(),
            keep_system: true,
            keep_private_ips: true,
            with_originals: false,
            system: None,
        }
    }
}
