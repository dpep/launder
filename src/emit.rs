//! Structured-output writers and the §7 secret rule.
//!
//! **Hard rule (overrides `--with-originals`):** `original` is never emitted for
//! a secret. For non-secret types it is omitted by default and included only
//! under `--with-originals`. The whole point of launder is defeated if a secret
//! reappears in the JSON.

use serde_json::{Value, json};

use crate::engine::Finding;
use crate::report::Report;

/// Serialize one finding, honoring the secret rule and `--with-originals`.
pub fn finding_to_json(f: &Finding, with_originals: bool) -> Value {
    let mut obj = json!({
        "type": f.kind.type_str(),
        "line": f.line,
        "col": f.col,
        "len": f.len,
        "replacement": f.replacement,
    });
    if let Some(subtype) = f.subtype {
        obj["subtype"] = json!(subtype);
    }
    if with_originals && !f.kind.is_secret() {
        obj["original"] = json!(f.original);
    }
    obj
}

/// The `summary` object: per-type counts and a total.
pub fn summary_to_json(report: &Report) -> Value {
    let mut counts = serde_json::Map::new();
    for (kind, count) in report.counts() {
        counts.insert((*kind).to_string(), json!(count));
    }
    json!({
        "total": report.total(),
        "by_type": Value::Object(counts),
    })
}
