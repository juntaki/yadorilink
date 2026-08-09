//! Freshness lint for the
//! agent runbook (`tests/dst_support/AGENT.md`).
//!
//! A stale runbook is worse than none (the design), so this lint fails when the
//! runbook and the tooling drift apart. Like the impact-map lint it is a plain
//! (non-`#![cfg(madsim)]`) test, so it runs under every `cargo test`. It checks:
//!  - every `dst-*` cargo alias in `.cargo/config.toml` is documented in the
//!    runbook, and every `cargo dst-*` command the runbook shows is a real
//!    alias (both directions);
//!  - every `--flag` the runbook mentions exists literally in the `xtask`
//!    source or the cargo aliases (no fictional options).

use std::collections::BTreeSet;
use std::path::PathBuf;

use toml::Value;

fn workspace_root() -> PathBuf {
    // Manifest dir is crates/yadorilink-sync-core; the workspace root is two up.
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap()
}

fn read(path: PathBuf) -> String {
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

fn runbook() -> String {
    read(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/dst_support/AGENT.md"))
}

fn xtask_source() -> String {
    read(workspace_root().join("xtask/src/main.rs"))
}

fn cargo_config() -> String {
    read(workspace_root().join(".cargo/config.toml"))
}

/// The `dst-*` alias names defined in `.cargo/config.toml`.
fn defined_aliases() -> BTreeSet<String> {
    toml::from_str::<Value>(&cargo_config())
        .expect(".cargo/config.toml is not valid TOML")
        .get("alias")
        .and_then(Value::as_table)
        .expect(".cargo/config.toml has no [alias] table")
        .keys()
        .filter(|k| k.starts_with("dst-"))
        .cloned()
        .collect()
}

/// The `dst-*` alias names the runbook shows as `cargo dst-…` commands.
fn documented_aliases(runbook: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for (i, _) in runbook.match_indices("cargo dst-") {
        let rest = &runbook[i + "cargo ".len()..];
        let name: String =
            rest.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '-').collect();
        if !name.is_empty() {
            out.insert(name);
        }
    }
    out
}

/// Every `--flag` token appearing in `text`.
fn flag_tokens(text: &str) -> BTreeSet<String> {
    let bytes = text.as_bytes();
    let mut out = BTreeSet::new();
    let mut i = 0;
    while i + 2 < bytes.len() {
        let is_boundary = i == 0 || !bytes[i - 1].is_ascii_alphanumeric();
        if is_boundary
            && bytes[i] == b'-'
            && bytes[i + 1] == b'-'
            && bytes[i + 2].is_ascii_lowercase()
        {
            let start = i;
            i += 2;
            while i < bytes.len() && (bytes[i].is_ascii_lowercase() || bytes[i] == b'-') {
                i += 1;
            }
            out.insert(text[start..i].trim_end_matches('-').to_string());
        } else {
            i += 1;
        }
    }
    out
}

#[test]
fn every_defined_alias_is_documented_in_the_runbook() {
    let runbook = runbook();
    let documented = documented_aliases(&runbook);
    let defined = defined_aliases();
    let missing: Vec<_> = defined.difference(&documented).collect();
    assert!(
        missing.is_empty(),
        "cargo aliases defined in .cargo/config.toml but not documented in AGENT.md: {missing:?}"
    );
}

#[test]
fn every_documented_alias_actually_exists() {
    let runbook = runbook();
    let documented = documented_aliases(&runbook);
    let defined = defined_aliases();
    let phantom: Vec<_> = documented.difference(&defined).collect();
    assert!(
        phantom.is_empty(),
        "AGENT.md shows `cargo <alias>` commands with no matching .cargo/config.toml alias: \
         {phantom:?}"
    );
}

#[test]
fn every_runbook_flag_exists_in_the_tooling() {
    let runbook = runbook();
    // Flags may be defined in the xtask source (its own options) or in the
    // cargo aliases (flags forwarded to cargo, e.g. --cfg via RUSTFLAGS).
    let haystack = format!("{}\n{}", xtask_source(), cargo_config());
    let phantom: Vec<_> = flag_tokens(&runbook)
        .into_iter()
        .filter(|flag| !haystack.contains(flag.as_str()))
        .collect();
    assert!(
        phantom.is_empty(),
        "AGENT.md documents --flags that no longer exist in xtask/.cargo/config.toml: {phantom:?}"
    );
}
