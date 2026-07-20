//! Completeness lint for
//! `tests/dst_support/impact_map.toml`.
//!
//! Deliberately NOT `#![cfg(madsim)]`: this is pure file inspection (no
//! simulated scheduler, no network), so it compiles and runs under a plain
//! `cargo test` and thus guards the map on every CI run — the map "cannot
//! silently rot" (the design). It checks both directions:
//!  - every `src/*.rs` top-level module has a `[modules]` entry, and every
//!    `[modules]` key names a module file that exists;
//!  - every `tests/dst_*.rs` scenario has a `[scenarios]` entry, and every
//!    `[scenarios]` key (and every scenario referenced from `[modules]`)
//!    names a scenario file that exists.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use toml::Value;

/// `src/*.rs` stems that are not sync-core "modules" for impact-map purposes.
const NON_MODULE_SRC: &[&str] = &["lib"];

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_map() -> Value {
    let path = crate_root().join("tests/dst_support/impact_map.toml");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read impact_map.toml at {}: {e}", path.display()));
    text.parse::<Value>().unwrap_or_else(|e| panic!("impact_map.toml is not valid TOML: {e}"))
}

/// Top-level `.rs` file stems under `dir` matching `pred`.
fn rs_stems(dir: &Path, pred: impl Fn(&str) -> bool) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for entry in
        std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display()))
    {
        let entry = entry.unwrap();
        if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if let Some(stem) = name.strip_suffix(".rs") {
            if pred(stem) {
                out.insert(stem.to_string());
            }
        }
    }
    out
}

fn actual_modules() -> BTreeSet<String> {
    rs_stems(&crate_root().join("src"), |stem| !NON_MODULE_SRC.contains(&stem))
}

fn actual_scenarios() -> BTreeSet<String> {
    // A DST *scenario* is a `dst_*.rs` test file. Sibling `dst_*_lint.rs`
    // helpers (this file, the runbook freshness lint) share the prefix but
    // are plain guard tests, not scenarios — exclude them by the `_lint`
    // suffix. (Most scenarios are `#![cfg(madsim)]`-gated, but not all —
    // `dst_materialization_crash_recovery` is a plain test — so the gate is
    // not a reliable discriminator; the `_lint` suffix is.)
    rs_stems(&crate_root().join("tests"), |stem| {
        stem.starts_with("dst_") && !stem.ends_with("_lint")
    })
}

fn mapped_modules(map: &Value) -> BTreeSet<String> {
    map.get("modules")
        .and_then(Value::as_table)
        .expect("impact_map.toml is missing a [modules] table")
        .keys()
        .cloned()
        .collect()
}

fn mapped_scenarios(map: &Value) -> BTreeSet<String> {
    map.get("scenarios")
        .and_then(Value::as_table)
        .expect("impact_map.toml is missing a [scenarios] table")
        .keys()
        .cloned()
        .collect()
}

/// Every scenario name referenced from a `[modules]` value.
fn scenarios_referenced_by_modules(map: &Value) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    if let Some(table) = map.get("modules").and_then(Value::as_table) {
        for scenarios in table.values() {
            if let Some(list) = scenarios.as_array() {
                for s in list {
                    if let Some(name) = s.as_str() {
                        out.insert(name.to_string());
                    }
                }
            }
        }
    }
    out
}

#[test]
fn every_source_module_is_in_the_impact_map() {
    let map = read_map();
    let actual = actual_modules();
    let mapped = mapped_modules(&map);

    let missing: Vec<_> = actual.difference(&mapped).collect();
    assert!(
        missing.is_empty(),
        "src modules absent from impact_map.toml [modules]: {missing:?} — add each with the \
         scenarios that exercise it (empty list `[]` if none yet)"
    );
}

#[test]
fn impact_map_names_no_phantom_module() {
    let map = read_map();
    let actual = actual_modules();
    let mapped = mapped_modules(&map);

    let phantom: Vec<_> = mapped.difference(&actual).collect();
    assert!(
        phantom.is_empty(),
        "[modules] keys with no matching src/*.rs file: {phantom:?} — a module was renamed or \
         removed; update impact_map.toml"
    );
}

#[test]
fn every_dst_scenario_is_in_the_impact_map() {
    let map = read_map();
    let actual = actual_scenarios();
    let mapped = mapped_scenarios(&map);

    let missing: Vec<_> = actual.difference(&mapped).collect();
    assert!(
        missing.is_empty(),
        "dst_*.rs scenarios absent from impact_map.toml [scenarios]: {missing:?} — add each with \
         the oracle kinds it asserts"
    );
}

#[test]
fn impact_map_names_no_phantom_scenario() {
    let map = read_map();
    let actual = actual_scenarios();
    let mapped = mapped_scenarios(&map);
    let referenced = scenarios_referenced_by_modules(&map);

    let phantom_keys: Vec<_> = mapped.difference(&actual).collect();
    assert!(
        phantom_keys.is_empty(),
        "[scenarios] keys with no matching tests/dst_*.rs file: {phantom_keys:?}"
    );

    let phantom_refs: Vec<_> = referenced.difference(&actual).collect();
    assert!(
        phantom_refs.is_empty(),
        "[modules] references scenarios with no matching tests/dst_*.rs file: {phantom_refs:?}"
    );
}
