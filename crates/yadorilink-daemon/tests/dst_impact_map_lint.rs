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

/// `impact_map.toml`'s `[modules]` table has always described
/// `yadorilink-sync-core`'s own `src/*.rs` modules -- the harness's actual
/// subject under test (`SyncState` and friends), not whichever crate
/// happens to physically host `dst_support/` and this lint. `dst_support/`
/// itself (and this lint with it) moved to `yadorilink-daemon` in Phase
/// 7D-10.4, but the map's *content* did not change meaning -- so this
/// checks `yadorilink-sync-core/src`, a sibling crate directory, rather
/// than `crate_root()`, which would silently start auditing
/// `yadorilink-daemon`'s own unrelated production modules
/// (`commit_orchestration`, `gc`, ...) that the DST harness never covered.
fn sync_core_root() -> PathBuf {
    crate_root().join("../yadorilink-sync-core")
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
    rs_stems(&sync_core_root().join("src"), |stem| !NON_MODULE_SRC.contains(&stem))
}

/// A DST *scenario* for impact-map purposes is a `dst_*.rs` test file that
/// actually builds on the shared `dst_support` harness (`mod dst_support;`)
/// -- the same content-based test Phase 7D-10.4 gave `xtask`'s own
/// `discover_scenarios()`, for the identical reason. Since the harness's
/// scenario files now split across two crates (most moved to
/// `yadorilink-daemon` in this same pass; `dst_peer_reconcile_race`
/// deliberately stayed in `yadorilink-sync-core`, deferred to
/// `peer_session.rs`'s own migration pass), this scans both `tests/`
/// directories rather than only `crate_root()`'s. The content filter (not a
/// name glob) is what correctly excludes `yadorilink-daemon`'s own
/// pre-existing, unrelated `dst_daemon_*.rs` integration tests (a different
/// harness that predates this move and was never described by this map)
/// and `dst_materialization_crash_recovery.rs` (moved to
/// `yadorilink-filesystem-sync`; never used `dst_support`, so it was never
/// really a "scenario" by this map's own definition even before the move).
fn actual_scenarios() -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for dir in [crate_root().join("tests"), sync_core_root().join("tests")] {
        for stem in rs_stems(&dir, |stem| stem.starts_with("dst_") && !stem.ends_with("_lint")) {
            let path = dir.join(format!("{stem}.rs"));
            let source = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
            if source.lines().any(|l| l.trim() == "mod dst_support;") {
                out.insert(stem);
            }
        }
    }
    out
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

// `#[ignore]` on all four tests below (Phase 7D-10's final sync-core
// deletion pass): every one calls `sync_core_root()`/`actual_modules()`/
// `actual_scenarios()`, which read `crates/yadorilink-sync-core/src`+`tests`
// -- a directory this pass deletes outright, so `std::fs::read_dir` would
// panic rather than fail a clean assertion. This lint's whole premise
// (`impact_map.toml`'s `[modules]` table describes `yadorilink-sync-core`'s
// own modules) no longer has a subject to check. Deliberately NOT deleted
// or redesigned here: what "the impact map's module set" should mean with
// no `yadorilink-sync-core` crate is a real design question (does it track
// `yadorilink-daemon`'s own modules now? some other unit?), explicitly
// named as Phase 7E's "impact-map lint gap" item, not this pass's. Ignored,
// not removed, so `impact_map.toml` and this lint's structure stay in place
// for that redesign to build on.
#[test]
#[ignore = "reads deleted yadorilink-sync-core/src; redesigning this lint is Phase 7E's impact-map lint gap item"]
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
#[ignore = "see every_source_module_is_in_the_impact_map's #[ignore] reason"]
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
#[ignore = "reads deleted yadorilink-sync-core/tests via actual_scenarios(); see every_source_module_is_in_the_impact_map's #[ignore] reason"]
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
#[ignore = "reads deleted yadorilink-sync-core/tests via actual_scenarios(); see every_source_module_is_in_the_impact_map's #[ignore] reason"]
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
