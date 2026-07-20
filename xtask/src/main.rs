//! `cargo xtask` — the single documented entry point for DST replay and the
//! tiered test lanes.
//!
//! Every environment knob an agent would otherwise have to remember
//! (`RUSTFLAGS="--cfg madsim"`, `DST_SEED`, `DST_VARIATIONS`, scenario
//! selection) lives *inside* this tool, so the operator-facing surface is one
//! command. Invoked directly (`cargo run -p xtask -- <cmd>`) or via the cargo
//! aliases in `.cargo/config.toml` (`cargo dst-replay …`, `cargo dst-lane1`).
//!
//! Subcommands (kept in sync with `.cargo/config.toml` aliases and
//! `tests/dst_support/AGENT.md`; the runbook freshness lint enforces this):
//!  dst-replay <bundle|corpus-entry> [--until-divergence] [--trace <glob>]
//!  [--profile relaxed] [--scenario <name>]
//!  dst-lane0 harness units + watcher conformance
//!  dst-lane1 [--ops <n>] each scenario x 1 seed, reduced op budget
//!  dst-lane2 [--variations <n>] [--keep <n>] standard sweep + retention prune
//!  dst-prune [--keep <n>] prune old bundle/coverage artifacts

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use serde::Deserialize;

const MADSIM_RUSTFLAGS: &str = "--cfg madsim";
const SYNC_CORE: &str = "yadorilink-sync-core";
const DEFAULT_KEEP: usize = 20;
const DEFAULT_LANE1_OPS: usize = 4;

/// The subset of a failure bundle (or corpus JSONL entry) `dst-replay` needs to
/// reconstruct the run: which scenario binary and which seed. Everything else
/// in the bundle is reproduced *by* the replay, not read from the file.
#[derive(Debug, Deserialize)]
struct ReplayTarget {
    /// The scenario test-binary name, e.g. `dst_two_device_chaos`. Optional on
    /// older corpus entries; then `--scenario` is required.
    scenario: Option<String>,
    seed: u64,
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (cmd, rest) = match args.split_first() {
        Some((c, r)) => (c.as_str(), r),
        None => {
            usage();
            return ExitCode::FAILURE;
        }
    };

    let result = match cmd {
        "dst-replay" => cmd_replay(rest),
        "dst-lane0" => cmd_lane0(rest),
        "dst-lane1" => cmd_lane1(rest),
        "dst-lane2" => cmd_lane2(rest),
        "dst-prune" => cmd_prune(rest),
        "-h" | "--help" | "help" => {
            usage();
            Ok(())
        }
        other => Err(format!("unknown subcommand `{other}`\n\nrun `cargo xtask --help`")),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("xtask: {e}");
            ExitCode::FAILURE
        }
    }
}

fn usage() {
    eprintln!(
        "cargo xtask <command>\n\n\
         DST replay and lanes:\n\
         \x20 dst-replay <bundle|corpus-entry> [--until-divergence] [--trace <glob>] \
         [--profile relaxed] [--scenario <name>]\n\
         \x20 dst-lane0                              harness units + watcher conformance\n\
         \x20 dst-lane1 [--ops <n>]                  each scenario x 1 seed, reduced op budget\n\
         \x20 dst-lane2 [--variations <n>] [--keep <n>]   standard sweep + retention prune\n\
         \x20 dst-prune [--keep <n>]                 prune old bundle/coverage artifacts"
    );
}

// ---------------------------------------------------------------------------
// dst-replay
// ---------------------------------------------------------------------------

fn cmd_replay(args: &[String]) -> Result<(), String> {
    let mut path: Option<String> = None;
    let mut until_divergence = false;
    let mut trace: Option<String> = None;
    let mut profile = "standard".to_string();
    let mut scenario_override: Option<String> = None;

    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--until-divergence" => until_divergence = true,
            "--trace" => trace = Some(next_value(&mut it, "--trace")?),
            "--profile" => profile = next_value(&mut it, "--profile")?,
            "--scenario" => scenario_override = Some(next_value(&mut it, "--scenario")?),
            other if other.starts_with("--") => {
                return Err(format!("dst-replay: unknown flag `{other}`"))
            }
            other => {
                if path.is_some() {
                    return Err(format!("dst-replay: unexpected extra argument `{other}`"));
                }
                path = Some(other.to_string());
            }
        }
    }

    let path = path.ok_or("dst-replay: missing <bundle|corpus-entry> path")?;
    if profile != "standard" && profile != "relaxed" {
        return Err(format!(
            "dst-replay: --profile must be `standard` or `relaxed`, got `{profile}`"
        ));
    }

    let target = load_target(Path::new(&path))?;
    let scenario = scenario_override
        .or(target.scenario)
        .ok_or("dst-replay: bundle has no `scenario` field; pass --scenario <name>")?;
    let seed = target.seed;

    eprintln!(
        "dst-replay: scenario={scenario} seed={seed} profile={profile} \
         until_divergence={until_divergence} trace={}",
        trace.as_deref().unwrap_or("<none>")
    );

    let mut cmd = madsim_test(&scenario);
    cmd.arg("--").arg("single_seed_smoke").arg("--exact").arg("--nocapture");
    cmd.env("DST_SEED", seed.to_string());
    cmd.env("DST_PROFILE", &profile);
    if until_divergence {
        cmd.env("DST_REPLAY_UNTIL_DIVERGENCE", "1");
    }
    if let Some(glob) = &trace {
        cmd.env("DST_TRACE_GLOB", glob);
    }

    run(cmd)?;

    // The scenario re-emits its bundle under the signature/seed path; report
    // where the operator will find it. (Path convention:.)
    let bundle_dir = failures_dir();
    println!(
        "dst-replay: run complete; refreshed bundle (if the violation reproduced) is under {} \
         (look for `*-{seed}.json`)",
        bundle_dir.display()
    );
    Ok(())
}

/// Reads a failure bundle (`*.json`, a single JSON object) or a corpus JSONL
/// entry (first line is used) into the `scenario`+`seed` we need.
fn load_target(path: &Path) -> Result<ReplayTarget, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read replay target {}: {e}", path.display()))?;
    let is_jsonl = path.extension().map(|e| e == "jsonl").unwrap_or(false);
    let doc = if is_jsonl {
        text.lines()
            .find(|l| !l.trim().is_empty())
            .ok_or_else(|| format!("{} is an empty corpus file", path.display()))?
    } else {
        text.trim()
    };
    serde_json::from_str(doc)
        .map_err(|e| format!("{} is not a recognizable bundle/corpus entry: {e}", path.display()))
}

// ---------------------------------------------------------------------------
// lanes
// ---------------------------------------------------------------------------

fn cmd_lane0(_args: &[String]) -> Result<(), String> {
    // Lane 0: the cheapest, seconds-scale tier — harness unit tests and lints.
    // The non-madsim lints (impact-map completeness, runbook freshness) run
    // under a plain build; the `dst_support` unit tests are madsim-gated and
    // run through the cheapest scenario binary.
    // The non-madsim harness guards: the two completeness lints, the fidelity
    // lint, and the watcher-event-decomposition conformance test (harden design
    // ) — the last is `#![cfg(not(madsim))]`, so it belongs in this plain leg,
    // not the madsim one.
    eprintln!("dst-lane0: harness lints + watcher conformance (non-madsim)");
    let mut lints = Command::new(cargo());
    lints
        .arg("test")
        .arg("-p")
        .arg(SYNC_CORE)
        .arg("--test")
        .arg("dst_impact_map_lint")
        .arg("--test")
        .arg("dst_runbook_freshness_lint")
        .arg("--test")
        .arg("dst_fidelity_lint")
        .arg("--test")
        .arg("watcher_decompose_conformance");
    run(lints)?;

    eprintln!("dst-lane0: dst_support unit tests (madsim)");
    let mut units = madsim_test("dst_watcher_debounce");
    units.arg("--").arg("dst_support::");
    run(units)?;
    Ok(())
}

fn cmd_lane1(args: &[String]) -> Result<(), String> {
    let ops = flag_usize(args, "--ops")?.unwrap_or(DEFAULT_LANE1_OPS);
    let scenarios = discover_scenarios()?;
    eprintln!("dst-lane1: {} scenarios x 1 seed, op budget {ops}", scenarios.len());
    for scenario in &scenarios {
        eprintln!("dst-lane1: {scenario}");
        let mut cmd = madsim_test(scenario);
        cmd.env("DST_VARIATIONS", "1");
        // Shared reduced-op knob (dst_support::lane::op_budget reads this).
        cmd.env("DST_OPS_BUDGET", ops.to_string());
        run(cmd)?;
    }
    Ok(())
}

fn cmd_lane2(args: &[String]) -> Result<(), String> {
    let variations = flag_usize(args, "--variations")?;
    let keep = flag_usize(args, "--keep")?.unwrap_or(DEFAULT_KEEP);
    let scenarios = discover_scenarios()?;
    eprintln!(
        "dst-lane2: standard sweep over {} scenarios{}",
        scenarios.len(),
        variations.map(|v| format!(" (DST_VARIATIONS={v})")).unwrap_or_default()
    );
    for scenario in &scenarios {
        eprintln!("dst-lane2: {scenario}");
        let mut cmd = madsim_test(scenario);
        if let Some(v) = variations {
            cmd.env("DST_VARIATIONS", v.to_string());
        }
        run(cmd)?;
    }
    prune_artifacts(keep);
    Ok(())
}

fn cmd_prune(args: &[String]) -> Result<(), String> {
    let keep = flag_usize(args, "--keep")?.unwrap_or(DEFAULT_KEEP);
    prune_artifacts(keep);
    Ok(())
}

// ---------------------------------------------------------------------------
// retention
// ---------------------------------------------------------------------------

/// Keeps the newest `keep` files (by mtime) in each of `target/dst-failures`
/// and `target/dst-coverage`, deleting the rest. Best-effort: a missing
/// directory or an un-stat-able entry is skipped, never fatal.
fn prune_artifacts(keep: usize) {
    for dir in [failures_dir(), coverage_dir()] {
        let pruned = prune_dir(&dir, keep);
        if pruned > 0 {
            eprintln!("dst-prune: removed {pruned} old artifact(s) from {}", dir.display());
        }
    }
}

fn prune_dir(dir: &Path, keep: usize) -> usize {
    let mut entries: Vec<(std::time::SystemTime, PathBuf)> = match std::fs::read_dir(dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
            .filter_map(|e| {
                let m = e.metadata().ok()?.modified().ok()?;
                Some((m, e.path()))
            })
            .collect(),
        Err(_) => return 0,
    };
    if entries.len() <= keep {
        return 0;
    }
    // Newest first; delete everything past `keep`.
    entries.sort_by_key(|(mtime, _)| std::cmp::Reverse(*mtime));
    let mut removed = 0;
    for (_, path) in entries.into_iter().skip(keep) {
        if std::fs::remove_file(&path).is_ok() {
            removed += 1;
        }
    }
    removed
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn cargo() -> String {
    std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string())
}

/// A `cargo test --test <scenario>` command for the sync-core crate, built
/// with the madsim cfg. RUSTFLAGS is *appended* to any the operator already
/// set (we don't clobber their flags, we add ours).
fn madsim_test(scenario: &str) -> Command {
    let mut cmd = Command::new(cargo());
    cmd.arg("test").arg("-p").arg(SYNC_CORE).arg("--test").arg(scenario);
    let existing = std::env::var("RUSTFLAGS").unwrap_or_default();
    let combined = if existing.is_empty() {
        MADSIM_RUSTFLAGS.to_string()
    } else if existing.contains("--cfg madsim") {
        existing
    } else {
        format!("{existing} {MADSIM_RUSTFLAGS}")
    };
    cmd.env("RUSTFLAGS", combined);
    cmd
}

fn run(mut cmd: Command) -> Result<(), String> {
    let status = cmd.status().map_err(|e| format!("failed to spawn `cargo`: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("`cargo` exited with {status}"))
    }
}

fn next_value(it: &mut std::slice::Iter<'_, String>, flag: &str) -> Result<String, String> {
    it.next().cloned().ok_or_else(|| format!("{flag} requires a value"))
}

fn flag_usize(args: &[String], flag: &str) -> Result<Option<usize>, String> {
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == flag {
            let v = it.next().ok_or_else(|| format!("{flag} requires a value"))?;
            let n = v.parse::<usize>().map_err(|_| format!("{flag}: `{v}` is not a number"))?;
            return Ok(Some(n));
        }
    }
    Ok(None)
}

fn workspace_root() -> PathBuf {
    // xtask lives at <root>/xtask, so its manifest dir's parent is the root.
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf()
}

fn failures_dir() -> PathBuf {
    workspace_root().join("target/dst-failures")
}

fn coverage_dir() -> PathBuf {
    workspace_root().join("target/dst-coverage")
}

/// The scenario test binaries, discovered from `tests/dst_*.rs` so the lanes
/// never drift from the actual scenario set (the impact-map lint guards the
/// same set from the map side). Returned sorted for stable ordering.
fn discover_scenarios() -> Result<Vec<String>, String> {
    let dir = workspace_root().join("crates/yadorilink-sync-core/tests");
    let mut out = BTreeMap::new();
    for entry in std::fs::read_dir(&dir).map_err(|e| format!("read tests dir: {e}"))? {
        let entry = entry.map_err(|e| format!("read tests dir entry: {e}"))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if let Some(stem) = name.strip_suffix(".rs") {
            if stem.starts_with("dst_") {
                out.insert(stem.to_string(), ());
            }
        }
    }
    if out.is_empty() {
        return Err("no dst_*.rs scenarios found".to_string());
    }
    Ok(out.into_keys().collect())
}
