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
//!  dst-replay <bundle|corpus-entry> [--trace <path>] [--scenario <name>]
//!  (--until-divergence and --profile are accepted but currently refused --
//!  see `single_seed_entry_point`)
//!  dst-lane0 harness units + watcher conformance
//!  dst-lane1 [--ops <n>] each scenario x 1 seed, reduced op budget
//!  dst-lane2 [--variations <n>] [--keep <n>] standard sweep + retention prune
//!  dst-targeted --scenario <name> (--seed <n> | --case <path> [--seed <n>]) [--n <count>]
//!  one fresh seed OR one recorded case, repeated, no corpus replay -- for an
//!  n-of-N confidence measurement
//!  dst-prune [--keep <n>] prune old bundle/coverage artifacts

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use serde::Deserialize;

const MADSIM_RUSTFLAGS: &str = "--cfg madsim";
const DAEMON: &str = "yadorilink-daemon";
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
        "dst-targeted" => cmd_targeted(rest),
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
         \x20 dst-replay <bundle|corpus-entry> [--trace <path>] [--scenario <name>]\n\
         \x20 dst-lane0                              harness units + watcher conformance\n\
         \x20 dst-lane1 [--ops <n>]                  each scenario x 1 seed, reduced op budget\n\
         \x20 dst-lane2 [--variations <n>] [--keep <n>]   standard sweep + retention prune\n\
         \x20 dst-targeted --scenario <name> (--seed <n> | --case <path> [--seed <n>]) [--n <count>]\n\
         \x20                                        one fresh seed or one recorded case x <count>, \
         no corpus replay\n\
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

    // Neither flag is wired to anything: no scenario reads a profile- or
    // until-divergence-selection env var. Previously these were silently
    // accepted and silently did nothing -- the same "looks like it worked"
    // failure mode this whole fix is about, just at the flag level instead
    // of the scenario level. Refuse outright instead of repeating it.
    if profile != "standard" {
        return Err(format!(
            "dst-replay: --profile {profile} is not implemented -- no scenario currently reads a \
             profile-selection env var."
        ));
    }
    if until_divergence {
        return Err(
            "dst-replay: --until-divergence is not implemented -- no scenario currently reads a \
             replay-until-divergence env var."
                .to_string(),
        );
    }

    let target = load_target(Path::new(&path))?;
    let scenario = scenario_override
        .or(target.scenario)
        .ok_or("dst-replay: bundle has no `scenario` field; pass --scenario <name>")?;
    let seed = target.seed;
    let entry_point = single_seed_entry_point(&scenario)?;

    eprintln!(
        "dst-replay: scenario={scenario} seed={seed} test={} trace={}",
        entry_point.test_name,
        trace.as_deref().unwrap_or("<none>")
    );

    let mut cmd = madsim_test(&scenario)?;
    cmd.arg("--").arg(entry_point.test_name).arg("--exact").arg("--nocapture");
    match entry_point.seed_env {
        SeedEnv::Direct => {
            cmd.env("DST_SEED", seed.to_string());
        }
        SeedEnv::BaseSeedSingleVariation => {
            cmd.env("DST_BASE_SEED", seed.to_string());
            cmd.env("DST_VARIATIONS", "1");
        }
    }
    if let Some(path_selector) = &trace {
        // Only `dst_two_device_chaos.rs` reads this selector today (an exact
        // path or comma-separated list, matched against `DST_TRACE_PATH` --
        // not a glob, despite this flag's name). For every other scenario
        // this env var is simply unread and `--trace` is a silent no-op;
        // that mismatch is a smaller, pre-existing rough edge left as is
        // rather than folded into this fix.
        cmd.env("DST_TRACE_PATH", path_selector);
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

/// How a scenario's single-seed entry point takes its seed.
enum SeedEnv {
    /// `DST_SEED=<seed>`, read directly by a purpose-built single-seed test.
    Direct,
    /// `DST_BASE_SEED=<seed>` + `DST_VARIATIONS=1`, read by the scenario's
    /// own sweep test to narrow it to exactly one variation -- the
    /// reproduction recipe every chaos scenario's own failure message
    /// documents (see [`cmd_targeted`]).
    BaseSeedSingleVariation,
}

/// A scenario's single-seed entry point: the `--exact` test-name filter to
/// pass to `cargo test`, and how that test reads the seed.
struct EntryPoint {
    test_name: &'static str,
    seed_env: SeedEnv,
}

/// Resolves which test in `scenario`'s binary reproduces one seed in
/// isolation, and how to pass it the seed.
///
/// This used to be a single hardcoded filter (`single_seed_smoke --exact`)
/// applied to every scenario. That name exists in exactly one scenario file
/// (`dst_watcher_debounce.rs`); for every other scenario the filter matched
/// zero tests, and a zero-tests-matched `cargo test` run exits 0 -- so
/// `dst-replay` reported success on every scenario but the one it was
/// originally written for, having actually run nothing. This table is the
/// fix: one real entry point per scenario, kept in sync by hand since it
/// mirrors code, not data the scenario files could plausibly assert about
/// themselves.
fn single_seed_entry_point(scenario: &str) -> Result<EntryPoint, String> {
    let (test_name, seed_env) = match scenario {
        "dst_watcher_debounce" => ("single_seed_smoke", SeedEnv::Direct),
        "dst_two_device_chaos" => ("two_device_chaos_scenario", SeedEnv::BaseSeedSingleVariation),
        "dst_three_device_mesh_chaos" => {
            ("three_device_mesh_chaos_scenario", SeedEnv::BaseSeedSingleVariation)
        }
        "dst_network_fault_chaos" => {
            ("network_fault_chaos_scenario", SeedEnv::BaseSeedSingleVariation)
        }
        "dst_directory_chaos" => ("directory_chaos_scenario", SeedEnv::BaseSeedSingleVariation),
        "dst_disk_crash_chaos" => {
            ("disk_fault_crash_restart_chaos_scenario", SeedEnv::BaseSeedSingleVariation)
        }
        "dst_hydration_under_fault_chaos" => {
            ("hydration_under_fault_chaos_scenario", SeedEnv::BaseSeedSingleVariation)
        }
        "dst_dag_catchup_chaos" => ("dag_catchup_chaos_scenario", SeedEnv::BaseSeedSingleVariation),
        "dst_generated_sweep" => ("dst_generated_sweep", SeedEnv::BaseSeedSingleVariation),
        // These scenarios' own test functions run a fixed, hardcoded set of
        // seeds/orderings with no env-var seed selection at all -- there is
        // no single-seed entry point to target, and no `--exact` filter
        // changes that. Refuse rather than silently run the whole fixed set
        // (which is not what a caller asking to replay one seed asked for)
        // or, worse, a filter that matches nothing.
        "dst_materialization_crash_recovery"
        | "dst_peer_reconcile_race"
        | "dst_directory_move_edit_race"
        | "dst_sec_convergence" => {
            return Err(format!(
                "dst-replay: {scenario} has no single-seed entry point -- its test function runs \
                 a fixed set of seeds/orderings with no env-var seed selection, so there is no \
                 way to isolate one seed by re-running it"
            ));
        }
        other => {
            return Err(format!(
                "dst-replay: unrecognized scenario `{other}` -- add its single-seed entry point \
                 to `single_seed_entry_point` in xtask/src/main.rs"
            ));
        }
    };
    Ok(EntryPoint { test_name, seed_env })
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

/// Resolves `--case <path>`'s `seed` field for [`cmd_targeted`]. `path` may be
/// a single-object bundle (same shape [`load_target`] reads) or a multi-line
/// `.jsonl` corpus file -- a scenario's own corpus, e.g., is one JSONL file
/// shared by every recorded regression, not one file per case.
///
/// For a `.jsonl` file: if `want_seed` is given (the caller also passed
/// `--seed`), returns the first entry whose `seed` matches it -- this is how
/// one specific recorded case is selected out of a shared corpus file, and it
/// is an error if none matches (never silently substitute a different case's
/// seed for the one asked for). If `want_seed` is `None`, returns the first
/// entry's seed, matching [`load_target`]'s existing single-entry-file
/// convention for a `.jsonl`.
///
/// For a single-object bundle file: parses it once and, if `want_seed` is
/// given, verifies it matches the file's own recorded seed rather than
/// silently ignoring a caller-supplied `--seed` that names a different case.
fn load_case_seed(path: &Path, want_seed: Option<u64>) -> Result<u64, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("cannot read case {}: {e}", path.display()))?;
    let is_jsonl = path.extension().map(|e| e == "jsonl").unwrap_or(false);

    if !is_jsonl {
        let target: ReplayTarget = serde_json::from_str(text.trim())
            .map_err(|e| format!("{} is not a recognizable case: {e}", path.display()))?;
        if let Some(want) = want_seed {
            if target.seed != want {
                return Err(format!(
                    "{}: recorded seed {} does not match --seed {want}",
                    path.display(),
                    target.seed
                ));
            }
        }
        return Ok(target.seed);
    }

    for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        let Ok(target) = serde_json::from_str::<ReplayTarget>(line) else { continue };
        match want_seed {
            Some(want) if target.seed == want => return Ok(target.seed),
            Some(_) => continue,
            None => return Ok(target.seed),
        }
    }
    match want_seed {
        Some(want) => Err(format!("{}: no entry with seed {want} found", path.display())),
        None => Err(format!("{} is an empty corpus file", path.display())),
    }
}

// ---------------------------------------------------------------------------
// lanes
// ---------------------------------------------------------------------------

fn cmd_lane0(_args: &[String]) -> Result<(), String> {
    // Lane 0: the cheapest, seconds-scale tier — harness unit tests and lints.
    // The non-madsim lints (runbook freshness, fidelity) run under a plain
    // build; the `dst_support` unit tests are madsim-gated and run through
    // the cheapest scenario binary.
    // The non-madsim harness guards: the runbook-freshness lint, the
    // fidelity lint, and the watcher-event-decomposition conformance test —
    // the last is `#![cfg(not(madsim))]`, so it belongs in this plain leg,
    // not the madsim one.
    // (`dst_impact_map_lint` used to run here too, but all four of its own
    // tests were permanently `#[ignore]`d against a deleted `yadorilink-
    // sync-core` crate — Track R, E0 cleanup removed the file entirely
    // rather than keep running a target with zero real tests.)
    eprintln!("dst-lane0: harness lints + watcher conformance (non-madsim)");
    let mut lints = Command::new(cargo());
    lints
        .arg("test")
        .arg("-p")
        .arg(DAEMON)
        .arg("--test")
        .arg("dst_runbook_freshness_lint")
        .arg("--test")
        .arg("dst_fidelity_lint")
        .arg("--test")
        .arg("watcher_decompose_conformance");
    run(lints)?;

    eprintln!("dst-lane0: dst_support unit tests (madsim)");
    let mut units = madsim_test("dst_watcher_debounce")?;
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
        let mut cmd = madsim_test(scenario)?;
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
        let mut cmd = madsim_test(scenario)?;
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
// dst-targeted
// ---------------------------------------------------------------------------

/// A fresh `DST_VARIATIONS=30` sweep of a chaos scenario can find zero
/// violations even when a specific known-bad seed fails reliably, because the
/// sweep's default base seed almost never lands on that exact seed -- the
/// release gate's "n>=30, zero violations" is not the same claim as
/// "this specific regression seed is fixed at n>=30". Confirming the latter
/// means running exactly one seed, repeatedly, independent of the sweep's own
/// seed-selection.
///
/// Every scenario's `#[test]` fn already replays its entire corpus (tens of
/// recorded regression cases) before running the fresh-sweep loop that
/// `DST_BASE_SEED`/`DST_VARIATIONS` actually target -- see each scenario's own
/// corpus-replay-loop doc comment. That is correct behavior for CI (a
/// regression corpus that isn't replayed on every run isn't a gate), but it
/// makes a targeted single-seed measurement cost almost entirely as much as
/// running the whole corpus: at n>=30 that is the difference between a
/// measurement someone will actually run and one that quietly never gets
/// re-checked. This command drives the same targeted-run mechanism
/// (`DST_BASE_SEED`+`DST_VARIATIONS=1`) the scenarios already document, plus
/// the dedicated `DST_SKIP_CORPUS_REPLAY` flag every corpus-bearing scenario
/// now honors (`dst_support::corpus::should_skip_replay`), so the corpus
/// really is skipped -- not merely emptied -- for every one of the `--n`
/// repeats.
///
/// The corpus directory is restored via `git checkout --` after every single
/// repeat, regardless of pass or fail: a targeted run that happens to
/// reproduce a failure would otherwise append it back into the very corpus
/// this command exists to run *without*, silently reintroducing the cost (and
/// the accumulate-forever bias named in the scenario files' own corpus-skip
/// doc comments) on the very next invocation. Refuses to run at all if that
/// directory already has uncommitted changes, rather than silently
/// discarding them.
///
/// `--seed <n>` runs a fresh, generator-driven case for that seed -- what
/// `DST_BASE_SEED`/`DST_VARIATIONS=1` already means everywhere else in this
/// tree, and what "§22's fresh sweep" gate is about. `--case <path>` instead
/// resolves a *recorded* corpus entry's own `seed` field (matched against
/// `--seed` too, when both are given, to disambiguate one entry out of a
/// shared multi-line corpus file) and repeats exactly that. These are NOT
/// the same claim: a corpus case is persisted as a full `Case` IR
/// specifically so a promoted failure survives this repo's generator
/// evolving out from under it (each scenario's own `corpus_path`/
/// `load_corpus_cases` doc comment says so), which means a fresh seed and a
/// recorded case sharing a numeral can diverge the moment the generator
/// changes. Reproducing a *specific known regression* means `--case`;
/// confirming the *release gate's fresh-sweep claim* means `--seed`.
fn cmd_targeted(args: &[String]) -> Result<(), String> {
    let scenario =
        flag_string(args, "--scenario")?.ok_or("dst-targeted: --scenario <name> is required")?;
    let case_path = flag_string(args, "--case")?;
    let explicit_seed = flag_u64(args, "--seed")?;
    let seed = match (&case_path, explicit_seed) {
        (Some(path), want) => load_case_seed(Path::new(path), want)?,
        (None, Some(s)) => s,
        (None, None) => {
            return Err("dst-targeted: either --seed <n> or --case <path> is required".to_string())
        }
    };
    let n = flag_usize(args, "--n")?.unwrap_or(1);
    if n == 0 {
        return Err("dst-targeted: --n must be at least 1".to_string());
    }

    let corpus_dir =
        workspace_root().join(format!("crates/{}/tests/dst_corpus", scenario_crate(&scenario)?));
    ensure_corpus_clean(&corpus_dir)?;

    // Snapshot once, outside the loop, to a scratch directory keyed by this
    // process's own pid (so two concurrent `dst-targeted` invocations, from
    // two different workers, never share -- let alone race over -- the same
    // snapshot). Every one of the `n` repeats restores from this local copy
    // with a plain filesystem copy, never `git`.
    //
    // This used to restore via `git checkout --` after every repeat. That
    // was wrong: it made a per-iteration operation contend with *any* git
    // activity anywhere in the shared worktree -- at n=300, with other
    // workers committing concurrently, a lock collision is not a risk, it
    // is a certainty (measured: it happened on run 1 of a real n=300
    // attempt). A plain directory copy touches no shared lock at all.
    // `ensure_corpus_clean` below is the one git call that remains -- it
    // runs once, before the loop, not once per repeat.
    let snapshot_dir =
        std::env::temp_dir().join(format!("dst-targeted-corpus-snapshot-{}", std::process::id()));
    let snapshot_result = (|| -> Result<(), String> {
        if snapshot_dir.exists() {
            std::fs::remove_dir_all(&snapshot_dir)
                .map_err(|e| format!("cannot clear stale snapshot dir: {e}"))?;
        }
        copy_dir_all(&corpus_dir, &snapshot_dir)
    })();
    if let Err(e) = snapshot_result {
        return Err(format!("dst-targeted: failed to snapshot {}: {e}", corpus_dir.display()));
    }

    eprintln!(
        "dst-targeted: scenario={scenario} seed={seed} n={n}{} (corpus replay skipped every run)",
        case_path.as_deref().map(|p| format!(" case={p}")).unwrap_or_default()
    );

    let mut pass = 0usize;
    let mut fail = 0usize;
    let mut failing_runs = Vec::new();
    let mut loop_err: Option<String> = None;
    for i in 1..=n {
        let mut cmd = madsim_test(&scenario)?;
        // `DST_BASE_SEED`+`DST_VARIATIONS=1` is the reproduction recipe every
        // chaos scenario's own failure message documents. `DST_SEED` is set
        // too, harmlessly, for the one scenario (`dst_watcher_debounce`)
        // whose single-seed entry point predates that convention and reads
        // `DST_SEED` directly instead.
        cmd.env("DST_BASE_SEED", seed.to_string());
        cmd.env("DST_VARIATIONS", "1");
        cmd.env("DST_SEED", seed.to_string());
        cmd.env("DST_SKIP_CORPUS_REPLAY", "1");

        let status = match cmd.status() {
            Ok(s) => s,
            Err(e) => {
                loop_err = Some(format!("failed to spawn `cargo`: {e}"));
                break;
            }
        };

        // Unconditional, pass or fail: never leave the corpus directory
        // mutated by this command, on any exit path. Fail-fast (as before)
        // if the restore itself cannot be trusted -- better a clear stop
        // than silently letting the next iteration replay a dirtied
        // corpus.
        if let Err(e) = restore_corpus_from_snapshot(&snapshot_dir, &corpus_dir) {
            loop_err = Some(e);
            break;
        }

        if status.success() {
            pass += 1;
            eprintln!("dst-targeted: run {i}/{n}: PASS");
        } else {
            fail += 1;
            failing_runs.push(i);
            eprintln!("dst-targeted: run {i}/{n}: FAIL ({status})");
        }
    }

    let _ = std::fs::remove_dir_all(&snapshot_dir);

    if let Some(e) = loop_err {
        return Err(format!("dst-targeted: {e}"));
    }

    let pass_rate = (pass as f64 / n as f64) * 100.0;
    println!(
        "TALLY scenario={scenario} seed={seed} n={n} pass={pass} fail={fail} \
         pass_rate={pass_rate:.1}%"
    );
    if !failing_runs.is_empty() {
        println!("dst-targeted: failing run(s): {failing_runs:?}");
    }
    Ok(())
}

/// Refuses to proceed if `dir` has any uncommitted change -- `dst-targeted`
/// snapshots this directory once, before the loop (see [`cmd_targeted`]'s
/// doc comment), which would otherwise silently discard real pending work
/// the moment this command ran by treating it as part of the pristine
/// baseline to restore back to after every repeat.
fn ensure_corpus_clean(dir: &Path) -> Result<(), String> {
    let output = Command::new("git")
        .arg("status")
        .arg("--porcelain")
        .arg("--")
        .arg(dir)
        .output()
        .map_err(|e| format!("failed to run `git status`: {e}"))?;
    if !output.status.success() {
        return Err(format!("`git status` exited with {}", output.status));
    }
    if !output.stdout.is_empty() {
        return Err(format!(
            "dst-targeted: {} has uncommitted changes -- commit or stash them first. \
             dst-targeted snapshots this directory once before its loop and restores that \
             snapshot after every repeat, which would otherwise silently discard whatever is \
             pending there.",
            dir.display()
        ));
    }
    Ok(())
}

/// Restores `dir` to exactly what `snapshot_dir` holds: removes `dir`
/// entirely and recreates it from the snapshot. A plain filesystem
/// operation, deliberately not `git` -- see [`cmd_targeted`]'s doc comment
/// on why a per-iteration git operation cannot survive a shared worktree
/// with concurrent git activity from other workers. Removing `dir`
/// entirely (rather than only overwriting files the snapshot already
/// knows about) also cleans up any stray new file a run created that
/// wasn't in the original snapshot, not just files it modified.
fn restore_corpus_from_snapshot(snapshot_dir: &Path, dir: &Path) -> Result<(), String> {
    if dir.exists() {
        std::fs::remove_dir_all(dir)
            .map_err(|e| format!("cannot remove {} to restore it: {e}", dir.display()))?;
    }
    copy_dir_all(snapshot_dir, dir)
        .map_err(|e| format!("cannot restore {} from snapshot: {e}", dir.display()))
}

/// Recursively copies every file and subdirectory under `src` into `dst`,
/// creating `dst` (and any nested directory) as needed. `std` has no
/// built-in recursive copy; this is the whole of what [`cmd_targeted`]'s
/// snapshot/restore needs, so a small hand-rolled walk is simpler than a
/// new dependency for one call site.
fn copy_dir_all(src: &Path, dst: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dst).map_err(|e| format!("cannot create {}: {e}", dst.display()))?;
    let entries =
        std::fs::read_dir(src).map_err(|e| format!("cannot read {}: {e}", src.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("cannot read entry in {}: {e}", src.display()))?;
        let file_type = entry
            .file_type()
            .map_err(|e| format!("cannot stat {}: {e}", entry.path().display()))?;
        let dst_path = dst.join(entry.file_name());
        if file_type.is_dir() {
            copy_dir_all(&entry.path(), &dst_path)?;
        } else if file_type.is_file() {
            std::fs::copy(entry.path(), &dst_path).map_err(|e| {
                format!("cannot copy {} to {}: {e}", entry.path().display(), dst_path.display())
            })?;
        }
        // Symlinks (neither a plain dir nor a plain file) are deliberately
        // skipped: the corpus directory this is used for holds only plain
        // JSONL files, and silently following a symlink out of the corpus
        // tree during a restore is not a case worth handling here.
    }
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

/// Which crate `scenario`'s test file actually lives in right now: checked
/// against the filesystem, not a hardcoded list, so this never drifts from
/// where a scenario really is after a move (Phase 7D-10.4 relocated the
/// daemon workflow/E2E cluster and the harness-dependent filesystem-sync
/// scenarios from `yadorilink-sync-core` to `yadorilink-daemon`; every
/// remaining scenario -- `dst_peer_reconcile_race` deferred to
/// `peer_session.rs`'s own migration pass -- moved to `yadorilink-peer-session`
/// before `yadorilink-sync-core` itself was deleted in Phase 7D-10's final
/// elimination pass, so `yadorilink-daemon` is the only crate left to check).
fn scenario_crate(scenario: &str) -> Result<&'static str, String> {
    let daemon_path =
        workspace_root().join(format!("crates/yadorilink-daemon/tests/{scenario}.rs"));
    if daemon_path.is_file() {
        return Ok(DAEMON);
    }
    Err(format!(
        "dst-scenario `{scenario}`: no `{scenario}.rs` found under yadorilink-daemon/tests"
    ))
}

/// A `cargo test --test <scenario>` command for whichever crate `scenario`
/// currently lives in, built with the madsim cfg. RUSTFLAGS is *appended* to
/// any the operator already set (we don't clobber their flags, we add ours).
fn madsim_test(scenario: &str) -> Result<Command, String> {
    let package = scenario_crate(scenario)?;
    let mut cmd = Command::new(cargo());
    cmd.arg("test").arg("-p").arg(package).arg("--test").arg(scenario);
    let existing = std::env::var("RUSTFLAGS").unwrap_or_default();
    let combined = if existing.is_empty() {
        MADSIM_RUSTFLAGS.to_string()
    } else if existing.contains("--cfg madsim") {
        existing
    } else {
        format!("{existing} {MADSIM_RUSTFLAGS}")
    };
    cmd.env("RUSTFLAGS", combined);
    Ok(cmd)
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

fn flag_u64(args: &[String], flag: &str) -> Result<Option<u64>, String> {
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == flag {
            let v = it.next().ok_or_else(|| format!("{flag} requires a value"))?;
            let n = v.parse::<u64>().map_err(|_| format!("{flag}: `{v}` is not a number"))?;
            return Ok(Some(n));
        }
    }
    Ok(None)
}

fn flag_string(args: &[String], flag: &str) -> Result<Option<String>, String> {
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == flag {
            let v = it.next().ok_or_else(|| format!("{flag} requires a value"))?;
            return Ok(Some(v.clone()));
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

/// The scenario test binaries, discovered from `tests/dst_*.rs` in
/// `yadorilink-daemon` (Phase 7D-10.4 split the harness's scenario files
/// across `yadorilink-sync-core` and `yadorilink-daemon`; Phase 7D-10's
/// final elimination pass deleted `yadorilink-sync-core` outright, and
/// every scenario it still owned moved to `yadorilink-peer-session` or
/// `yadorilink-daemon` before that deletion, so `yadorilink-daemon` is now
/// the sole scenario home) so the lane never drifts from the actual
/// scenario set (an impact-map lint used to guard the same set from the
/// map side; it only ever ran against the now-deleted `yadorilink-sync-core`
/// and was removed rather than kept as a permanently-`#[ignore]`d no-op --
/// Track R, E0 cleanup). A `dst_*.rs`
/// file only counts as a lane scenario if it actually declares
/// `mod dst_support;` -- this excludes `yadorilink-daemon`'s own
/// pre-existing, unrelated `dst_daemon_*.rs` integration tests (a
/// different, non-`dst_support` DST harness that predates this move)
/// without relying on a naming-convention guess. Returned sorted for stable
/// ordering.
fn discover_scenarios() -> Result<Vec<String>, String> {
    let dirs = [workspace_root().join("crates/yadorilink-daemon/tests")];
    let mut out = BTreeMap::new();
    for dir in &dirs {
        for entry in std::fs::read_dir(dir).map_err(|e| format!("read {}: {e}", dir.display()))? {
            let entry = entry.map_err(|e| format!("read {} entry: {e}", dir.display()))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let Some(stem) = name.strip_suffix(".rs") else { continue };
            if !stem.starts_with("dst_") {
                continue;
            }
            let path = entry.path();
            let source = std::fs::read_to_string(&path)
                .map_err(|e| format!("read {}: {e}", path.display()))?;
            if source.lines().any(|l| l.trim() == "mod dst_support;") {
                out.insert(stem.to_string(), ());
            }
        }
    }
    if out.is_empty() {
        return Err("no dst_*.rs scenarios found".to_string());
    }
    Ok(out.into_keys().collect())
}
