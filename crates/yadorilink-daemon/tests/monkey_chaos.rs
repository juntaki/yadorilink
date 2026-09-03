//! Chaos/monkey test: a randomized sequence of concurrent file operations
//! (create, edit, delete, rename) from several real daemon-equivalent
//! devices sharing one folder group, driven at real wall-clock speed over
//! directly-paired peer sessions, but exercising many more, unscripted
//! interleavings than any single hand-written scenario would, in the hope
//! of surfacing race conditions that a fixed test sequence wouldn't
//! happen to hit. Not a regression test for one specific bug — a
//! generic invariant check ("every device converges to the identical
//! final file set") run repeatedly (see `scripts/heat-run.sh`) to build
//! confidence beyond what scripted tests alone can.
//!
//! Seeded via `MONKEY_CHAOS_SEED` (or a freshly generated seed, logged at
//! the start of every run, when that env var is unset) rather than
//! `rand::random`, so a failing run's exact interleaving is
//! reproducible: re-run with `MONKEY_CHAOS_SEED=<logged seed> cargo test
//! -p yadorilink-daemon --test monkey_chaos -- --nocapture`. A failing
//! seed is also appended to the checked-in corpus at
//! `tests/dst_corpus/monkey_chaos_seeds.txt`, which `replay_known_failing_
//! seeds` below always re-runs, so a found race becomes a permanent
//! regression check rather than a one-off heat-run finding. Every action
//! taken is still logged via `tracing::info!` so a failure's exact
//! operation sequence is reconstructable from `--nocapture` output too.

mod support;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use futures_util::FutureExt as _;
use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use sha2::{Digest, Sha256};
use support::{open_file_backed_replica_coordinator, real_entry_names, TestAccount};
use yadorilink_daemon::adapters::runtime::link_runtime_controller::LinkRuntimeController;
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_local_storage::FsBlockStore;
use yadorilink_replica_domain::change::{Op, PutOrigin};
use yadorilink_replica_domain::ids::ChangeHash;
use yadorilink_sync_sqlite::dag_store::DagHashDisposition;

const DEVICE_COUNT: usize = 4;
const CANDIDATE_FILE_COUNT: usize = 8;
const ROUNDS: usize = 40;
/// Phase 1 (convergence): every device's snapshot must agree at least once
/// within this budget. Its own deadline, not shared with phase 2's --
/// nesting a stability window inside one shared clock (the pre-two-phase
/// design) meant a run that took most of this budget to first converge had
/// almost no time left to also *confirm* stability, timing out despite
/// devices already holding byte-identical content. Confirmed as a real CI
/// failure this way on a slower (GitHub-hosted) runner: a corpus seed
/// reached genuine four-way agreement but the shared clock had already
/// spent most of its budget getting there.
const PHASE1_CONVERGENCE_TIMEOUT: Duration = Duration::from_secs(180);
/// Phase 2 (stability confirmation): once phase 1 first observes agreement,
/// it must hold continuously for this long before the run is accepted --
/// any change resets this clock, but never phase 1's own (already-spent)
/// budget. Total worst-case wait is therefore PHASE1 + PHASE2 = 210s, not
/// PHASE1 alone.
const PHASE2_STABILITY_TIMEOUT: Duration = Duration::from_secs(30);
const CONVERGENCE_POLL_INTERVAL: Duration = Duration::from_millis(100);
/// How often the convergence-wait loop emits one DAG-progress line per
/// device (in poll iterations; 50 polls ~= 5s). The line shows *DAG-level*
/// progress (heads, admitted/orphan/missing counts, self-authored count,
/// dirty-journal depth) precisely because the disk snapshot the pass/fail
/// check polls cannot distinguish "delivery stalled" from "projection
/// lagging" from "a device is still emitting new local changes".
const DAG_PROGRESS_EVERY_POLLS: u32 = 50;
/// How often the (much more verbose) per-head divergence report is emitted
/// during the wait, in poll iterations (300 polls ~= 30s).
const DAG_HEAD_REPORT_EVERY_POLLS: u32 = 300;

/// Diagnostic-only phase-1 override, read from
/// `MONKEY_CHAOS_DIAG_PHASE1_SECS`. CI never sets it, so the budget CI
/// actually enforces stays [`PHASE1_CONVERGENCE_TIMEOUT`] — this exists so a
/// diagnostic rerun on a contended host can keep observing DAG progress past
/// the 180s mark (distinguishing "permanently stalled" from "extremely slow
/// but still progressing") without weakening the real gate. It is not a way
/// to make the test pass: a run that only converges thanks to this override
/// still violated the 180s contract, and the progress log shows exactly when
/// convergence actually happened.
fn phase1_timeout_for_this_run() -> Duration {
    match std::env::var("MONKEY_CHAOS_DIAG_PHASE1_SECS") {
        Err(_) => PHASE1_CONVERGENCE_TIMEOUT,
        Ok(raw) => {
            let secs: u64 = raw.parse().unwrap_or_else(|e| {
                panic!(
                    "MONKEY_CHAOS_DIAG_PHASE1_SECS={raw:?} is not a whole number of seconds: {e}"
                )
            });
            let timeout = Duration::from_secs(secs);
            eprintln!(
                "MONKEY_CHAOS diagnostic mode: phase-1 budget overridden to {timeout:?} (normal \
                 budget {PHASE1_CONVERGENCE_TIMEOUT:?}); convergence after the normal budget is \
                 still a failure of the 180s contract, just an observed one"
            );
            timeout
        }
    }
}

fn corpus_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/dst_corpus/monkey_chaos_seeds.txt")
}

/// Seeds from a prior failing run, persisted so they're always re-run
/// (see `replay_known_failing_seeds`) instead of only surfacing once on
/// whichever heat-run happened to find them. Blank lines and `#`-prefixed
/// comments are ignored so the corpus file can carry context per seed.
fn load_corpus_seeds() -> Vec<u64> {
    let Ok(contents) = std::fs::read_to_string(corpus_path()) else {
        return Vec::new();
    };
    contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| line.parse::<u64>().ok())
        .collect()
}

/// Appends `seed` to the corpus file (creating it/its directory if
/// needed), best-effort -- a failure to persist the seed must not itself
/// panic out of a panic hook.
fn record_failing_seed(seed: u64) {
    let path = corpus_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    use std::io::Write;
    if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        let _ = writeln!(file, "{seed}");
    }
}

fn seed_from_env_or_random() -> u64 {
    std::env::var("MONKEY_CHAOS_SEED")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or_else(rand::random)
}

struct TestDevice {
    device_id: String,
    state: Arc<DaemonState>,
    root: tempfile::TempDir,
    _store_dir: tempfile::TempDir,
    // Uses file-backed WAL (production's concurrency model) instead of
    // open_in_memory's shared-cache backend — see
    // open_file_backed_replica_coordinator's doc comment. Held only to keep the
    // backing temp file alive for the test's duration.
    _index_dir: tempfile::TempDir,
}

async fn setup_device(account: &TestAccount, name: &str) -> TestDevice {
    let device_id = support::register_device(account, name, [0u8; 32]).await;
    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
    let (sync_state, index_dir) = open_file_backed_replica_coordinator();
    let sync_state = Arc::new(sync_state);
    let state = DaemonState::new(device_id.clone(), sync_state, store);
    // Give the device a change-signing key before its link watch starts, so the
    // change-DAG emitter is wired and local edits actually propagate. Without
    // this, nothing this device writes is ever emitted to its peers.
    support::ensure_device_signing_key(&state);
    TestDevice {
        device_id,
        state,
        root: tempfile::tempdir().unwrap(),
        _store_dir: store_dir,
        _index_dir: index_dir,
    }
}

async fn start_watching(device: &TestDevice, group_id: &str) {
    let local_path = device.root.path().to_string_lossy().to_string();
    device.state.replica_coordinator.link_repository().add_link(&local_path, group_id).unwrap();
    LinkRuntimeController::new(device.state.clone())
        .start(local_path, group_id.to_string())
        .unwrap();
}

/// Tears down one seed's daemon mesh when dropped: aborts every paired
/// session's `run()` task and stops every device's link watch (the
/// watcher/debounce/executor/repair tasks `LinkRuntimeController::start`
/// spawned).
///
/// Without this, nothing in this file ever tears a seed's mesh down --
/// `connect_two_daemons`'s session tasks hold *strong* `Arc<DaemonState>`
/// references (via `set_pending_local_change_flush` and friends) and run
/// forever since nothing closes their channel or aborts them, and
/// `LinkRuntimeController::start`'s tasks are equally permanent until
/// `LinkRuntimeController::stop` is called. `replay_known_failing_seeds` runs every corpus seed's
/// `run_chaos` sequentially in the *same* process, so without teardown each
/// seed leaves its entire 4-device mesh (12 session tasks plus each
/// device's watcher/debounce/executor/repair tasks and SQLite pool) running
/// underneath the next one -- confirmed as the actual cause of a real CI
/// failure: the second of two corpus seeds failed initial DAG handshake
/// negotiation within its 10s budget, competing with the first seed's
/// still-fully-running mesh for the same process's CPU/disk.
///
/// A plain end-of-function cleanup call would not be enough: a panic (a
/// genuine convergence-divergence failure, the exact thing this test exists
/// to catch) must tear the mesh down too, or the *next* seed inherits it.
/// `Drop` runs during unwinding as well as on a normal return, so
/// constructing this right after the mesh connects and letting it fall out
/// of scope covers both paths uniformly.
/// One paired session's `run()` task, labeled with the two device ids it
/// connects — lets a convergence-wait timeout (or an immediate
/// early-exit check) name exactly which pairing died instead of only
/// dumping an opaque `Vec<JoinHandle<()>>`.
struct SessionTask {
    local: String,
    peer: String,
    handle: tokio::task::JoinHandle<()>,
}

struct MeshTeardownGuard {
    session_handles: Vec<SessionTask>,
    links: Vec<(Arc<DaemonState>, String)>,
}

impl Drop for MeshTeardownGuard {
    fn drop(&mut self) {
        for task in &self.session_handles {
            task.handle.abort();
        }
        // `LinkRuntimeController::stop` is `async` (it now genuinely
        // waits for every aborted task, including a `spawn_blocking` scan,
        // to actually finish before releasing the sync-root lock -- see
        // its own doc), and `Drop::drop` cannot `.await`. This teardown
        // guard only needs "stop reacting to new events, don't leak the OS
        // lock" for the NEXT seed in this same test process, not the
        // stronger "nothing is still running" guarantee real production
        // shutdown needs, so a plain abort-and-drop is enough here.
        for (state, local_path) in &self.links {
            if let Some(runtime) = state.links.remove_if_ready(local_path) {
                runtime.abort_tasks();
            }
        }
    }
}

/// Panics with a precise diagnosis if any paired session's `run()` task has
/// already exited. These tasks are only ever meant to stop when
/// `MeshTeardownGuard` aborts them at the end of a seed's run; an earlier,
/// unrequested exit (a panic inside the session, or an `Err` return logged
/// by `spawn_paired_session`'s own error arm) means that pairing has gone
/// silently dead -- convergence can never complete without it, so the
/// convergence-wait loop would otherwise burn its whole budget only to
/// report a generic "never reached agreement" timeout with no hint that a
/// session, not the DAG/materialization logic, is what actually stopped
/// working. Checked every poll iteration rather than only after a timeout,
/// so the failure is attributed to its real cause immediately instead of
/// up to `PHASE1_CONVERGENCE_TIMEOUT` later.
fn panic_if_any_session_died(session_handles: &[SessionTask], elapsed: Duration) {
    for task in session_handles {
        if task.handle.is_finished() {
            panic!(
                "paired session {} -> {} exited before the mesh was torn down (after {elapsed:?} \
                 of the chaos/convergence run) -- convergence cannot complete without it; see \
                 that session's own tracing::error! log line above for its exit cause",
                task.local, task.peer
            );
        }
    }
}

/// Pairs every device with every other over loopback (a full mesh), the
/// direct-transport stand-in for the coordination-driven peer connections
/// the orchestrator would establish for an authorized group. Returns every
/// paired session's `JoinHandle` so the caller can build a
/// [`MeshTeardownGuard`] -- see that type's doc comment for why leaving them
/// running is a real bug, not just tidiness.
#[must_use]
async fn connect_mesh(devices: &[TestDevice], group_id: &str) -> Vec<SessionTask> {
    let mut handles = Vec::new();
    let groups = [group_id.to_string()];
    for i in 0..devices.len() {
        for j in (i + 1)..devices.len() {
            let [handle_a, handle_b] = support::connect_two_daemons_with_handles(
                &devices[i].state,
                &devices[i].device_id,
                &devices[j].state,
                &devices[j].device_id,
                &groups,
            )
            .await;
            handles.push(SessionTask {
                local: devices[i].device_id.clone(),
                peer: devices[j].device_id.clone(),
                handle: handle_a,
            });
            handles.push(SessionTask {
                local: devices[j].device_id.clone(),
                peer: devices[i].device_id.clone(),
                handle: handle_b,
            });
        }
    }
    handles
}

#[derive(Clone, Copy)]
enum Action {
    WriteNew,
    Edit,
    Delete,
    Rename,
}

/// Real (non-artifact) file entries, keyed by name, valued by a content
/// hash — cheap to compare across devices without holding whole file
/// contents in memory, and immune to `real_entry_names`' own exclusion
/// of transient materialization/probe artifacts.
fn snapshot(root: &std::path::Path) -> HashMap<String, String> {
    real_entry_names(root)
        .into_iter()
        .map(|name| {
            let hash = match std::fs::read(root.join(&name)) {
                Ok(content) => hex::encode(Sha256::digest(&content)),
                // Distinct from a genuinely empty file's hash
                // (`hex::encode(Sha256::digest(b""))`): collapsing a read
                // error (e.g. a materialization rename racing this exact
                // read, or a real "file vanished mid-poll") into "empty"
                // would make an in-flight write look identical to a real
                // zero-byte file, hiding exactly the kind of transient
                // mid-flight state this snapshot exists to distinguish from
                // genuine divergence.
                Err(e) => format!("<read-error: {e}>"),
            };
            (name, hash)
        })
        .collect()
}

/// Diagnostic-only: a device's own index state for `path`, independent of
/// what's actually materialized on disk -- distinguishes "this device's
/// index has no record of this file at all" (propagation never reached
/// it) from "the index has a record but it's not materialized" (e.g.
/// stuck `Hydrating`/`Placeholder`, or held due to a hazard).
fn describe_index_state(state: &DaemonState, group_id: &str, path: &str) -> String {
    let record = state.replica_coordinator.file_index_repository().get_file(group_id, path);
    let materialization = state
        .replica_coordinator
        .materialization_state_repository()
        .get_materialization_state(group_id, path);
    let held =
        state.replica_coordinator.materialization_state_repository().get_held_state(group_id, path);
    format!("record={record:?} materialization={materialization:?} held={held:?}")
}

/// Detailed per-device diagnostics for every path that currently differs
/// across `snapshots` (relative to device-0): each device's DAG group heads
/// (do the devices even agree on the same frontier?) plus `describe_index_state`
/// for each affected path. Shared by both the timeout-path context dump
/// below and the final strict-equality check, so a run that times out
/// *inside* the convergence/stability wait -- never reaching the code
/// after it -- still surfaces the same DAG-level diagnostics a slower or
/// CI-only divergence would otherwise only reveal on a later reproduction
/// attempt.
/// Empty when nothing currently differs.
fn diff_diagnostics(
    devices: &[TestDevice],
    group_id: &str,
    snapshots: &[HashMap<String, String>],
) -> String {
    let reference = &snapshots[0];
    let mut affected: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for snap in &snapshots[1..] {
        affected.extend(reference.keys().filter(|k| !snap.contains_key(*k)).cloned());
        affected.extend(snap.keys().filter(|k| !reference.contains_key(*k)).cloned());
        affected.extend(
            reference.keys().filter(|k| snap.get(*k).is_some_and(|v| v != &reference[*k])).cloned(),
        );
    }
    if affected.is_empty() {
        return String::new();
    }
    let mut out = String::new();
    for (d, device) in devices.iter().enumerate() {
        let heads = match device.state.replica_coordinator.sqlite().dag_group_heads(group_id) {
            Ok(hs) => hs.iter().map(|h| h.to_hex()).collect::<Vec<_>>(),
            Err(e) => vec![format!("<error reading heads: {e}>")],
        };
        out.push_str(&format!("  device-{d} dag_group_heads={heads:?}\n"));
    }
    for name in &affected {
        for (d, device) in devices.iter().enumerate() {
            out.push_str(&format!(
                "  device-{d} sync_state[{name:?}]: {}\n",
                describe_index_state(&device.state, group_id, name)
            ));
        }
        // Which admitted changes touch this path at all, from device-0's
        // DAG (arbitrary but sufficient in the shape this exists to
        // diagnose — identical heads everywhere). Distinguishes "no change
        // ever carried this path durably" (an ephemeral-derivation copy
        // kept only by devices that passed through a transient frontier —
        // a retroactivity gap) from "a change carries it but one device's
        // projection skipped it" (a projection bug).
        match devices[0]
            .state
            .replica_coordinator
            .change_history_repository()
            .dag_list_group_changes(group_id)
        {
            Err(e) => out.push_str(&format!("  history[{name:?}]: <error: {e}>\n")),
            Ok(changes) => {
                let mut touched = false;
                for change in &changes {
                    let touching: Vec<String> = change
                        .ops
                        .iter()
                        .filter(|op| match op {
                            Op::Put { path, .. } | Op::Delete { path } => path.as_str() == name,
                            Op::Move { from, to, .. } => {
                                from.as_str() == name || to.as_str() == name
                            }
                        })
                        .map(|op| summarize_ops(std::slice::from_ref(op)))
                        .collect();
                    if !touching.is_empty() {
                        touched = true;
                        out.push_str(&format!(
                            "  history[{name:?}]: change {} author={} lamport={}: {}\n",
                            short_hash(&change.compute_hash()),
                            author_label(devices, &change.device_id.0),
                            change.lamport,
                            touching.join("; "),
                        ));
                    }
                }
                if !touched {
                    out.push_str(&format!(
                        "  history[{name:?}]: NO admitted change on device-0 touches this path \
                         (ephemeral-derivation-only content)\n"
                    ));
                }
            }
        }
    }
    out
}

/// First 8 hex chars — enough to correlate hashes across a log by eye
/// without each line being unreadably wide.
fn short_hash(hash: &ChangeHash) -> String {
    hash.to_hex()[..8].to_string()
}

/// `device-N` when `author` is one of this run's devices; the raw id
/// otherwise (which would itself be a finding — no other author exists).
fn author_label(devices: &[TestDevice], author: &str) -> String {
    match devices.iter().position(|d| d.device_id == author) {
        Some(i) => format!("device-{i}"),
        None => format!("unknown({author})"),
    }
}

fn summarize_ops(ops: &[Op]) -> String {
    ops.iter()
        .map(|op| match op {
            Op::Put { path, origin: PutOrigin::Direct, .. } => format!("put {}", path.as_str()),
            Op::Put { path, origin: PutOrigin::ConflictCopy { source_path, .. }, .. } => {
                format!("conflict-copy {} (from {})", path.as_str(), source_path.as_str())
            }
            Op::Delete { path } => format!("delete {}", path.as_str()),
            Op::Move { from, to, .. } => format!("move {} -> {}", from.as_str(), to.as_str()),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// One compact DAG-progress line per device: current heads, admitted /
/// unapplied / orphaned / provably-missing counts, how many admitted
/// changes this device authored *itself* (still growing after the last
/// chaos round ⇒ something — watcher echo, dirty-journal redrive, conflict
/// projection — is generating new local commits, i.e. divergence is being
/// *produced*, not just undelivered), the dirty-journal depth, and
/// materialization counts (hydrated/placeholder/hydrating). Every value is
/// best-effort: a read error becomes part of the line, never a panic —
/// diagnostics must not kill the run they are diagnosing.
fn dag_progress_report(devices: &[TestDevice], group_id: &str, elapsed: Duration) -> String {
    let mut out = String::new();
    let t = elapsed.as_secs();
    for (d, device) in devices.iter().enumerate() {
        let sync = &device.state.replica_coordinator;
        let heads = match sync.sqlite().dag_group_heads(group_id) {
            Ok(hs) => {
                let mut short: Vec<String> = hs.iter().map(short_hash).collect();
                short.sort();
                format!("[{}]", short.join(","))
            }
            Err(e) => format!("<error: {e}>"),
        };
        let line = match sync.change_history_repository().dag_group_diagnostics(group_id) {
            Ok(diag) => {
                let self_authored =
                    diag.admitted_by_author.get(&device.device_id).copied().unwrap_or(0);
                let dirty = match sync.dirty_path_repository().list_dirty_paths(group_id) {
                    Ok(v) => v.len().to_string(),
                    Err(e) => format!("<error: {e}>"),
                };
                let mat = match sync
                    .materialization_state_repository()
                    .materialization_counts(group_id)
                {
                    Ok(m) => format!("{}/{}/{}", m.hydrated, m.placeholder, m.hydrating),
                    Err(e) => format!("<error: {e}>"),
                };
                let missing: Vec<String> =
                    diag.orphan_missing_frontier.iter().map(short_hash).collect();
                format!(
                    "[dag t={t:>3}s] device-{d} heads={heads} admitted={} unapplied={} \
                     orphans={} missing={missing:?} self_authored={self_authored} dirty={dirty} \
                     mat(h/p/hy)={mat}",
                    diag.admitted_total, diag.admitted_unapplied, diag.orphan_total,
                )
            }
            Err(e) => {
                format!("[dag t={t:>3}s] device-{d} heads={heads} <diagnostics error: {e}>")
            }
        };
        out.push_str(&line);
        out.push('\n');
    }
    out
}

/// Per-head detail whenever the devices' head sets disagree: for every head
/// any device currently holds, each device's disposition for that hash
/// (admitted / admitted-but-unprojected / orphaned-waiting-on-hashes /
/// MISSING), plus the change's own author, lamport, parents and ops from
/// whichever device can decode it. This is the report that distinguishes
/// the competing explanations for a divergent frontier: a head every other
/// device reports MISSING and whose author is the holding device itself
/// points at local emission (watcher echo / late dirty-journal redrive); a
/// head sitting orphaned with a non-empty waiting_on set points at
/// request/delivery; a head admitted everywhere but still a *head* only
/// somewhere points at frontier/announce bookkeeping.
fn divergent_head_report(devices: &[TestDevice], group_id: &str) -> String {
    let per_device_heads: Vec<Vec<ChangeHash>> = devices
        .iter()
        .map(|device| {
            device.state.replica_coordinator.sqlite().dag_group_heads(group_id).unwrap_or_default()
        })
        .collect();
    let all_agree = per_device_heads[1..].iter().all(|hs| {
        let (a, b): (std::collections::BTreeSet<String>, std::collections::BTreeSet<String>) = (
            hs.iter().map(|h| h.to_hex()).collect(),
            per_device_heads[0].iter().map(|h| h.to_hex()).collect(),
        );
        a == b
    });
    if all_agree {
        return "  all devices report identical dag_group_heads\n".to_string();
    }
    // Keyed by full hex for stable ordering; value is the hash itself.
    let union: std::collections::BTreeMap<String, ChangeHash> =
        per_device_heads.iter().flatten().map(|h| (h.to_hex(), *h)).collect();
    let mut out = String::from("  divergent head detail (one line per head in the union):\n");
    for (hex, hash) in &union {
        let mut states = Vec::with_capacity(devices.len());
        let mut decoded = None;
        for (d, device) in devices.iter().enumerate() {
            let sync = &device.state.replica_coordinator;
            let is_head = per_device_heads[d].contains(hash);
            let head_marker = if is_head { "*" } else { "" };
            match sync.change_history_repository().dag_describe_hash(hash) {
                Ok(DagHashDisposition::Admitted { applied, change }) => {
                    let projected = if applied { "" } else { ",unprojected" };
                    states.push(format!("device-{d}{head_marker}=admitted{projected}"));
                    decoded.get_or_insert(change);
                }
                Ok(DagHashDisposition::Orphaned { received_seq, change }) => {
                    let waiting: Vec<String> = sync
                        .sqlite()
                        .dag_missing_ancestor_frontier([*hash])
                        .map(|f| f.iter().map(short_hash).collect())
                        .unwrap_or_else(|e| vec![format!("<error: {e}>")]);
                    states.push(format!(
                        "device-{d}{head_marker}=orphaned(seq={received_seq},waiting_on={waiting:?})"
                    ));
                    decoded.get_or_insert(change);
                }
                Ok(DagHashDisposition::Missing) => {
                    states.push(format!("device-{d}{head_marker}=MISSING"));
                }
                Err(e) => states.push(format!("device-{d}{head_marker}=<error: {e}>")),
            }
        }
        out.push_str(&format!("  head {}: {}\n", &hex[..8], states.join(" ")));
        match decoded {
            Some(change) => {
                let parents: Vec<String> = change.parents.iter().map(short_hash).collect();
                out.push_str(&format!(
                    "    author={} lamport={} parents={parents:?} ops=[{}]\n",
                    author_label(devices, &change.device_id.0),
                    change.lamport,
                    summarize_ops(&change.ops),
                ));
            }
            None => out.push_str("    (no device could produce this change's content)\n"),
        }
    }
    out
}

async fn run_chaos(seed: u64) {
    let _ = tracing_subscriber::fmt::try_init();
    // Run the daemon's materialization-repair sweep from the very start of
    // the run, at the same 1s cadence `support::spawn_paired_session`
    // already intends for it. Without this default-override the intent
    // silently never engages on a fast host: the scheduler's FIRST sleep is
    // taken at `DaemonState::new` with the production 90s default (the
    // per-state 1s setter only affects the sleep *after* that), and a fast
    // run finishes well under 90s having executed zero sweeps — while a
    // contended CI run crosses 90s mid-run and suddenly gets 1s-cadence
    // sweeps for the rest of it. That hidden regime switch is exactly how
    // the sweep's conflict-copy backfill divergence stayed reproducible
    // only on a loaded host. Forcing it from t=0 makes every run, fast or
    // slow, exercise the same sweep-active system CI failures actually ran.
    // `MONKEY_CHAOS_DIAG_SWEEP_SECS` overrides the cadence for diagnosis.
    //
    // 5s, not `spawn_paired_session`'s 1s: the sweep must be ACTIVE from
    // t=0 (regime parity with the >90s CI runs — that's what makes this
    // class reproducible at all), but its cadence is a duty-cycle knob, and
    // 1s was itself a measured liveness hazard on a slow-disk CI runner: an
    // audit re-reconciling a large still-unapplied backlog issues a stream
    // of small write transactions (each an fsync), SQLite grants its single
    // writer lock with no fairness, and a peer session's admission write on
    // the SAME device lost that race for 37 straight seconds — the last
    // device sat one announced change behind everyone with the rest of the
    // mesh fully idle. At 5s the backstop still re-drives anything stuck
    // well within the 180s budget; it just stops monopolizing the writer.
    let sweep_secs: u64 = match std::env::var("MONKEY_CHAOS_DIAG_SWEEP_SECS") {
        Err(_) => 5,
        Ok(raw) => raw.parse().unwrap_or_else(|e| {
            panic!("MONKEY_CHAOS_DIAG_SWEEP_SECS={raw:?} is not a whole number of seconds: {e}")
        }),
    };
    yadorilink_daemon::daemon_state::set_default_materialization_repair_sweep_interval_for_tests(
        Duration::from_secs(sweep_secs),
    );
    let coordination_addr = support::start_coordination_server().await;
    let account = support::register_and_login(&coordination_addr, "monkey-chaos@example.com").await;

    let mut devices = Vec::with_capacity(DEVICE_COUNT);
    for i in 0..DEVICE_COUNT {
        devices.push(setup_device(&account, &format!("device-{i}")).await);
    }
    let group_id = support::create_folder_group(&account, "monkey-chaos-group").await;
    for device in &devices {
        support::grant_access(&account, &group_id, &device.device_id).await;
    }
    for device in &devices {
        start_watching(device, &group_id).await;
    }
    let session_handles = connect_mesh(&devices, &group_id).await;
    // `spawn_paired_session` set each device's PER-STATE sweep interval to
    // its generic 1s; re-align it with this test's 5s choice (see
    // `sweep_secs` above for why 1s is a writer-starvation hazard here) so
    // every sleep after the first also runs at 5s, not just the first.
    for device in &devices {
        device.state.set_materialization_repair_sweep_interval(Duration::from_secs(sweep_secs));
    }
    // Constructed immediately after the mesh connects (before any chaos
    // operation that could panic) and never explicitly dropped early: `Drop`
    // runs whether this function returns normally or panics, so this seed's
    // entire mesh is guaranteed torn down before `replay_known_failing_
    // seeds`'s loop -- or `random_concurrent_operations...`'s own single
    // run -- moves on. See `MeshTeardownGuard`'s doc comment.
    let mesh_teardown = MeshTeardownGuard {
        session_handles,
        links: devices
            .iter()
            .map(|d| (d.state.clone(), d.root.path().to_string_lossy().into_owned()))
            .collect(),
    };

    // Give peer sessions a moment to establish before the chaos begins.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let candidate_names: Vec<String> =
        (0..CANDIDATE_FILE_COUNT).map(|i| format!("chaos-{i:02}.bin")).collect();

    let mut rng = StdRng::seed_from_u64(seed);
    for round in 0..ROUNDS {
        let device_idx = rng.random_range(0..DEVICE_COUNT);
        let device = &devices[device_idx];
        let name = &candidate_names[rng.random_range(0..CANDIDATE_FILE_COUNT)];
        let path = device.root.path().join(name);
        // Delete/Rename need `path` to actually exist *on this device's
        // own local view* first -- a real user can only act on a file
        // they can see. Without this check, a delete/rename issued before
        // this device has synced an earlier write from another device
        // would silently no-op (`std::fs::remove_file`/`rename` on a
        // nonexistent path just errors, previously discarded via `let _
        // =`), while still being logged as if it happened -- creating an
        // artificial, test-only mismatch between what was logged and
        // what devices actually converged on, that looked like a sync
        // bug but wasn't one.
        let path_exists = path.exists();
        let action = match rng.random_range(0..4) {
            0 => Action::WriteNew,
            1 => Action::Edit,
            2 if path_exists => Action::Delete,
            3 if path_exists => Action::Rename,
            _ => Action::WriteNew,
        };
        match action {
            Action::WriteNew | Action::Edit => {
                let content = format!("round {round} device {device_idx} name {name}");
                std::fs::write(&path, content.as_bytes()).unwrap();
                tracing::info!(round, device = %device.device_id, name = %name, "wrote");
            }
            Action::Delete => {
                std::fs::remove_file(&path).unwrap();
                tracing::info!(round, device = %device.device_id, name = %name, "deleted");
            }
            Action::Rename => {
                let other_name = &candidate_names[rng.random_range(0..CANDIDATE_FILE_COUNT)];
                let other_path = device.root.path().join(other_name);
                std::fs::rename(&path, &other_path).unwrap();
                tracing::info!(
                    round,
                    device = %device.device_id,
                    from = %name,
                    to = %other_name,
                    "renamed"
                );
            }
        }
        // Real, if small and randomized, gap between actions — enough for
        // the debounce accumulator/watcher to see distinct windows most
        // of the time, without making this test glacially slow.
        tokio::time::sleep(Duration::from_millis(rng.random_range(10..60))).await;
    }

    // Timestamp marker for log analysis: every DAG-progress line after this
    // point reflects a system whose *entire* nominal input has already been
    // issued -- any device whose self-authored admitted count still grows
    // well past this point is generating new local commits on its own.
    eprintln!("MONKEY_CHAOS all {ROUNDS} rounds issued; entering convergence wait");

    // A short fixed pause before the stability-wait even starts polling,
    // so the very last round's own debounce window (up to
    // DEFAULT_MAX_FLUSH_INTERVAL, 2s) has a moment to at least begin
    // flushing before the "has anything changed recently" check below
    // starts measuring from a true baseline, rather than measuring
    // "stability" against a snapshot taken while the last round's change
    // hadn't even been indexed yet.
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Let everything settle in two separate phases, each with its own
    // budget (see PHASE1_CONVERGENCE_TIMEOUT/PHASE2_STABILITY_TIMEOUT's own
    // doc comments for why they are not one shared clock):
    //   phase 1 (convergence): poll until every device's snapshot first
    //     agrees, within PHASE1_CONVERGENCE_TIMEOUT.
    //   phase 2 (stability): once phase 1 succeeds, the agreement must hold
    //     continuously for PHASE2_STABILITY_TIMEOUT -- any change resets
    //     *only* phase 2's clock, never phase 1's already-spent budget.
    // Bounded overall by phase1 + phase2 (210s), not phase 1's budget alone.
    let devices_ref = &devices;
    let phase1_timeout = phase1_timeout_for_this_run();
    let started = tokio::time::Instant::now();
    let phase1_deadline = started + phase1_timeout;
    let overall_deadline = started + phase1_timeout + PHASE2_STABILITY_TIMEOUT;

    let mut last_snapshots: Vec<HashMap<String, String>> =
        devices_ref.iter().map(|d| snapshot(d.root.path())).collect();
    let mut stable_since: Option<tokio::time::Instant> = None;
    // Diagnostic counters -- surfaced only on a timeout panic, never affect
    // pass/fail on their own.
    let mut replica_mismatch_polls = 0u32; // polls where devices disagreed with each other
    let mut snapshot_changed_polls = 0u32; // polls where the tracked snapshot changed at all
    let mut read_error_polls = 0u32; // polls where any device hit a transient read error
    let mut current_stable_polls = 0u32;
    let mut max_stable_polls = 0u32;
    let mut first_equal_elapsed: Option<Duration> = None;
    let mut last_change_elapsed = Duration::ZERO;

    // Takes every counter as an explicit argument rather than capturing the
    // loop's mutable locals by reference -- a capturing closure held across
    // the loop's own later mutations of those same locals would conflict
    // with the borrow checker (this closure is only ever invoked, and only
    // needs each value, at the instant of a timeout panic).
    #[allow(clippy::too_many_arguments)]
    let timeout_context = |current: &[HashMap<String, String>],
                           replica_mismatch_polls: u32,
                           snapshot_changed_polls: u32,
                           read_error_polls: u32,
                           current_stable_polls: u32,
                           max_stable_polls: u32,
                           first_equal_elapsed: Option<Duration>,
                           last_change_elapsed: Duration| {
        let dump = current
            .iter()
            .enumerate()
            .map(|(i, snap)| format!("device-{i} snapshot={snap:?}"))
            .collect::<Vec<_>>()
            .join("\n");
        // DAG-heads + index-state detail for whatever currently differs. A
        // timeout here means the code after this loop (which would
        // otherwise produce this same detail) never runs, so without this
        // the only diagnostic a CI-only timeout leaves behind is raw file
        // content -- not enough to tell a stalled delivery/admission from a
        // materialization determinism bug apart.
        let diag = diff_diagnostics(devices_ref, &group_id, current);
        let progress = dag_progress_report(devices_ref, &group_id, started.elapsed());
        let head_report = divergent_head_report(devices_ref, &group_id);
        format!(
            "replica_mismatch_polls={replica_mismatch_polls} snapshot_changed_polls={snapshot_changed_polls} \
             read_error_polls={read_error_polls} current_stable_polls={current_stable_polls} \
             max_stable_polls={max_stable_polls} first_equal_elapsed={first_equal_elapsed:?} \
             last_change_elapsed={last_change_elapsed:?}\n{dump}\n\
             --- DAG heads / sync_state detail for currently-differing paths ---\n{diag}\
             --- DAG progress at timeout ---\n{progress}\
             --- per-head DAG disposition across devices ---\n{head_report}"
        )
    };

    let mut polls = 0u32;
    loop {
        let now = tokio::time::Instant::now();
        panic_if_any_session_died(&mesh_teardown.session_handles, now.duration_since(started));
        polls += 1;
        if polls.is_multiple_of(DAG_PROGRESS_EVERY_POLLS) {
            eprint!("{}", dag_progress_report(devices_ref, &group_id, now.duration_since(started)));
            if polls.is_multiple_of(DAG_HEAD_REPORT_EVERY_POLLS) {
                eprint!("{}", divergent_head_report(devices_ref, &group_id));
            }
        }
        let current: Vec<HashMap<String, String>> =
            devices_ref.iter().map(|d| snapshot(d.root.path())).collect();
        let replicas_equal = current[1..].iter().all(|snapshot| snapshot == &current[0]);
        let has_read_error =
            current.iter().any(|snap| snap.values().any(|v| v.starts_with("<read-error:")));
        if !replicas_equal {
            replica_mismatch_polls += 1;
        }
        if has_read_error {
            read_error_polls += 1;
        }
        let changed_since_last = current != last_snapshots;
        if changed_since_last {
            snapshot_changed_polls += 1;
            last_change_elapsed = now.duration_since(started);
            last_snapshots = current.clone();
        }

        if replicas_equal {
            if first_equal_elapsed.is_none() {
                first_equal_elapsed = Some(now.duration_since(started));
            }
            if changed_since_last || stable_since.is_none() {
                stable_since = Some(now);
                current_stable_polls = 0;
            } else {
                current_stable_polls += 1;
                max_stable_polls = max_stable_polls.max(current_stable_polls);
            }
            if now.duration_since(stable_since.expect("just set above")) >= PHASE2_STABILITY_TIMEOUT
            {
                break;
            }
        } else {
            stable_since = None;
            current_stable_polls = 0;
        }

        if first_equal_elapsed.is_none() && now >= phase1_deadline {
            panic!(
                "phase 1 (convergence) never reached agreement across all devices within \
                 {phase1_timeout:?}:\n{}",
                timeout_context(
                    &current,
                    replica_mismatch_polls,
                    snapshot_changed_polls,
                    read_error_polls,
                    current_stable_polls,
                    max_stable_polls,
                    first_equal_elapsed,
                    last_change_elapsed,
                )
            );
        }
        if now >= overall_deadline {
            panic!(
                "phase 2 (stability) never held agreement for {PHASE2_STABILITY_TIMEOUT:?} \
                 straight within the overall {:?} budget:\n{}",
                phase1_timeout + PHASE2_STABILITY_TIMEOUT,
                timeout_context(
                    &current,
                    replica_mismatch_polls,
                    snapshot_changed_polls,
                    read_error_polls,
                    current_stable_polls,
                    max_stable_polls,
                    first_equal_elapsed,
                    last_change_elapsed,
                )
            );
        }
        tokio::time::sleep(CONVERGENCE_POLL_INTERVAL).await;
    }

    // Success-path summary: how long convergence actually took matters even
    // when the run passes -- a pass that only just fit the budget on a
    // loaded host is the same underlying slowness as a failure, observed
    // from the lucky side. The final progress report also records whether
    // any device authored more changes than the rounds gave it a reason to.
    eprintln!(
        "MONKEY_CHAOS converged: first_equal={first_equal_elapsed:?} \
         stability_confirmed_at={:?}",
        started.elapsed()
    );
    eprint!("{}", dag_progress_report(devices_ref, &group_id, started.elapsed()));

    let final_snapshots: Vec<HashMap<String, String>> =
        devices.iter().map(|d| snapshot(d.root.path())).collect();
    let reference = &final_snapshots[0];
    for (i, snap) in final_snapshots.iter().enumerate().skip(1) {
        if snap == reference {
            continue;
        }
        let only_in_reference: Vec<&String> =
            reference.keys().filter(|k| !snap.contains_key(*k)).collect();
        let only_in_other: Vec<&String> =
            snap.keys().filter(|k| !reference.contains_key(*k)).collect();
        let differing_content: Vec<&String> = reference
            .keys()
            .filter(|k| snap.get(*k).is_some_and(|v| v != &reference[*k]))
            .collect();
        let index_dump = diff_diagnostics(&devices, &group_id, &final_snapshots);
        panic!(
            "device-{i} diverged from device-0's final file set after {ROUNDS} random operations\n\
             only on device-0: {only_in_reference:?}\n\
             only on device-{i}: {only_in_other:?}\n\
             present on both but different content: {differing_content:?}\n\
             --- sync_state (index) detail for affected names ---\n{index_dump}"
        );
    }
}

/// Catches a panic inside `run_chaos` (an assertion failure, an
/// `unwrap`, or the final divergence `panic!`) so the seed can be
/// recorded before the failure is re-raised. Uses `catch_unwind` on the
/// future directly rather than `tokio::spawn`, so the caller controls
/// exactly where the panic re-raises without depending on `run_chaos`'s
/// future being `Send`. `AssertUnwindSafe` is sound here because on a
/// caught panic this function immediately re-raises it and the (possibly
/// torn) local state inside `run_chaos` is simply dropped, never observed
/// again.
async fn run_chaos_recording_seed_on_failure(seed: u64) {
    let result = std::panic::AssertUnwindSafe(run_chaos(seed)).catch_unwind().await;
    if let Err(panic_payload) = result {
        record_failing_seed(seed);
        std::panic::resume_unwind(panic_payload);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn random_concurrent_operations_converge_to_an_identical_file_set() {
    let seed = seed_from_env_or_random();
    eprintln!(
        "MONKEY_CHAOS_SEED={seed} (reproduce with: MONKEY_CHAOS_SEED={seed} cargo test -p \
         yadorilink-daemon --test monkey_chaos random_concurrent_operations -- --nocapture)"
    );
    tracing::info!(seed, "starting monkey_chaos run");
    run_chaos_recording_seed_on_failure(seed).await;
}

/// Re-runs every seed recorded in `tests/dst_corpus/monkey_chaos_seeds.txt`
/// (see the module doc comment), so a race this chaos test previously
/// found stays covered by CI/heat-run as a permanent regression check
/// instead of only surfacing again if a future run happens to pick the
/// same interleaving. A no-op (and instantly passing) while the corpus is
/// empty.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn replay_known_failing_seeds() {
    let _ = tracing_subscriber::fmt::try_init();
    for seed in load_corpus_seeds() {
        // Plain stdout, not just `tracing::info!`: a corpus replay failure
        // in ordinary CI output (no RUST_LOG set) previously gave no way to
        // tell which of possibly several corpus seeds actually failed.
        eprintln!(
            "MONKEY_CHAOS replaying corpus seed={seed} (reproduce with: MONKEY_CHAOS_SEED={seed} \
             cargo test -p yadorilink-daemon --test monkey_chaos random_concurrent_operations -- \
             --nocapture)"
        );
        tracing::info!(seed, "replaying corpus seed");
        run_chaos_recording_seed_on_failure(seed).await;
    }
}
