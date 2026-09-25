//! Block-store garbage collection: idle-triggered and on-demand
//! mark-and-sweep scheduling, daemon-wide "only one sweep at a
//! time" coordination, and last-run bookkeeping for `yadorilink status`/
//! `gc [--dry-run]`. Mirrors this crate's existing dispatch-module
//! convention (`update_ipc`, `reporting_ipc`): this module
//! owns the actual GC logic, `control_socket.rs` only translates to/from
//! the wire types.
//!
//! Liveness is computed fresh from the index
//! (`SyncState::live_block_hashes_including_all_dag_retention_roots`) on
//! every sweep rather than transactionally refcounted, so this module needs
//! no persisted state of its own beyond simple bookkeeping counters (below)
//! — a crash mid-sweep just leaves some already-deleted blocks deleted and
//! the rest untouched, safely resumed by the next sweep (content-addressed
//! `delete` is idempotent).

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use yadorilink_local_storage::GcReport;

use crate::adapters::block_store_ports::BlockStorePortsAdapter;
use crate::daemon_state::DaemonState;

/// "Comfortably larger than normal sync-burst duration" — the daemon must
/// have seen no local-change/peer-reconciliation/hydration activity for
/// at least this long before an idle-triggered sweep may run at all. A
/// documented starting point (the exact constant is left to
/// implementation), not a value tuned against production telemetry.
pub const GC_IDLE_THRESHOLD: Duration = Duration::from_secs(5 * 60);

/// "Comfortably larger than the normal local-change/hydration processing
/// latency between a block write and its index commit" — a stored block
/// whose on-disk mtime is newer than this is
/// never swept even if it currently looks unreferenced, since the index
/// row that will reference it may simply not have committed yet (every
/// block-write path writes the block before the referencing index row
/// commits — see `SyncState::live_block_hashes`'s doc comment).
pub const GC_GRACE_WINDOW: Duration = Duration::from_secs(10 * 60);

/// How often the idle scheduler re-checks whether it's been idle long
/// enough to sweep — independent of `GC_IDLE_THRESHOLD` (this is only the
/// poll cadence), short enough that a sweep starts promptly once the
/// daemon does go idle.
pub const GC_IDLE_POLL_INTERVAL: Duration = Duration::from_secs(30);

/// Why a requested sweep did not run (or did not complete).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GcTriggerError {
    /// Another sweep (idle-triggered or on-demand) is
    /// already in progress.
    AlreadyRunning,
    /// GC "runs after sync activity quiesces or on an explicit command,
    /// never mid-burst" — a sync-critical write
    /// (`DaemonState::is_write_safe_point`) was in flight at the moment
    /// this sweep was attempted.
    SyncBurstInProgress,
    /// The live-set query or the sweep itself failed.
    Failed(String),
}

impl std::fmt::Display for GcTriggerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GcTriggerError::AlreadyRunning => {
                write!(f, "a garbage-collection sweep is already in progress; try again shortly")
            }
            GcTriggerError::SyncBurstInProgress => write!(
                f,
                "sync activity is in progress; garbage collection was skipped to avoid \
                 contention -- try again once idle, or wait for the next automatic sweep"
            ),
            GcTriggerError::Failed(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for GcTriggerError {}

fn now_unix() -> i64 {
    SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// Runs one sweep (real or `--dry-run`) against this
/// daemon's block store, enforcing both daemon-wide invariants this
/// change requires — never two sweeps at once, never
/// concurrently with a sync-critical write ("never mid-burst") —
/// regardless of whether the caller is the idle scheduler
/// or an on-demand `gc`/`gc --dry-run` IPC request. An
/// on-demand trigger firing during an idle-triggered attempt does not
/// double-run.
///
/// -style runtime hygiene, mirroring `SegmentBlockStore::present_blocks`:
/// the actual sweep is synchronous, batch-throttled blocking I/O
/// (`SegmentBlockStore::sweep`'s own pacing sleep between batches,
/// `SyncState::live_block_hashes_including_all_dag_retention_roots`'s SQLite
/// scan) — run through
/// `block_in_place` off the async caller's own poll when a multi-threaded
/// tokio runtime is current, so a large sweep never stalls the runtime's
/// other work (the control socket, peer sessions,...) for its duration.
pub async fn run_sweep(state: Arc<DaemonState>, dry_run: bool) -> Result<GcReport, GcTriggerError> {
    run_sweep_with_grace_cutoff(state, dry_run, SystemTime::now() - GC_GRACE_WINDOW).await
}

/// Parameterized by the grace cutoff directly (rather than always deriving
/// it from `GC_GRACE_WINDOW`) so this module's own tests can exercise a
/// real deletion without waiting out the real multi-minute grace window —
/// mirrors `fs_backend.rs`'s own sweep tests, which likewise pass an
/// explicit `grace_cutoff` (e.g. `SystemTime::now + 1s`) rather than a
/// duration. `run_sweep` above is the only production call site and
/// always uses the real `GC_GRACE_WINDOW`.
async fn run_sweep_with_grace_cutoff(
    state: Arc<DaemonState>,
    dry_run: bool,
    grace_cutoff: SystemTime,
) -> Result<GcReport, GcTriggerError> {
    // Offloads onto a `block_in_place` worker when a multi-thread runtime is
    // current, otherwise runs inline (never a multi-thread worker to offload
    // onto: a current-thread runtime, called outside a runtime, or the
    // deterministic simulator, whose tokio shim exposes neither
    // `runtime_flavor()` nor `block_in_place`). Shared with every other
    // call site in this crate that wraps a plain synchronous function this
    // way -- see `daemon_state::run_blocking_sweep_offloaded`'s doc comment.
    crate::daemon_state::run_blocking_sweep_offloaded(|| {
        run_sweep_sync(&state, dry_run, grace_cutoff)
    })
}

fn run_sweep_sync(
    state: &DaemonState,
    dry_run: bool,
    grace_cutoff: SystemTime,
) -> Result<GcReport, GcTriggerError> {
    let _guard = state.gc.try_start().map_err(|()| GcTriggerError::AlreadyRunning)?;

    // "Never mid-burst" — checked *after* claiming `running` (so a
    // genuinely concurrent attempt observes the more specific
    // `AlreadyRunning` rather than this) but before any real work starts.
    // A manual `gc` bypasses the *idle wait*, not this check: bypassing
    // the idle wait does not bypass the "never concurrently with another
    // sweep" invariant; never running during active sync IO is a
    // stronger, always-on invariant, not just a property of the idle
    // trigger.
    if !state.is_write_safe_point() {
        return Err(GcTriggerError::SyncBurstInProgress);
    }
    // Close the check/snapshot race: a writer that starts after the safe-point
    // check either finishes before this guard is acquired (and is included in
    // `live`) or waits until deletion has completed.
    let _block_deletion = state.begin_block_deletion();

    // `live_block_hashes` alone already includes every retained
    // version/trash record's blocks (any `deleted = 0` row, current or
    // superseded/trashed alike — see its own doc comment). This is also
    // why a full-replica-handoff lease's pin needs no block-level
    // awareness here: a leased `(path, version_seq)` row only stops being
    // a `files` row (and so only stops contributing its blocks to `live`)
    // once `SyncState::expire_superseded_and_trashed_versions` actually
    // deletes it, and that retention sweep is exactly what
    // `SyncState::leased_version_keys_for_group` gates. As long as the row
    // survives retention, its blocks are already live from this sweep's
    // own point of view — the pin's real enforcement point is retention,
    // not GC.
    let live = state
        .replica_coordinator
        .materialization_state_repository()
        .live_block_hashes_including_all_dag_retention_roots()
        .map_err(|e| GcTriggerError::Failed(e.to_string()))?;
    // `DaemonState::block_store` is already an erased `Arc<dyn BlockStore +
    // Send + Sync>`, which does not itself unsize-coerce to `&dyn
    // BlockReclamationStore` (that re-coercion needs a declared supertrait
    // relationship, not one established only via a blanket impl) — wrap it
    // through the adapter, same as every other daemon-side call site below.
    let block_reclamation = BlockStorePortsAdapter::new(state.block_store.clone());
    let report = yadorilink_filesystem_sync::block_deletion::sweep_globally_unreferenced_blocks(
        &_block_deletion,
        &block_reclamation,
        &live,
        grace_cutoff,
        dry_run,
    )
    .map_err(|e| GcTriggerError::Failed(e.to_string()))?;

    if dry_run {
        state.gc.record_dry_run(report.bytes_reclaimed);
    } else {
        // Everything reclaimable as of this snapshot was just reclaimed.
        state.gc.record_real_sweep(now_unix(), report.blocks_deleted, report.bytes_reclaimed);
    }
    Ok(report)
}

/// the idle scheduler's single tick — called on
/// `GC_IDLE_POLL_INTERVAL` by the periodic task `DaemonState::new` spawns,
/// and called directly (with an injected `idle_threshold`) by this
/// module's own tests so they never have to wait out the real
/// multi-minute `GC_IDLE_THRESHOLD`. Returns `None` when not idle long
/// enough to attempt a sweep at all; `Some(_)` with the attempt's outcome
/// otherwise. `AlreadyRunning`/`SyncBurstInProgress` are expected, benign
/// outcomes for the scheduler specifically (an on-demand sweep may
/// already be running, or activity may have resumed in the gap between
/// the idle check and the attempt) — the caller logs those at `debug`,
/// reserving `warn` for `Failed`.
pub async fn maybe_run_idle_sweep(
    state: &Arc<DaemonState>,
    idle_threshold: Duration,
) -> Option<Result<GcReport, GcTriggerError>> {
    if state.idle_duration() < idle_threshold {
        return None;
    }
    Some(run_sweep(state.clone(), false).await)
}

/// resolves `materialization::run_eviction_sweep`'s previously
/// entirely-absent periodic caller — `run_eviction_sweep` existed but
/// had no periodic caller in the daemon at all. Runs on the same
/// idle-scheduler cadence as the GC sweep above: every `OnDemand` link
/// with a configured `max_local_size_bytes` cap gets that cap enforced
/// here too, not only reactively on measured disk-space pressure
/// (`run_disk_pressure_eviction_sweep`, already wired from
/// `hydration.rs`'s materialize path) or never at all between hydrations.
/// Deliberately not gated on `idle_duration`/`is_write_safe_point` the way
/// the GC sweep above is — eviction only ever demotes an already-hydrated
/// file back to a placeholder (index write + one file rename), the same
/// bounded, synchronous-SQLite-and-filesystem-only shape as
/// `run_retention_expiry_sweep`, not the store-wide directory walk GC's
/// sweep performs, so it does not compete for IO the way this change's
/// own scheduling logic exists to protect against.
///
/// Logs (rather than propagates) a per-link failure so one link's error
/// never stops the sweep from covering the rest, mirroring
/// `run_retention_expiry_sweep`'s own per-link error handling.
pub fn run_periodic_capacity_eviction_sweep(state: &DaemonState) {
    let links = match state.replica_coordinator.link_repository().list_links() {
        Ok(links) => links,
        Err(e) => {
            tracing::warn!(error = %e, "periodic capacity-eviction sweep: failed to list links");
            return;
        }
    };
    for link in links {
        // An orphaned link is no longer a live sync target -- eviction still
        // writes to disk (renaming a hydrated file back to a placeholder),
        // which would violate "orphaned never touches on-disk files" the
        // same way any other sync activity would.
        if link.orphaned {
            continue;
        }
        if link.materialization_policy
            != yadorilink_replica_domain::session_state::MaterializationPolicy::OnDemand
            || link.max_local_size_bytes.is_none()
        {
            continue;
        }
        if !yadorilink_filesystem_sync::placeholder_backend::on_demand_pipeline_is_connected() {
            tracing::warn!(
                group_id = %link.group_id,
                local_path = %link.local_path,
                "periodic capacity-eviction sweep: on-demand placeholder pipeline is not \
                 connected; refusing to evict"
            );
            continue;
        }
        let root = std::path::Path::new(&link.local_path);
        let root_lease = match state.root_lease_for(&link.group_id) {
            Ok(lease) => lease,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    group_id = %link.group_id,
                    local_path = %link.local_path,
                    "periodic capacity-eviction sweep: no live root lease for this link"
                );
                continue;
            }
        };
        let root_op = match root_lease.begin_operation() {
            Ok(op) => op,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    group_id = %link.group_id,
                    local_path = %link.local_path,
                    "periodic capacity-eviction sweep: root lease refused a new operation"
                );
                continue;
            }
        };
        let root_commit_permit = root_op.permit();
        // See `run_sweep_sync`'s matching comment: `state.block_store` is an
        // already-erased `Arc<dyn BlockStore + Send + Sync>`, so it needs the
        // adapter to reach `&dyn BlockReclamationStore`.
        let block_reclamation = BlockStorePortsAdapter::new(state.block_store.clone());
        // This loop only reaches OnDemand links, so this device is not a full
        // replica of the group; custody is consulted per file so the sweep only
        // reclaims blocks a full replica is confirmed to hold.
        match yadorilink_filesystem_sync::materialization_eviction::run_eviction_sweep(
            yadorilink_filesystem_sync::materialization_eviction::MaterializationContext {
                state: state.replica_coordinator.as_ref(),
                liveness_gate: state.block_liveness_gate(),
                store: &block_reclamation,
                root,
                permit: &root_commit_permit,
            },
            &link.group_id,
            false,
            link.max_local_size_bytes,
            state,
        ) {
            Ok(evicted) if !evicted.is_empty() => {
                tracing::debug!(
                    group_id = %link.group_id,
                    local_path = %link.local_path,
                    evicted_count = evicted.len(),
                    "periodic capacity-eviction sweep evicted files back to placeholders"
                );
            }
            Ok(_) => {}
            Err(e) => tracing::warn!(
                error = %e,
                group_id = %link.group_id,
                local_path = %link.local_path,
                "periodic capacity-eviction sweep failed for this link"
            ),
        }
    }
}

#[cfg(test)]
mod tests;
