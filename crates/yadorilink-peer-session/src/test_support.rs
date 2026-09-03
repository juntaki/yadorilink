//! In-memory `PeerReplicaStatePort` test double, `#[cfg(test)]`-only, for
//! `peer_session.rs`'s own unit tests. Built instead of depending on
//! `yadorilink-sync-core`'s real, SQL-backed `SyncState` (forbidden --
//! this crate may not depend on `yadorilink-sync-core`, even as a
//! dev-dependency, see this crate's own module doc) or relocating every
//! `SyncState`-touching test to `yadorilink-sync-core/tests/peer_session.rs`
//! as an external, public-API-only integration test (which would gut most
//! of them: they are white-box tests of `peer_session.rs`'s own internal
//! logic -- hazard classification, wire encoding, admission bookkeeping --
//! that only incidentally need a handle satisfying the port for setup, not
//! tests of `SyncState`'s own SQL/persistence semantics).
//!
//! Plain `HashMap`s behind one `Mutex`, single-process, no real
//! persistence. Deliberately not a `SyncState` reimplementation: this
//! models only the observable contract `PeerReplicaStatePort` promises,
//! not `SyncState`'s internal SQL schema or transaction boundaries. A
//! handful of methods this fake's calling tests never reach are left
//! `unimplemented!()` -- a panic there is a loud, immediate signal this
//! fake needs extending for a new test, not silently wrong behavior.
//!
//! Several setup helpers below (`new_arc`, `set_link_gate`,
//! `set_materialization_policy`, `set_windows_symlink_opt_in`,
//! `seed_version`, `seed_file_version`, `seed_block_provenance`,
//! `dag_has_change`, `dag_has_change_or_buffered_orphan`,
//! `dag_admit_change`) were built against the port's full surface for
//! modules that, on inspection, turned out to need real `dag_store`
//! SQL/signing machinery this fake deliberately doesn't reimplement (see
//! `yadorilink-sync-core/tests/peer_session.rs`'s `promoted_orphan_
//! projection_tests`/`reconcile_group_paths_flush_tests`/
//! `dag_convergence_authority_tests`/`authorization_monotonicity_tests`/
//! `dag_negotiated_restart_regression_tests`/`version_hash_exact_
//! capability_tests`, relocated there instead). Kept, not deleted: they're
//! genuinely useful for the next test that only needs the port as
//! plumbing, and deleting working, documented setup code the moment its
//! first caller moves elsewhere just to silence `dead_code` would be
//! counter-productive.
#![allow(dead_code)]

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::{Arc, Mutex};

use yadorilink_replica_domain::admission::{AdmitOutcome, AdmitResult, ChangeOrdering};
use yadorilink_replica_domain::change::Change;
use yadorilink_replica_domain::file::{FileRecord, FileVersion, RecordKind};
use yadorilink_replica_domain::ids::{ChangeHash, VersionHash};
use yadorilink_replica_domain::session_state::{
    CurrentVersionRecord, HeldState, LinkGate, MaterializationPolicy, MaterializationState,
    StartupFailed, VersionRecord,
};
use yadorilink_root_authority::root_commit::RootCommitPermit;

use crate::error::PeerSessionError;
use crate::ports::{MaterializedFingerprint, OpenMaterializationIntent, PeerReplicaStatePort};

/// Per-`(group_id, path)` bookkeeping this fake tracks -- every column
/// `PeerReplicaStatePort` exposes a getter/setter for, flattened into one
/// row instead of `SyncState`'s several backing tables.
#[derive(Default, Clone)]
struct Row {
    current: Option<FileRecord>,
    record_kind: Option<RecordKind>,
    symlink_target: Option<Vec<u8>>,
    symlink_out_of_root: bool,
    unix_mode: Option<u32>,
    xattrs: Vec<(String, Vec<u8>)>,
    origin_device_id: Option<String>,
    authoring_change_hash: Option<ChangeHash>,
    materialization_state: Option<MaterializationState>,
    placeholder_identity: Option<yadorilink_local_storage::PlaceholderDiskIdentity>,
    pinned: bool,
    held: Option<HeldState>,
    last_accessed_unix_nanos: Option<i64>,
    materialization_intent_open: bool,
    dirty: bool,
    versions: Vec<VersionRecord>,
}

struct GroupState {
    link_gate: LinkGate,
    materialization_policy: Option<MaterializationPolicy>,
    windows_symlink_opt_in: bool,
    rows: HashMap<String, Row>,
    heads: Vec<ChangeHash>,
    history_paths: HashSet<String>,
    block_provenance: HashSet<Vec<u8>>,
    device_frontier: HashMap<String, ChangeHash>,
}

impl Default for GroupState {
    fn default() -> Self {
        Self {
            link_gate: LinkGate::NoLiveLink,
            materialization_policy: None,
            windows_symlink_opt_in: false,
            rows: HashMap::new(),
            heads: Vec::new(),
            history_paths: HashSet::new(),
            block_provenance: HashSet::new(),
            device_frontier: HashMap::new(),
        }
    }
}

#[derive(Default)]
struct Inner {
    groups: HashMap<String, GroupState>,
    changes: HashMap<ChangeHash, Change>,
    encoded: HashMap<ChangeHash, Vec<u8>>,
    applied: HashSet<ChangeHash>,
    /// Orphans buffered until their parents arrive, matching the real
    /// dag_store's own admission-ordering contract closely enough for
    /// this file's tests: `dag_admit_change_with_versions` only inserts a
    /// change once every parent is already present, and promotes any
    /// buffered orphan whose parents just became satisfied.
    orphans: Vec<Change>,
    file_versions: HashMap<(String, VersionHash), FileVersion>,
    path_locks: HashMap<(String, String), Arc<tokio::sync::Mutex<()>>>,
    verify_root_fails: bool,
    /// Forces `record_acknowledged_frontier` to fail -- for characterizing
    /// the frontier-write-failure-continues-with-warning behavior
    /// `announce_local_commit`/`handle_change_batch` both document at their
    /// own `tracing::warn!` call sites: a failed frontier write is logged
    /// but never aborts the caller.
    record_acknowledged_frontier_fails: bool,
    /// Counts `notify_materialization_wake` calls -- lets a test assert the
    /// wake-once-per-batch (not once-per-change) invariant `handle_change_
    /// batch`'s own `if !affected_paths.is_empty()` gate documents.
    notify_materialization_wake_count: usize,
    /// Groups `notify_retirement_wake` has been called with, in call order
    /// (duplicates kept) -- lets a test assert which groups an admission or
    /// job-completion path actually marked dirty.
    notify_retirement_wake_calls: Vec<String>,
    /// Same shape as `notify_retirement_wake_calls`, for `notify_hazard_
    /// recheck_wake`.
    notify_hazard_recheck_wake_calls: Vec<String>,
    /// C4-6: forces `finalize_projected_mutations_batch` to fail -- for
    /// asserting that a batch commit's own transaction failure never
    /// leaves a caller believing any of its paths settled (see `try_
    /// commit_ordinary_batch`'s own doc comment: the whole call errors
    /// instead of returning a "some settled, some retry" result, so
    /// nothing it touched can be read as done).
    finalize_projected_mutations_batch_fails: bool,
    /// M6PHASE cross-file provenance batching: forces `record_group_block_
    /// provenance` to fail -- for asserting that a failed cross-file
    /// provenance transaction never lets a dependent ordinary candidate
    /// publish/settle (see `try_commit_ordinary_batch`'s own fail-closed
    /// handling of this).
    record_group_block_provenance_fails: bool,
    /// C4-7 phase 2: counts of the two writer_gate-consuming calls a fully-
    /// settled re-examination must make ZERO of -- lets a test assert that
    /// precisely, rather than only inferring it from observed row state.
    apply_incoming_metadata_atomic_calls: usize,
    apply_projected_row_atomic_calls: usize,
    /// C4-7 phase 3: counts `set_authoring_change_hash` calls -- an
    /// already-fully-settled tombstone re-examination must make ZERO of
    /// these too.
    set_authoring_change_hash_calls: usize,
    /// C4-12 decision 3d: per-`(group_id, path)` filesystem-side mutation
    /// fence, bumped by `dag_bump_mutation_fence` and read (create-at-0 if
    /// absent) by `dag_snapshot_mutation_fence` -- this fake's stand-in for
    /// `path_actual_mutation_fences`.
    mutation_fences: HashMap<(String, String), i64>,
    /// C4-12 decision 3e: last-published materialized-generation evidence
    /// per `(group_id, path)`, keyed by the mutation-fence value it was
    /// published under -- this fake's stand-in for
    /// `path_materialized_generations`. Deliberately doesn't model the
    /// causal-frontier half of the real CAS (no DAG in this fake); only the
    /// mutation-fence half is enforced, matching what this file's tests
    /// actually need to exercise (the race the fence exists to catch).
    materialized_generations:
        HashMap<(String, String), (i64, Vec<ChangeHash>, Option<RecordKind>, Option<VersionHash>)>,
    /// M6PHASE provenance-write-amplification investigation: one entry per
    /// `record_group_block_provenance` CALL (not per hash), each holding
    /// the exact hash slice that call was given -- a "counting fake" for
    /// asserting one batched call for N blocks, not merely eventual
    /// `block_provenance` table contents (which cannot distinguish "one
    /// call with N hashes" from "N calls with one hash each").
    record_group_block_provenance_batches: Vec<Vec<Vec<u8>>>,
    /// Same counting-fake reasoning as `record_group_block_provenance_
    /// batches` above, for asserting the pre-existing stale-refusal-clear
    /// behavior (`(group_id, path, version_hash_hex, peer_device_id)` per
    /// call) survives the provenance-batching change unaffected.
    clear_block_fetch_refusal_calls: Vec<(String, String, String, String)>,
}

/// The fake itself. `Arc`-wrapped by callers exactly like a real
/// `Arc<dyn PeerReplicaStatePort>` would be.
#[derive(Default)]
pub struct FakeReplicaState {
    inner: Mutex<Inner>,
    /// Call-graph regression counters:
    /// `dag_list_unapplied_changes`/`dag_mark_applied` must
    /// never be reached from the periodic materialization audit's
    /// production call graph -- these count every call, from any caller,
    /// so a test can assert zero rather than relying on comments.
    unapplied_changes_call_count: std::sync::atomic::AtomicUsize,
    mark_applied_call_count: std::sync::atomic::AtomicUsize,
}

impl FakeReplicaState {
    /// See the fields' own doc comment.
    pub fn dag_list_unapplied_changes_call_count(&self) -> usize {
        self.unapplied_changes_call_count.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// See the fields' own doc comment.
    pub fn dag_mark_applied_call_count(&self) -> usize {
        self.mark_applied_call_count.load(std::sync::atomic::Ordering::Relaxed)
    }
    /// Returns a bare, un-`Arc`-wrapped fake -- most of this file's tests
    /// call a free function taking `&dyn PeerReplicaStatePort` directly
    /// (unsize-coercing `&FakeReplicaState`), matching how they used to
    /// hold a bare `SyncState`. Tests that construct a real
    /// `PeerSyncSession` (which holds `Arc<dyn PeerReplicaStatePort>`)
    /// should use [`Self::new_arc`] instead.
    pub fn new() -> Self {
        Self::default()
    }

    pub fn new_arc() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Test-setup helper: registers `group_id` as known (defaulting to
    /// `LinkGate::Live`) and, if `root` is given, writes the on-disk root
    /// marker file this fake's own `verify_root` checks for -- mirroring
    /// `SyncState::add_link` + `VerifiedRoot::open`'s combined effect on
    /// the one thing production code (`materialize_symlink_at`'s
    /// `state.verify_root` call) actually observes, without needing
    /// `VerifiedRoot`'s real cryptographic-token machinery.
    pub fn add_link(&self, root: Option<&Path>, group_id: &str) {
        let mut inner = self.lock();
        let local_path = root.map(|r| r.to_string_lossy().to_string()).unwrap_or_default();
        let group = inner.groups.entry(group_id.to_string()).or_default();
        group.link_gate = LinkGate::Live { local_path, policy: MaterializationPolicy::Eager };
        if let Some(root) = root {
            let _ = std::fs::write(
                root.join(yadorilink_replica_domain::reserved_paths::ROOT_MARKER_FILE_NAME),
                b"fake-root-marker",
            );
        }
    }

    /// Forces `verify_root` to fail for every group until reset -- a
    /// no-filesystem alternative to a test deleting the on-disk marker
    /// file when it doesn't have (or want) a real tempdir root.
    pub fn set_verify_root_fails(&self, fails: bool) {
        self.lock().verify_root_fails = fails;
    }

    /// See `Inner::record_acknowledged_frontier_fails`'s doc comment.
    pub fn set_record_acknowledged_frontier_fails(&self, fails: bool) {
        self.lock().record_acknowledged_frontier_fails = fails;
    }

    /// See `Inner::finalize_projected_mutations_batch_fails`'s doc comment.
    pub fn set_finalize_projected_mutations_batch_fails(&self, fails: bool) {
        self.lock().finalize_projected_mutations_batch_fails = fails;
    }

    /// See `Inner::record_group_block_provenance_fails`'s doc comment.
    pub fn set_record_group_block_provenance_fails(&self, fails: bool) {
        self.lock().record_group_block_provenance_fails = fails;
    }

    /// See `Inner::notify_materialization_wake_count`'s doc comment.
    pub fn notify_materialization_wake_count(&self) -> usize {
        self.lock().notify_materialization_wake_count
    }

    /// See `Inner::apply_incoming_metadata_atomic_calls`'s doc comment.
    pub fn apply_incoming_metadata_atomic_calls(&self) -> usize {
        self.lock().apply_incoming_metadata_atomic_calls
    }

    /// See `Inner::apply_projected_row_atomic_calls`'s doc comment.
    pub fn apply_projected_row_atomic_calls(&self) -> usize {
        self.lock().apply_projected_row_atomic_calls
    }

    /// See `Inner::set_authoring_change_hash_calls`'s doc comment.
    pub fn set_authoring_change_hash_calls(&self) -> usize {
        self.lock().set_authoring_change_hash_calls
    }

    /// See `Inner::notify_retirement_wake_calls`'s doc comment.
    pub fn notify_retirement_wake_calls(&self) -> Vec<String> {
        self.lock().notify_retirement_wake_calls.clone()
    }

    /// See `Inner::record_group_block_provenance_batches`'s doc comment.
    pub fn record_group_block_provenance_batches(&self) -> Vec<Vec<Vec<u8>>> {
        self.lock().record_group_block_provenance_batches.clone()
    }

    /// See `Inner::clear_block_fetch_refusal_calls`'s doc comment.
    pub fn clear_block_fetch_refusal_calls(&self) -> Vec<(String, String, String, String)> {
        self.lock().clear_block_fetch_refusal_calls.clone()
    }

    /// See `Inner::notify_hazard_recheck_wake_calls`'s doc comment.
    pub fn notify_hazard_recheck_wake_calls(&self) -> Vec<String> {
        self.lock().notify_hazard_recheck_wake_calls.clone()
    }

    pub fn set_link_gate(&self, group_id: &str, gate: LinkGate) {
        self.lock().groups.entry(group_id.to_string()).or_default().link_gate = gate;
    }

    pub fn set_materialization_policy(
        &self,
        group_id: &str,
        policy: Option<MaterializationPolicy>,
    ) {
        self.lock().groups.entry(group_id.to_string()).or_default().materialization_policy = policy;
    }

    pub fn set_windows_symlink_opt_in(&self, group_id: &str, opt_in: bool) {
        self.lock().groups.entry(group_id.to_string()).or_default().windows_symlink_opt_in = opt_in;
    }

    /// Test-setup helper: unconditionally stores `record` as the current
    /// row for `(group_id, record.path)`, matching what `SyncState::
    /// upsert_file` (no origin tracking) does for test fixtures that call
    /// it directly rather than through the port's `upsert_file_with_origin`.
    pub fn seed_file(&self, group_id: &str, record: &FileRecord) {
        let mut inner = self.lock();
        let row = inner
            .groups
            .entry(group_id.to_string())
            .or_default()
            .rows
            .entry(record.path.clone())
            .or_default();
        row.current = Some(record.clone());
    }

    /// Test-setup helper mirroring `SyncState::seed_version_history` /
    /// direct retained-version insertion for tests asserting on
    /// `list_versions`.
    pub fn seed_version(&self, group_id: &str, path: &str, version: VersionRecord) {
        let mut inner = self.lock();
        let row = inner
            .groups
            .entry(group_id.to_string())
            .or_default()
            .rows
            .entry(path.to_string())
            .or_default();
        row.versions.push(version);
    }

    /// Test-setup helper: inserts a change directly into the DAG without
    /// going through admission ordering (parents assumed already
    /// satisfied) -- for tests seeding retained history a peer is assumed
    /// to already share, not exercising admission itself.
    pub fn seed_change(&self, change: Change, applied: bool) {
        let mut inner = self.lock();
        let hash = change.compute_hash();
        let group_id = change.group_id.as_str().to_string();
        let parents = change.parents.clone();
        inner.encoded.insert(hash, change.encode());
        inner.changes.insert(hash, change);
        if applied {
            inner.applied.insert(hash);
        }
        let group = inner.groups.entry(group_id).or_default();
        group.heads.retain(|h| !parents.contains(h));
        if !group.heads.contains(&hash) {
            group.heads.push(hash);
        }
    }

    pub fn seed_file_version(&self, group_id: &str, version: FileVersion) {
        let hash = version.compute_hash();
        self.lock().file_versions.insert((group_id.to_string(), hash), version);
    }

    pub fn seed_block_provenance(&self, group_id: &str, block_hash: &[u8]) {
        self.lock()
            .groups
            .entry(group_id.to_string())
            .or_default()
            .block_provenance
            .insert(block_hash.to_vec());
    }

    /// Test-setup helper mirroring `SyncState::upsert_file` (the no-
    /// origin-tracking write, distinct from the port's
    /// `upsert_file_with_origin`) -- same as [`Self::seed_file`], with an
    /// ignored trailing `&RootCommitPermit` so existing call sites
    /// carrying one over from `SyncState::upsert_file`'s real signature
    /// need no further edits.
    pub fn upsert_file(
        &self,
        group_id: &str,
        record: &FileRecord,
        _permit: &RootCommitPermit,
    ) -> Result<(), PeerSessionError> {
        self.seed_file(group_id, record);
        Ok(())
    }

    /// No-op stand-ins for `SyncState::begin_group_startup`/
    /// `mark_group_ready`: this fake's own `wait_group_ready` always
    /// succeeds unconditionally (no startup gate to arm), so these exist
    /// only so call sites ported from `SyncState`-based fixtures compile
    /// unchanged. The returned token carries no meaning.
    pub fn begin_group_startup(&self, _group_id: &str) -> u64 {
        0
    }

    pub fn mark_group_ready(&self, _group_id: &str, _generation: u64) {}

    /// Mirrors `SyncState::dag_has_change_or_buffered_orphan`.
    pub fn dag_has_change_or_buffered_orphan(
        &self,
        hash: &ChangeHash,
    ) -> Result<bool, PeerSessionError> {
        let inner = self.lock();
        Ok(inner.changes.contains_key(hash)
            || inner.orphans.iter().any(|c| &c.compute_hash() == hash))
    }

    /// Mirrors `SyncState::dag_admit_change` (no explicit `versions` --
    /// delegates to the same admission logic backing the port's own
    /// `dag_admit_change_with_versions` with an empty version list).
    pub fn dag_admit_change(
        &self,
        change: &Change,
        applied: bool,
    ) -> Result<AdmitResult, PeerSessionError> {
        PeerReplicaStatePort::dag_admit_change_with_versions(self, change, &[], applied)
    }

    fn is_ancestor_locked(inner: &Inner, ancestor: &ChangeHash, descendant: &ChangeHash) -> bool {
        if ancestor == descendant {
            return false;
        }
        let mut frontier = vec![*descendant];
        let mut seen = HashSet::new();
        while let Some(h) = frontier.pop() {
            if !seen.insert(h) {
                continue;
            }
            let Some(change) = inner.changes.get(&h) else { continue };
            for parent in &change.parents {
                if parent == ancestor {
                    return true;
                }
                frontier.push(*parent);
            }
        }
        false
    }

    /// Promotes any buffered orphan whose parents are now all present,
    /// recursively, appending each promoted hash to `newly_admitted`.
    fn promote_orphans_locked(inner: &mut Inner, newly_admitted: &mut Vec<ChangeHash>) {
        loop {
            let ready_idx = inner
                .orphans
                .iter()
                .position(|c| c.parents.iter().all(|p| inner.changes.contains_key(p)));
            let Some(idx) = ready_idx else { break };
            let change = inner.orphans.remove(idx);
            let hash = change.compute_hash();
            let group_id = change.group_id.as_str().to_string();
            inner.encoded.insert(hash, change.encode());
            inner.changes.insert(hash, change);
            let group = inner.groups.entry(group_id).or_default();
            group
                .heads
                .retain(|h| !inner.changes.get(h).map(|c| c.parents.contains(h)).unwrap_or(false));
            group.heads.push(hash);
            newly_admitted.push(hash);
        }
    }
}

#[async_trait::async_trait]
impl PeerReplicaStatePort for FakeReplicaState {
    async fn wait_group_ready(&self, _group_id: &str) -> Result<(), StartupFailed> {
        Ok(())
    }

    fn path_lock(&self, group_id: &str, path: &str) -> Arc<tokio::sync::Mutex<()>> {
        self.lock()
            .path_locks
            .entry((group_id.to_string(), path.to_string()))
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }

    fn link_gate_for_group(&self, group_id: &str) -> Result<LinkGate, PeerSessionError> {
        Ok(self.lock().groups.entry(group_id.to_string()).or_default().link_gate.clone())
    }

    fn materialization_policy_for_group(
        &self,
        group_id: &str,
    ) -> Result<Option<MaterializationPolicy>, PeerSessionError> {
        Ok(self.lock().groups.entry(group_id.to_string()).or_default().materialization_policy)
    }

    fn windows_symlink_opt_in_for_group(&self, group_id: &str) -> Result<bool, PeerSessionError> {
        Ok(self.lock().groups.entry(group_id.to_string()).or_default().windows_symlink_opt_in)
    }

    fn get_file(&self, group_id: &str, path: &str) -> Result<Option<FileRecord>, PeerSessionError> {
        Ok(self
            .lock()
            .groups
            .get(group_id)
            .and_then(|g| g.rows.get(path))
            .and_then(|r| r.current.clone()))
    }

    fn get_files_by_paths(
        &self,
        group_id: &str,
        paths: &[String],
    ) -> Result<HashMap<String, FileRecord>, PeerSessionError> {
        let inner = self.lock();
        let mut out = HashMap::new();
        if let Some(group) = inner.groups.get(group_id) {
            for path in paths {
                if let Some(record) = group.rows.get(path).and_then(|r| r.current.clone()) {
                    out.insert(path.clone(), record);
                }
            }
        }
        Ok(out)
    }

    fn has_real_current_row(&self, group_id: &str, path: &str) -> Result<bool, PeerSessionError> {
        Ok(self
            .lock()
            .groups
            .get(group_id)
            .and_then(|g| g.rows.get(path))
            .map(|r| r.current.is_some())
            .unwrap_or(false))
    }

    fn get_record_kind(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<RecordKind>, PeerSessionError> {
        Ok(self
            .lock()
            .groups
            .get(group_id)
            .and_then(|g| g.rows.get(path))
            .and_then(|r| r.record_kind))
    }

    fn get_symlink_target(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<Vec<u8>>, PeerSessionError> {
        Ok(self
            .lock()
            .groups
            .get(group_id)
            .and_then(|g| g.rows.get(path))
            .and_then(|r| r.symlink_target.clone()))
    }

    fn get_symlink_out_of_root(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<bool, PeerSessionError> {
        Ok(self
            .lock()
            .groups
            .get(group_id)
            .and_then(|g| g.rows.get(path))
            .map(|r| r.symlink_out_of_root)
            .unwrap_or(false))
    }

    fn get_xattrs(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Vec<(String, Vec<u8>)>, PeerSessionError> {
        Ok(self
            .lock()
            .groups
            .get(group_id)
            .and_then(|g| g.rows.get(path))
            .map(|r| r.xattrs.clone())
            .unwrap_or_default())
    }

    fn get_unix_mode(&self, group_id: &str, path: &str) -> Result<Option<u32>, PeerSessionError> {
        Ok(self
            .lock()
            .groups
            .get(group_id)
            .and_then(|g| g.rows.get(path))
            .and_then(|r| r.unix_mode))
    }

    fn get_origin_device_id(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<String>, PeerSessionError> {
        Ok(self
            .lock()
            .groups
            .get(group_id)
            .and_then(|g| g.rows.get(path))
            .and_then(|r| r.origin_device_id.clone()))
    }

    fn get_authoring_change_hash(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<ChangeHash>, PeerSessionError> {
        Ok(self
            .lock()
            .groups
            .get(group_id)
            .and_then(|g| g.rows.get(path))
            .and_then(|r| r.authoring_change_hash))
    }

    fn set_authoring_change_hash(
        &self,
        group_id: &str,
        path: &str,
        hash: &ChangeHash,
    ) -> Result<(), PeerSessionError> {
        let mut inner = self.lock();
        inner.set_authoring_change_hash_calls += 1;
        inner
            .groups
            .entry(group_id.to_string())
            .or_default()
            .rows
            .entry(path.to_string())
            .or_default()
            .authoring_change_hash = Some(*hash);
        Ok(())
    }

    fn get_materialization_state(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<MaterializationState>, PeerSessionError> {
        Ok(self
            .lock()
            .groups
            .get(group_id)
            .and_then(|g| g.rows.get(path))
            .and_then(|r| r.materialization_state))
    }

    fn set_materialization_state(
        &self,
        group_id: &str,
        path: &str,
        state: MaterializationState,
        _permit: &RootCommitPermit,
    ) -> Result<(), PeerSessionError> {
        self.lock()
            .groups
            .entry(group_id.to_string())
            .or_default()
            .rows
            .entry(path.to_string())
            .or_default()
            .materialization_state = Some(state);
        Ok(())
    }

    fn transition_materialization_state_if_same_authoring(
        &self,
        group_id: &str,
        path: &str,
        expected: MaterializationState,
        expected_authoring_hash: Option<&ChangeHash>,
        next: MaterializationState,
    ) -> Result<bool, PeerSessionError> {
        let mut inner = self.lock();
        let row = inner
            .groups
            .entry(group_id.to_string())
            .or_default()
            .rows
            .entry(path.to_string())
            .or_default();
        if row.materialization_state != Some(expected) {
            return Ok(false);
        }
        if row.authoring_change_hash.as_ref() != expected_authoring_hash {
            return Ok(false);
        }
        row.materialization_state = Some(next);
        Ok(true)
    }

    fn record_materialized_fingerprint(
        &self,
        _group_id: &str,
        _path: &str,
        _fingerprint: Option<MaterializedFingerprint>,
        _permit: &RootCommitPermit,
    ) -> Result<(), PeerSessionError> {
        // No fake-state consumer needs this yet -- mirrors this mock's
        // existing footprint for other write-only accessors.
        Ok(())
    }

    fn record_placeholder_generation(
        &self,
        group_id: &str,
        path: &str,
        identity: yadorilink_local_storage::PlaceholderDiskIdentity,
        _provider_kind: &str,
        _permit: &RootCommitPermit,
    ) -> Result<(), PeerSessionError> {
        self.lock()
            .groups
            .entry(group_id.to_string())
            .or_default()
            .rows
            .entry(path.to_string())
            .or_default()
            .placeholder_identity = Some(identity);
        Ok(())
    }

    fn record_placeholder_generation_if_absent(
        &self,
        group_id: &str,
        path: &str,
        candidate: yadorilink_local_storage::PlaceholderDiskIdentity,
        _provider_kind: &str,
        _permit: &RootCommitPermit,
    ) -> Result<yadorilink_local_storage::PlaceholderDiskIdentity, PeerSessionError> {
        let mut guard = self.lock();
        let row = guard
            .groups
            .entry(group_id.to_string())
            .or_default()
            .rows
            .entry(path.to_string())
            .or_default();
        if let Some(existing) = row.placeholder_identity {
            return Ok(existing);
        }
        row.placeholder_identity = Some(candidate);
        Ok(candidate)
    }

    fn clear_placeholder_generation(
        &self,
        group_id: &str,
        path: &str,
        _permit: &RootCommitPermit,
    ) -> Result<(), PeerSessionError> {
        self.lock()
            .groups
            .entry(group_id.to_string())
            .or_default()
            .rows
            .entry(path.to_string())
            .or_default()
            .placeholder_identity = None;
        Ok(())
    }

    fn is_pinned(&self, group_id: &str, path: &str) -> Result<bool, PeerSessionError> {
        Ok(self
            .lock()
            .groups
            .get(group_id)
            .and_then(|g| g.rows.get(path))
            .map(|r| r.pinned)
            .unwrap_or(false))
    }

    fn set_pinned(&self, group_id: &str, path: &str, pinned: bool) -> Result<(), PeerSessionError> {
        self.lock()
            .groups
            .entry(group_id.to_string())
            .or_default()
            .rows
            .entry(path.to_string())
            .or_default()
            .pinned = pinned;
        Ok(())
    }

    fn touch_last_accessed(
        &self,
        group_id: &str,
        path: &str,
        unix_ts: i64,
    ) -> Result<(), PeerSessionError> {
        self.lock()
            .groups
            .entry(group_id.to_string())
            .or_default()
            .rows
            .entry(path.to_string())
            .or_default()
            .last_accessed_unix_nanos = Some(unix_ts);
        Ok(())
    }

    fn clear_held(&self, group_id: &str, path: &str) -> Result<(), PeerSessionError> {
        self.lock()
            .groups
            .entry(group_id.to_string())
            .or_default()
            .rows
            .entry(path.to_string())
            .or_default()
            .held = None;
        Ok(())
    }

    fn set_held(
        &self,
        group_id: &str,
        path: &str,
        reason: &str,
        since_unix_nanos: i64,
    ) -> Result<(), PeerSessionError> {
        self.lock()
            .groups
            .entry(group_id.to_string())
            .or_default()
            .rows
            .entry(path.to_string())
            .or_default()
            .held = Some(HeldState { reason: reason.to_string(), since_unix_nanos });
        Ok(())
    }

    fn has_materialization_intent(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<bool, PeerSessionError> {
        Ok(self
            .lock()
            .groups
            .get(group_id)
            .and_then(|g| g.rows.get(path))
            .map(|r| r.materialization_intent_open)
            .unwrap_or(false))
    }

    fn list_materialization_repair_candidates(
        &self,
        group_id: &str,
    ) -> Result<Vec<String>, PeerSessionError> {
        let inner = self.lock();
        Ok(inner
            .groups
            .get(group_id)
            .map(|g| {
                g.rows
                    .iter()
                    .filter(|(_, r)| {
                        r.materialization_state == Some(MaterializationState::Placeholder)
                    })
                    .map(|(path, _)| path.clone())
                    .collect()
            })
            .unwrap_or_default())
    }

    fn notify_materialization_wake(&self) {
        self.lock().notify_materialization_wake_count += 1;
    }

    fn notify_retirement_wake(&self, group_id: &str) {
        self.lock().notify_retirement_wake_calls.push(group_id.to_string());
    }

    fn notify_hazard_recheck_wake(&self, group_id: &str) {
        self.lock().notify_hazard_recheck_wake_calls.push(group_id.to_string());
    }

    fn is_path_dirty(&self, group_id: &str, path: &str) -> Result<bool, PeerSessionError> {
        Ok(self
            .lock()
            .groups
            .get(group_id)
            .and_then(|g| g.rows.get(path))
            .map(|r| r.dirty)
            .unwrap_or(false))
    }

    fn list_versions(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Vec<VersionRecord>, PeerSessionError> {
        Ok(self
            .lock()
            .groups
            .get(group_id)
            .and_then(|g| g.rows.get(path))
            .map(|r| r.versions.clone())
            .unwrap_or_default())
    }

    fn upsert_file_with_origin(
        &self,
        group_id: &str,
        record: &FileRecord,
        origin_device_id: &str,
        _permit: &RootCommitPermit,
    ) -> Result<(), PeerSessionError> {
        let mut inner = self.lock();
        let row = inner
            .groups
            .entry(group_id.to_string())
            .or_default()
            .rows
            .entry(record.path.clone())
            .or_default();
        row.current = Some(record.clone());
        row.origin_device_id = Some(origin_device_id.to_string());
        Ok(())
    }

    fn upsert_file_with_origin_and_author(
        &self,
        group_id: &str,
        record: &FileRecord,
        origin_device_id: &str,
        authoring_change_hash: &ChangeHash,
        _permit: &RootCommitPermit,
    ) -> Result<(), PeerSessionError> {
        let mut inner = self.lock();
        let row = inner
            .groups
            .entry(group_id.to_string())
            .or_default()
            .rows
            .entry(record.path.clone())
            .or_default();
        row.current = Some(record.clone());
        row.origin_device_id = Some(origin_device_id.to_string());
        row.authoring_change_hash = Some(*authoring_change_hash);
        Ok(())
    }

    fn group_has_block_provenance(
        &self,
        group_id: &str,
        block_hash: &[u8],
    ) -> Result<bool, PeerSessionError> {
        Ok(self
            .lock()
            .groups
            .get(group_id)
            .map(|g| g.block_provenance.contains(block_hash))
            .unwrap_or(false))
    }

    fn group_has_block_provenance_batch(
        &self,
        group_id: &str,
        block_hashes: &[Vec<u8>],
    ) -> Result<std::collections::HashSet<Vec<u8>>, PeerSessionError> {
        let inner = self.lock();
        let Some(group) = inner.groups.get(group_id) else {
            return Ok(std::collections::HashSet::new());
        };
        Ok(block_hashes
            .iter()
            .filter(|hash| group.block_provenance.contains(hash.as_slice()))
            .cloned()
            .collect())
    }

    fn record_group_block_provenance(
        &self,
        group_id: &str,
        block_hashes: &[Vec<u8>],
    ) -> Result<(), PeerSessionError> {
        let mut inner = self.lock();
        if inner.record_group_block_provenance_fails {
            return Err(PeerSessionError::from(std::io::Error::other(
                "simulated record_group_block_provenance failure (test-forced)",
            )));
        }
        inner.record_group_block_provenance_batches.push(block_hashes.to_vec());
        let group = inner.groups.entry(group_id.to_string()).or_default();
        for hash in block_hashes {
            group.block_provenance.insert(hash.clone());
        }
        Ok(())
    }

    fn record_block_fetch_refusal(
        &self,
        _group_id: &str,
        _path: &str,
        _version_hash: &str,
        _peer_device_id: &str,
        _reason: &str,
        _refused_at_unix_nanos: i64,
    ) -> Result<(), PeerSessionError> {
        // No fake-state consumer needs this yet -- the real, persistent
        // implementation lives in `yadorilink-daemon`'s `ReplicaCoordinator`
        // (see `DurabilityFacts::known_unobtainable_required_content`'s own
        // doc comment). A no-op here matches this mock's existing footprint.
        Ok(())
    }

    fn clear_block_fetch_refusal(
        &self,
        group_id: &str,
        path: &str,
        version_hash: &str,
        peer_device_id: &str,
    ) -> Result<(), PeerSessionError> {
        self.lock().clear_block_fetch_refusal_calls.push((
            group_id.to_string(),
            path.to_string(),
            version_hash.to_string(),
            peer_device_id.to_string(),
        ));
        Ok(())
    }

    fn dag_group_heads(&self, group_id: &str) -> Result<Vec<ChangeHash>, PeerSessionError> {
        Ok(self.lock().groups.get(group_id).map(|g| g.heads.clone()).unwrap_or_default())
    }

    fn dag_group_history_paths(&self, group_id: &str) -> Result<HashSet<String>, PeerSessionError> {
        Ok(self.lock().groups.get(group_id).map(|g| g.history_paths.clone()).unwrap_or_default())
    }

    fn dag_list_unapplied_changes(&self, group_id: &str) -> Result<Vec<Change>, PeerSessionError> {
        self.unapplied_changes_call_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let inner = self.lock();
        Ok(inner
            .changes
            .iter()
            .filter(|(hash, c)| c.group_id.as_str() == group_id && !inner.applied.contains(*hash))
            .map(|(_, c)| c.clone())
            .collect())
    }

    fn dag_has_change(&self, hash: &ChangeHash) -> Result<bool, PeerSessionError> {
        Ok(self.lock().changes.contains_key(hash))
    }

    fn dag_has_change_or_pruned(
        &self,
        _group_id: &str,
        hash: &ChangeHash,
    ) -> Result<bool, PeerSessionError> {
        Ok(self.lock().changes.contains_key(hash))
    }

    fn current_authoring_relation(
        &self,
        group_id: &str,
        path: &str,
        incoming: &ChangeHash,
    ) -> Result<Option<ChangeOrdering>, PeerSessionError> {
        let inner = self.lock();
        let Some(current) = inner
            .groups
            .get(group_id)
            .and_then(|g| g.rows.get(path))
            .and_then(|r| r.authoring_change_hash)
        else {
            return Ok(None);
        };
        Ok(Some(Self::compare_locked(&inner, &current, incoming)))
    }

    fn dag_missing_ancestor_frontier(
        &self,
        roots: Vec<ChangeHash>,
    ) -> Result<Vec<ChangeHash>, PeerSessionError> {
        let inner = self.lock();
        let mut missing = Vec::new();
        let mut seen = HashSet::new();
        let mut frontier = roots;
        while let Some(hash) = frontier.pop() {
            if !seen.insert(hash) {
                continue;
            }
            if let Some(change) = inner.changes.get(&hash) {
                frontier.extend(change.parents.iter().copied());
                continue;
            }
            // Not durably admitted yet, but this change's own bytes may
            // already be sitting in the orphan buffer (received, held only
            // because ITS parent hasn't arrived) -- matching real
            // production's `missing_ancestor_frontier_on_conn`, walk
            // through it to that parent instead of reporting the orphan
            // hash itself as "missing". Without this, a batch of buffered
            // orphans that excludes only the true root reports every
            // orphan as its own missing parent, and re-requesting that
            // set (instead of the true root) never converges -- exactly
            // the DAG-paging livelock this whole fake exists to help
            // catch, not reproduce as an artifact of its own simplicity.
            match inner.orphans.iter().find(|c| c.compute_hash() == hash) {
                Some(orphan) => frontier.extend(orphan.parents.iter().copied()),
                None => missing.push(hash),
            }
        }
        Ok(missing)
    }

    fn dag_get_change(&self, hash: &ChangeHash) -> Result<Option<Change>, PeerSessionError> {
        Ok(self.lock().changes.get(hash).cloned())
    }

    fn dag_get_encoded(&self, hash: &ChangeHash) -> Result<Option<Vec<u8>>, PeerSessionError> {
        Ok(self.lock().encoded.get(hash).cloned())
    }

    fn dag_has_file_version(
        &self,
        group_id: &str,
        hash: &VersionHash,
    ) -> Result<bool, PeerSessionError> {
        Ok(self.lock().file_versions.contains_key(&(group_id.to_string(), *hash)))
    }

    fn dag_get_file_version(
        &self,
        group_id: &str,
        hash: &VersionHash,
    ) -> Result<Option<FileVersion>, PeerSessionError> {
        Ok(self.lock().file_versions.get(&(group_id.to_string(), *hash)).cloned())
    }

    fn dag_parents_of(&self, hash: &ChangeHash) -> Result<Vec<ChangeHash>, PeerSessionError> {
        Ok(self.lock().changes.get(hash).map(|c| c.parents.clone()).unwrap_or_default())
    }

    fn dag_is_ancestor(
        &self,
        ancestor: &ChangeHash,
        descendant: &ChangeHash,
    ) -> Result<bool, PeerSessionError> {
        let inner = self.lock();
        Ok(Self::is_ancestor_locked(&inner, ancestor, descendant))
    }

    fn dag_admit_change_with_versions(
        &self,
        change: &Change,
        versions: &[FileVersion],
        applied: bool,
    ) -> Result<AdmitResult, PeerSessionError> {
        let mut inner = self.lock();
        let hash = change.compute_hash();
        if inner.changes.contains_key(&hash) {
            return Ok(AdmitResult { outcome: AdmitOutcome::Applied, newly_admitted: vec![] });
        }
        for version in versions {
            inner.file_versions.insert(
                (change.group_id.as_str().to_string(), version.compute_hash()),
                version.clone(),
            );
        }
        let parents_present = change.parents.iter().all(|p| inner.changes.contains_key(p));
        if !parents_present {
            inner.orphans.push(change.clone());
            return Ok(AdmitResult { outcome: AdmitOutcome::Orphaned, newly_admitted: vec![] });
        }
        inner.encoded.insert(hash, change.encode());
        inner.changes.insert(hash, change.clone());
        if applied {
            inner.applied.insert(hash);
        }
        {
            let group = inner.groups.entry(change.group_id.as_str().to_string()).or_default();
            group.heads.retain(|h| !change.parents.contains(h));
            group.heads.push(hash);
        }
        let mut newly_admitted = vec![hash];
        Self::promote_orphans_locked(&mut inner, &mut newly_admitted);
        Ok(AdmitResult { outcome: AdmitOutcome::Applied, newly_admitted })
    }

    fn dag_mark_applied(&self, hash: &ChangeHash) -> Result<(), PeerSessionError> {
        self.mark_applied_call_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.lock().applied.insert(*hash);
        Ok(())
    }

    fn dag_bump_mutation_fence(
        &self,
        group_id: &str,
        path: &str,
        _mutation_kind: &str,
    ) -> Result<i64, PeerSessionError> {
        let mut inner = self.lock();
        let entry =
            inner.mutation_fences.entry((group_id.to_string(), path.to_string())).or_insert(0);
        *entry += 1;
        Ok(*entry)
    }

    fn dag_snapshot_mutation_fence(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<i64, PeerSessionError> {
        let mut inner = self.lock();
        Ok(*inner.mutation_fences.entry((group_id.to_string(), path.to_string())).or_insert(0))
    }

    fn dag_publish_materialized_generation_if_fence_current(
        &self,
        group_id: &str,
        path: &str,
        causal_basis: &[ChangeHash],
        state: crate::ports::ExactActualState,
        expected_mutation_generation: i64,
    ) -> Result<bool, PeerSessionError> {
        let (object_kind, version) = match state {
            crate::ports::ExactActualState::Object { kind, version, .. } => {
                (Some(kind), Some(version))
            }
            crate::ports::ExactActualState::Absent => (None, None),
        };
        let mut inner = self.lock();
        let key = (group_id.to_string(), path.to_string());
        let current = *inner.mutation_fences.get(&key).unwrap_or(&0);
        if current != expected_mutation_generation {
            return Ok(false);
        }
        inner
            .materialized_generations
            .insert(key, (current, causal_basis.to_vec(), object_kind, version));
        Ok(true)
    }

    fn dag_get_device_frontier(
        &self,
        group_id: &str,
        device_id: &str,
    ) -> Result<Option<ChangeHash>, PeerSessionError> {
        Ok(self.lock().groups.get(group_id).and_then(|g| g.device_frontier.get(device_id).copied()))
    }

    /// This fake tracks no `resolved_path_state_hash`/filesystem identity
    /// at all (its `materialized_generations` map exists only to support
    /// `dag_publish_materialized_generation_if_fence_current`'s own CAS
    /// bookkeeping) -- so it always reports "not confirmable," exactly the
    /// safe, always-correct default this method's own contract describes
    /// for every case it cannot conclusively confirm. No test in this
    /// crate depends on the fake ever authorizing a zero-work close.
    fn dag_zero_work_settlement_if_already_current(
        &self,
        _group_id: &str,
        _path: &str,
        _resolution: &yadorilink_replica_engine::conflict::PathResolution,
        _winner_version_hash: Option<&yadorilink_replica_domain::ids::VersionHash>,
    ) -> Result<Option<(crate::ports::ExactActualState, i64)>, PeerSessionError> {
        Ok(None)
    }

    /// `true`, deliberately, even though this fake's settlement check above
    /// always declines: this method exists purely to let a caller SKIP work,
    /// so `true` ("don't skip") is its conservative answer, and it keeps
    /// every test exercising the full resolve-then-check path exactly as it
    /// did before this short-circuit existed. A fake that answered `false`
    /// would silently stop tests from reaching the resolution logic at all.
    fn dag_has_usable_materialized_generation(
        &self,
        _group_id: &str,
        _path: &str,
    ) -> Result<bool, PeerSessionError> {
        Ok(true)
    }

    fn open_materialization_intent_guard<'a>(
        &'a self,
        group_id: &'a str,
        path: &'a str,
        _target_version_hash: &[u8],
        _permit: &'a RootCommitPermit,
    ) -> Result<Box<dyn OpenMaterializationIntent + Send + 'a>, PeerSessionError> {
        self.lock()
            .groups
            .entry(group_id.to_string())
            .or_default()
            .rows
            .entry(path.to_string())
            .or_default()
            .materialization_intent_open = true;
        struct Guard<'a> {
            state: &'a FakeReplicaState,
            group_id: &'a str,
            path: &'a str,
        }
        impl<'a> OpenMaterializationIntent for Guard<'a> {
            fn clear(self: Box<Self>) -> Result<(), PeerSessionError> {
                self.state
                    .lock()
                    .groups
                    .entry(self.group_id.to_string())
                    .or_default()
                    .rows
                    .entry(self.path.to_string())
                    .or_default()
                    .materialization_intent_open = false;
                Ok(())
            }
        }
        Ok(Box::new(Guard { state: self, group_id, path }))
    }

    fn open_projected_upserts_batch(
        &self,
        group_id: &str,
        upserts: &[crate::ports::PreparedProjectedUpsert],
        _permit: &RootCommitPermit,
    ) -> Result<(), PeerSessionError> {
        let mut inner = self.lock();
        for u in upserts {
            let row = inner
                .groups
                .entry(group_id.to_string())
                .or_default()
                .rows
                .entry(u.rel_path.clone())
                .or_default();
            row.current = Some(u.record.clone());
            row.origin_device_id = Some(u.origin_device_id.clone());
            row.authoring_change_hash = u.authoring_change_hash;
            row.held = None;
            row.materialization_intent_open = true;
            // C4-7: applied here, in the same fake "transaction" as the
            // row above, matching `ReplicaCoordinator::
            // open_projected_upserts_batch`'s real behavior -- metadata is
            // no longer applied per-candidate by `revalidate_ordinary_
            // upsert`.
            row.record_kind = Some(u.metadata.record_kind);
            row.symlink_target = u.metadata.symlink_target.clone();
            row.symlink_out_of_root = u.metadata.symlink_out_of_root;
            row.unix_mode = u.metadata.unix_mode;
            row.xattrs = u.metadata.xattrs.clone();
        }
        Ok(())
    }

    fn finalize_projected_mutations_batch(
        &self,
        group_id: &str,
        finished_upserts: &[crate::ports::FinishedProjectedUpsert],
        deletes: &[crate::ports::PreparedProjectedDelete],
        _permit: &RootCommitPermit,
    ) -> Result<(), PeerSessionError> {
        let mut inner = self.lock();
        if inner.finalize_projected_mutations_batch_fails {
            return Err(PeerSessionError::InvalidInput(
                "fake finalize_projected_mutations_batch forced to fail".to_string(),
            ));
        }
        for u in finished_upserts {
            inner
                .groups
                .entry(group_id.to_string())
                .or_default()
                .rows
                .entry(u.rel_path.clone())
                .or_default()
                .materialization_intent_open = false;
        }
        for d in deletes {
            let row = inner
                .groups
                .entry(group_id.to_string())
                .or_default()
                .rows
                .entry(d.rel_path.clone())
                .or_default();
            row.current = Some(d.record.clone());
            row.origin_device_id = Some(d.origin_device_id.clone());
            row.authoring_change_hash = d.authoring_change_hash;
            row.held = None;
        }
        Ok(())
    }

    fn verify_root(&self, root: &Path, _group_id: &str) -> Result<(), PeerSessionError> {
        let inner = self.lock();
        if inner.verify_root_fails {
            return Err(PeerSessionError::InvalidInput(
                "fake root verification forced to fail".to_string(),
            ));
        }
        let marker = root.join(yadorilink_replica_domain::reserved_paths::ROOT_MARKER_FILE_NAME);
        if marker.exists() {
            Ok(())
        } else {
            Err(PeerSessionError::InvalidInput(format!(
                "root {root:?} has no identity marker (fake verify_root)"
            )))
        }
    }

    fn list_files(&self, group_id: &str) -> Result<Vec<FileRecord>, PeerSessionError> {
        Ok(self
            .lock()
            .groups
            .get(group_id)
            .map(|g| g.rows.values().filter_map(|r| r.current.clone()).collect())
            .unwrap_or_default())
    }

    fn dag_compare_authoring(
        &self,
        _group_id: &str,
        local: &ChangeHash,
        incoming: &ChangeHash,
    ) -> Result<Option<ChangeOrdering>, PeerSessionError> {
        let inner = self.lock();
        if !inner.changes.contains_key(local) || !inner.changes.contains_key(incoming) {
            return Ok(None);
        }
        Ok(Some(Self::compare_locked(&inner, local, incoming)))
    }

    fn dag_group_file_version_references_block(
        &self,
        group_id: &str,
        block_hash: &[u8],
    ) -> Result<bool, PeerSessionError> {
        let inner = self.lock();
        Ok(inner
            .file_versions
            .iter()
            .any(|((g, _), v)| g == group_id && v.blocks.iter().any(|b| b.hash.0 == block_hash)))
    }

    fn group_retained_version_references_block(
        &self,
        group_id: &str,
        block_hash: &[u8],
    ) -> Result<bool, PeerSessionError> {
        let inner = self.lock();
        Ok(inner
            .groups
            .get(group_id)
            .map(|g| {
                g.rows.values().any(|r| {
                    r.versions.iter().any(|v| v.blocks.iter().any(|b| b.hash == block_hash))
                })
            })
            .unwrap_or(false))
    }

    fn get_current_version_record(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<CurrentVersionRecord>, PeerSessionError> {
        let inner = self.lock();
        Ok(inner.groups.get(group_id).and_then(|g| g.rows.get(path)).and_then(|r| {
            r.current.as_ref().map(|record| CurrentVersionRecord {
                blocks: record.blocks.clone(),
                size: record.size,
                mtime_unix_nanos: record.mtime_unix_nanos,
                deleted: record.deleted,
                record_kind: r.record_kind.unwrap_or(RecordKind::File),
                symlink_target: r.symlink_target.clone(),
                unix_mode: r.unix_mode,
                xattrs: r.xattrs.clone(),
            })
        }))
    }

    fn get_held_state(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<HeldState>, PeerSessionError> {
        Ok(self
            .lock()
            .groups
            .get(group_id)
            .and_then(|g| g.rows.get(path))
            .and_then(|r| r.held.clone()))
    }

    fn ensure_bootstrap_row_for_metadata(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<(), PeerSessionError> {
        self.lock()
            .groups
            .entry(group_id.to_string())
            .or_default()
            .rows
            .entry(path.to_string())
            .or_default();
        Ok(())
    }

    fn set_record_kind(
        &self,
        group_id: &str,
        path: &str,
        kind: RecordKind,
        _permit: &RootCommitPermit,
    ) -> Result<(), PeerSessionError> {
        self.lock()
            .groups
            .entry(group_id.to_string())
            .or_default()
            .rows
            .entry(path.to_string())
            .or_default()
            .record_kind = Some(kind);
        Ok(())
    }

    fn set_symlink_target(
        &self,
        group_id: &str,
        path: &str,
        target: Option<&[u8]>,
    ) -> Result<(), PeerSessionError> {
        self.lock()
            .groups
            .entry(group_id.to_string())
            .or_default()
            .rows
            .entry(path.to_string())
            .or_default()
            .symlink_target = target.map(|t| t.to_vec());
        Ok(())
    }

    fn set_symlink_out_of_root(
        &self,
        group_id: &str,
        path: &str,
        out_of_root: bool,
    ) -> Result<(), PeerSessionError> {
        self.lock()
            .groups
            .entry(group_id.to_string())
            .or_default()
            .rows
            .entry(path.to_string())
            .or_default()
            .symlink_out_of_root = out_of_root;
        Ok(())
    }

    fn set_unix_mode(
        &self,
        group_id: &str,
        path: &str,
        unix_mode: Option<u32>,
        _permit: &RootCommitPermit,
    ) -> Result<(), PeerSessionError> {
        self.lock()
            .groups
            .entry(group_id.to_string())
            .or_default()
            .rows
            .entry(path.to_string())
            .or_default()
            .unix_mode = unix_mode;
        Ok(())
    }

    fn set_xattrs(
        &self,
        group_id: &str,
        path: &str,
        xattrs: &[(String, Vec<u8>)],
        _permit: &RootCommitPermit,
    ) -> Result<(), PeerSessionError> {
        self.lock()
            .groups
            .entry(group_id.to_string())
            .or_default()
            .rows
            .entry(path.to_string())
            .or_default()
            .xattrs = xattrs.to_vec();
        Ok(())
    }

    fn apply_incoming_metadata_atomic(
        &self,
        group_id: &str,
        path: &str,
        meta: &yadorilink_replica_domain::session_state::LocalFileMetaColumns,
        _permit: &RootCommitPermit,
    ) -> Result<(), PeerSessionError> {
        let mut inner = self.lock();
        inner.apply_incoming_metadata_atomic_calls += 1;
        let row = inner
            .groups
            .entry(group_id.to_string())
            .or_default()
            .rows
            .entry(path.to_string())
            .or_default();
        row.record_kind = Some(meta.record_kind);
        row.symlink_target = meta.symlink_target.clone();
        row.symlink_out_of_root = meta.symlink_out_of_root;
        row.unix_mode = meta.unix_mode;
        row.xattrs = meta.xattrs.clone();
        Ok(())
    }

    fn apply_projected_row_atomic(
        &self,
        group_id: &str,
        record: &FileRecord,
        origin_device_id: &str,
        authoring_change_hash: Option<&ChangeHash>,
        meta: &yadorilink_replica_domain::session_state::LocalFileMetaColumns,
        _permit: &RootCommitPermit,
    ) -> Result<(), PeerSessionError> {
        let mut inner = self.lock();
        inner.apply_projected_row_atomic_calls += 1;
        let row = inner
            .groups
            .entry(group_id.to_string())
            .or_default()
            .rows
            .entry(record.path.clone())
            .or_default();
        row.current = Some(record.clone());
        row.origin_device_id = Some(origin_device_id.to_string());
        if let Some(hash) = authoring_change_hash {
            row.authoring_change_hash = Some(*hash);
        }
        row.record_kind = Some(meta.record_kind);
        row.symlink_target = meta.symlink_target.clone();
        row.symlink_out_of_root = meta.symlink_out_of_root;
        row.unix_mode = meta.unix_mode;
        row.xattrs = meta.xattrs.clone();
        Ok(())
    }

    fn record_acknowledged_frontier(
        &self,
        group: &yadorilink_replica_domain::ids::FolderGroupId,
        device: &yadorilink_replica_domain::ids::DeviceId,
        frontier: &[ChangeHash],
    ) -> Result<(), PeerSessionError> {
        if self.lock().record_acknowledged_frontier_fails {
            return Err(PeerSessionError::InvalidInput(
                "fake-injected record_acknowledged_frontier failure".to_string(),
            ));
        }
        if let Some(latest) = frontier.iter().max() {
            self.lock()
                .groups
                .entry(group.as_str().to_string())
                .or_default()
                .device_frontier
                .insert(device.as_str().to_string(), *latest);
        }
        Ok(())
    }

    fn diagnostic_projection_obligation(
        &self,
        _group_id: &str,
        _path: &str,
    ) -> Result<Option<String>, PeerSessionError> {
        // This fake has no `projection_obligations` model of its own --
        // diagnostic-only, never asserted on by any test.
        Ok(None)
    }
}

impl FakeReplicaState {
    fn compare_locked(inner: &Inner, a: &ChangeHash, b: &ChangeHash) -> ChangeOrdering {
        if a == b {
            ChangeOrdering::Equal
        } else if Self::is_ancestor_locked(inner, a, b) {
            ChangeOrdering::Before
        } else if Self::is_ancestor_locked(inner, b, a) {
            ChangeOrdering::After
        } else {
            ChangeOrdering::Concurrent
        }
    }
}
