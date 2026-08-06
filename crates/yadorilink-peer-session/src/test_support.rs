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
use crate::ports::{OpenMaterializationIntent, PeerReplicaStatePort};

/// Per-`(group_id, path)` bookkeeping this fake tracks -- every column
/// `PeerReplicaStatePort` exposes a getter/setter for, flattened into one
/// row instead of `SyncState`'s several backing tables.
#[derive(Default, Clone)]
struct Row {
    current: Option<FileRecord>,
    record_kind: Option<RecordKind>,
    symlink_target: Option<Vec<u8>>,
    symlink_out_of_root: bool,
    exec_bit: bool,
    origin_device_id: Option<String>,
    authoring_change_hash: Option<ChangeHash>,
    materialization_state: Option<MaterializationState>,
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
}

/// The fake itself. `Arc`-wrapped by callers exactly like a real
/// `Arc<dyn PeerReplicaStatePort>` would be.
#[derive(Default)]
pub struct FakeReplicaState {
    inner: Mutex<Inner>,
}

impl FakeReplicaState {
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

    /// See `Inner::notify_materialization_wake_count`'s doc comment.
    pub fn notify_materialization_wake_count(&self) -> usize {
        self.lock().notify_materialization_wake_count
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
        _permit: &RootCommitPermit<'_>,
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

    /// Mirrors `SyncState::dag_has_change` (distinct from the port's own
    /// `dag_has_change_or_pruned`, which this fake -- never pruning --
    /// answers identically anyway).
    pub fn dag_has_change(&self, hash: &ChangeHash) -> Result<bool, PeerSessionError> {
        Ok(self.lock().changes.contains_key(hash))
    }

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

    fn get_exec_bit(&self, group_id: &str, path: &str) -> Result<bool, PeerSessionError> {
        Ok(self
            .lock()
            .groups
            .get(group_id)
            .and_then(|g| g.rows.get(path))
            .map(|r| r.exec_bit)
            .unwrap_or(false))
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
        self.lock()
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
        _permit: &RootCommitPermit<'_>,
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

    fn materialization_enqueue_pending(
        &self,
        _group_id: &str,
        _path: &str,
        _version_hash: &[u8],
        _trigger_lamport: u64,
        _now: i64,
    ) -> Result<(), PeerSessionError> {
        Ok(())
    }

    fn notify_materialization_wake(&self) {
        self.lock().notify_materialization_wake_count += 1;
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
        _permit: &RootCommitPermit<'_>,
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
        _permit: &RootCommitPermit<'_>,
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

    fn record_group_block_provenance(
        &self,
        group_id: &str,
        block_hashes: &[Vec<u8>],
    ) -> Result<(), PeerSessionError> {
        let mut inner = self.lock();
        let group = inner.groups.entry(group_id.to_string()).or_default();
        for hash in block_hashes {
            group.block_provenance.insert(hash.clone());
        }
        Ok(())
    }

    fn dag_group_heads(&self, group_id: &str) -> Result<Vec<ChangeHash>, PeerSessionError> {
        Ok(self.lock().groups.get(group_id).map(|g| g.heads.clone()).unwrap_or_default())
    }

    fn dag_group_history_paths(&self, group_id: &str) -> Result<HashSet<String>, PeerSessionError> {
        Ok(self.lock().groups.get(group_id).map(|g| g.history_paths.clone()).unwrap_or_default())
    }

    fn dag_list_unapplied_changes(&self, group_id: &str) -> Result<Vec<Change>, PeerSessionError> {
        let inner = self.lock();
        Ok(inner
            .changes
            .iter()
            .filter(|(hash, c)| c.group_id.as_str() == group_id && !inner.applied.contains(*hash))
            .map(|(_, c)| c.clone())
            .collect())
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
            match inner.changes.get(&hash) {
                Some(change) => frontier.extend(change.parents.iter().copied()),
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
        self.lock().applied.insert(*hash);
        Ok(())
    }

    fn dag_get_device_frontier(
        &self,
        group_id: &str,
        device_id: &str,
    ) -> Result<Option<ChangeHash>, PeerSessionError> {
        Ok(self.lock().groups.get(group_id).and_then(|g| g.device_frontier.get(device_id).copied()))
    }

    fn open_materialization_intent_guard<'a>(
        &'a self,
        group_id: &'a str,
        path: &'a str,
        _target_version_hash: &[u8],
        _permit: &'a RootCommitPermit<'a>,
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
                exec_bit: r.exec_bit,
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
        _permit: &RootCommitPermit<'_>,
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

    fn set_exec_bit(
        &self,
        group_id: &str,
        path: &str,
        exec_bit: bool,
        _permit: &RootCommitPermit<'_>,
    ) -> Result<(), PeerSessionError> {
        self.lock()
            .groups
            .entry(group_id.to_string())
            .or_default()
            .rows
            .entry(path.to_string())
            .or_default()
            .exec_bit = exec_bit;
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
