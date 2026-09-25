//! Convergence work that has no peer in it.
//!
//! Some of what a device owes a folder is decided entirely by its own state.
//! Whether an ephemeral conflict copy is still justified by the current
//! frontier is a question about this device's DAG, its file index and its
//! disk; no peer is consulted, and none can answer it.
//!
//! That work lived on `PeerSyncSession`, which had two consequences. A device
//! with no peer connected — solo, newly linked, offline — could not do it at
//! all, so the daemon manufactured a session over an inert channel with its
//! own device id standing in as the peer's. And because constructing that
//! session ran the netmap authenticator, doing so could quarantine another
//! session's authorization, which is why callers preferred to borrow a live
//! peer's session when one happened to exist. A synthetic peer, a fabricated
//! identity, and a construction-order hazard, all to run work that never
//! needed a peer.
//!
//! Here that work has no peer to fabricate:
//!
//! ```text
//!   LocalConvergenceExecutor   this device's DAG, index, roots and disk
//!   PeerSyncSession            a real peer, real transports, and one of these
//! ```
//!
//! Deliberately no transport field, of any shape. A `None` here would be the
//! same defect one type further along: the point is not that the transport is
//! absent, it is that there is nothing for it to do.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex};

use yadorilink_local_storage::{
    verify_delete_target_within_canonical_root, verify_delete_target_within_root,
};
use yadorilink_peer_session::PeerSessionError;
use yadorilink_replica_domain::file::FileRecord;
use yadorilink_replica_domain::ids::ChangeHash;
use yadorilink_replica_domain::session_state::LinkGate;
use yadorilink_root_authority::root_commit::{RootCommitPermit, RootLease};

use yadorilink_peer_session::hazard;
use yadorilink_peer_session::peer_session::RootCommitAuthorityProvider;
use yadorilink_replica_engine::conflict::{resolve_path_heads, PathHead, PathResolution};
use yadorilink_root_authority::ignore_patterns::{
    is_ignore_file_relative_path, EffectiveIgnoreSet,
};

/// The local half of convergence: everything decided from this device alone.
pub struct LocalConvergenceExecutor {
    pub(crate) state: Arc<crate::replica_coordinator::ReplicaCoordinator>,
    /// This device. Not a peer's id standing in for one — the origin recorded
    /// for a purely local mutation is genuinely this device.
    pub(crate) local_device_id: String,
    pub(crate) root_commit_authority_provider: Arc<dyn RootCommitAuthorityProvider>,
    /// This device's own effective ignore set per group, with bounded
    /// staleness.
    ///
    /// Device-local by definition: it is *this* device's filter on what it
    /// projects, unsynced, and independent of what any peer thinks. It sat on
    /// the session only because the code that consulted it did.
    pub(crate) ignore_sets:
        StdMutex<HashMap<String, (Arc<EffectiveIgnoreSet>, std::time::Instant)>>,
    /// Forces a path's pending local debounce entry into the index before
    /// this device reconciles it.
    ///
    /// Local by nature: it flushes *this* device's own accumulator, and had
    /// nothing to do with a peer beyond being reached from a session.
    pub(crate) pending_local_change_flush:
        Arc<dyn yadorilink_peer_session::peer_session::PendingLocalChangeFlush>,
    /// `raw root -> canonical root`, per group. See
    /// [`Self::canonical_sync_root`].
    pub(crate) canonical_sync_roots: StdMutex<HashMap<String, (PathBuf, PathBuf)>>,
    /// This device's block content. Reading and writing it is local work; only
    /// *obtaining* a block this device does not have needs a peer.
    pub(crate) store: Arc<dyn yadorilink_peer_session::ports::BlockContentStore>,
    /// How many blocks each group has been allowed to eagerly fetch.
    ///
    /// A budget on this device's own appetite for content, spent by whatever
    /// drives convergence here. It bounds work, so it is charged exactly once
    /// per record -- see `materialize_local`'s own note on why re-entry after
    /// a block request must not charge it again.
    pub(crate) eager_admission: StdMutex<HashMap<String, u64>>,
    /// Announces that this device is writing block content, so unrelated
    /// bookkeeping can stand back while it does.
    pub(crate) block_write_activity_provider:
        Arc<dyn yadorilink_peer_session::peer_session::BlockWriteActivityProvider>,
    /// Free-space policy for this device's own writes. Both are about the
    /// disk under this device's feet, which no peer has an opinion about.
    /// Test-only, one-shot failure injection, armed on ONE executor.
    ///
    /// These were process-global statics. A one-shot flag plus a global
    /// scope is a race between every test in the binary: the arming test
    /// does not necessarily reach the consumption point first, so an
    /// unrelated concurrent hydration takes the failure meant for it. That
    /// is exactly what turned up -- a test asserting its own injected
    /// metadata-apply failure found no content on disk, because another
    /// test's post-hold-clear arming had already failed its write. Per
    /// executor, an arming can only ever be consumed by the attempt the
    /// arming test drives.
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) force_hydration_failure_after_hold_cleared: std::sync::atomic::AtomicBool,
    /// Consumed by `hydrate_file_with_timeout_locked` right where
    /// `apply_unix_mode`/`apply_xattrs` would run -- simulates a real,
    /// repeatable failure there (a chmod `EPERM`, an xattr `EOPNOTSUPP`) that
    /// a permission trick or filesystem capability gap isn't reliably
    /// reproducible for in a portable test. Proves the commit (CAS-to-
    /// `Hydrated` and the transition intent guard's clear) that now runs
    /// BEFORE this point survives such a failure intact: the row stays
    /// `Hydrated` with its already-durable content, and the intent guard is
    /// already cleared, rather than the whole attempt reverting to
    /// `Placeholder` with a permanently dangling intent the way it would if
    /// this failure fired before that commit.
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) force_hydration_failure_during_metadata_apply: std::sync::atomic::AtomicBool,
    pub(crate) headroom_override_bytes: StdMutex<Option<u64>>,
    pub(crate) headroom_enforced: std::sync::atomic::AtomicBool,
}

/// Whether this executor runs the materialize-time disk-headroom preflight,
/// and against what reserve.
///
/// A constructor argument rather than a post-construction setter on purpose.
/// The preflight used to be switched on by a caller reaching in afterwards,
/// and when the peer-session facade that did the reaching was collapsed the
/// call went with it: every executor was built with enforcement off, while
/// the value it should have been built with was still being computed and
/// passed on every peer connection. A decision that must be made for the
/// executor to exist cannot be forgotten by the next caller that builds one.
#[derive(Clone, Copy, Debug)]
pub struct HeadroomPolicy {
    /// `false` leaves `preflight_disk_headroom` an unconditional `Ok` -- see
    /// its doc comment for why that, not enforcement, is the default.
    pub enforced: bool,
    /// `None` means the built-in `max(1 GiB, 5%)` formula.
    pub override_bytes: Option<u64>,
}

impl HeadroomPolicy {
    /// No preflight at all: what every executor in a test gets unless that
    /// test is specifically about disk pressure.
    pub fn disabled() -> Self {
        Self { enforced: false, override_bytes: None }
    }
}

#[cfg(test)]
mod published_fixture;

#[cfg(test)]
mod block_provenance_batching_tests;
pub use yadorilink_peer_session::convergence_driver::ConvergenceDriver;

mod hydrate;
pub mod types;
use types::*;
pub mod call_timer;
mod knobs;
mod materialize;
#[cfg(test)]
mod ordinary_batch_tests;

/// A file this device is still writing must never be overwritten with
/// this device's own older version of it.
#[cfg(test)]
mod growing_file_projection_tests;

/// An own change derived from local disk capture never writes that disk
/// back; a disk that moved on is captured instead.
#[cfg(test)]
mod own_head_recapture_tests;

/// What the namespace makes a reconcile do on disk -- relocating a file a
/// live descendant displaces, putting it back, adopting and removing
/// directories held only for descendants -- is never captured as a change.
#[cfg(test)]
mod namespace_capture_tests;

#[cfg(test)]
mod projection_attempt_tests;

#[cfg(test)]
mod retirement_audit_guard_tests;

/// The materialization audit's payload *producer*, which is the one
/// materialization input this device reads out of its own index rather
/// than receiving from a peer or deriving from a resolved DAG version.
#[cfg(test)]
mod materialization_audit_payload_tests;

/// `materialize_symlink_at` and
/// `try_apply_metadata_only_update`, exercised directly against a
/// `SyncState` + tempdir — no `PeerSyncSession`/channel needed, since
/// neither function touches the network (see both functions' doc
/// comments for why, and for the wire-schema gap they operate under).
#[cfg(test)]
mod symlink_and_metadata_only_update_tests;

/// the per-(session, group) eager-fetch admission
/// budget (`admit_eager_blocks_impl`, wired into
/// `PeerSyncSession::admit_eager_blocks`) — exercised against a small
/// synthetic `max_per_group` rather than the real (deliberately huge)
/// `MAX_EAGER_BLOCKS_PER_GROUP_PER_SESSION`, for the same reason as
/// `cardinality_cap_tests` above.
#[cfg(test)]
mod eager_admission_tests;

#[cfg(test)]
mod hazard_reason_tests;

#[cfg(test)]
mod require_physical_kind_matches_tests;

#[cfg(test)]
mod path_safety_tests;

#[cfg(test)]
mod frontier_freshness_tests;

/// Liveness regression for `ignore_sets`'s bounded-staleness reload: a
/// `.yadorilinkignore` edit must eventually take effect for incoming records
/// on a peer session that never gets reconstructed, not stay frozen for the
/// session's whole lifetime. Rewinds the cached entry's own `Instant`
/// (`rewind_ignore_set_cache_for_tests`) instead of sleeping the real
/// `IGNORE_SET_REFRESH_INTERVAL`, so this stays fast and deterministic.
#[cfg(test)]
mod ignore_set_liveness_tests;
mod namespace_steps;
mod reconcile;

/// What `LocalConvergenceExecutor::own_capture_on_disk` found about a
/// head's relation to the disk it would be projected onto.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OwnCaptureOnDisk {
    /// Not this device's own capture of the path: projection is decided as
    /// for any other change.
    NotACapture,
    /// An own capture the disk still holds, or whose disk state is not this
    /// check's finding: the existing handling decides.
    Holds,
    /// An own capture the disk has moved on from: something else is there
    /// now, and it is newer local state.
    MovedOn,
    /// An own capture whose file was deleted or renamed away since.
    Removed,
}

impl OwnCaptureOnDisk {
    /// Whether what disk holds now has to be captured instead of the head
    /// being projected.
    pub(crate) fn superseded(self) -> bool {
        matches!(self, Self::MovedOn | Self::Removed)
    }
}

/// Whether `materialize_dag_content_head` applies the recapture rule to an
/// own captured head the disk has moved on from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OwnCaptureRule {
    /// Capture what disk holds instead of projecting the head.
    RecaptureFirst,
    /// A recapture already ran and found nothing newer: project as for any
    /// other change.
    ProjectAsBefore,
}

/// Whether the regular file at `out_path` already has `version`'s mode and
/// replicated extended attributes -- read-only, the same comparison that
/// decides whether a metadata repair has anything to write.
pub(crate) fn mode_and_xattrs_match_disk(
    out_path: &Path,
    version: &yadorilink_replica_domain::file::FileVersion,
) -> Result<bool, PeerSessionError> {
    Ok(yadorilink_local_storage::unix_mode_already_matches_disk(out_path, version.meta.unix_mode)?
        && yadorilink_local_storage::xattrs_already_match_disk(out_path, &version.meta.xattrs)?)
}

/// What `recapture_instead_of_projecting` achieved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Recapture {
    /// A newer change now supersedes the head.
    Superseded,
    /// The path could not be captured yet (it is still changing).
    StillChanging,
    /// The capture authored nothing: the head is still the path's winner.
    NothingNewer,
}

impl LocalConvergenceExecutor {
    pub fn new(
        state: Arc<crate::replica_coordinator::ReplicaCoordinator>,
        local_device_id: String,
        root_commit_authority_provider: Arc<dyn RootCommitAuthorityProvider>,
        pending_local_change_flush: Arc<
            dyn yadorilink_peer_session::peer_session::PendingLocalChangeFlush,
        >,
        sync_roots: HashMap<String, PathBuf>,
        store: Arc<dyn yadorilink_peer_session::ports::BlockContentStore>,
        block_write_activity_provider: Arc<
            dyn yadorilink_peer_session::peer_session::BlockWriteActivityProvider,
        >,
        headroom: HeadroomPolicy,
    ) -> Arc<Self> {
        // Seeded from the roots known at construction. A root that cannot be
        // canonicalized — an external volume that is not mounted — is simply
        // absent, and the containment checks fall back to the raw path rather
        // than treating its absence as permission to write.
        let canonical_sync_roots = StdMutex::new(
            sync_roots
                .iter()
                .filter_map(|(group_id, root)| {
                    let canonical = std::fs::canonicalize(root).ok()?;
                    Some((group_id.clone(), (root.clone(), canonical)))
                })
                .collect(),
        );
        Arc::new(Self {
            state,
            local_device_id,
            root_commit_authority_provider,
            ignore_sets: StdMutex::new(
                sync_roots
                    .iter()
                    .map(|(group_id, root)| {
                        // A load failure -- an I/O error other than "file not
                        // found", which `load_for_link_root` already handles
                        // -- falls back to the built-in defaults rather than
                        // to no filtering, so a transient read error never
                        // widens what this device projects.
                        let set = EffectiveIgnoreSet::load_for_link_root(root)
                            .unwrap_or_else(|_| EffectiveIgnoreSet::defaults_only());
                        (group_id.clone(), (Arc::new(set), std::time::Instant::now()))
                    })
                    .collect(),
            ),
            pending_local_change_flush,
            canonical_sync_roots,
            store,
            eager_admission: StdMutex::new(HashMap::new()),
            block_write_activity_provider,
            #[cfg(any(test, feature = "test-support"))]
            force_hydration_failure_after_hold_cleared: std::sync::atomic::AtomicBool::new(false),
            #[cfg(any(test, feature = "test-support"))]
            force_hydration_failure_during_metadata_apply: std::sync::atomic::AtomicBool::new(
                false,
            ),
            headroom_override_bytes: StdMutex::new(headroom.override_bytes),
            headroom_enforced: std::sync::atomic::AtomicBool::new(headroom.enforced),
        })
    }

    pub fn state(&self) -> &Arc<crate::replica_coordinator::ReplicaCoordinator> {
        &self.state
    }

    pub fn local_device_id(&self) -> &str {
        &self.local_device_id
    }

    /// This group's local root, resolved live from the link table.
    ///
    /// Never cached: a relink moves it, and a write aimed at where a folder
    /// used to be is a write outside the folder that exists.
    pub fn sync_root(&self, group_id: &str) -> Result<PathBuf, PeerSessionError> {
        match self.state.link_gate_for_group(group_id)? {
            LinkGate::Live { local_path, .. } | LinkGate::Paused { local_path } => {
                Ok(PathBuf::from(local_path))
            }
            LinkGate::NoLiveLink => Err(PeerSessionError::PathEscapesRoot(format!(
                "no live link for group {group_id}; refusing to resolve a local path"
            ))),
        }
    }

    /// `raw_root`'s canonical form, cached per group.
    ///
    /// Keyed by the raw root the caller just resolved, not merely by group: a
    /// cache that remembered only "group → canonical" would keep handing back
    /// the canonical form of a *previous* root after a relink, which is
    /// exactly the stale-root failure `sync_root` resolves live to avoid. A
    /// mismatch re-canonicalizes rather than trusting the entry.
    ///
    /// `None` when the root cannot be canonicalized — most often because it
    /// does not exist, an external volume that is not mounted. The caller
    /// falls back to the non-canonical containment check rather than treating
    /// this as permission to write.
    pub fn canonical_sync_root(&self, group_id: &str, raw_root: &Path) -> Option<PathBuf> {
        let mut cache =
            self.canonical_sync_roots.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some((cached_raw, canonical)) = cache.get(group_id) {
            if cached_raw == raw_root {
                return Some(canonical.clone());
            }
        }
        let canonical = std::fs::canonicalize(raw_root).ok()?;
        cache.insert(group_id.to_string(), (raw_root.to_path_buf(), canonical.clone()));
        Some(canonical)
    }

    /// Where `path` lives on this device's disk for `group_id`.
    /// Whether this path is observably absent on disk right now.
    ///
    /// A tombstoned index row does not answer this. Local capture marks
    /// a directory's orphaned children deleted while holding no lock on
    /// the children -- it passes `publish_absent_proof = false` for
    /// exactly that reason -- and an external create under an ignored
    /// path is never adopted at all, so the mutation fence never moves
    /// to invalidate a proof minted from the row alone.
    ///
    /// `symlink_metadata`, not `metadata`: a dangling symlink at this
    /// name is something on disk, not an absence.
    ///
    /// Only for the lanes that want to settle `ExactAbsent` WITHOUT
    /// performing a delete. A lane that just removed the file has
    /// already observed the absence it is about to claim, and needs no
    /// second look -- this is the same line
    /// `dag_zero_work_settlement_if_already_current` draws when it
    /// re-checks disk before authorizing skipped physical work.
    pub(crate) fn observably_absent_on_disk(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<bool, PeerSessionError> {
        let out_path = self.local_file_path(group_id, path)?;
        match std::fs::symlink_metadata(&out_path) {
            // `ENOTDIR`: a component above the name is not a directory, so
            // nothing can be at the name.
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                ) =>
            {
                Ok(true)
            }
            // Present, or unreadable. Either way this attempt has not
            // observed an absence, so it may not claim one.
            _ => Ok(false),
        }
    }

    /// [`Self::observably_absent_on_disk`] for a path this device has
    /// already found to collide with a live sibling under this volume's
    /// case/normalization folding.
    ///
    /// On such a volume, looking the path up resolves to the sibling's own
    /// entry, so the lookup alone can never report this path absent while
    /// the sibling lives: an already-landed tombstone would come back for
    /// another pass on every redelivery for as long as the sibling exists.
    /// So the path is also looked for component by component in directory
    /// listings, where the collision -- in the leaf or in any ancestor --
    /// is visible; see [`hazard::observably_absent_by_exact_name`] for what
    /// counts as a match and why an unanswerable listing is not an absence.
    fn observably_absent_by_exact_name(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<bool, PeerSessionError> {
        if self.observably_absent_on_disk(group_id, path)? {
            return Ok(true);
        }
        let root = self.sync_root(group_id)?;
        Ok(hazard::observably_absent_by_exact_name(&root, path))
    }

    /// Whether the regular file at `out_path` holds bytes this device has
    /// not captured, so writing over it (or deleting it) now would destroy
    /// a local edit with no conflict copy and no trace.
    ///
    /// Asked of the bytes themselves, right before the write, because the
    /// flush guard that runs earlier is scheduling-dependent: a write can
    /// land after it, and a capture can fail on a file that is still being
    /// written. Which bytes count as "captured" depends on the row:
    ///
    /// * `Hydrated`: the row claims disk holds its version, so any
    ///   divergence is an unauthored edit -- including a row with no blocks,
    ///   whose version says the file is empty.
    /// * `Placeholder` for which this device did not write the placeholder
    ///   on disk (no recorded placeholder, or the object is no longer that
    ///   untouched placeholder): a capture whose own disk observation raced
    ///   leaves exactly this, naming what it read while disk moved on. Real
    ///   bytes that match neither the row's version nor `incoming` (the
    ///   version about to be written, if any) are an uncaptured edit.
    ///   An untouched placeholder is left out: disagreeing with its row is
    ///   its whole point, and reading another provider's placeholder could
    ///   trigger its hydration.
    ///
    /// Every other state keeps its own handling. A missing path, a
    /// symlink, a directory or a tombstoned row is not this check's
    /// finding either -- see `revalidate_target` for why an absent path
    /// in particular must not be declined.
    pub(crate) fn disk_holds_uncaptured_local_bytes(
        &self,
        group_id: &str,
        rel_path: &str,
        out_path: &Path,
        incoming: Option<&[yadorilink_replica_domain::file::BlockInfo]>,
    ) -> Result<bool, PeerSessionError> {
        use yadorilink_local_storage::{disk_content_comparison, DiskContentComparison};
        use yadorilink_replica_domain::session_state::MaterializationState;
        let Ok(lstat) = std::fs::symlink_metadata(out_path) else { return Ok(false) };
        if !lstat.is_file() {
            return Ok(false);
        }
        let Some(local_row) = self.state.get_file(group_id, rel_path)? else { return Ok(false) };
        if local_row.deleted {
            return Ok(false);
        }
        let differs_from = |blocks: &[yadorilink_replica_domain::file::BlockInfo]| {
            disk_content_comparison(out_path, blocks)
                .map(|found| found == DiskContentComparison::PresentButDifferent)
        };
        match self.state.get_materialization_state(group_id, rel_path).ok().flatten() {
            Some(MaterializationState::Hydrated) => Ok(differs_from(&local_row.blocks)?),
            Some(MaterializationState::Placeholder) => {
                if self.is_untouched_placeholder_of_this_device(
                    group_id, rel_path, out_path, &lstat, &local_row,
                ) {
                    return Ok(false);
                }
                if !differs_from(&local_row.blocks)? {
                    return Ok(false);
                }
                match incoming {
                    Some(incoming) => Ok(differs_from(incoming)?),
                    None => Ok(true),
                }
            }
            _ => Ok(false),
        }
    }

    /// Whether projecting `head` at `rel_path` would write this device's
    /// own capture of the path back over a disk that has moved on since.
    ///
    /// A change local capture emitted was read off this disk: the disk was
    /// its source, so projecting it can never legitimately change the disk.
    /// Either the disk still holds what was captured (and the caller's
    /// "already current" checks settle it with no write), or what is there
    /// now is a newer local state -- this device's own, whatever the row
    /// claims about it -- that has to be captured as a newer change, never
    /// overwritten with the older one.
    ///
    /// Which changes are captures is recorded by the capture routes when
    /// they emit (`ReplicaCoordinator::is_local_capture`), not inferred
    /// here: a restore or a repair carrier is just as much this device's
    /// own change, and writing the disk is exactly what it is for. A peer's
    /// change is never a capture of this disk, and neither is an own head
    /// projected as a conflict copy, at a path other than the one captured.
    ///
    /// What counts as the disk having moved on, by the kind `version`
    /// names:
    /// * a regular file: a regular file whose bytes, mode or replicated
    ///   extended attributes are not `version`'s (capture records a change
    ///   to any of them as an edit; an mtime alone it does not), unless it
    ///   is an untouched placeholder this device wrote for the head -- it
    ///   stands for the head's content, and hydrating it destroys nothing
    ///   -- or a symlink in its place;
    /// * a symlink: a symlink with another target, or a regular file in
    ///   its place;
    /// * a directory: a directory with another mode, or anything else in
    ///   its place;
    /// * a file or a symlink: nothing at the path while the row still
    ///   holds it live and hydrated -- the file was deleted or renamed away
    ///   (`OwnCaptureOnDisk::Removed`). A row that is not hydrated keeps
    ///   its existing handling: nothing proves a file was ever there;
    /// * a directory: nothing at the path while the row still holds it
    ///   live. Capturing it proved it was there, so it was removed.
    ///
    /// A directory where a file or a link was captured is left to its
    /// existing handling (a type change, which capture does not author
    /// over a live file row).
    pub(crate) fn own_capture_on_disk(
        &self,
        group_id: &str,
        rel_path: &str,
        head: &PathHead,
        version: &yadorilink_replica_domain::file::FileVersion,
    ) -> Result<OwnCaptureOnDisk, PeerSessionError> {
        use yadorilink_local_storage::{disk_content_comparison, DiskContentComparison};
        use yadorilink_replica_domain::file::RecordKind;
        use yadorilink_replica_domain::session_state::MaterializationState;
        if head.device_id != self.local_device_id
            || !self.state.is_local_capture(group_id, rel_path, &ChangeHash(head.change_hash))?
        {
            return Ok(OwnCaptureOnDisk::NotACapture);
        }
        let kind = version.meta.record_kind;
        let out_path = self.local_file_path(group_id, rel_path)?;
        let lstat = match std::fs::symlink_metadata(&out_path) {
            Ok(lstat) => lstat,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                ) =>
            {
                let live_row =
                    self.state.get_file(group_id, rel_path)?.is_some_and(|row| !row.deleted);
                let removed = live_row
                    && (kind == RecordKind::Directory
                        || self.state.get_materialization_state(group_id, rel_path).ok().flatten()
                            == Some(MaterializationState::Hydrated));
                return Ok(if removed {
                    OwnCaptureOnDisk::Removed
                } else {
                    OwnCaptureOnDisk::Holds
                });
            }
            Err(_) => return Ok(OwnCaptureOnDisk::Holds),
        };
        let file_type = lstat.file_type();
        let moved_on = match kind {
            RecordKind::Directory if file_type.is_dir() => {
                version.meta.unix_mode.is_some()
                    && yadorilink_local_storage::unix_mode_from_metadata(&lstat)
                        != version.meta.unix_mode
            }
            RecordKind::Directory => true,
            RecordKind::Symlink if file_type.is_symlink() => {
                let target = std::fs::read_link(&out_path)
                    .map_err(yadorilink_local_storage::StorageError::Io)?;
                version.meta.symlink_target.as_deref()
                    != Some(
                        yadorilink_root_authority::fs_identity::target_to_bytes(&target).as_slice(),
                    )
            }
            RecordKind::Symlink => file_type.is_file(),
            _ if file_type.is_symlink() => true,
            _ if !file_type.is_file() => false,
            _ => {
                if self.state.get_materialization_state(group_id, rel_path).ok().flatten()
                    == Some(MaterializationState::Placeholder)
                {
                    if let Some(row) = self.state.get_file(group_id, rel_path)? {
                        if self.is_untouched_placeholder_of_this_device(
                            group_id, rel_path, &out_path, &lstat, &row,
                        ) {
                            return Ok(OwnCaptureOnDisk::Holds);
                        }
                    }
                }
                let record = file_record_from_version(rel_path, version);
                disk_content_comparison(&out_path, &record.blocks)?
                    == DiskContentComparison::PresentButDifferent
                    || !mode_and_xattrs_match_disk(&out_path, version)?
            }
        };
        Ok(if moved_on { OwnCaptureOnDisk::MovedOn } else { OwnCaptureOnDisk::Holds })
    }

    /// Whether the object at a `Placeholder` row's path is still a
    /// placeholder (as opposed to real bytes someone wrote there). On unix
    /// that is the `(dev, ino)` this device recorded when it wrote the
    /// placeholder, still sparse; with nothing recorded, a sparse file of
    /// the row's size. A placeholder of another provider is taken at its
    /// word (reading it could hydrate it), and so is any state this
    /// cannot read.
    #[cfg(unix)]
    fn is_untouched_placeholder_of_this_device(
        &self,
        group_id: &str,
        rel_path: &str,
        _out_path: &Path,
        lstat: &std::fs::Metadata,
        row: &FileRecord,
    ) -> bool {
        use std::os::unix::fs::MetadataExt as _;
        match self
            .state
            .materialization_state_repository()
            .get_placeholder_generation(group_id, rel_path)
        {
            Ok(Some(recorded)) => {
                recorded.provider_kind != yadorilink_local_storage::INTERNAL_INODE_PROVIDER_KIND
                    || (yadorilink_local_storage::PlaceholderDiskIdentity::from_metadata(lstat)
                        == Some(recorded.identity)
                        && lstat.blocks() == 0)
            }
            Ok(None) => lstat.len() == row.size && lstat.blocks() == 0,
            Err(_) => true,
        }
    }

    /// On Windows, the same fail-closed rule local capture applies
    /// (`untouched_placeholder_verdict`): only a CfAPI placeholder this
    /// device recorded a generation for, still reporting `Untouched`, is
    /// taken as untouched. A row with no recorded generation is by
    /// construction not a placeholder this device wrote -- it is what a
    /// capture whose disk observation raced leaves over real bytes -- so
    /// its bytes are compared, unless the object still carries a cloud
    /// recall attribute: reading a dehydrated cloud file would hydrate it,
    /// so that object is taken at its word. Another provider's placeholder
    /// and any state this cannot read are taken at their word too.
    #[cfg(windows)]
    fn is_untouched_placeholder_of_this_device(
        &self,
        group_id: &str,
        rel_path: &str,
        out_path: &Path,
        lstat: &std::fs::Metadata,
        _row: &FileRecord,
    ) -> bool {
        use std::os::windows::fs::MetadataExt as _;
        use yadorilink_filesystem_sync::placeholder_backend::PlaceholderStatus;
        const FILE_ATTRIBUTE_OFFLINE: u32 = 0x0000_1000;
        const FILE_ATTRIBUTE_RECALL_ON_OPEN: u32 = 0x0004_0000;
        const FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS: u32 = 0x0040_0000;
        let recall = FILE_ATTRIBUTE_OFFLINE
            | FILE_ATTRIBUTE_RECALL_ON_OPEN
            | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS;
        let reading_could_hydrate = lstat.file_attributes() & recall != 0;
        match self
            .state
            .materialization_state_repository()
            .get_placeholder_generation(group_id, rel_path)
        {
            Ok(Some(recorded))
                if recorded.provider_kind
                    == yadorilink_local_storage::WINDOWS_CFAPI_GENERATION_PROVIDER_KIND =>
            {
                reading_could_hydrate
                    || crate::placeholder_inspect_windows::inspect_placeholder(
                        out_path,
                        recorded.identity.ino,
                    ) == PlaceholderStatus::Untouched
            }
            Ok(Some(_)) => true,
            Ok(None) => reading_could_hydrate,
            Err(_) => true,
        }
    }

    /// Elsewhere a placeholder is the platform provider's object, and
    /// reading it is not free of side effects: always taken at its word.
    #[cfg(not(any(unix, windows)))]
    fn is_untouched_placeholder_of_this_device(
        &self,
        _group_id: &str,
        _rel_path: &str,
        _out_path: &Path,
        _lstat: &std::fs::Metadata,
        _row: &FileRecord,
    ) -> bool {
        true
    }

    pub fn local_file_path(&self, group_id: &str, path: &str) -> Result<PathBuf, PeerSessionError> {
        Ok(self.sync_root(group_id)?.join(path))
    }

    /// Applies a tombstone: remove the file, then record the deletion.
    ///
    /// No blocks, by construction — an absence has no content to fetch — which
    /// is why this belongs here and the rest of `materialize` does not. The
    /// ordering is the point: recording the tombstone *before* a removal that
    /// then fails (a locked or open file, common on Windows) would leave the
    /// index saying `deleted = true` while the file is still there, and the
    /// next scan would resurrect it as a brand-new local edit.
    pub async fn materialize_tombstone(
        &self,
        group_id: &str,
        record: &FileRecord,
        origin_device_id: &str,
        authoring_change_hash: Option<&ChangeHash>,
        root_commit_permit: &RootCommitPermit<'_>,
    ) -> Result<MaterializeResult, PeerSessionError> {
        // Recomputed here rather than passed in: a hazardous name is a fact
        // about this device's own root and policy, and this is the type that
        // owns both.
        let hazard_reason = self.hazard_reason_for(group_id, record)?;
        // A hazardous tombstone must NOT go through the ordinary `hold`
        // path used below for non-delete records: `hold_record` upserts
        // the INCOMING record as-is, and for a tombstone that means
        // writing `deleted=true` over whatever row already exists at
        // `record.path` -- while `remove_file` is deliberately never
        // called, so any content already on disk there is untouched. That
        // is exactly the "index says deleted, disk still has the file"
        // divergence this same branch's own comment above already
        // identifies as dangerous (a later scan reads it as a brand-new
        // local edit and resurrects + re-propagates it) -- for a held
        // CREATE this divergence is intentional and accounted for (disk
        // keeps whatever it had, index tracks the latest
        // known-but-unwritten metadata), but for a held DELETE it
        // recreates the exact hazard the ordering comment above was
        // written to prevent. So: only mark the existing row held, in
        // place, without adopting the incoming tombstone's fields. If
        // there is no GENUINE content row for this path, there is nothing
        // on disk to diverge from and the tombstone is simply dropped.
        // "Genuine" is `has_real_current_row`, not `get_file(...)
        // .is_some()`: `apply_locked_record`'s caller no longer bootstraps
        // a metadata scaffold for a tombstone record (a tombstone has no
        // kind/target/exec-bit to materialize), but a scaffold can still
        // exist here from an earlier, unrelated record at the same path
        // (e.g. a held CREATE's own bootstrap), so this check stays
        // defense-in-depth rather than relying on that invariant alone. A
        // dropped tombstone reports `Settled` or `RetryRequired` depending
        // on WHY there was no genuine row to hold, not uniformly: an
        // already-deleted genuine row (the redelivery case just below)
        // means this exact deletion already converged -- nothing is
        // pending, so `Settled` is correct and reporting `RetryRequired`
        // would just churn forever on a redundant resend. Every other case
        // -- a genuine LIVE row moved to `held`, or a scaffold/no row at
        // all -- means the deletion has NOT converged anywhere yet, so a
        // caller must not treat this path as resolved for this attempt.
        // The held-live-row case looks superficially like "a hazard
        // correctly moved the record to hold", which `MaterializeResult`'s
        // own doc comment reserves for `Settled`. It is not: `set_held`
        // only stamps `held_reason`/`held_since_unix_nanos` onto the
        // EXISTING (still-live) row -- it records neither the pending
        // tombstone's authoring identity nor that a deletion is even
        // pending, so nothing downstream can tell "this path is durably
        // resolved" from "this path has a live file that happens to carry
        // a hold reason". `RetryRequired` keeps the change unprojected, so
        // the periodic audit keeps retrying this exact path (cheap: just
        // this hazard check plus a `set_held` UPDATE) until the collision
        // genuinely clears -- no dependency on the original sending peer
        // still being connected, or on any peer resending at all.
        if let Some(reason) = &hazard_reason {
            let has_real_row = self.state.has_real_current_row(group_id, &record.path)?;
            let existing = self.state.get_file(group_id, &record.path)?;
            match existing {
                Some(row) if has_real_row && !row.deleted => {
                    // `RetryRequired` (below) means the periodic
                    // materialization audit re-enters this exact
                    // branch on every tick while the collision
                    // persists (see this `if let Some(reason)`
                    // block's own doc comment) -- calling `set_held`
                    // unconditionally on every one of those re-drives
                    // would stamp a fresh `now_unix_nanos()` each
                    // time, so a path held for hours would always
                    // read as "held since a moment ago". Only stamp
                    // when the reason actually changes (a first hold,
                    // or the collision shifted to a different sibling)
                    // so `held_since_unix_nanos` reflects when THIS
                    // hold reason first applied, not when it was last
                    // re-confirmed.
                    self.state.rehold_if_reason_changed(group_id, &record.path, reason)?;
                    return Ok(MaterializeResult::RetryRequired);
                }
                // Already a genuine tombstone, not a scaffold: holding
                // it would be the "orphaned held entry on a
                // tombstoned path" state `clear_held`'s own doc
                // comment says this crate deliberately avoids --
                // reachable if this exact tombstone already landed
                // once (clearing any prior hold) and a peer's
                // periodic resend redelivers it after a fresh
                // collision appears.
                //
                // "Already converged" only holds if the row's
                // authoring identity actually matches this exact
                // incoming tombstone. Defense-in-depth, not a live
                // production fix: `apply_locked_record`'s
                // `ChangeOrdering::Before` branch is this sub-case's
                // only conceivable caller, and its only current
                // caller (`rematerialize_one_record`, the
                // materialization audit) already filters out every
                // `deleted` record before this could ever run --
                // `reconcile_local_materialization_audit`'s own
                // `if record.deleted { continue; }` plus its
                // `list_materialization_repair_candidates` query's
                // `AND f.deleted = 0` -- so this branch is unreachable
                // by any caller in this codebase today. Kept correct
                // anyway for a future caller (a strictly newer
                // descendant tombstone -- e.g. a later device
                // re-tombstones an already-deleted path, minting a new
                // change on top of the one this row was last stamped
                // with) that reaches it without the same filtering:
                // fast-pathing to `Settled` without updating
                // `authoring_change_hash` would leave the row's
                // authoring identity stuck at the OLD tombstone
                // forever, with every future `dag_compare_authoring`
                // call against it re-entering this same branch. NOTE:
                // this write trusts its caller for causal ordering --
                // it does not itself verify the supplied hash is
                // newer, only that it differs, so any FUTURE caller of
                // this branch must guarantee ordering the same way
                // `ChangeOrdering::Before` does before ever reaching
                // here. Advancing the column is otherwise safe: it
                // only touches the index column, never disk or
                // `deleted`, so it carries none of the "index says
                // deleted, disk has content" risk this whole branch
                // exists to avoid.
                Some(row) if has_real_row && row.deleted => {
                    if let Some(hash) = authoring_change_hash {
                        let current =
                            self.state.get_authoring_change_hash(group_id, &record.path)?;
                        if current.as_ref() != Some(hash) {
                            self.state.set_authoring_change_hash(group_id, &record.path, hash)?;
                        }
                    }
                    // "Already absent" has to be observed, not inferred
                    // from the row: see `observably_absent_on_disk`. By
                    // exact name, because this name collides with a live
                    // sibling that a plain lookup resolves to instead.
                    if !self.observably_absent_by_exact_name(group_id, &record.path)? {
                        return Ok(MaterializeResult::RetryRequired);
                    }
                    // No disk mutation occurred here
                    // (the path is now, verifiably, absent) -- a
                    // snapshot, never a bump, of the mutation fence.
                    let mutation_generation =
                        self.state.dag_snapshot_mutation_fence(group_id, &record.path)?;
                    return Ok(MaterializeResult::Settled(SettlementEvidence::ExactAbsent {
                        mutation_generation,
                    }));
                }
                _ => return Ok(MaterializeResult::RetryRequired),
            }
        }
        let out_path = self.local_file_path(group_id, &record.path)?;
        // Same defense-in-depth as every write branch's
        // `verify_write_target` call: an intermediate directory symlink
        // can redirect this lexically-safe (`..`-free,
        // non-absolute) path outside `group_id`'s sync root, and
        // `remove_file` follows that symlink chain exactly as
        // `create`/`rename` do. See `verify_delete_target`'s doc
        // comment.
        self.verify_delete_target(group_id, &out_path)?;
        // The same last line of defence the content write has: a delete is
        // just as final for bytes this device never captured. A local edit
        // still on disk here is retried, not removed -- once captured, it
        // meets this tombstone as a concurrent edit instead of vanishing.
        if self.disk_holds_uncaptured_local_bytes(group_id, &record.path, &out_path, None)? {
            tracing::info!(
                group_id,
                path = %record.path,
                "declining a tombstone whose target no longer matches this device's indexed \
                 content; an unauthored local edit is on disk and deleting it would destroy it"
            );
            return Ok(MaterializeResult::RetryRequired);
        }
        // Opened before the delete syscall below, not after -- same
        // "before the bytes are written" contract every OTHER physical
        // mutator in this codebase already follows
        // (`MaterializationIntentGuard::open`'s own doc comment), just
        // applied to a removal instead of a write. Without this, a
        // crash between the `remove_file` below and `persist_
        // materialized_record`'s own index commit leaves this row at
        // whatever `materialization_state` it had BEFORE this
        // tombstone (typically `Hydrated`, from being genuinely
        // materialized until a moment ago) with the file now
        // genuinely missing and `record.deleted` still `false` in the
        // index -- exactly the "Hydrated + missing + no intent" shape
        // every repair/reconcile scan disambiguates via this same
        // intent journal. This path's projection obligation (bumped at
        // this Delete `Change`'s own admission, before `materialize`
        // was ever called for it) already covers most of that window,
        // but only reliably for `reconcile_disk_with_ignore`'s live
        // per-path read -- `materialization_repair.rs`'s own sweep
        // reads a whole-pass SNAPSHOT of outstanding obligations, taken
        // once per pass, so a sweep that started before this exact
        // admission would miss it and could still emit a second,
        // redundant tombstone for a path that is (accurately, just not
        // yet index-confirmed) already gone -- harmless in outcome
        // (the file really is deleted) but not something worth relying
        // on when a real intent closes the gap outright. A deletion's
        // own intent has no content to name; the owner records a delete
        // marker as its target and classifies the intent as a delete,
        // so repair leaves a file missing under it to this delete
        // rather than rebuilding it.
        //
        // The fence is bumped right after, inside this path's lock (held by every
        // caller of `materialize` for
        // its whole call), before the first mutating syscall below --
        // the bump is what invalidates this path's existing proof, and
        // it must land even if the delete itself turns out to be a
        // same-instant no-op (`NotFound`, below): a mutator's OWN
        // absence of visible effect never licenses skipping the
        // invalidation, since a concurrent mutator elsewhere could
        // otherwise still be trusted to hold a proof this call is
        // about to make stale. Safe-but-pessimistic, never a lock:
        // `path_lock` alone still serializes writers of this path.
        let (delete_intent_guard, mutation_generation) =
            self.state.open_tombstone_delete(group_id, &record.path, root_commit_permit)?;
        // `std::fs::remove_file` on a
        // symlink path is a plain `unlink` of that directory entry
        // — it removes the link itself and never follows it to
        // touch whatever the link points at, symlink or not. This is
        // exactly the "tombstone removes the link, never the
        // target" requirement, and needs no kind-specific branching
        // here: the same call is already correct for a symlink
        // record's tombstone as it is for a regular file's. See
        // `tests/peer_session.rs`'s
        // `symlink_tombstone_removes_link_but_never_its_target` for
        // a real assertion of this against an actual target file.
        let removal = self.remove_for_tombstone(group_id, &record.path, &out_path)?;
        // Settle: clear any hold, record the deletion in the index, and
        // only then clear the intent -- see the settle operations' own doc
        // comments. A retained directory settles the same way: the entry is
        // deleted, only the directory stays.
        match authoring_change_hash {
            Some(hash) => {
                self.state.settle_tombstone_delete(
                    delete_intent_guard,
                    group_id,
                    record,
                    origin_device_id,
                    hash,
                    &|| self.root_lease_for(group_id),
                )?;
            }
            // No DAG change authors this tombstone -- this call's only
            // caller with `None` is `retire_unjustified_ephemeral_conflict_
            // copies`, deleting a path no admitted change ever touched (a
            // pure local artifact of the projection fixpoint, per that
            // function's own doc comment). `persist_row_under_fresh_operation`
            // would upsert a 'current' row via `upsert_file_with_origin`,
            // which the schema's `files_require_authoring_identity_on_*`
            // triggers unconditionally reject once this group has ANY DAG
            // history (see `dc3b5c36`'s "every current row" invariant,
            // added months after this retirement call already existed with
            // `None` -- a confirmed, reproduced regression: every retry
            // hits the same trigger, forever, since nothing about a purely
            // local decision can ever satisfy "verified authoring
            // identity"). There is no fact to assert here, so erase the
            // row instead of asserting a tombstone -- exactly
            // `erase_local_only_file`'s ("not a tombstone, an erasure",
            // mirroring `FileIndexRepository::remove_file`'s own existing
            // ignore-sweep use) documented semantics.
            None => {
                self.state.settle_retired_copy_erase(
                    delete_intent_guard,
                    group_id,
                    &record.path,
                    root_commit_permit,
                )?;
            }
        }
        if let TombstoneRemoval::Retained { reason, removable } = removal {
            self.keep_directory_a_delete_found_not_empty(
                group_id,
                &record.path,
                reason,
                removable.as_deref(),
            )?;
            return Ok(MaterializeResult::Settled(SettlementEvidence::Retained {
                reason: reason.to_string(),
            }));
        }
        return Ok(MaterializeResult::Settled(SettlementEvidence::ExactAbsent {
            mutation_generation,
        }));
    }

    /// Removes what a tombstone deletes at `out_path`: the file or symlink
    /// (a plain unlink, which never follows a link), or the directory --
    /// only when it is empty, with a single non-recursive `rmdir`.
    ///
    /// A directory that is not empty is kept, with everything in it, and
    /// reported [`TombstoneRemoval::Retained`]: whatever keeps it is either
    /// something this device does not replicate (a user's untracked file,
    /// an ignored `.git`, the `.DS_Store` a Finder window leaves), which the
    /// sync engine never deletes on anyone's behalf, or live descendants,
    /// which a directory delete does not reach. Either way the entry's
    /// delete is settled; retrying would only find the same directory. A
    /// directory that was removed has nothing structural or retained left
    /// to record.
    ///
    /// Only a directory the index holds as a replicated directory is
    /// removed. A directory standing where the index holds a file or a
    /// symlink was put there by something else -- a local change of kind
    /// that capture has not recorded -- and is kept even when empty.
    pub(crate) fn remove_for_tombstone(
        &self,
        group_id: &str,
        rel_path: &str,
        out_path: &Path,
    ) -> Result<TombstoneRemoval, PeerSessionError> {
        if std::fs::symlink_metadata(out_path).is_ok_and(|meta| meta.is_dir()) {
            if self.state.get_record_kind(group_id, rel_path)?
                != Some(yadorilink_replica_domain::file::RecordKind::Directory)
            {
                return Ok(TombstoneRemoval::Retained {
                    reason: self.retained_directory_reason_for(group_id, rel_path)?,
                    removable: None,
                });
            }
            if !self.is_materialized_directory_at(group_id, rel_path, out_path)? {
                return Ok(TombstoneRemoval::Retained {
                    reason: yadorilink_sync_sqlite::structural_origin::RETAINED_REPLACED_LOCALLY,
                    removable: None,
                });
            }
            if let Some(removal) = self.remove_directory_if_empty(group_id, rel_path, out_path)? {
                return Ok(removal);
            }
        }
        match std::fs::remove_file(out_path) {
            Ok(()) => Ok(TombstoneRemoval::Removed),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(TombstoneRemoval::Removed),
            Err(e) => Err(PeerSessionError::from(e)),
        }
    }

    /// Whether the directory at `out_path` is the object this device
    /// materialized for `rel_path`'s Directory entry. The row's kind says
    /// the entry is a directory, not that the directory now standing at its
    /// name is the one the entry put there: the user may have removed it and
    /// made another. An unobservable path, or no recorded identity, is not a
    /// match -- the directory is kept.
    fn is_materialized_directory_at(
        &self,
        group_id: &str,
        rel_path: &str,
        out_path: &Path,
    ) -> Result<bool, PeerSessionError> {
        let Ok(observed) =
            yadorilink_root_authority::fs_identity::FileIdentity::observe_path(out_path)
        else {
            return Ok(false);
        };
        self.state
            .is_materialized_directory_object(
                group_id,
                rel_path,
                &self.sync_root(group_id)?,
                &observed,
            )
            .map_err(crate::sync_error::SyncError::from)
            .map_err(PeerSessionError::from)
    }

    /// One non-recursive `rmdir` of the directory at `out_path`: removed
    /// (and its structural and retained records forgotten) when empty,
    /// retained when not. `None` when what is there is no longer a
    /// directory.
    ///
    /// Every caller first checks that the directory at `out_path` is the
    /// object it may remove (the materialized directory, or the retained one
    /// a delete aimed at) and only then calls this, and the `rmdir` goes by
    /// name. Neither macOS nor Linux can remove a directory by descriptor or
    /// make a removal conditional on the object's identity, so a directory
    /// swapped in at the same name between that check and the `rmdir` --
    /// by a process that does not take this daemon's path lock -- is removed
    /// in its place if it is empty. Only an empty directory can be affected:
    /// the `rmdir` refuses anything with an entry in it, and never touches a
    /// file. Moving the directory aside first to check it under a private
    /// name would close that gap only by making a non-empty directory, with
    /// its tracked children, vanish from its name for a moment, which is
    /// worse. The same gap sits between a failed `rmdir` and the identity
    /// recorded for a retained directory below.
    fn remove_directory_if_empty(
        &self,
        group_id: &str,
        rel_path: &str,
        out_path: &Path,
    ) -> Result<Option<TombstoneRemoval>, PeerSessionError> {
        use yadorilink_local_storage::EmptyDirectoryRemoval;
        Ok(match yadorilink_local_storage::remove_empty_dir(out_path)? {
            EmptyDirectoryRemoval::Removed => {
                self.state
                    .forget_removed_directory(group_id, rel_path)
                    .map_err(crate::sync_error::SyncError::from)?;
                Some(TombstoneRemoval::Removed)
            }
            EmptyDirectoryRemoval::Absent => Some(TombstoneRemoval::Removed),
            // The directory this delete aimed at: bound to its identity,
            // so a later pass removes this object once it is empty, and
            // never a different directory made at the same path.
            EmptyDirectoryRemoval::NotEmpty => Some(TombstoneRemoval::Retained {
                reason: self.retained_directory_reason_for(group_id, rel_path)?,
                removable: yadorilink_root_authority::fs_identity::FileIdentity::observe_path(
                    out_path,
                )
                .ok()
                .map(Box::new),
            }),
            EmptyDirectoryRemoval::NotADirectory => None,
        })
    }

    /// Records the directory a delete aimed at and found not empty as
    /// retained. When what keeps it is live descendants, it is adopted as
    /// structural too: from now on it is their container, derived state
    /// like any directory this device created for descendants, and capture
    /// must never read it as a user's directory and author back the entry
    /// the delete removed. Once the last descendant goes, it is removed.
    pub(crate) fn keep_directory_a_delete_found_not_empty(
        &self,
        group_id: &str,
        rel_path: &str,
        reason: &str,
        removable: Option<&yadorilink_root_authority::fs_identity::FileIdentity>,
    ) -> Result<(), PeerSessionError> {
        self.state
            .keep_retained_directory(group_id, rel_path, reason, removable)
            .map_err(crate::sync_error::SyncError::from)?;
        if let Some(identity) = removable {
            if reason == yadorilink_sync_sqlite::structural_origin::RETAINED_LIVE_DESCENDANTS {
                self.state
                    .adopt_as_structural_directory(group_id, rel_path, identity)
                    .map_err(crate::sync_error::SyncError::from)?;
            }
        }
        Ok(())
    }

    /// Why a non-empty directory whose entry is deleted stays: live
    /// descendants, or content this device does not replicate.
    fn retained_directory_reason_for(
        &self,
        group_id: &str,
        rel_path: &str,
    ) -> Result<&'static str, PeerSessionError> {
        Ok(
            if self
                .state
                .has_live_descendant(group_id, rel_path)
                .map_err(crate::sync_error::SyncError::from)?
            {
                yadorilink_sync_sqlite::structural_origin::RETAINED_LIVE_DESCENDANTS
            } else {
                yadorilink_sync_sqlite::structural_origin::RETAINED_UNTRACKED_CONTENT
            },
        )
    }

    /// A tombstone already recorded for `rel_path` while a directory still
    /// stands at its name: either the directory an earlier delete aimed at
    /// and retained, which is removed now if it has since become empty, or
    /// a directory no delete aimed at -- one standing where the index held
    /// a file, or one made after the delete and not captured -- which is
    /// kept for good, however empty. `None` when no directory is there.
    /// Never a retry: what is on disk decides the answer at once.
    pub(crate) fn settle_directory_at_deleted_path(
        &self,
        group_id: &str,
        rel_path: &str,
    ) -> Result<Option<SettlementEvidence>, PeerSessionError> {
        let out_path = self.local_file_path(group_id, rel_path)?;
        if !std::fs::symlink_metadata(&out_path).is_ok_and(|meta| meta.is_dir()) {
            return Ok(None);
        }
        if let Some(evidence) = self.remove_retained_directory_if_empty(group_id, rel_path)? {
            return Ok(Some(evidence));
        }
        // A directory this device made only to hold descendants (a file's
        // parent, or the container a relocated file left behind) goes once
        // nothing needs it.
        if let Some(evidence) = self.prune_directory_made_for_descendants(group_id, rel_path)? {
            return Ok(Some(evidence));
        }
        let reason = self.retained_directory_reason_for(group_id, rel_path)?;
        self.state
            .keep_retained_directory(group_id, rel_path, reason, None)
            .map_err(crate::sync_error::SyncError::from)?;
        Ok(Some(SettlementEvidence::Retained { reason: reason.to_string() }))
    }

    /// Removes the directory at `rel_path` if it is the very object an
    /// earlier delete aimed at and retained, and it is now empty
    /// (`ExactAbsent`); if it is that object but still not empty, keeps it
    /// (`Retained`). `None` when what is at the path is not such a
    /// directory: nothing recorded, recorded as kept, or a different
    /// object at the same path.
    fn remove_retained_directory_if_empty(
        &self,
        group_id: &str,
        rel_path: &str,
    ) -> Result<Option<SettlementEvidence>, PeerSessionError> {
        let out_path = self.local_file_path(group_id, rel_path)?;
        let Ok(observed) =
            yadorilink_root_authority::fs_identity::FileIdentity::observe_path(&out_path)
        else {
            return Ok(None);
        };
        if !self
            .state
            .is_removable_retained_directory(
                group_id,
                rel_path,
                &self.sync_root(group_id)?,
                &observed,
            )
            .map_err(crate::sync_error::SyncError::from)?
        {
            return Ok(None);
        }
        self.verify_delete_target(group_id, &out_path)?;
        let mutation_generation =
            self.state.begin_retained_directory_removal(group_id, rel_path)?;
        Ok(match self.remove_directory_if_empty(group_id, rel_path, &out_path)? {
            Some(TombstoneRemoval::Removed) => {
                Some(SettlementEvidence::ExactAbsent { mutation_generation })
            }
            Some(TombstoneRemoval::Retained { reason, removable }) => {
                self.keep_directory_a_delete_found_not_empty(
                    group_id,
                    rel_path,
                    reason,
                    removable.as_deref(),
                )?;
                Some(SettlementEvidence::Retained { reason: reason.to_string() })
            }
            None => None,
        })
    }

    /// Re-examines every retained directory above a path this pass
    /// removed, deepest first, and removes each one that is now empty.
    ///
    /// A directory's delete can run before its children's: a peer's
    /// `rm -rf` wider than one commit chunk puts the directory in an
    /// earlier chunk than some of its children, the engine's bounded calls
    /// can split the paths across passes, and a child's delete can be
    /// retried. The directory's `rmdir` then finds it not empty and it is
    /// retained, and its own path is never reconciled again. Removing its
    /// last child is what empties it, so that is when it is re-examined.
    /// Only a directory a delete aimed at, and only that same object, is
    /// ever removed here.
    ///
    /// Takes each ancestor's path lock, so it must be called holding none.
    /// Best effort: a failure is logged and leaves the directory retained,
    /// exactly as it was before this ran.
    pub(crate) async fn remove_emptied_retained_ancestors<'a>(
        &self,
        group_id: &str,
        removed_paths: impl IntoIterator<Item = &'a String>,
    ) {
        let mut ancestors = std::collections::BTreeSet::new();
        for path in removed_paths {
            let mut rest = path.as_str();
            while let Some((parent, _)) = rest.rsplit_once('/') {
                ancestors.insert(parent.to_string());
                rest = parent;
            }
        }
        // Reverse order: every descendant sorts after its ancestor.
        for ancestor in ancestors.into_iter().rev() {
            let path_lock = self.state.path_lock(group_id, &ancestor);
            let _guard = path_lock.lock().await;
            let outcome = (|| -> Result<Option<SettlementEvidence>, PeerSessionError> {
                if self
                    .state
                    .retained_directory_reason(group_id, &ancestor)
                    .map_err(crate::sync_error::SyncError::from)?
                    .is_some()
                    && self.state.get_file(group_id, &ancestor)?.is_some_and(|row| row.deleted)
                {
                    if let Some(evidence) =
                        self.remove_retained_directory_if_empty(group_id, &ancestor)?
                    {
                        return Ok(Some(evidence));
                    }
                }
                // A directory this device created only to hold what was
                // just removed goes with it, once nothing else needs it.
                self.prune_directory_made_for_descendants(group_id, &ancestor)
            })();
            match outcome {
                Ok(Some(SettlementEvidence::ExactAbsent { .. })) => tracing::debug!(
                    group_id,
                    path = %ancestor,
                    "removed a retained directory its last child's delete emptied"
                ),
                Ok(_) => {}
                Err(error) => tracing::warn!(
                    group_id,
                    path = %ancestor,
                    %error,
                    "could not re-examine a retained directory after a child's delete; it \
                     stays retained"
                ),
            }
        }
    }

    /// Whether this device refuses to write `record`'s name.
    pub(crate) fn hazard_reason_for(
        &self,
        group_id: &str,
        record: &FileRecord,
    ) -> Result<Option<String>, PeerSessionError> {
        hazard_reason_for_policy(
            self.state.as_ref(),
            &self.sync_root(group_id)?,
            group_id,
            record,
            hazard::NamePolicy::local(),
        )
    }

    /// Refuses a delete aimed outside this group's root.
    ///
    /// An intermediate directory symlink can redirect a lexically safe,
    /// `..`-free path outside the sync root, and `remove_file` follows that
    /// chain exactly as `create`/`rename` do.
    pub fn verify_delete_target(
        &self,
        group_id: &str,
        out_path: &Path,
    ) -> Result<(), PeerSessionError> {
        let raw_root = self.sync_root(group_id)?;
        let raw_root = raw_root.as_path();
        self.state.verify_root(raw_root, group_id)?;
        if out_path.parent() == Some(raw_root) {
            return Ok(());
        }
        match self.canonical_sync_root(group_id, raw_root) {
            Some(canonical_root) => {
                Ok(verify_delete_target_within_canonical_root(out_path, &canonical_root)?)
            }
            None => Ok(verify_delete_target_within_root(out_path, raw_root)?),
        }
    }

    /// The live heads for `path`: the changes touching it that are
    /// causally maximal in the currently admitted DAG.
    ///
    /// One read of a derived index. Which touchers are still live is
    /// decided once, when a change is admitted, and recorded; resolving a
    /// path reads that decision rather than re-deriving it. Nothing here
    /// decodes an encoded change, walks ancestry, or costs anything
    /// proportional to the group's history length.
    ///
    /// This used to walk the group's ancestry backwards from its current
    /// heads, decoding every visited change and scanning its ops, keeping
    /// the ones that touched `path` and discarding the rest. That cost
    /// the whole of the group's history per path resolved, however rarely
    /// the path itself had been written: on a 10,000-file import admitted
    /// as one-op changes, resolving eight paths cost ~92,000 change
    /// decodes.
    ///
    /// Note for whoever reads this next: an intermediate form kept that
    /// walk's shape but found candidates through an index of "every
    /// change that ever touched this path", then re-checked reachability
    /// and supersession on every read. It removed the history-length
    /// dependence but left a per-read ancestry check proportional to how
    /// often the path had been written. A per-tick memo was then added on
    /// top, sharing one result between fetch-origin selection and
    /// missing-content detection, and was removed again when the per-read
    /// cost itself went away -- at which point it bought nothing and cost
    /// a freshness invariant plus a parallel set of entry points through
    /// four modules. Both steps point the same way: make the per-call
    /// cost go away rather than arrange for the call to happen fewer
    /// times.
    pub(crate) fn store_live_heads_for_path(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Vec<PathHead>, PeerSessionError> {
        Ok(self.state.dag_path_live_heads(group_id, path)?)
    }

    /// The conflict-copy paths `path`'s own resolution derives right now.
    ///
    /// Empty when the path resolves to `Absent` or has no concurrent losing
    /// content head. See [`PeerSyncSession::conflict_copy_paths_for`] for why
    /// this is asked from outside at all.
    pub fn conflict_copy_paths_for(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Vec<String>, PeerSessionError> {
        use yadorilink_replica_engine::conflict::{resolve_path_heads, PathResolution};
        let heads = self.combined_heads(group_id, path, None)?;
        match resolve_path_heads(path, &heads) {
            PathResolution::Present { conflict_copies, .. } => {
                Ok(conflict_copies.into_iter().map(|copy| copy.path).collect())
            }
            _ => Ok(Vec::new()),
        }
    }

    pub fn combined_heads(
        &self,
        group_id: &str,
        path: &str,
        derived_head: Option<&PathHead>,
    ) -> Result<Vec<PathHead>, PeerSessionError> {
        let direct = self.store_live_heads_for_path(group_id, path)?;

        // The stored heads are already causally maximal among themselves
        // -- that is what makes them stored heads -- so with nothing to
        // merge in, they are the answer, and no ancestry question arises
        // at all. This is the hot path: every ordinary resolution takes
        // it.
        let Some(derived) = derived_head else {
            return Ok(direct);
        };

        // A derived head is a head this device reasoned its way to rather
        // than read, so its causal relation to the stored ones is the one
        // thing not already settled. Only that relation is asked about:
        // each comparison is against the derived head, never between two
        // stored heads, so the work is bounded by the path's live width
        // and by nothing else.
        let mut live = Vec::new();
        let mut derived_superseded = false;
        for head in &direct {
            let head_hash = ChangeHash(head.change_hash);
            let derived_hash = ChangeHash(derived.change_hash);
            if self.state.dag_is_ancestor(&head_hash, &derived_hash)? {
                // This stored head is in the derived head's past: the
                // derived head replaces it.
                continue;
            }
            if self.state.dag_is_ancestor(&derived_hash, &head_hash)? {
                derived_superseded = true;
            }
            live.push(head.clone());
        }
        if !derived_superseded {
            live.push(derived.clone());
        }
        Ok(live)
    }

    /// Standalone entry point for the retirement step alone -- see
    /// `retire_unjustified_ephemeral_conflict_copies`'s own doc comment for
    /// what it does and why. `engine_wrapper.rs`'s event-driven retirement
    /// loop calls this directly instead of the full `reconcile_local_
    /// materialization_audit` below, which also re-drives unapplied-change
    /// reprojection and materialization-repair candidates -- heavier work
    /// a frontier-changed/job-completed retirement trigger has no bearing
    /// on. Single-flights per group through its OWN `RetirementAuditGuard`
    /// key -- a SEPARATE key space from `reconcile_local_materialization_
    /// audit`/`reconcile_paths_directly`'s `MaterializationAuditGuard`, so
    /// a full audit already in flight for a group no longer makes THIS
    /// call report `RetirementAttempt::Busy`; only two retirement passes
    /// for the same group ever contend with each other. See
    /// `RetirementAuditGuard`'s own doc comment for why that coarser
    /// group-wide sharing was never actually load-bearing for correctness,
    /// and `RetirementAttempt`'s own doc comment for what each variant
    /// means for a generation-tracked caller.
    ///
    /// Whole-pass frontier freshness: `frontier_before` is this device's
    /// own admitted DAG heads for `group_id`, read right after the
    /// `RetirementAuditGuard` is acquired (before any copy is examined);
    /// `frontier_after` is the same read again right after the retirement
    /// pass returns (after every mutation it made is durable). If they
    /// differ, some OTHER admission (a peer's change arriving, or a local
    /// edit) landed while this pass was evaluating justification against
    /// whatever frontier was current when it started -- every individual
    /// decision inside the pass was locally consistent with SOME real
    /// frontier, but not provably the one current when the pass returns,
    /// so the whole pass reports `RetirementAttempt::FrontierChanged`
    /// instead of its own inner outcome, even if that inner outcome was
    /// `Settled`. This deliberately does not attempt a per-copy freshness
    /// recheck immediately before each delete (Commit 5's own scope is the
    /// whole-pass guard only) -- see `retire_unjustified_ephemeral_
    /// conflict_copies`'s own doc comment for why a copy this pass
    /// mutated is never left in a worse state than before, only
    /// potentially stale, and a caller that does not complete the
    /// generation on `FrontierChanged` gets exactly the re-evaluation
    /// against the CURRENT frontier that closes the gap.
    pub async fn retire_conflict_copies_only(
        &self,
        group_id: &str,
    ) -> Result<RetirementAttempt, PeerSessionError> {
        if !matches!(self.state.link_gate_for_group(group_id)?, LinkGate::Live { .. }) {
            return Ok(RetirementAttempt::Settled { retired: 0 });
        }
        let Some(_guard) = RetirementAuditGuard::try_acquire(&self.state, group_id) else {
            return Ok(RetirementAttempt::Busy);
        };
        let frontier_before = self.state.dag_group_heads(group_id)?;
        let audit_attempt_id = next_audit_attempt_id();
        let (outcome, retired_generations) =
            self.retire_unjustified_ephemeral_conflict_copies(group_id, audit_attempt_id).await?;
        let frontier_after = self.state.dag_group_heads(group_id)?;
        if frontier_changed_during_pass(&frontier_before, &frontier_after) {
            // The deletions already happened and are not undone, but
            // `frontier_before` is no longer provably this group's causal
            // basis, so none of `retired_generations` is published here --
            // each path's own pre-delete fence bump already made its
            // prior proof non-usable, which is all the invariant requires
            // in this case.
            return Ok(RetirementAttempt::FrontierChanged);
        }
        // Publish regardless of whether `outcome` itself is `Settled` or
        // `RetryRequired` -- `RetryRequired` means some OTHER copy was
        // never re-verified this pass, which says nothing about the
        // copies this pass genuinely did delete. Each publication is its
        // own per-path CAS on the fence value that path's own pre-delete
        // bump produced; a CAS failure for one path never blocks
        // another's.
        // Held across the publications, not merely across the deletes:
        // the proof is what says this path is exactly absent, and it is
        // published after the delete that made it so. A root swapped in
        // between would make that claim about a root this device no
        // longer owns.
        let root_commit_authority = self.root_lease_for(group_id)?;
        let root_commit_authority_op = root_commit_authority.begin_operation()?;
        let root_commit_permit = root_commit_authority_op.permit();
        self.state.publish_retired_copy_absence(
            group_id,
            &frontier_before,
            &retired_generations,
            &root_commit_permit,
        );
        Ok(outcome)
    }

    /// Removes locally-materialized conflict copies that are pure artifacts
    /// of a *transient* frontier: (a) no admitted change carries the copy
    /// path (it exists only because this device's projection fixpoint
    /// happened to run at a moment when its losing head was live), and (b)
    /// the CURRENT frontier's resolution of the base path no longer derives
    /// it (the loser has since been superseded — typically by its own
    /// author's next edit, which closes the conflict window without any
    /// cross-branch merge and therefore without any carrier obligation).
    ///
    /// This closes a confirmed, reproduced convergence divergence (seed
    /// `1254137095109609298` under contention, and ~1-in-3 locally with the
    /// repair sweep active from t=0): devices reconcile at whatever
    /// intermediate frontiers their arrival order produces, so a device
    /// that passed through the transient concurrent moment materializes and
    /// indexes the copy while a device that first reconciled after the
    /// window closed never derives it — four identical DAGs, identical
    /// resolutions, permanently different file sets, and nothing on either
    /// side ever changes its mind. Retiring the unjustified copy makes
    /// every device converge on the durable-plus-currently-justified copy
    /// set: a copy for a loser that is STILL live stays (condition (b))
    /// until the retroactive repair loop makes it durable, and a copy any
    /// change carries stays permanently (condition (a)).
    ///
    /// Safety: a user file that merely mimics the copy naming is protected
    /// by (a) — its own creation/edit emits a change carrying the path
    /// (the same argument that lets `backfill_missing_history` skip
    /// copy-shaped paths). Before deleting, any same-path local edit still
    /// sitting in the debounce accumulator is flushed and history re-read
    /// (the flushed change then protects it), a path still in the dirty
    /// journal is skipped outright (its pending change is not yet
    /// re-driven), and the whole check-then-delete runs under the path
    /// lock, mirroring `reconcile_group_paths`' Absent-branch discipline.
    ///
    /// Returns `RetirementAttempt::Settled` only if every copy-shaped file
    /// this pass examined was either justified or successfully retired.
    /// One copy's tombstone `materialize` returning `MaterializeResult::
    /// RetryRequired` (transient block/disk condition) makes the WHOLE
    /// pass `RetirementAttempt::RetryRequired`, even if every other copy
    /// settled cleanly: the caller uses this to decide whether it may
    /// consider the frontier generation it targeted fully verified, and a
    /// pass that skipped even one copy's re-evaluation has not verified
    /// it. The operation is idempotent regardless -- a copy already
    /// retired by an earlier pass this same call just does not appear in
    /// `copy_shaped` on the next one.
    /// Returns the pass's `RetirementAttempt` status ALONGSIDE the set of
    /// paths it physically deleted, each mapped to the mutation-fence value
    /// (`E`) its own pre-delete bump produced -- a pass's status and the
    /// paths it mutated are independent facts, and only
    /// `retire_conflict_copies_only` (the caller with its
    /// own frontier-freshness proof) may use this map to publish.
    pub(crate) async fn retire_unjustified_ephemeral_conflict_copies(
        &self,
        group_id: &str,
        audit_attempt_id: u64,
    ) -> Result<(RetirementAttempt, std::collections::BTreeMap<String, i64>), PeerSessionError>
    {
        let mut retired_generations = std::collections::BTreeMap::new();
        let root_commit_authority = self.root_lease_for(group_id)?;
        let root_commit_authority_op = root_commit_authority.begin_operation()?;
        let root_commit_permit = root_commit_authority_op.permit();
        let LinkGate::Live { .. } = self.state.link_gate_for_group(group_id)? else {
            return Ok((RetirementAttempt::Settled { retired: 0 }, retired_generations));
        };
        let copy_shaped: Vec<FileRecord> = self
            .state
            .list_files(group_id)?
            .into_iter()
            .filter(|r| {
                !r.deleted && yadorilink_replica_domain::conflict::is_conflict_copy_path(&r.path)
            })
            .collect();
        if copy_shaped.is_empty() {
            return Ok((RetirementAttempt::Settled { retired: 0 }, retired_generations));
        }
        let mut retired = 0usize;
        let mut retry_required = false;
        let history = self.state.dag_group_history_paths(group_id)?;
        for record in copy_shaped {
            if history.contains(&record.path) {
                continue;
            }
            if self.state.is_path_dirty(group_id, &record.path)? {
                continue;
            }
            if yadorilink_replica_domain::conflict::conflict_copy_stem_was_truncated(&record.path) {
                // The copy's name was shortened to fit the filesystem's
                // per-component limit, so it no longer spells its source
                // path in full. Resolving the prefix would find nothing
                // and make a perfectly justified copy look unjustified,
                // and this audit deletes what it finds unjustified. An
                // inversion that cannot be trusted is not evidence.
                continue;
            }
            let base = yadorilink_replica_domain::conflict::conflict_copy_source_path(&record.path);
            let inputs = self.combined_heads(group_id, &base, None)?;
            let justified = match resolve_path_heads(&base, &inputs) {
                PathResolution::Present { conflict_copies, .. } => {
                    conflict_copies.iter().any(|cc| cc.path == record.path)
                }
                PathResolution::Absent => false,
            };
            // The per-path resolver knows only conflict copies. A file the
            // namespace relocates -- or keeps at its copy name because a
            // directory holds its own -- lives only at that copy.
            if justified || self.copy_justified_by_namespace(group_id, &base, &record.path)? {
                continue;
            }
            // This device's own debounce accumulator, flushed before the
            // path is reconciled against anything.
            tracing::debug!(
                group_id,
                path = %record.path,
                "checking this link's debounce accumulator for a pending local change"
            );
            if self
                .pending_local_change_flush
                .flush_pending_local_change(group_id, &record.path)
                .await
                == yadorilink_peer_session::peer_session::PendingLocalFlushOutcome::RetryRequired
            {
                // A local edit to this copy could not be captured; it is
                // not this audit's to delete. A later audit re-examines it.
                continue;
            }
            if self.state.dag_group_history_paths(group_id)?.contains(&record.path) {
                // The flush just made a real local edit of this path durable
                // -- it is user content now, not an ephemeral artifact.
                continue;
            }
            let path_lock = self.state.path_lock(group_id, &record.path);
            let _guard = path_lock.lock().await;
            let still_live =
                self.state.get_file(group_id, &record.path)?.map(|r| !r.deleted).unwrap_or(false);
            if !still_live {
                continue;
            }
            let tombstone = FileRecord {
                path: record.path.clone(),
                size: 0,
                mtime_unix_nanos: 0,
                blocks: Vec::new(),
                deleted: true,
            };
            // The origin is this device. A retirement is decided from local
            // state alone, so attributing its tombstone to whichever peer
            // happened to own the session that ran it was never right — it
            // only ever looked right because the synthetic session used this
            // device's own id as its peer's.
            match self
                .materialize_tombstone(
                    group_id,
                    &tombstone,
                    &self.local_device_id,
                    None,
                    &root_commit_permit,
                )
                .await
            {
                Ok(MaterializeResult::Settled(evidence)) => {
                    retired += 1;
                    // A tombstone `materialize` call only ever settles as
                    // `ExactAbsent` -- the hazardous-tombstone sub-branch
                    // reports `RetryRequired` instead (see `materialize`'s
                    // own doc comment on the `if record.deleted` branch).
                    // Recorded defensively rather than assumed: only a
                    // real, fence-carrying `ExactAbsent` is ever eligible
                    // for `retire_conflict_copies_only`'s own publication.
                    if let SettlementEvidence::ExactAbsent { mutation_generation } = evidence {
                        retired_generations.insert(record.path.clone(), mutation_generation);
                    }
                    tracing::info!(
                        group_id,
                        path = %record.path,
                        audit_attempt_id,
                        "retired an ephemeral conflict copy no longer justified by the current frontier"
                    )
                }
                // `RetryRequired` is not a retirement -- the copy is still
                // live, so the next audit re-evaluates it -- but it also
                // means THIS pass never verified this copy's justification
                // against the frontier it targeted, so the whole pass must
                // report `RetryRequired`, not `Settled`: a caller that
                // completed its target generation on a pass that silently
                // skipped a copy's re-evaluation would never re-examine it
                // again unless some unrelated future event happened to
                // re-mark the group dirty.
                Ok(MaterializeResult::RetryRequired) => {
                    retry_required = true;
                    tracing::debug!(
                        group_id,
                        path = %record.path,
                        audit_attempt_id,
                        "deferred retiring an ephemeral conflict copy; will re-evaluate next audit"
                    )
                }
                // Same reasoning as `RetryRequired` above: a transient
                // per-copy failure must not let the pass as a whole report
                // `Settled` for a generation whose frontier this copy was
                // never actually re-verified against.
                Err(e) => {
                    retry_required = true;
                    tracing::warn!(
                        group_id,
                        path = %record.path,
                        error = %e,
                        "failed to retire an unjustified ephemeral conflict copy; will retry next audit"
                    )
                }
            }
        }
        Ok((
            if retry_required {
                RetirementAttempt::RetryRequired
            } else {
                RetirementAttempt::Settled { retired }
            },
            retired_generations,
        ))
    }

    /// This session's currently-effective ignore set for `group_id` --
    /// see `ignore_sets`'s own doc comment for the bounded-staleness
    /// reasoning. Reloads from the group's current live root (`self.
    /// sync_root`, not a cached one) once the cached entry is older than
    /// `IGNORE_SET_REFRESH_INTERVAL`; a reload that fails (no live link
    /// right now, e.g. a transient relink) falls back to whatever is
    /// already cached rather than discarding it, and only returns `None`
    /// if nothing has ever been successfully loaded for this group at
    /// all.
    pub(crate) fn effective_ignore_set(&self, group_id: &str) -> Option<Arc<EffectiveIgnoreSet>> {
        let mut cache = self.ignore_sets.lock().unwrap_or_else(|p| p.into_inner());
        if let Some((set, loaded_at)) = cache.get(group_id) {
            if loaded_at.elapsed() < IGNORE_SET_REFRESH_INTERVAL {
                return Some(set.clone());
            }
        }
        match self.sync_root(group_id) {
            Ok(root) => {
                let set = Arc::new(
                    EffectiveIgnoreSet::load_for_link_root(&root)
                        .unwrap_or_else(|_| EffectiveIgnoreSet::defaults_only()),
                );
                cache.insert(group_id.to_string(), (set.clone(), std::time::Instant::now()));
                Some(set)
            }
            Err(_) => cache.get(group_id).map(|(set, _)| set.clone()),
        }
    }

    /// Whether `path` matches this device's
    /// own effective ignore pattern set for `group_id` (built-in defaults
    /// plus this device's `.yadorilinkignore`, if any). A group with no
    /// entry in `ignore_sets` (not one of `sync_roots`) is never ignored
    /// by this check — that shouldn't happen for a group this session
    /// actually shares, since `ignore_sets` is derived from the same
    /// `sync_roots` map `shares_group`'s caller relies on.
    ///
    /// This is a purely local filter (ignore patterns are
    /// device-local, never synced) — it decides what *this* device does
    /// with an incoming record (skip materializing/indexing/forwarding
    /// it), and has no effect on what the sending peer, or this device's
    /// other peers, do with the same path.
    ///
    /// A directory-only pattern (`build/`) covers the path only when the
    /// path is a directory: whether it is comes from what the namespace
    /// places there, an explicit or a structural directory, never from
    /// what happens to be on this device's disk.
    pub fn is_locally_ignored(&self, group_id: &str, path: &str) -> bool {
        self.effective_ignore_set(group_id).is_some_and(|set| {
            is_ignore_file_relative_path(path)
                || set.is_ignored(path, false)
                || (set.is_ignored(path, true)
                    && matches!(
                        self.state.desired_path_state(group_id, path),
                        Ok(yadorilink_sync_sqlite::desired_state::DesiredPathState::ExplicitDirectory { .. }
                            | yadorilink_sync_sqlite::desired_state::DesiredPathState::StructuralDirectory)
                    ))
        })
    }

    /// Test-only accessor letting `ignore_set_liveness_tests` age a cached
    /// entry past `IGNORE_SET_REFRESH_INTERVAL` without a real sleep.
    #[cfg(test)]
    pub(crate) fn rewind_ignore_set_cache_for_tests(
        &self,
        group_id: &str,
        age: std::time::Duration,
    ) {
        let mut cache = self.ignore_sets.lock().unwrap_or_else(|p| p.into_inner());
        if let Some((_, loaded_at)) = cache.get_mut(group_id) {
            *loaded_at =
                std::time::Instant::now().checked_sub(age).expect("age must not underflow Instant");
        }
    }

    /// The zero-work-close pre-check for one path: without any block fetch
    /// or disk write, resolves `path`'s current DAG heads (the SAME
    /// resolution `reconcile_group_paths` performs internally, just for
    /// one path and with none of its write-side effects) and asks the
    /// zero-work port method whether disk already, verifiably, holds that
    /// exact state. Returns the ready-to-close evidence when it does;
    /// `None` whenever it cannot conclusively confirm this (an ignored
    /// path, no live heads, an `Absent` resolution -- retirement's own
    /// publication path already covers deletes, so this pre-check only
    /// ever concerns itself with `Present` -- or the port method itself
    /// reporting "not confirmable"). `None` must always be read as "let
    /// the ordinary reconcile attempt handle this path," never as an
    /// error.
    pub fn zero_work_settlement_for_path(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<SettlementEvidence>, PeerSessionError> {
        if self.is_locally_ignored(group_id, path) {
            return Ok(None);
        }
        // Cheapest question first. `dag_zero_work_settlement_if_already_current`
        // below cannot return anything but `None` without a usable
        // `path_materialized_generations` record for this path -- that
        // fence-checked point lookup is the first thing it does -- yet every
        // input it needs to be ASKED costs a full per-path DAG ancestry walk
        // (`combined_heads` -> `store_live_heads_for_path`), which fetches and
        // wire-decodes each change it passes, per path, with no memoization
        // across paths or across ticks.
        //
        // On a replica catching up to a bulk import that is every path, and the
        // walk is at its deepest: the scheduler's pre-check loop runs this for
        // its whole claimed batch on every tick, so the device spends entire
        // ticks resolving heads only to hand them to a check that was always
        // going to decline. Measured on a 91k-path catch-up: ~6.6s per tick to
        // advance 8 paths, with the receiving device producing no files at all
        // for 36 minutes.
        //
        // Asking the O(1) question first cannot change any answer -- it is the
        // same conjunct, evaluated earlier -- and a record that appears just
        // after this returns `false` only means the ordinary reconcile attempt
        // handles the path, which is exactly what `None` already means here.
        if !self.state.dag_has_usable_materialized_generation(group_id, path)? {
            return Ok(None);
        }
        let inputs = self.combined_heads(group_id, path, None)?;
        if inputs.is_empty() {
            return Ok(None);
        }
        let resolution = resolve_path_heads(path, &inputs);
        let PathResolution::Present { winner, conflict_copies } = &resolution else {
            // An `Absent` resolution has its own, already-covered
            // publication path (retirement's tombstone evidence); this
            // pre-check only ever short-circuits a real, present write.
            return Ok(None);
        };
        // The evidence below speaks for the winner's content at `path`
        // only. A resolution with concurrent losers also owes each loser's
        // content at its conflict-copy path, which that evidence says
        // nothing about: closing here would retire the obligation with the
        // losing content never written anywhere on this device. That is
        // exactly the case where this device's own edit won against an
        // admitted remote edit -- the winner is already on disk, so the
        // check would confirm, and the remote edit would be lost locally
        // while the peer keeps both. The ordinary attempt resolves and
        // writes the copies.
        if !conflict_copies.is_empty() {
            return Ok(None);
        }
        if inputs[*winner].content.is_none() {
            return Ok(None);
        }
        match self.state.dag_zero_work_settlement_if_already_current(group_id, path)? {
            Some((exact_state, mutation_generation)) => Ok(Some(
                SettlementEvidence::from_exact_actual_state(exact_state, mutation_generation),
            )),
            None => Ok(None),
        }
    }

    /// This group's root-commit authority, for a mutation that needs one.
    ///
    /// Fails closed. A caller with no real per-link fence lookup is built with
    /// a deny-by-default provider, which reports no live link for every group
    /// and lands here — never a permissive fallback lease.
    pub fn root_lease_for(&self, group_id: &str) -> Result<Arc<RootLease>, PeerSessionError> {
        self.root_commit_authority_provider.root_lease_for(group_id).ok_or_else(|| {
            PeerSessionError::NotFound(format!(
                "no live root-commit authority for group {group_id} (no established link, \
                 or no provider injected)"
            ))
        })
    }
}
