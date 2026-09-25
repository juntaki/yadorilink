//! Owner operations of the structural-directory ledger
//! (`yadorilink_sync_sqlite::structural_origin`): which directories this
//! device created only to hold descendants, and which directories whose
//! entry is deleted it keeps on disk because they are not empty.
//!
//! A lane never calls the ledger's primitives itself. The `mkdir` helper
//! reaches the two-phase origin protocol through
//! `yadorilink_filesystem_sync::materialization_execution::
//! GroupStructuralLedger`, which calls the three port methods backed by
//! [`ReplicaCoordinator::record_structural_directory_intent`],
//! [`ReplicaCoordinator::complete_structural_directory_origin`] and
//! [`ReplicaCoordinator::abandon_structural_directory_intent`]; recovery,
//! adoption, rekeying and forgetting are the operations below.

use yadorilink_root_authority::fs_identity::{FileIdentity, TimestampGranularity};
use yadorilink_sync_sqlite::structural_origin::StructuralOriginCompletion;
use yadorilink_sync_sqlite::SyncSqliteError;

use super::super::ReplicaCoordinator;

/// How old an unresolved structural intent must be before the periodic
/// sweep resolves it. Between an intent and its completion the materializer
/// runs one `mkdir`, one `lstat` and one write transaction; five minutes
/// is far longer than that takes even behind a contended writer gate, so
/// an intent this old belongs to a writer that died between the two
/// phases (a crash, or a panic unwinding past the `mkdir`). Dropping a
/// live intent by mistake is safe in any case: its completion then finds
/// no pending intent, records the directory as of lost provenance, and it
/// is `OriginUnknown` -- kept, never authored.
pub(crate) const STALE_STRUCTURAL_INTENT_AGE: std::time::Duration =
    std::time::Duration::from_secs(5 * 60);

fn now_unix_nanos() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

impl ReplicaCoordinator {
    /// Phase 1 of a structural `mkdir`: the intent and the fence bump for
    /// `path`, committed before the syscall.
    pub(crate) fn record_structural_directory_intent(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<(), SyncSqliteError> {
        self.sqlite().dag_record_structural_intent(group_id, path, now_unix_nanos())?;
        Ok(())
    }

    /// Phase 2 of a structural `mkdir` that created the directory. A
    /// refusal (no pending intent, a moved fence, not a directory) is not
    /// an error: the directory is `OriginUnknown`, which keeps it and
    /// authors nothing.
    pub(crate) fn complete_structural_directory_origin(
        &self,
        group_id: &str,
        path: &str,
        identity: &FileIdentity,
    ) -> Result<(), SyncSqliteError> {
        let completion = self.sqlite().dag_complete_structural_origin(
            group_id,
            path,
            identity,
            now_unix_nanos(),
        )?;
        if completion != StructuralOriginCompletion::Recorded {
            tracing::info!(
                group_id,
                path,
                ?completion,
                "a structural directory this device created was not recorded as structural; \
                 it is kept and treated as of unknown origin"
            );
        }
        Ok(())
    }

    /// Phase 2 of a structural `mkdir` that did not create the directory.
    pub(crate) fn abandon_structural_directory_intent(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<(), SyncSqliteError> {
        self.sqlite().dag_abandon_structural_intent(group_id, path)?;
        Ok(())
    }

    /// Startup recovery: at startup no `mkdir` is in flight, so every
    /// structural intent is an interrupted one and is resolved (never
    /// completed). Must run before any link starts. See
    /// [`Self::resolve_unresolved_structural_intents`].
    pub(crate) fn drop_interrupted_structural_intents_at_startup(
        &self,
    ) -> Result<Vec<(String, String)>, SyncSqliteError> {
        self.resolve_unresolved_structural_intents(i64::MAX)
    }

    /// Periodic backstop: resolves the structural intents older than
    /// [`STALE_STRUCTURAL_INTENT_AGE`], for a writer that died between the
    /// two phases while the daemon kept running -- and retries every intent
    /// an earlier pass had to keep.
    pub(crate) fn drop_stale_structural_intents(
        &self,
    ) -> Result<Vec<(String, String)>, SyncSqliteError> {
        let cutoff = now_unix_nanos()
            .saturating_sub(STALE_STRUCTURAL_INTENT_AGE.as_nanos().min(i64::MAX as u128) as i64);
        self.resolve_unresolved_structural_intents(cutoff)
    }

    /// Drops each structural intent recorded before `cutoff` and, in the
    /// same transaction, records the directory now at its path -- which
    /// may be the one the interrupted `mkdir` created -- as of lost
    /// provenance, bound to its identity: capture then keeps it and
    /// authors nothing, rather than reading a directory with no record as
    /// one a user made. Returns the intents dropped.
    ///
    /// An intent is dropped with nothing recorded only when its root is
    /// there and nothing that could be the `mkdir`'s directory is at the
    /// path. One whose root cannot be looked at -- no live link for the
    /// group, a root not (yet) mounted, an observation that failed -- is
    /// kept: it still reads as a `mkdir` in flight, never as a user's
    /// directory, and the periodic sweep resolves it once the root is
    /// back.
    fn resolve_unresolved_structural_intents(
        &self,
        cutoff: i64,
    ) -> Result<Vec<(String, String)>, SyncSqliteError> {
        let intents = self.sqlite().dag_list_unresolved_structural_intents(cutoff)?;
        let resolutions: Vec<_> = intents
            .into_iter()
            .filter_map(|intent| {
                let found = self.directory_an_interrupted_mkdir_may_have_made(&intent)?;
                Some((intent, found))
            })
            .collect();
        self.sqlite()
            .dag_drop_structural_intents_recording_lost_provenance(&resolutions, now_unix_nanos())
    }

    /// What is at an interrupted structural intent's path: `Some(Some(_))`
    /// a directory (the one the `mkdir` may have made), `Some(None)`
    /// nothing that could be, `None` when that cannot be told now.
    fn directory_an_interrupted_mkdir_may_have_made(
        &self,
        intent: &yadorilink_sync_sqlite::structural_origin::UnresolvedStructuralIntent,
    ) -> Option<Option<FileIdentity>> {
        let (group_id, path) = (intent.group_id.as_str(), intent.path.as_str());
        let root = match self.link_repository().live_link_local_path_for_group(group_id) {
            Ok(Some(root)) => std::path::PathBuf::from(root),
            Ok(None) => return None,
            Err(error) => {
                tracing::warn!(group_id, path, %error, "could not find the root of an interrupted structural intent; kept");
                return None;
            }
        };
        if !std::fs::metadata(&root).is_ok_and(|meta| meta.is_dir()) {
            return None;
        }
        // A path reached through a symlinked component is not in this
        // folder: nothing of the `mkdir`'s can be there.
        let Ok(target) = yadorilink_local_storage::resolve_read_path_without_traversal(
            &root,
            std::path::Path::new(path),
        ) else {
            return Some(None);
        };
        match FileIdentity::observe_path(&target) {
            Ok(identity) => Some(
                (identity.object_kind
                    == yadorilink_root_authority::fs_identity::ObjectKind::Directory)
                    .then_some(identity),
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Some(None),
            Err(error) => {
                tracing::warn!(group_id, path, %error, "could not observe the path of an interrupted structural intent; kept");
                None
            }
        }
    }

    /// Records the directory now at `path` (observed as `identity`) as
    /// structural: its explicit entry was deleted while live descendants
    /// keep it on disk.
    pub(crate) fn adopt_as_structural_directory(
        &self,
        group_id: &str,
        path: &str,
        identity: &FileIdentity,
    ) -> Result<(), SyncSqliteError> {
        self.sqlite().dag_adopt_structural_directory(group_id, path, identity, now_unix_nanos())
    }

    /// Follows a structural directory a rename moved to `to_path`.
    pub(crate) fn follow_renamed_structural_directory(
        &self,
        group_id: &str,
        to_path: &str,
        identity: &FileIdentity,
        birth_time_granularity: TimestampGranularity,
    ) -> Result<Option<String>, SyncSqliteError> {
        self.sqlite().dag_rekey_structural_origin(
            group_id,
            to_path,
            identity,
            birth_time_granularity,
            now_unix_nanos(),
        )
    }

    /// Settles a directory removed from disk: nothing is structural or
    /// retained at `path` any more.
    pub(crate) fn forget_removed_directory(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<(), SyncSqliteError> {
        self.sqlite().dag_forget_structural_origin(group_id, path)?;
        self.sqlite().clear_retained_directory(group_id, path)?;
        Ok(())
    }

    /// Records that the directory at `path` stays on disk although its
    /// entry is settled as deleted, with `reason` for status. `removable`
    /// is the identity of the directory a delete aimed at, which goes once
    /// it is empty; `None` keeps whatever directory is there for good.
    pub(crate) fn keep_retained_directory(
        &self,
        group_id: &str,
        path: &str,
        reason: &str,
        removable: Option<&FileIdentity>,
    ) -> Result<(), SyncSqliteError> {
        self.sqlite().record_retained_directory(group_id, path, reason, removable, now_unix_nanos())
    }

    /// Whether `observed`, the directory now at `path`, is the very object
    /// this device materialized for the path's explicit Directory entry --
    /// the identity its `ExactObject{Directory}` settlement published. Only
    /// that directory is what a Directory tombstone deletes: a directory
    /// the user put in its place (or one whose identity this device never
    /// recorded) is not, however empty.
    pub(crate) fn is_materialized_directory_object(
        &self,
        group_id: &str,
        path: &str,
        sync_root: &std::path::Path,
        observed: &FileIdentity,
    ) -> Result<bool, SyncSqliteError> {
        use yadorilink_root_authority::fs_identity::IdentityComparison;
        Ok(self.sqlite().dag_materialized_directory_identity(group_id, path)?.is_some_and(
            |recorded| {
                recorded.compare(
                    observed,
                    super::super::peer_replica_state::cached_birth_time_granularity(sync_root),
                ) == IdentityComparison::SameObject
            },
        ))
    }

    /// Whether `observed`, the directory now at `path`, is the very one an
    /// earlier delete aimed at and retained -- and so may be removed once
    /// it is empty. A directory recorded as kept, or a different object at
    /// the same path (it inherits nothing), is not.
    pub(crate) fn is_removable_retained_directory(
        &self,
        group_id: &str,
        path: &str,
        sync_root: &std::path::Path,
        observed: &FileIdentity,
    ) -> Result<bool, SyncSqliteError> {
        use yadorilink_root_authority::fs_identity::IdentityComparison;
        use yadorilink_sync_sqlite::structural_origin::RetainedDirectory;
        Ok(match self.sqlite().retained_directory(group_id, path)? {
            RetainedDirectory::RemovableWhenEmpty(recorded) => {
                recorded.compare(
                    observed,
                    super::super::peer_replica_state::cached_birth_time_granularity(sync_root),
                ) == IdentityComparison::SameObject
            }
            RetainedDirectory::None | RetainedDirectory::Kept => false,
        })
    }

    /// Open half of removing a directory an earlier delete retained, now
    /// that it may have become empty: bump the path's fence (tx) before
    /// the `rmdir`. Returns the fence value the removal settles under.
    pub(crate) fn begin_retained_directory_removal(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<i64, yadorilink_peer_session::PeerSessionError> {
        self.begin_directory_removal(group_id, path, "retained_directory_rmdir")
    }

    /// Open half of any non-recursive `rmdir` the namespace decides (a
    /// retained directory now empty, a structural directory nothing needs
    /// any more, a replicated directory an entry supersedes): bump the
    /// path's fence (tx) before the syscall. Returns the fence value the
    /// removal settles under.
    pub(crate) fn begin_directory_removal(
        &self,
        group_id: &str,
        path: &str,
        why: &'static str,
    ) -> Result<i64, yadorilink_peer_session::PeerSessionError> {
        self.dag_bump_mutation_fence(group_id, path, why)
    }

    /// The fence value evidence about the directory standing at `path` is
    /// valid under, when nothing was mutated to get it there (or the
    /// structural `mkdir` already bumped it): a snapshot, never a bump.
    pub(crate) fn directory_settlement_generation(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<i64, yadorilink_peer_session::PeerSessionError> {
        self.dag_snapshot_mutation_fence(group_id, path)
    }

    /// Drops the retained record for `path`: it holds an entry again.
    pub(crate) fn release_retained_directory(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<bool, SyncSqliteError> {
        self.sqlite().clear_retained_directory(group_id, path)
    }

    /// Every entry this device keeps at its copy name because, on this
    /// volume, a directory holds a name that folds to its own.
    pub(crate) fn entries_held_beside_folded_directories(
        &self,
        group_id: &str,
    ) -> Result<Vec<String>, SyncSqliteError> {
        self.sqlite().retained_paths_with_reason(
            group_id,
            yadorilink_sync_sqlite::structural_origin::RETAINED_FOLDED_NAME,
        )
    }

    /// The reason a directory at `path` is retained, if it is.
    pub(crate) fn retained_directory_reason(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<String>, SyncSqliteError> {
        self.sqlite().retained_directory_reason(group_id, path)
    }

    /// Whether anything strictly below `path` holds a live content head.
    pub(crate) fn has_live_descendant(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<bool, SyncSqliteError> {
        self.sqlite().dag_has_live_descendant(group_id, path)
    }

    /// What the ledger says about the directory `observed` at `path` now:
    /// structural (this device made or adopted exactly this object for
    /// descendants), pending, or of unknown origin.
    pub(crate) fn structural_origin_status(
        &self,
        group_id: &str,
        path: &str,
        sync_root: &std::path::Path,
        observed: Option<&FileIdentity>,
    ) -> Result<yadorilink_sync_sqlite::structural_origin::StructuralOriginStatus, SyncSqliteError>
    {
        Ok(self.sqlite().dag_structural_directory_origin(group_id, path)?.status(
            observed,
            super::super::peer_replica_state::cached_birth_time_granularity(sync_root),
        ))
    }

    /// What the namespace requires at `path` on its own account (one
    /// transaction).
    pub(crate) fn desired_path_state(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<yadorilink_sync_sqlite::desired_state::DesiredPathState, SyncSqliteError> {
        self.sqlite().dag_desired_path_state(group_id, path)
    }

    /// One directory level of the desired namespace, relocated and
    /// conflict-copy entries included (one transaction).
    pub(crate) fn desired_level_projection(
        &self,
        group_id: &str,
        parent: &str,
    ) -> Result<yadorilink_replica_engine::namespace::NamespaceProjection, SyncSqliteError> {
        self.sqlite().dag_desired_level_projection(group_id, parent)
    }
}
