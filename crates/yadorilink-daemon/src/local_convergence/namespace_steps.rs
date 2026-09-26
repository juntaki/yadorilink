//! The namespace steps of a reconcile pass: what a path has to be once
//! the tree around it is taken into account, and the disk work that gets
//! it there.
//!
//! Replication is per path; a filesystem is a tree. `a` cannot be a file
//! while `a/x` lives, and a directory this device made only to hold `a/x`
//! goes when `a/x` goes. The namespace projection
//! (`yadorilink_replica_engine::namespace`) decides the tree; these steps
//! carry it out for the paths a pass touches and their ancestors:
//!
//! * a path a live descendant needs becomes a directory (structural, or the
//!   explicit Directory its own heads name), and a File or Symlink there
//!   moves beside it under its conflict-copy name -- written there first,
//!   removed from the path only once the copy holds it;
//! * a directory this device created only for descendants is removed with
//!   a single non-recursive `rmdir` once nothing needs it and it is empty;
//! * a file whose name is held by a directory this device may not remove
//!   -- one holding content it does not replicate, or one it did not make
//!   -- stays at its copy name, and the path settles as retained instead of
//!   retrying.
//!
//! None of it is authored. The relocation removes the path's index row
//! rather than tombstoning it, so capture finds neither a file to delete
//! nor a directory it did not know about; every step bumps the path's
//! mutation fence before it touches disk.

use std::path::Path;

use yadorilink_peer_session::peer_session::PendingLocalFlushOutcome;
use yadorilink_peer_session::PeerSessionError;
use yadorilink_replica_domain::file::RecordKind;
use yadorilink_replica_domain::ids::VersionHash;
use yadorilink_replica_domain::session_state::MaterializationPolicy;
use yadorilink_replica_engine::conflict::PathHead;
use yadorilink_replica_engine::namespace::{PhysicalNode, Placement};
use yadorilink_sync_sqlite::desired_state::DesiredPathState;
use yadorilink_sync_sqlite::structural_origin::{
    StructuralOriginStatus, RETAINED_UNTRACKED_CONTENT,
};

use super::types::{MaterializeResult, SettlementEvidence};

fn sqlite_error(error: yadorilink_sync_sqlite::SyncSqliteError) -> PeerSessionError {
    PeerSessionError::from(crate::sync_error::SyncError::from(error))
}

/// Every proper ancestor of `path`, nearest first.
pub(crate) fn proper_ancestors(path: &str) -> impl Iterator<Item = &str> {
    std::iter::successors(path.rsplit_once('/').map(|(parent, _)| parent), |p| {
        p.rsplit_once('/').map(|(parent, _)| parent)
    })
}

/// `path`'s parent, `""` for a path at the root.
pub(crate) fn parent_of(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(parent, _)| parent)
}

/// What a directory standing where an entry has to go turned out to be.
pub(crate) enum DirectoryInTheWay {
    /// Nothing is in the way (or it was removed): write the entry.
    Clear,
    /// The directory stays, so the entry cannot take its name. The path is
    /// settled as retained and the entry is kept at its copy name.
    Held(MaterializeResult),
}

impl super::LocalConvergenceExecutor {
    /// What the namespace requires at `path` on its own account.
    pub(crate) fn desired_own_state(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<DesiredPathState, PeerSessionError> {
        self.state.desired_path_state(group_id, path).map_err(sqlite_error)
    }

    /// The kind of the version a head names, when this replica holds it.
    pub(crate) fn head_kind(
        &self,
        group_id: &str,
        head: &PathHead,
    ) -> Result<Option<RecordKind>, PeerSessionError> {
        let Some(content) = head.content.as_ref() else { return Ok(None) };
        Ok(self
            .state
            .dag_get_file_version(group_id, &VersionHash(content.version_hash))?
            .map(|version| version.meta.record_kind))
    }

    /// Whether the namespace needs a directory at `path`: structural, or
    /// the explicit Directory its heads name. `false` when that cannot be
    /// decided here yet.
    pub(crate) fn namespace_needs_directory(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<bool, PeerSessionError> {
        match self.state.desired_path_state(group_id, path) {
            Ok(desired) => Ok(matches!(
                desired,
                DesiredPathState::StructuralDirectory | DesiredPathState::ExplicitDirectory { .. }
            )),
            Err(yadorilink_sync_sqlite::SyncSqliteError::NotFound(_)) => Ok(false),
            Err(e) => Err(sqlite_error(e)),
        }
    }

    /// The proper ancestors of `path` whose own live heads name a File or
    /// Symlink: the ones a pass over `path` also has to decide, because
    /// `path` living below them displaces that leaf, and `path` going can
    /// bring it back.
    pub(crate) fn ancestors_holding_leaves(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Vec<String>, PeerSessionError> {
        let mut out = Vec::new();
        for ancestor in proper_ancestors(path) {
            for head in self.store_live_heads_for_path(group_id, ancestor)? {
                if matches!(
                    self.head_kind(group_id, &head)?,
                    Some(RecordKind::File | RecordKind::Symlink)
                ) {
                    out.push(ancestor.to_string());
                    break;
                }
            }
        }
        Ok(out)
    }

    /// Where the namespace relocates `path`'s own File or Symlink winner,
    /// when `path` has to be a directory: `(copy name, version)`. Empty when
    /// nothing is relocated. The name is read from the projection of
    /// `path`'s own directory level, so a name another entry already holds
    /// is disambiguated exactly as every other device disambiguates it.
    /// `None` when the level cannot be decided here yet: a live version at
    /// it is not held locally.
    #[allow(clippy::type_complexity)]
    pub(crate) fn relocated_copies_of(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<Vec<(String, [u8; 32])>>, PeerSessionError> {
        let level = match self.state.desired_level_projection(group_id, parent_of(path)) {
            Ok(level) => level,
            Err(yadorilink_sync_sqlite::SyncSqliteError::NotFound(_)) => return Ok(None),
            Err(e) => return Err(sqlite_error(e)),
        };
        Ok(Some(
            level
                .nodes()
                .iter()
                .filter_map(|(name, node)| match node {
                    PhysicalNode::Entry(entry)
                        if entry.placement == Placement::Relocated && entry.source == path =>
                    {
                        Some((name.clone(), entry.version_hash))
                    }
                    _ => None,
                })
                .collect(),
        ))
    }

    /// Makes `path` the directory its live descendants need, when it has no
    /// explicit entry of its own: keeps a directory already there, creates
    /// one (recorded as structural) when nothing is, and moves a File or
    /// Symlink out of the way -- only once `leaf_is_placed_elsewhere` says
    /// its content already stands at its copy name.
    pub(crate) async fn settle_structural_container(
        &self,
        group_id: &str,
        path: &str,
        leaf_is_placed_elsewhere: bool,
    ) -> Result<MaterializeResult, PeerSessionError> {
        if !self.displace_leaf_for_directory(group_id, path, leaf_is_placed_elsewhere).await? {
            return Ok(MaterializeResult::RetryRequired);
        }
        let path_lock = self.state.path_lock(group_id, path);
        let _guard = path_lock.lock().await;
        let out_path = self.local_file_path(group_id, path)?;
        match std::fs::symlink_metadata(&out_path) {
            Ok(meta) if meta.is_dir() => {}
            Ok(_) => return Ok(MaterializeResult::RetryRequired),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                self.create_structural_directory_at(group_id, &out_path)?;
                #[cfg(test)]
                displacement_crash::stop_at(
                    &out_path,
                    displacement_crash::Stage::AfterStructuralMkdir,
                )?;
            }
            Err(e) => return Err(PeerSessionError::from(e)),
        }
        let identity =
            yadorilink_root_authority::fs_identity::FileIdentity::observe_path(&out_path)
                .ok()
                .filter(|identity| {
                    identity.object_kind
                        == yadorilink_root_authority::fs_identity::ObjectKind::Directory
                });
        let Some(identity) = identity else {
            return Ok(MaterializeResult::RetryRequired);
        };
        self.retire_superseded_directory_entry(group_id, path, &out_path, &identity)?;
        let mutation_generation = self.state.directory_settlement_generation(group_id, path)?;
        Ok(MaterializeResult::Settled(SettlementEvidence::StructuralDirectory {
            identity: Box::new(Some(identity)),
            mutation_generation,
        }))
    }

    /// The explicit Directory entry a directory kept only for descendants
    /// used to be: its index row still claims the path, which a structural
    /// directory's proof can never be published over. The row is removed
    /// -- the entry is superseded, not deleted by this device -- and the
    /// directory, when it is the very object this device materialized for
    /// that entry, is adopted as structural, so it goes with the last
    /// descendant. A directory the user put there instead stays theirs.
    ///
    /// The caller holds `path`'s lock.
    fn retire_superseded_directory_entry(
        &self,
        group_id: &str,
        path: &str,
        out_path: &Path,
        identity: &yadorilink_root_authority::fs_identity::FileIdentity,
    ) -> Result<(), PeerSessionError> {
        let live_directory_row =
            self.state.get_file(group_id, path)?.is_some_and(|row| !row.deleted)
                && self.state.get_record_kind(group_id, path)? == Some(RecordKind::Directory);
        if !live_directory_row {
            return Ok(());
        }
        if self.is_materialized_directory_at(group_id, path, out_path)? {
            self.state
                .adopt_as_structural_directory(group_id, path, identity)
                .map_err(sqlite_error)?;
        }
        #[cfg(test)]
        displacement_crash::stop_at(out_path, displacement_crash::Stage::BeforeEntryRetired)?;
        let authority = self.root_lease_for(group_id)?;
        let authority_op = authority.begin_operation()?;
        let permit = authority_op.permit();
        let (intent, _mutation_generation) =
            self.state.open_tombstone_delete(group_id, path, &permit)?;
        self.state.settle_retired_copy_erase(intent, group_id, path, &permit)?;
        tracing::debug!(
            group_id,
            path,
            "a superseded directory entry stays on disk only for its live descendants"
        );
        Ok(())
    }

    /// Clears a File or Symlink out of `path`, which has to become a
    /// directory. `true` when nothing but a directory (or nothing at all)
    /// is left there.
    ///
    /// The leaf goes only when `leaf_is_placed_elsewhere` (its content
    /// stands at its copy name), when disk still holds exactly what its
    /// index row says (an edit nobody captured is captured first, and the
    /// path retried), and under the path lock with the fence bumped and a
    /// delete intent open. Its index row is removed, not tombstoned: the
    /// entry is not deleted, it lives on at its copy name, and a row that
    /// claimed it at `path` would read to capture as a file gone missing.
    pub(crate) async fn displace_leaf_for_directory(
        &self,
        group_id: &str,
        path: &str,
        leaf_is_placed_elsewhere: bool,
    ) -> Result<bool, PeerSessionError> {
        let out_path = self.local_file_path(group_id, path)?;
        let leaf_on_disk = std::fs::symlink_metadata(&out_path).is_ok_and(|meta| !meta.is_dir());
        let row_claims_leaf = self.state.get_file(group_id, path)?.is_some_and(|row| !row.deleted)
            && self.state.get_record_kind(group_id, path)? != Some(RecordKind::Directory);
        if !leaf_on_disk && !row_claims_leaf {
            return Ok(true);
        }
        if leaf_on_disk && !row_claims_leaf {
            // Nothing this device replicates is there: content it has not
            // captured, which it never removes.
            return Ok(false);
        }
        if !leaf_is_placed_elsewhere {
            return Ok(false);
        }
        if self.flush_local_changes_before_reconcile(group_id, path).await
            == PendingLocalFlushOutcome::RetryRequired
        {
            return Ok(false);
        }
        let path_lock = self.state.path_lock(group_id, path);
        let _guard = path_lock.lock().await;
        if leaf_on_disk {
            if self.disk_holds_uncaptured_local_bytes(group_id, path, &out_path, None)? {
                tracing::info!(
                    group_id,
                    path,
                    "not moving a file out of a name its live descendants need: it holds an \
                     edit this device has not captured yet"
                );
                return Ok(false);
            }
            self.verify_delete_target(group_id, &out_path)?;
        }
        let authority = self.root_lease_for(group_id)?;
        let authority_op = authority.begin_operation()?;
        let permit = authority_op.permit();
        let (intent, _mutation_generation) =
            self.state.open_tombstone_delete(group_id, path, &permit)?;
        #[cfg(test)]
        displacement_crash::stop_at(&out_path, displacement_crash::Stage::BeforeUnlink)?;
        match std::fs::symlink_metadata(&out_path) {
            Ok(meta) if !meta.is_dir() => match std::fs::remove_file(&out_path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(PeerSessionError::from(e)),
            },
            _ => {}
        }
        #[cfg(test)]
        displacement_crash::stop_at(&out_path, displacement_crash::Stage::BeforeRowErase)?;
        self.state.settle_retired_copy_erase(intent, group_id, path, &permit)?;
        tracing::debug!(
            group_id,
            path,
            "moved a file out of a name its live descendants need; it lives on at its copy name"
        );
        Ok(true)
    }

    /// A directory standing at `path`, where the namespace places an entry
    /// (`winner`). Removed when this device made it only for descendants,
    /// or a delete aimed at it, and it is empty now; otherwise it is kept,
    /// with everything in it, and the entry is kept at its copy name
    /// instead -- written there if it is not there already -- with `path`
    /// settled as retained. Never retried: what is on disk decides at once.
    pub(crate) async fn clear_directory_for_entry(
        &self,
        group_id: &str,
        path: &str,
        demand_path: &str,
        winner: &PathHead,
        policy: MaterializationPolicy,
    ) -> Result<DirectoryInTheWay, PeerSessionError> {
        let out_path = self.local_file_path(group_id, path)?;
        if !std::fs::symlink_metadata(&out_path).is_ok_and(|meta| meta.is_dir()) {
            return Ok(DirectoryInTheWay::Clear);
        }
        let reason = {
            let path_lock = self.state.path_lock(group_id, path);
            let _guard = path_lock.lock().await;
            if self.prune_directory_made_for_descendants(group_id, path)?.is_some() {
                return Ok(DirectoryInTheWay::Clear);
            }
            // The replicated directory the new entry supersedes: removed
            // like a Directory tombstone's target, when it is empty.
            // Only the very object this device materialized for it: a
            // directory the user put there in its place is theirs.
            let replicated_directory =
                self.state.get_file(group_id, path)?.is_some_and(|row| !row.deleted)
                    && self.state.get_record_kind(group_id, path)? == Some(RecordKind::Directory)
                    && self.is_materialized_directory_at(group_id, path, &out_path)?;
            if replicated_directory && self.remove_superseded_directory(group_id, path)? {
                return Ok(DirectoryInTheWay::Clear);
            }
            if self.holds_tracked_content(group_id, path, &out_path)? {
                // Replicated entries below still wait for their deletes,
                // in a pass of their own: not content this device keeps,
                // and the pass that removes the last of them brings this
                // path back.
                return Ok(DirectoryInTheWay::Held(MaterializeResult::RetryRequired));
            }
            let observed =
                yadorilink_root_authority::fs_identity::FileIdentity::observe_path(&out_path).ok();
            let structural = self.origin_status(group_id, path, observed.as_ref())?
                == StructuralOriginStatus::Structural;
            let reason = RETAINED_UNTRACKED_CONTENT;
            // This device made it, adopted it, or held it as a replicated
            // directory: once it is empty, it may go. Anything else is kept
            // for good.
            let removable = if structural || replicated_directory { observed } else { None };
            self.state
                .keep_retained_directory(group_id, path, reason, removable.as_ref())
                .map_err(sqlite_error)?;
            reason
        };
        tracing::info!(
            group_id,
            path,
            "a directory this device may not remove holds the name an entry needs; the entry \
             stays at its copy name"
        );
        let copy = yadorilink_replica_engine::namespace::first_copy_name(path, winner);
        let placed = match self
            .materialize_dag_content_head(
                group_id,
                &copy,
                demand_path,
                winner,
                policy,
                Some(winner),
                None,
            )
            .await?
        {
            MaterializeResult::Settled(_) => true,
            MaterializeResult::RetryRequired => false,
        };
        Ok(DirectoryInTheWay::Held(if placed {
            MaterializeResult::Settled(SettlementEvidence::Retained { reason: reason.to_string() })
        } else {
            MaterializeResult::RetryRequired
        }))
    }

    /// Whether anything under the directory at `path` (`out_path`) is an
    /// entry this device's index tracks as live. Only directories this
    /// device made for descendants are searched below: a tracked entry sits
    /// under tracked or structural directories all the way down.
    fn holds_tracked_content(
        &self,
        group_id: &str,
        path: &str,
        out_path: &Path,
    ) -> Result<bool, PeerSessionError> {
        let mut pending = vec![(path.to_string(), out_path.to_path_buf())];
        while let Some((rel, dir)) = pending.pop() {
            for entry in std::fs::read_dir(&dir)? {
                let entry = entry?;
                let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                    continue;
                };
                let child = format!("{rel}/{name}");
                if self.state.get_file(group_id, &child)?.is_some_and(|row| !row.deleted) {
                    return Ok(true);
                }
                if !entry.file_type()?.is_dir() {
                    continue;
                }
                let observed = yadorilink_root_authority::fs_identity::FileIdentity::observe_path(
                    &entry.path(),
                )
                .ok();
                if self.origin_status(group_id, &child, observed.as_ref())?
                    == StructuralOriginStatus::Structural
                {
                    pending.push((child, entry.path()));
                }
            }
        }
        Ok(false)
    }

    /// Removes the directory at `path` if this device created (or adopted)
    /// exactly that object only to hold descendants, the namespace needs
    /// nothing there any more, and it is empty: one non-recursive `rmdir`,
    /// after a fence bump. `ExactAbsent` when it went; `None` when it stays
    /// (not structural, still needed, not empty, or not a directory).
    ///
    /// The caller holds `path`'s lock. The identity check and the `rmdir`
    /// are two steps, and the `rmdir` goes by name: the same window
    /// `LocalConvergenceExecutor::remove_directory_if_empty` documents, where
    /// only an empty directory swapped in at this name between the two, by
    /// a process that does not take this daemon's path lock, can be removed
    /// in its place. That helper is not reused here because it records a
    /// directory it finds not empty as retained, bound to its identity for
    /// a later removal; a structural directory that still holds something
    /// is simply left as it is.
    pub(crate) fn prune_directory_made_for_descendants(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<SettlementEvidence>, PeerSessionError> {
        use yadorilink_local_storage::EmptyDirectoryRemoval;
        let out_path = self.local_file_path(group_id, path)?;
        let Ok(observed) =
            yadorilink_root_authority::fs_identity::FileIdentity::observe_path(&out_path)
        else {
            self.forget_structural_record_of_a_removed_directory(group_id, path, &out_path)?;
            return Ok(None);
        };
        if self.origin_status(group_id, path, Some(&observed))?
            != StructuralOriginStatus::Structural
        {
            return Ok(None);
        }
        if matches!(
            self.desired_own_state(group_id, path)?,
            DesiredPathState::StructuralDirectory | DesiredPathState::ExplicitDirectory { .. }
        ) {
            return Ok(None);
        }
        self.verify_delete_target(group_id, &out_path)?;
        let mutation_generation =
            self.state.begin_directory_removal(group_id, path, "structural_directory_rmdir")?;
        Ok(match yadorilink_local_storage::remove_empty_dir(&out_path)? {
            EmptyDirectoryRemoval::Removed | EmptyDirectoryRemoval::Absent => {
                #[cfg(test)]
                displacement_crash::stop_at(
                    &out_path,
                    displacement_crash::Stage::AfterStructuralRmdir,
                )?;
                self.state.forget_removed_directory(group_id, path).map_err(sqlite_error)?;
                tracing::debug!(
                    group_id,
                    path,
                    "removed a directory this device created only for descendants that are gone"
                );
                Some(SettlementEvidence::ExactAbsent { mutation_generation })
            }
            EmptyDirectoryRemoval::NotEmpty | EmptyDirectoryRemoval::NotADirectory => None,
        })
    }

    /// Nothing is at `path` (`out_path`), yet a structural directory is
    /// recorded there: one this device removed, stopped (a crash, an error)
    /// before it forgot the record. The record names nothing any more and
    /// nothing else would ever look at it, so it is forgotten now. A pending
    /// `mkdir` intent is not a record of a removed directory, and stays.
    ///
    /// The caller holds `path`'s lock.
    fn forget_structural_record_of_a_removed_directory(
        &self,
        group_id: &str,
        path: &str,
        out_path: &Path,
    ) -> Result<(), PeerSessionError> {
        use yadorilink_sync_sqlite::structural_origin::StructuralDirectoryOrigin;
        if !matches!(
            std::fs::symlink_metadata(out_path),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound
        ) {
            return Ok(());
        }
        let recorded = self
            .state
            .sqlite()
            .dag_structural_directory_origin(group_id, path)
            .map_err(sqlite_error)?;
        if matches!(recorded, StructuralDirectoryOrigin::Recorded(_)) {
            self.state.forget_removed_directory(group_id, path).map_err(sqlite_error)?;
        }
        Ok(())
    }

    /// One non-recursive `rmdir` of the replicated directory at `path`,
    /// after a fence bump, for an entry that supersedes it. `true` when it
    /// is gone. The caller holds `path`'s lock. Between the identity check
    /// and the `rmdir` by name lies the window `remove_directory_if_empty`
    /// documents; only an empty directory can be affected.
    fn remove_superseded_directory(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<bool, PeerSessionError> {
        use yadorilink_local_storage::EmptyDirectoryRemoval;
        let out_path = self.local_file_path(group_id, path)?;
        self.verify_delete_target(group_id, &out_path)?;
        self.state.begin_directory_removal(group_id, path, "superseded_directory_rmdir")?;
        Ok(match yadorilink_local_storage::remove_empty_dir(&out_path)? {
            EmptyDirectoryRemoval::Removed | EmptyDirectoryRemoval::Absent => {
                #[cfg(test)]
                displacement_crash::stop_at(
                    &out_path,
                    displacement_crash::Stage::AfterSupersededRmdir,
                )?;
                self.state.forget_removed_directory(group_id, path).map_err(sqlite_error)?;
                true
            }
            EmptyDirectoryRemoval::NotEmpty | EmptyDirectoryRemoval::NotADirectory => false,
        })
    }

    fn origin_status(
        &self,
        group_id: &str,
        path: &str,
        observed: Option<&yadorilink_root_authority::fs_identity::FileIdentity>,
    ) -> Result<StructuralOriginStatus, PeerSessionError> {
        self.state
            .structural_origin_status(group_id, path, &self.sync_root(group_id)?, observed)
            .map_err(sqlite_error)
    }

    /// Creates the directory at `out_path` itself (and any missing
    /// ancestor) through the recording `mkdir` helper, so each one is
    /// bound to its identity as structural.
    fn create_structural_directory_at(
        &self,
        group_id: &str,
        out_path: &Path,
    ) -> Result<(), PeerSessionError> {
        let raw_root = self.sync_root(group_id)?;
        self.state.verify_root(&raw_root, group_id)?;
        let canonical_root = self.canonical_sync_root(group_id, &raw_root).ok_or_else(|| {
            PeerSessionError::PathEscapesRoot(format!(
                "the root of group {group_id} cannot be resolved; not creating {}",
                out_path.display()
            ))
        })?;
        Ok(yadorilink_local_storage::create_dir_all_never_through_a_symlink(
            out_path,
            &canonical_root,
            out_path,
            &self.structural_ledger(group_id),
        )?)
    }

    /// The order a pass visits its paths in, and where its second phase
    /// starts. First every path that resolves to nothing (a removal),
    /// deepest first: a directory's tracked contents are gone before
    /// anything is decided about the directory. Then the rest, shallowest
    /// first: a directory is in place before anything is written into it.
    /// At one depth, a derived copy comes before a path that has to be a
    /// directory, so a relocated file is at its copy name before the name
    /// it leaves is turned into a directory.
    #[allow(clippy::type_complexity)]
    pub(crate) fn namespace_order(
        &self,
        group_id: &str,
        paths: &std::collections::BTreeSet<String>,
        derived: &std::collections::BTreeMap<String, PathHead>,
        desired_of: &std::collections::BTreeMap<String, Option<DesiredPathState>>,
    ) -> Result<(Vec<String>, usize), PeerSessionError> {
        let depth = |path: &str| path.bytes().filter(|b| *b == b'/').count();
        let mut removals: Vec<&String> = Vec::new();
        let mut rest: Vec<(usize, u8, &String)> = Vec::new();
        for path in paths {
            let heads = self.combined_heads(group_id, path, derived.get(path))?;
            let removal = !self.is_locally_ignored(group_id, path)
                && matches!(
                    yadorilink_replica_engine::conflict::resolve_path_heads(path, &heads),
                    yadorilink_replica_engine::conflict::PathResolution::Absent
                );
            if removal {
                removals.push(path);
                continue;
            }
            let rank = if derived.contains_key(path) {
                0
            } else if matches!(
                desired_of.get(path),
                Some(Some(
                    DesiredPathState::StructuralDirectory
                        | DesiredPathState::ExplicitDirectory { .. }
                ))
            ) {
                1
            } else {
                2
            };
            rest.push((depth(path), rank, path));
        }
        removals.sort_by(|a, b| depth(b).cmp(&depth(a)).then_with(|| b.cmp(a)));
        rest.sort();
        let phase_two_start = removals.len();
        let order = removals
            .into_iter()
            .cloned()
            .chain(rest.into_iter().map(|(_, _, path)| path.clone()))
            .collect();
        Ok((order, phase_two_start))
    }

    /// What `path` needs before its own winner can be written, given the
    /// namespace: `None` to go on and write the winner as ever; `Some` when
    /// the namespace decided the path here.
    ///
    /// * A structural directory: the leaf on disk moves out once its
    ///   content stands at its copy name (written earlier in this pass;
    ///   see [`Self::leaf_is_held_at_its_copy`]), and the path settles as
    ///   the directory its descendants need.
    /// * An explicit directory: the same for a leaf on disk, then the
    ///   Directory version is written -- not the per-path winner, which may
    ///   be a File the directory displaces.
    /// * An entry: a directory standing at its name is removed if this
    ///   device made it for descendants that are gone, or kept, with the
    ///   entry held at its copy name. On a volume that folds names, the
    ///   same holds for a directory spelled differently (`folded_leaf`: a
    ///   descendant in this pass needs one).
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn namespace_step(
        &self,
        group_id: &str,
        path: &str,
        demand_path: &str,
        inputs: &[PathHead],
        winner: usize,
        desired: Option<DesiredPathState>,
        derived: &std::collections::BTreeMap<String, PathHead>,
        settled: &std::collections::BTreeMap<String, SettlementEvidence>,
        folded_leaf: bool,
        policy: MaterializationPolicy,
        satisfied: Option<&super::types::BlockRequirement>,
    ) -> Result<Option<MaterializeResult>, PeerSessionError> {
        let placed = || self.leaf_is_held_at_its_copy(group_id, path, inputs, derived, settled);
        match desired {
            Some(DesiredPathState::StructuralDirectory) => {
                Ok(Some(self.settle_structural_container(group_id, path, placed()?).await?))
            }
            Some(DesiredPathState::ExplicitDirectory { version }) => {
                let winner_is_directory = inputs[winner]
                    .content
                    .as_ref()
                    .is_some_and(|content| content.version_hash == version.0);
                // A leaf on disk under the directory's name is a File
                // head the directory displaces (gone once its copy is
                // written) or a version the directory superseded.
                if !self.displace_leaf_for_directory(group_id, path, placed()?).await? {
                    return Ok(Some(MaterializeResult::RetryRequired));
                }
                if winner_is_directory {
                    return Ok(None);
                }
                let Some(directory) = inputs.iter().find(|head| {
                    head.content.as_ref().is_some_and(|content| content.version_hash == version.0)
                }) else {
                    return Ok(Some(MaterializeResult::RetryRequired));
                };
                Ok(Some(
                    self.materialize_dag_content_head(
                        group_id,
                        path,
                        demand_path,
                        directory,
                        policy,
                        None,
                        satisfied,
                    )
                    .await?,
                ))
            }
            Some(DesiredPathState::Entry { .. }) => {
                if folded_leaf || self.folded_directory_holds_name(group_id, path)? {
                    return Ok(Some(
                        self.hold_entry_beside_folded_directory(
                            group_id,
                            path,
                            demand_path,
                            inputs,
                            winner,
                            derived,
                            settled,
                            policy,
                        )
                        .await?,
                    ));
                }
                match self
                    .clear_directory_for_entry(group_id, path, demand_path, &inputs[winner], policy)
                    .await?
                {
                    DirectoryInTheWay::Clear => Ok(None),
                    DirectoryInTheWay::Held(result) => Ok(Some(result)),
                }
            }
            Some(DesiredPathState::Absent) | None => Ok(None),
        }
    }

    /// Whether the File or Symlink this device holds at `path` -- the head
    /// its index row was written from -- also stands at a copy name, with
    /// its content on disk there, written earlier in this pass. Only then
    /// may it leave `path` for a directory. A copy that settled without
    /// its bytes (a name this device ignores, a hazard, a placeholder
    /// deferred) holds nothing. A row naming no live head holds a version
    /// every live head superseded, which is owed no copy.
    pub(crate) fn leaf_is_held_at_its_copy(
        &self,
        group_id: &str,
        path: &str,
        inputs: &[PathHead],
        derived: &std::collections::BTreeMap<String, PathHead>,
        settled: &std::collections::BTreeMap<String, SettlementEvidence>,
    ) -> Result<bool, PeerSessionError> {
        use yadorilink_replica_domain::conflict::{
            conflict_copy_source_path, is_conflict_copy_path,
        };
        let Some(authoring) = self.state.get_authoring_change_hash(group_id, path)? else {
            return Ok(false);
        };
        if !inputs.iter().any(|head| head.change_hash == authoring.0) {
            return Ok(true);
        }
        let mut copies = derived
            .iter()
            .filter(|(copy, head)| {
                head.change_hash == authoring.0
                    && is_conflict_copy_path(copy)
                    && conflict_copy_source_path(copy) == path
            })
            .peekable();
        if copies.peek().is_none() {
            return Ok(false);
        }
        Ok(copies.all(|(copy, _)| settled.get(copy).is_some_and(content_on_disk)))
    }

    /// The index of the head the namespace places at `path` among `heads`
    /// (`None` when the path resolves to nothing). The per-path winner,
    /// except that a live Directory head wins the path whatever else is
    /// there: the best-ranked Directory head then names the directory, and
    /// a File or Symlink that outranks it is relocated beside it. A derived
    /// copy name holds exactly the head it was derived for.
    pub(crate) fn namespace_winner(
        &self,
        group_id: &str,
        path: &str,
        heads: &[PathHead],
        derived: bool,
    ) -> Result<Option<usize>, PeerSessionError> {
        use yadorilink_replica_engine::conflict::{
            dag_conflict_loser_is_a, resolve_path_heads, PathResolution,
        };
        let PathResolution::Present { winner, .. } = resolve_path_heads(path, heads) else {
            return Ok(None);
        };
        if derived || heads.len() < 2 {
            return Ok(Some(winner));
        }
        let mut best: Option<usize> = None;
        for (index, head) in heads.iter().enumerate() {
            if self.head_kind(group_id, head)? != Some(RecordKind::Directory) {
                continue;
            }
            if best.is_none_or(|b| {
                dag_conflict_loser_is_a(
                    heads[b].lamport,
                    &heads[b].change_hash,
                    head.lamport,
                    &head.change_hash,
                )
            }) {
                best = Some(index);
            }
        }
        Ok(Some(best.unwrap_or(winner)))
    }

    /// Whether the namespace keeps content at `copy`, a conflict-copy name
    /// of `base`: the projection places an entry of `base` there (a
    /// relocated winner, or a conflict copy under a disambiguated name), or
    /// `base`'s own winner is held there because a directory this device
    /// may not remove stands at `base`. A retained record at `base` found
    /// stale -- the winner stands at `base` itself again -- is dropped.
    pub(crate) fn copy_justified_by_namespace(
        &self,
        group_id: &str,
        base: &str,
        copy: &str,
    ) -> Result<bool, PeerSessionError> {
        let level = match self.state.desired_level_projection(group_id, parent_of(copy)) {
            Ok(level) => level,
            // Undecidable here: never evidence that the copy may go.
            Err(_) => return Ok(true),
        };
        if matches!(level.get(copy), Some(PhysicalNode::Entry(entry)) if entry.source == base) {
            return Ok(true);
        }
        if self.state.retained_directory_reason(group_id, base).map_err(sqlite_error)?.is_none() {
            return Ok(false);
        }
        let heads = self.combined_heads(group_id, base, None)?;
        let Some(winner) = self.namespace_winner(group_id, base, &heads, false)? else {
            return Ok(false);
        };
        if !matches!(
            self.head_kind(group_id, &heads[winner])?,
            Some(RecordKind::File | RecordKind::Symlink)
        ) {
            return Ok(false);
        }
        if self.winner_stands_at_its_name(group_id, base, &heads[winner])? {
            // Whatever held the name is gone and the entry is back at it:
            // the record is stale, and the copy a duplicate.
            self.state.release_retained_directory(group_id, base).map_err(sqlite_error)?;
            return Ok(false);
        }
        Ok(self.state.get_authoring_change_hash(group_id, copy)?.map(|hash| hash.0)
            == Some(heads[winner].change_hash))
    }

    /// Whether `path` itself holds `winner` on disk: a File or Symlink
    /// there, not a directory under a name that folds to it, and its index
    /// row written from exactly that head.
    fn winner_stands_at_its_name(
        &self,
        group_id: &str,
        path: &str,
        winner: &PathHead,
    ) -> Result<bool, PeerSessionError> {
        let out_path = self.local_file_path(group_id, path)?;
        if !std::fs::symlink_metadata(&out_path).is_ok_and(|meta| !meta.is_dir()) {
            return Ok(false);
        }
        if self.exact_name_folded_elsewhere(&out_path)?.is_some() {
            return Ok(false);
        }
        Ok(self.state.get_file(group_id, path)?.is_some_and(|row| !row.deleted)
            && self.state.get_authoring_change_hash(group_id, path)?.map(|hash| hash.0)
                == Some(winner.change_hash))
    }

    /// The tracked File or Symlink standing in the way of directory
    /// `path` on a volume that folds names: `path` does not exist under its
    /// own exact name, yet looking it up finds a non-directory -- a sibling
    /// whose name folds to the same one (`A` for `a`). Returns that
    /// sibling's path when this device tracks it.
    pub(crate) fn folded_leaf_in_the_way(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<Option<String>, PeerSessionError> {
        let out_path = self.local_file_path(group_id, path)?;
        if !std::fs::symlink_metadata(&out_path).is_ok_and(|meta| !meta.is_dir()) {
            return Ok(None);
        }
        let Some(folded) = self.exact_name_folded_elsewhere(&out_path)? else {
            return Ok(None);
        };
        let parent = parent_of(path);
        let sibling = if parent.is_empty() { folded } else { format!("{parent}/{folded}") };
        Ok(self
            .state
            .get_file(group_id, &sibling)?
            .is_some_and(|row| !row.deleted)
            .then_some(sibling))
    }

    /// Whether a directory (not a symlink to one) stands at `path` on disk.
    pub(crate) fn directory_on_disk(&self, group_id: &str, path: &str) -> bool {
        self.local_file_path(group_id, path)
            .is_ok_and(|out| std::fs::symlink_metadata(out).is_ok_and(|meta| meta.is_dir()))
    }

    /// Whether a directory holds `path`'s name on this volume under another
    /// exact spelling (`a/` for `A`): the entry cannot take its name here.
    pub(crate) fn folded_directory_holds_name(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<bool, PeerSessionError> {
        let out_path = self.local_file_path(group_id, path)?;
        if !std::fs::symlink_metadata(&out_path).is_ok_and(|meta| meta.is_dir()) {
            return Ok(false);
        }
        Ok(self.exact_name_folded_elsewhere(&out_path)?.is_some())
    }

    /// When `out_path` answers a lookup but no entry of its parent has its
    /// exact name, the name of the entry that answered (the one the volume
    /// folds it to). `None` when the exact name exists, or nothing answers.
    fn exact_name_folded_elsewhere(
        &self,
        out_path: &Path,
    ) -> Result<Option<String>, PeerSessionError> {
        let (Some(parent), Some(name)) = (out_path.parent(), out_path.file_name()) else {
            return Ok(None);
        };
        let Ok(target) = std::fs::symlink_metadata(out_path) else { return Ok(None) };
        Ok(entry_answering_under_another_name(parent, name, &target)?)
    }

    /// Keeps `path`'s winner at its copy name because, on this volume, a
    /// directory the tree needs holds a name that folds to `path`'s own.
    /// The projection is fold-free and every device computes the same one;
    /// this is this device's own arrangement of it, never authored.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn hold_entry_beside_folded_directory(
        &self,
        group_id: &str,
        path: &str,
        demand_path: &str,
        inputs: &[PathHead],
        winner: usize,
        derived: &std::collections::BTreeMap<String, PathHead>,
        settled: &std::collections::BTreeMap<String, SettlementEvidence>,
        policy: MaterializationPolicy,
    ) -> Result<MaterializeResult, PeerSessionError> {
        let winner = &inputs[winner];
        let copy = yadorilink_replica_engine::namespace::first_copy_name(path, winner);
        let written = self
            .materialize_dag_content_head(
                group_id,
                &copy,
                demand_path,
                winner,
                policy,
                Some(winner),
                None,
            )
            .await?;
        if !matches!(written, MaterializeResult::Settled(ref evidence) if content_on_disk(evidence))
        {
            return Ok(MaterializeResult::RetryRequired);
        }
        // The copy just written holds the winner; a leaf on disk written
        // from another head needs its own copy, written earlier.
        let placed = match self.state.get_authoring_change_hash(group_id, path)? {
            Some(authoring) if authoring.0 == winner.change_hash => true,
            _ => self.leaf_is_held_at_its_copy(group_id, path, inputs, derived, settled)?,
        };
        if !self.displace_leaf_for_directory(group_id, path, placed).await? {
            return Ok(MaterializeResult::RetryRequired);
        }
        let reason = yadorilink_sync_sqlite::structural_origin::RETAINED_FOLDED_NAME;
        self.state.keep_retained_directory(group_id, path, reason, None).map_err(sqlite_error)?;
        tracing::info!(
            group_id,
            path,
            copy = %copy,
            "this volume folds the name to a directory the tree needs; the entry stays at its \
             copy name here"
        );
        Ok(MaterializeResult::Settled(SettlementEvidence::Retained { reason: reason.to_string() }))
    }

    /// What the namespace requires of `path` on its own account (`None`
    /// when a live version there is not held locally yet, so it cannot be
    /// decided), and -- when `path` has to be a directory while its
    /// per-path `winner` is a File or Symlink -- the copy names that winner
    /// is relocated to.
    #[allow(clippy::type_complexity)]
    pub(crate) fn namespace_relocation(
        &self,
        group_id: &str,
        path: &str,
        winner: &PathHead,
    ) -> Result<(Option<DesiredPathState>, Option<Vec<String>>), PeerSessionError> {
        let desired = match self.state.desired_path_state(group_id, path) {
            Ok(desired) => desired,
            Err(yadorilink_sync_sqlite::SyncSqliteError::NotFound(_)) => return Ok((None, None)),
            Err(e) => return Err(sqlite_error(e)),
        };
        let needs_directory = matches!(
            desired,
            DesiredPathState::StructuralDirectory | DesiredPathState::ExplicitDirectory { .. }
        );
        if !needs_directory
            || !matches!(
                self.head_kind(group_id, winner)?,
                Some(RecordKind::File | RecordKind::Symlink)
            )
        {
            return Ok((Some(desired), None));
        }
        let winner_version = winner.content.as_ref().map(|content| content.version_hash);
        // `None`: a sibling at this level whose live version this replica
        // does not hold yet leaves the copy name undecidable. No copy is
        // written, so the leaf stays where it is and this path retries;
        // the rest of the pass goes on.
        let Some(relocated) = self.relocated_copies_of(group_id, path)? else {
            return Ok((Some(desired), Some(Vec::new())));
        };
        let copies = relocated
            .into_iter()
            .filter(|(_, version)| Some(*version) == winner_version)
            .map(|(copy, _)| copy)
            .collect();
        Ok((Some(desired), Some(copies)))
    }

    /// `copies` without the Directory losers: a directory loses its
    /// metadata to the winning directory's and is owed no copy.
    pub(crate) fn leaf_conflict_copies(
        &self,
        group_id: &str,
        inputs: &[PathHead],
        copies: Vec<yadorilink_replica_engine::conflict::ConflictCopy>,
    ) -> Result<Vec<yadorilink_replica_engine::conflict::ConflictCopy>, PeerSessionError> {
        let mut out = Vec::with_capacity(copies.len());
        for copy in copies {
            if self.head_kind(group_id, &inputs[copy.head])? != Some(RecordKind::Directory) {
                out.push(copy);
            }
        }
        Ok(out)
    }
}

/// Whether a settlement leaves the entry's content at its name on disk:
/// the exact object, or the placeholder an on-demand folder materializes
/// in its place.
fn content_on_disk(evidence: &SettlementEvidence) -> bool {
    matches!(
        evidence,
        SettlementEvidence::ExactObject { .. } | SettlementEvidence::PolicyPlaceholder
    )
}

/// The name of the entry of `parent` that is the object `target` describes
/// (as `symlink_metadata` of `name` reported it), when no entry of `parent`
/// is spelled exactly `name`. `None` when `name` itself exists, or no entry
/// is that object.
fn entry_answering_under_another_name(
    parent: &Path,
    name: &std::ffi::OsStr,
    target: &std::fs::Metadata,
) -> std::io::Result<Option<String>> {
    let mut answered = None;
    for entry in std::fs::read_dir(parent)? {
        let entry = entry?;
        if entry.file_name() == name {
            return Ok(None);
        }
        // `DirEntry::metadata` does not follow a symlink (on Unix it is
        // `symlink_metadata` of the entry): a symlink, dangling or not,
        // compares as the link itself, as `target` does.
        if let Ok(meta) = entry.metadata() {
            if same_object(&meta, target) {
                answered = entry.file_name().to_str().map(str::to_string);
            }
        }
    }
    Ok(answered)
}

#[cfg(unix)]
fn same_object(a: &std::fs::Metadata, b: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    a.dev() == b.dev() && a.ino() == b.ino()
}

#[cfg(not(unix))]
fn same_object(a: &std::fs::Metadata, b: &std::fs::Metadata) -> bool {
    a.file_type() == b.file_type() && a.len() == b.len() && a.modified().ok() == b.modified().ok()
}

/// A test's stand-in for moving a leaf aside stopping partway: armed for
/// one leaf's absolute path and stage, it fires once. `Stop::Crash`
/// panics, ending the whole pass there as a process exit would;
/// `Stop::Error` returns an error, as a failing syscall or store write
/// does, and the pass goes on with its other paths. Either way the open
/// intent is dropped uncleared.
#[cfg(test)]
pub(crate) mod displacement_crash {
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum Stage {
        /// The copy is written and the delete intent is open; the leaf is
        /// still at its name.
        BeforeUnlink,
        /// The leaf is unlinked; its index row is not erased yet.
        BeforeRowErase,
        /// A structural container is created (and recorded by the `mkdir`
        /// helper); its settlement is not committed yet. Keyed by the
        /// container's path.
        AfterStructuralMkdir,
        /// A superseded explicit Directory entry's directory is adopted as
        /// structural; the entry's row is not erased yet.
        BeforeEntryRetired,
        /// A directory made only for descendants is removed from disk; its
        /// structural record is not forgotten yet.
        AfterStructuralRmdir,
        /// A replicated directory an entry supersedes is removed from disk;
        /// its records are not forgotten yet.
        AfterSupersededRmdir,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum Stop {
        Crash,
        Error,
    }

    static ARMED: Mutex<Vec<(PathBuf, Stage, Stop)>> = Mutex::new(Vec::new());

    pub(crate) fn arm(leaf: &Path, stage: Stage, stop: Stop) {
        ARMED.lock().unwrap().push((leaf.to_path_buf(), stage, stop));
    }

    pub(crate) fn is_armed(leaf: &Path, stage: Stage) -> bool {
        ARMED.lock().unwrap().iter().any(|(path, s, _)| path == leaf && *s == stage)
    }

    pub(crate) fn disarm(leaf: &Path, stage: Stage) {
        ARMED.lock().unwrap().retain(|(path, s, _)| !(path == leaf && *s == stage));
    }

    pub(super) fn stop_at(
        leaf: &Path,
        stage: Stage,
    ) -> Result<(), yadorilink_peer_session::PeerSessionError> {
        let stop = {
            let mut armed = ARMED.lock().unwrap();
            let Some(at) = armed.iter().position(|(path, s, _)| path == leaf && *s == stage) else {
                return Ok(());
            };
            armed.remove(at).2
        };
        let message = format!("simulated {stop:?} {stage:?} at {}", leaf.display());
        match stop {
            Stop::Crash => panic!("{message}"),
            Stop::Error => Err(std::io::Error::other(message).into()),
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::entry_answering_under_another_name;

    /// What a folding volume's lookup of `name` returns, on any volume:
    /// the entry `A` itself, not what it points to.
    fn lookup_answer(dir: &std::path::Path, spelled: &str) -> std::fs::Metadata {
        std::fs::symlink_metadata(dir.join(spelled)).unwrap()
    }

    #[test]
    fn a_symlink_answering_under_another_spelling_is_found() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("t"), b"target").unwrap();
        std::os::unix::fs::symlink("t", dir.path().join("A")).unwrap();

        let target = lookup_answer(dir.path(), "A");
        let found = entry_answering_under_another_name(dir.path(), "a".as_ref(), &target).unwrap();

        assert_eq!(found.as_deref(), Some("A"));
    }

    #[test]
    fn a_dangling_symlink_answering_under_another_spelling_is_found() {
        let dir = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink("nowhere", dir.path().join("A")).unwrap();

        let target = lookup_answer(dir.path(), "A");
        let found = entry_answering_under_another_name(dir.path(), "a".as_ref(), &target).unwrap();

        assert_eq!(found.as_deref(), Some("A"));
    }

    #[test]
    fn a_symlink_to_the_looked_up_object_is_not_the_entry_that_answered() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("A"), b"file").unwrap();
        std::os::unix::fs::symlink("A", dir.path().join("link")).unwrap();

        let target = lookup_answer(dir.path(), "A");
        let found = entry_answering_under_another_name(dir.path(), "a".as_ref(), &target).unwrap();

        assert_eq!(found.as_deref(), Some("A"), "the link to it must not answer");
    }

    #[test]
    fn the_exact_name_existing_answers_nothing() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a"), b"file").unwrap();

        let target = lookup_answer(dir.path(), "a");
        let found = entry_answering_under_another_name(dir.path(), "a".as_ref(), &target).unwrap();

        assert_eq!(found, None);
    }
}
