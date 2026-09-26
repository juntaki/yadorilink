use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use yadorilink_local_storage::check_disk_headroom;
use yadorilink_local_storage::{
    verify_write_target_within_canonical_root, verify_write_target_within_root,
};
use yadorilink_peer_session::hazard;
use yadorilink_peer_session::PeerSessionError;
use yadorilink_replica_domain::file::FileVersion;
use yadorilink_replica_domain::file::{FileRecord, RecordKind};
use yadorilink_replica_domain::ids::{ChangeHash, VersionHash};
use yadorilink_replica_domain::session_state::LinkGate;
use yadorilink_replica_domain::session_state::MaterializationPolicy;
use yadorilink_replica_engine::conflict::{resolve_path_heads, PathHead, PathResolution};

use super::types::*;
use super::{mode_and_xattrs_match_disk, OwnCaptureOnDisk, OwnCaptureRule, Recapture};
use yadorilink_peer_session::peer_session::*;
use yadorilink_root_authority::fs_identity::disk_race_fingerprint;

impl super::LocalConvergenceExecutor {
    /// Which of `paths` name content this device does not hold.
    ///
    /// The one question in convergence whose answer is not on this device, and
    /// it is asked once for a whole pass rather than per path in the middle of
    /// one. Advisory: a driver with a peer obtains these and runs the pass;
    /// the pass then re-resolves everything itself, so a plan that has gone
    /// stale by then costs a wasted fetch, never a wrong write.
    ///
    /// A device with no peer never calls this. Its obligations simply stay
    /// open until an explicit wake, which is what "unavailable" has always
    /// meant here.
    pub fn content_missing_locally(
        &self,
        group_id: &str,
        paths: &std::collections::BTreeSet<String>,
    ) -> Result<Vec<BlockRequirement>, PeerSessionError> {
        let mut missing = Vec::new();
        for path in paths {
            let heads = self.combined_heads(group_id, path, None)?;
            let heads: &[PathHead] = &heads;
            let resolution = resolve_path_heads(path, heads);
            let PathResolution::Present { winner, conflict_copies, .. } = resolution else {
                continue;
            };
            if let Some(requirement) =
                self.block_requirement_for(group_id, path, path, &heads[winner])?
            {
                missing.push(requirement);
            }
            // A conflict copy is DERIVED, at a name that is not in `paths`
            // and that only the resolution above knows. Nothing else can
            // obtain its content: the pass that materializes it runs after
            // this prefetch, and when it finds blocks missing it reports
            // `RetryRequired` without ever reaching for the transport. The
            // engine then keeps the SOURCE path outstanding -- correctly,
            // since the copy derived from it is unresolved -- and re-drives
            // with that source path again, prefetching the winner's content
            // for the n-th time and the copy's never.
            //
            // The result was a livelock with no lock and no park: unbounded
            // work, zero possible progress, and a copy that existed on
            // exactly one device -- the author of the losing content, the
            // only one already holding those blocks.
            for copy in &conflict_copies {
                // Demand is INHERITED from the source path, not from the
                // copy's own name: nobody pins a conflict copy, and an
                // on-demand folder that refused it would leave the source
                // path unresolvable for as long as the loser stays live.
                if let Some(requirement) =
                    self.block_requirement_for(group_id, &copy.path, path, &heads[copy.head])?
                {
                    missing.push(requirement);
                }
            }
        }
        Ok(missing)
    }

    /// What `path` would need fetched to materialize `head`'s content, or
    /// `None` if there is nothing to fetch -- no content, no known version,
    /// a deletion, or blocks this device already holds.
    ///
    /// Shared by the winner and by each derived conflict copy, so the two
    /// cannot drift into asking different questions about the same thing.
    fn block_requirement_for(
        &self,
        group_id: &str,
        path: &str,
        demand_path: &str,
        head: &PathHead,
    ) -> Result<Option<BlockRequirement>, PeerSessionError> {
        let Some(content) = head.content.as_ref() else {
            return Ok(None);
        };
        let Some(version) =
            self.state.dag_get_file_version(group_id, &VersionHash(content.version_hash))?
        else {
            return Ok(None);
        };
        let record = file_record_from_version(path, &version);
        if record.deleted || !self.blocks_missing_locally(group_id, &record)? {
            return Ok(None);
        }
        // Sampled now, before anything is requested, so the guard against
        // a local editor writing during the fetch has something from
        // before the window to compare against.
        let observed_disk = self
            .local_file_path(group_id, path)
            .ok()
            .and_then(|out_path| disk_race_fingerprint(&out_path));
        Ok(Some(BlockRequirement {
            path: path.to_string(),
            demand_path: demand_path.to_string(),
            version_hash: version.version_hash,
            record,
            observed_disk,
        }))
    }

    /// Reconcile `paths` using only what this device already holds.
    ///
    /// The whole of convergence except obtaining content: everything here is
    /// decided from this device's own disk, index and DAG. A path whose
    /// content is absent records a retriable placeholder and stays open.
    pub async fn reconcile_paths(
        &self,
        group_id: &str,
        paths: std::collections::BTreeSet<String>,
    ) -> Result<Option<ProjectionAttempt>, PeerSessionError> {
        let audit_attempt_id = next_audit_attempt_id();
        // This entry point obtains no content (it reconciles from what this
        // device already holds), so its timer has no block-fetch half to
        // share -- created here purely to satisfy the one-timer-per-attempt
        // shape the fetching entry point needs.
        let call_timer = crate::local_convergence::call_timer::ReconcileCallTimer::new();
        self.reconcile_group_paths_guarded(
            group_id,
            paths,
            &self.local_device_id,
            &HashMap::new(),
            audit_attempt_id,
            &call_timer,
        )
        .await
    }

    /// Whether the hazard re-check would only repeat its last decision for
    /// `path`: the path is held because its existing file is not readable
    /// by its owner, and neither that file, the path's mutation fence nor
    /// the version the path resolves to has changed since. Re-running the
    /// path then cannot come out differently, so the sweep skips it rather
    /// than re-examining it on every tick. Any other hold, and a path that
    /// no longer resolves to content, is re-examined as before.
    pub(crate) fn metadata_unprovable_hold_unchanged(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<bool, PeerSessionError> {
        let held_for_metadata = self.state.get_held_state(group_id, path)?.is_some_and(|held| {
            held.reason
                .starts_with(yadorilink_peer_session::hazard::HELD_REASON_METADATA_UNPROVABLE)
        });
        if !held_for_metadata {
            return Ok(false);
        }
        let heads = self.combined_heads(group_id, path, None)?;
        let version = match resolve_path_heads(path, &heads) {
            PathResolution::Present { winner, .. } => match heads[winner].content.as_ref() {
                Some(content) => VersionHash(content.version_hash),
                None => return Ok(false),
            },
            PathResolution::Absent => return Ok(false),
        };
        let out_path = self.sync_root(group_id)?.join(path);
        self.state.metadata_unprovable_hold_unchanged(group_id, path, &out_path, &version)
    }

    /// The evidence for a path this attempt found already absent -- in the
    /// index and on disk -- and so did not touch: no disk mutation occurred,
    /// so its mutation fence is snapshotted, never bumped. One place for
    /// every already-absent settle (a deleted row's tombstone already
    /// reflected, and a path an installed base leaves with no head at all).
    fn already_absent(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<SettlementEvidence, PeerSessionError> {
        let mutation_generation = self.state.dag_snapshot_mutation_fence(group_id, path)?;
        Ok(SettlementEvidence::ExactAbsent { mutation_generation })
    }

    /// Bounded commit size for `try_commit_ordinary_batch`, matching the
    /// convergence engine's own per-tick path budget so a larger reconcile
    /// window still commits in engine-sized chunks rather than one unbounded
    /// transaction.
    const ORDINARY_BATCH_MAX_PATHS: usize = 8;

    fn block_write_activity_provider(
        &self,
    ) -> Arc<dyn yadorilink_peer_session::peer_session::BlockWriteActivityProvider> {
        self.block_write_activity_provider.clone()
    }

    /// `reconcile_one_file`'s guard: if a handle is set and it reports a
    /// pending, undispatched local entry for `rel_path`, that entry is now
    /// captured into the index by the time this returns. Called *before*
    /// `reconcile_one_file` acquires `SyncState::path_lock` for the same
    /// path — the handle's own flush goes through the ordinary
    /// `LocalChangeProcessor::process_event_with_ignore` dispatch, which
    /// acquires that same lock itself, so calling this while already
    /// holding it (as `reconcile_one_file` does for the rest of its body,
    /// including every `materialize`/`resolve_and_apply_conflict` call
    /// downstream of it) would deadlock. Because every `materialize` call
    /// in this module happens from within `reconcile_one_file`'s
    /// already-locked body, this single guard — run once, up front —
    /// covers both the "materialize-side" and
    /// "`reconcile_one_file`-side" serialization requirements: by the time
    /// any downstream `materialize` call writes to disk, a local change
    /// that was still pending here has already been indexed.
    pub(crate) async fn flush_pending_local_change_before_reconcile(
        &self,
        group_id: &str,
        rel_path: &str,
    ) -> PendingLocalFlushOutcome {
        let handle = self.pending_local_change_flush.clone();
        // Marks that the guard was reached for this path — the first fork
        // when a local write is lost despite this guard existing. A missing
        // trace line here means the guard never ran on that route at all,
        // which is a different bug from it running and finding nothing.
        yadorilink_peer_session::dst_trace(rel_path, || {
            format!("flush guard entered on {}", self.local_device_id)
        });
        tracing::debug!(
            group_id,
            path = rel_path,
            "checking this link's debounce accumulator for a pending local change before reconciling this path"
        );
        handle.flush_pending_local_change(group_id, rel_path).await
    }

    /// Both pre-write guards for `rel_path` -- its own pending edit and a
    /// case-fold sibling's -- settled only if both are. `RetryRequired`
    /// means a local edit may be sitting uncaptured on disk, and the caller
    /// must not write to (or delete) the path on this pass.
    pub(crate) async fn flush_local_changes_before_reconcile(
        &self,
        group_id: &str,
        rel_path: &str,
    ) -> PendingLocalFlushOutcome {
        let ancestors = self.capture_vanished_explicit_ancestors(group_id, rel_path).await;
        let own = self.flush_pending_local_change_before_reconcile(group_id, rel_path).await;
        let sibling = self.flush_case_fold_sibling_before_reconcile(group_id, rel_path).await;
        ancestors.and(own).and(sibling)
    }

    /// Captures the removal of each ancestor of `rel_path` that the index
    /// holds as a live explicit directory but that is gone from disk,
    /// before anything is written below it.
    ///
    /// Writing `rel_path` creates its missing ancestors. An explicit
    /// directory the user just removed (`rm -rf`) whose removal capture has
    /// not seen yet would come back that way -- and capture, finding it on
    /// disk again, would never author its deletion: the user's delete of
    /// the directory would be lost, and the directory kept as an explicit
    /// entry for good instead of as the container of what arrived in it.
    /// Capturing first turns it into the point deletes the removal was, so
    /// the write recreates the ancestor only as the structural container it
    /// now is. An ancestor the materializer is still placing (an open
    /// intent) is not a removal.
    async fn capture_vanished_explicit_ancestors(
        &self,
        group_id: &str,
        rel_path: &str,
    ) -> PendingLocalFlushOutcome {
        let Ok(root) = self.sync_root(group_id) else {
            return PendingLocalFlushOutcome::Settled;
        };
        let mut outcome = PendingLocalFlushOutcome::Settled;
        let components: Vec<&str> = rel_path.split('/').collect();
        for depth in 1..components.len() {
            let ancestor = components[..depth].join("/");
            let vanished = matches!(
                std::fs::symlink_metadata(root.join(&ancestor)),
                Err(error) if matches!(
                    error.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                )
            );
            if !vanished {
                continue;
            }
            let explicit = self
                .state
                .file_index_repository()
                .canonical_current_row(group_id, &ancestor)
                .ok()
                .flatten()
                .is_some_and(|row| {
                    !row.snapshot.deleted
                        && row.snapshot.record_kind
                            == yadorilink_replica_domain::file::RecordKind::Directory
                });
            let in_flight = self
                .state
                .materialization_intent_repository()
                .has_materialization_intent(group_id, &ancestor)
                .unwrap_or(true);
            if explicit && !in_flight {
                outcome = outcome.and(
                    self.pending_local_change_flush
                        .capture_local_path_state(group_id, &ancestor)
                        .await,
                );
                // Everything below it was removed with it and has just
                // been captured; there is nothing deeper to look for.
                break;
            }
        }
        outcome
    }

    /// Like `flush_pending_local_change_before_reconcile` above, but for
    /// the *other* case-variant path that would collide with `rel_path` on
    /// a case-insensitive filesystem.
    ///
    /// Without this, `hazard_reason_for`'s `state.list_files(group_id)`
    /// read (used to detect a case-fold collision before materializing an
    /// incoming record — see `hazard_reason_for_policy`) only sees what's
    /// already indexed in `SyncState`. A local write to the colliding
    /// sibling name, still sitting undispatched in this link's debounce
    /// accumulator, is invisible to that read — so the incoming record
    /// for the other case-variant can materialize for real (no collision
    /// detected) instead of being held, silently overwriting/losing this
    /// device's own not-yet-indexed write with no conflict artifact at
    /// all. Same failure shape `flush_pending_local_change_before_
    /// reconcile` already closes for the exact-same-path case, just
    /// reached via case-fold adjacency instead of path identity.
    ///
    /// Only meaningful (and only called) when `hazard::is_case_insensitive_
    /// filesystem` is true for this group's root — on a case-sensitive
    /// filesystem, two differently-cased names are simply unrelated
    /// files, and this extra round trip would have nothing to find.
    pub(crate) async fn flush_case_fold_sibling_before_reconcile(
        &self,
        group_id: &str,
        rel_path: &str,
    ) -> PendingLocalFlushOutcome {
        // No root for this group means nothing of ours is on disk to collide
        // with, so there is no case-fold sibling to flush.
        let Ok(root) = self.sync_root(group_id) else {
            return PendingLocalFlushOutcome::Settled;
        };
        if !hazard::is_case_insensitive_filesystem(&root) {
            return PendingLocalFlushOutcome::Settled;
        }
        let handle = self.pending_local_change_flush.clone();
        tracing::debug!(
            group_id,
            path = rel_path,
            "checking this link's debounce accumulator for a pending case-fold sibling change before reconciling this path"
        );
        handle.flush_case_fold_sibling(group_id, rel_path).await
    }

    /// attempts to admit `block_count` more blocks to eager
    /// fetch for `group_id` under this session's cumulative budget
    /// (`MAX_EAGER_BLOCKS_PER_GROUP_PER_SESSION`), returning whether the
    /// admission succeeded. On success, the group's counter is
    /// incremented by `block_count`; on failure, the counter is
    /// unchanged and the caller is expected to fall back to a
    /// placeholder instead of fetching.
    /// How many blocks this session has charged to `group_id`'s eager
    /// admission budget so far. Exists so a test can assert that a record is
    /// charged for exactly once, which a materialization that hands out a
    /// block request and is then re-entered could easily get wrong: the
    /// charge is a side effect, not a recomputable value.
    #[cfg(any(test, feature = "test-support"))]
    pub fn eager_blocks_admitted(&self, group_id: &str) -> u64 {
        let admission = self.eager_admission.lock().unwrap_or_else(|p| p.into_inner());
        admission.get(group_id).copied().unwrap_or(0)
    }

    pub(crate) fn admit_eager_blocks(&self, group_id: &str, block_count: u64) -> bool {
        let mut admission =
            self.eager_admission.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        admit_eager_blocks_impl(
            &mut admission,
            group_id,
            block_count,
            MAX_EAGER_BLOCKS_PER_GROUP_PER_SESSION,
        )
    }

    /// Re-validates one [`yadorilink_peer_session::ports::PreparedProjectedUpsert`]
    /// under `try_commit_ordinary_batch`'s already-acquired path lock, and
    /// reports whether it still survives to publish. `false` means the
    /// caller must treat this path as `retry`, never `settled` -- nothing
    /// was committed for it. Purely read-only: no `writer_gate`
    /// acquisition of its own. `prepared.metadata` is applied later, as
    /// part of `open_projected_upserts_batch`'s own transaction, not here
    /// -- it is kept out of this per-candidate revalidation step (calling
    /// `apply_incoming_wire_metadata` individually per candidate would
    /// defeat the batch's own "2 transactions total" design) so a batch's metadata writes commit atomically with its rows/
    /// intents instead of one `writer_gate` hit per candidate.
    ///
    /// Returns the path's own resolved frontier on success -- the basis
    /// this candidate's physical write will realize, captured here under
    /// the batch's path lock rather than re-derived from the group's heads
    /// later. `None` is the `retry` verdict.
    async fn revalidate_ordinary_upsert(
        &self,
        group_id: &str,
        prepared: &yadorilink_peer_session::ports::PreparedProjectedUpsert,
        call_timer: &crate::local_convergence::call_timer::ReconcileCallTimer,
    ) -> Result<Option<Vec<ChangeHash>>, PeerSessionError> {
        // CONV-7-equivalent recheck, now safely under this batch's lock:
        // re-resolve the path's current winner and confirm it is still the
        // exact change this candidate was prepared against. A path that
        // now resolves to a different winner (or to Absent) is dropped --
        // simpler than `materialize_dag_content_head`'s in-place upgrade,
        // and just as correct: the dropped candidate's own change re-drives
        // through the ordinary retry path next reconcile pass.
        let dag_started = std::time::Instant::now();
        let fresh =
            self.combined_heads(group_id, &prepared.rel_path, prepared.derived_head.as_ref())?;
        call_timer.add_dag_resolution(dag_started.elapsed());
        let still_current = match resolve_path_heads(&prepared.rel_path, &fresh) {
            PathResolution::Present { winner, .. } => {
                Some(ChangeHash(fresh[winner].change_hash)) == prepared.authoring_change_hash
            }
            PathResolution::Absent => false,
        };
        if !still_current {
            return Ok(None);
        }
        if self.hazard_reason_for(group_id, &prepared.record)?.is_some() {
            return Ok(None);
        }
        // Same divergence guard `materialize()`'s own eager-write branch
        // runs immediately before it would overwrite existing content: an
        // unauthored local edit that landed on disk after this candidate's
        // blocks were fetched (in the unlocked prepare step) must not be
        // silently destroyed by this batch's publish.
        if self.disk_holds_uncaptured_local_bytes(
            group_id,
            &prepared.rel_path,
            &prepared.out_path,
            Some(&prepared.record.blocks),
        )? {
            return Ok(None);
        }
        Ok(Some(fresh.iter().map(|head| ChangeHash(head.change_hash)).collect()))
    }

    /// Thin wrapper over `hold_record`
    /// (see that free function's doc comment) using this session's own
    /// `SyncState`.
    pub(crate) fn hold(
        &self,
        group_id: &str,
        record: &FileRecord,
        reason: &str,
        origin_device_id: &str,
        authoring_change_hash: Option<&ChangeHash>,
    ) -> Result<(), PeerSessionError> {
        let authority = self.root_lease_for(group_id)?;
        let authority_op = authority.begin_operation()?;
        let permit = authority_op.permit();
        hold_record(
            self.state.as_ref(),
            group_id,
            record,
            reason,
            origin_device_id,
            authoring_change_hash,
            &permit,
        )
    }

    /// Builds `SettlementEvidence::ExactObject` from the row `materialize`
    /// just durably committed for `path` -- the version identity is read
    /// back from the just-written row rather than threaded in as a
    /// parameter, since none of `materialize`'s own branches ever receive
    /// a `VersionHash` directly (`FileRecord` carries no such field).
    /// `mutation_generation` is the fence value the caller's own bump (or,
    /// for a content-identical verification, snapshot) returned.
    /// `written` is the version the physical write put on disk, carried
    /// from the payload that produced those bytes.
    ///
    /// This function does not decide the version and has no way to. It
    /// confirms that the target version is still what the row names, and
    /// that the object on disk matches it in kind and in replicated
    /// xattrs. There is deliberately no API left that discovers a proof's
    /// version from the row: that is how a write for V1 came to be
    /// published as V2, and leaving such a helper in place -- even unused
    /// -- is how it would come back.
    ///
    /// `None` means the row has moved off `written` since: the bytes are
    /// real but they are no longer what this path wants, so there is no
    /// exact claim to make and the caller must retry rather than settle.
    pub(crate) fn exact_object_evidence_after_write(
        &self,
        group_id: &str,
        path: &str,
        kind: RecordKind,
        written: &FileVersion,
        mutation_generation: i64,
        xattrs: &XattrEvidence,
    ) -> Result<Option<SettlementEvidence>, PeerSessionError> {
        let current_version = self
            .state
            .get_current_version_record(group_id, path)?
            .map(|current| current.to_file_version())
            .ok_or_else(|| {
                PeerSessionError::CorruptState(format!(
                    "materialize committed {path} but its version record is unexpectedly absent"
                ))
            })?;
        if current_version.version_hash != written.version_hash {
            return Ok(None);
        }
        let version = written.version_hash;
        let out_path = self.local_file_path(group_id, path)?;
        // The `ExactObject` proof gate: `version_hash` bakes replicated
        // xattr bytes directly into its identity (`FileVersion::compute_
        // hash`), so this evidence must never claim exactness without a
        // strict, on-disk confirmation that they actually landed --
        // `apply_xattrs` itself never surfaces a `fsetxattr`/`fremovexattr`
        // failure as an `Err`, so nothing upstream of this call would
        // otherwise ever catch one. Scoped to `RecordKind::File` only,
        // matching `verify_replicated_xattrs_exact`'s own contract: a
        // symlink/directory version's `xattrs` is always empty (never
        // scanned, see `FileMeta::xattrs`'s own doc) and its path must
        // never be opened with symlink-following semantics here (a
        // dangling symlink is perfectly valid and has no followable
        // target at all).
        //
        // A caller that just wrote the file passes the attempt's own
        // confirmation, taken before the final mode was applied; one that
        // did not passes `ReproveFromDisk`, and disk is re-read strictly.
        if kind == RecordKind::File {
            require_xattr_evidence(path, &out_path, &written.meta.xattrs, xattrs)?;
        }
        // Defense-in-depth: `FileVersion`
        // accepts `RecordKind::Directory` (and, in principle, a
        // `RecordKind::Symlink` whose disk object is something else
        // entirely), but `materialize()` has no directory-specific
        // physical branch today -- a directory version falls through to
        // the ordinary regular-file reconstruct path, which creates a
        // regular file, not a directory. Without this check, a
        // hand-crafted, validly-signed version claiming `Directory` could
        // settle as `ExactObject` while the physical object on disk is a
        // `RegularFile`. `FileIdentity::observe_path(...).ok()` below
        // this point silently accepts `None` too (no disk object at all),
        // so this also closes that gap for every kind, not just
        // Directory.
        require_physical_kind_matches(path, &out_path, kind)?;
        Ok(Some(SettlementEvidence::ExactObject {
            kind,
            version,
            identity: Box::new(
                yadorilink_root_authority::fs_identity::FileIdentity::observe_path(&out_path).ok(),
            ),
            mutation_generation,
        }))
    }

    /// The ordinary batch's per-path finish after its rename: the mode and
    /// xattrs from `written_version` (the payload the bytes came from, not
    /// the row, which a concurrent supersession can move), then the exact
    /// evidence for them. `None` is `exact_object_evidence_after_write`'s:
    /// the row has moved off that version.
    fn finish_ordinary_batch_write(
        &self,
        group_id: &str,
        prepared: &yadorilink_peer_session::ports::PreparedProjectedUpsert,
        kind: RecordKind,
        mutation_generation: i64,
    ) -> Result<Option<SettlementEvidence>, PeerSessionError> {
        #[cfg(test)]
        if let Some(e) = self
            .state
            .test_observers
            .take_ordinary_batch_metadata_fault(group_id, &prepared.rel_path)
        {
            return Err(e);
        }
        let applied = yadorilink_local_storage::apply_file_metadata_verified(
            &prepared.out_path,
            prepared.written_version.meta.unix_mode,
            &prepared.written_version.meta.xattrs,
        )?;
        let xattrs = XattrEvidence::from(applied);
        self.exact_object_evidence_after_write(
            group_id,
            &prepared.rel_path,
            kind,
            &prepared.written_version,
            mutation_generation,
            &xattrs,
        )
    }

    /// Does this device hold every block `record` names, *as this group*?
    ///
    /// Both halves matter. A block present in the store but with no provenance
    /// for this group was obtained by some other group and is not this one's
    /// to use, which is exactly the condition the block lane treats as
    /// missing. Purely local: two batched reads, no network.
    pub(crate) fn blocks_missing_locally(
        &self,
        group_id: &str,
        record: &FileRecord,
    ) -> Result<bool, PeerSessionError> {
        self.blocks_missing_locally_in_batch(group_id, record, None)
    }

    /// As [`Self::blocks_missing_locally`], but a block an earlier file in the
    /// same reconciliation window already obtained counts as held even though
    /// its provenance row is still queued behind that window's batch flush.
    fn blocks_missing_locally_in_batch(
        &self,
        group_id: &str,
        record: &FileRecord,
        batch: Option<&ReconcileProvenanceBatch>,
    ) -> Result<bool, PeerSessionError> {
        if record.blocks.is_empty() {
            return Ok(false);
        }
        let hashes: Vec<_> = record.blocks.iter().map(|b| hex::encode(&b.hash)).collect();
        let present = self.store.present_blocks(&hashes)?;
        let provenance = self.state.group_has_block_provenance_batch(
            group_id,
            &record.blocks.iter().map(|b| b.hash.clone()).collect::<Vec<_>>(),
        )?;
        Ok(record.blocks.iter().zip(present).any(|(block, present)| {
            !present
                || !(provenance.contains(&block.hash)
                    || batch.is_some_and(|b| b.already_known(&block.hash)))
        }))
    }

    /// defense-in-depth check before writing through `out_path`
    /// — see `chunker::verify_write_target_within_canonical_root`'s doc
    /// comment. Uses the cached canonical root (`canonical_sync_roots`)
    /// when available (the common case, avoiding a repeated
    /// canonicalize-the-whole-root cost on this per-peer-message hot
    /// path); falls back to resolving `group_id`'s root fresh for the
    /// rare case it wasn't cached at session construction time.
    ///
    /// Also re-runs `VerifiedRoot::verify` — `materialize`'s own
    /// verification at its own start proves the root's identity BEFORE
    /// any block fetch, but a fetch can run for up to
    /// `DEFAULT_HYDRATION_TIMEOUT` (30s), during which the mountpoint
    /// this device resolved as the sync root can be unmounted and
    /// replaced (a fresh empty directory, or a different volume) without
    /// changing anything a bare `canonicalize`/containment check can see
    /// — a replaced mountpoint's path still resolves and still contains
    /// `out_path` lexically. Since this function already runs immediately
    /// before every physical write in every `materialize`/`hydrate_file_
    /// with_timeout` branch, re-verifying identity here (not just
    /// containment) closes that window at its narrowest point, for both
    /// callers, in one place — cheap enough to run unconditionally: one
    /// canonicalize, one lock, and one marker-file read, not a directory
    /// walk.
    /// The structural-directory ledger every `mkdir` this executor runs
    /// in `group_id`'s root records into.
    pub(crate) fn structural_ledger<'a>(
        &'a self,
        group_id: &'a str,
    ) -> yadorilink_filesystem_sync::materialization_execution::GroupStructuralLedger<'a> {
        yadorilink_filesystem_sync::materialization_execution::GroupStructuralLedger::new(
            self.state.as_ref(),
            group_id,
        )
    }

    pub fn verify_write_target(
        &self,
        group_id: &str,
        out_path: &Path,
    ) -> Result<(), PeerSessionError> {
        // Resolve the root first and fail closed on an unknown group: with the
        // old empty-path default, `out_path` was a bare relative filename whose
        // parent is `""` -- exactly the empty root -- so the fast path below
        // returned Ok and this check passed trivially for the one case it most
        // needed to reject.
        let raw_root = self.sync_root(group_id)?;
        let raw_root = raw_root.as_path();
        self.state.verify_root(raw_root, group_id)?;
        // Fast path: is specifically about a symlink at an
        // *intermediate* directory component between the sync root and
        // the file — when `out_path`'s parent *is* the sync root itself
        // (an ordinary top-level file, no subdirectory in `record.path`
        // at all), there is no intermediate component that could be such
        // a symlink, so the expensive canonicalize round trip has nothing
        // to catch here. Purely structural (no filesystem access) — safe
        // to check before paying for the syscalls below, and matters in
        // practice: this runs on every eager materialize/hydrate, a
        // per-peer-message-concurrency-bounded hot path where two peers
        // can legitimately race each other fetching each other's content
        // for the two sides of the same conflict.
        if out_path.parent() == Some(raw_root) {
            return Ok(());
        }
        match self.canonical_sync_root(group_id, raw_root) {
            Some(canonical_root) => Ok(verify_write_target_within_canonical_root(
                out_path,
                &canonical_root,
                &self.structural_ledger(group_id),
            )?),
            None => Ok(verify_write_target_within_root(
                out_path,
                raw_root,
                &self.structural_ledger(group_id),
            )?),
        }
    }

    /// Disk-space headroom preflight
    /// before a hydration fetch or a materialize-to-temp-and-rename write
    /// begins, scoped to the volume hosting `group_id`'s local sync root —
    /// called from both of this session's write paths that reach
    /// `reconstruct_file` (`hydrate_file_with_timeout`'s single-session
    /// hydration, and `materialize`'s eager-fetch branch). A no-op (fast
    /// path, no filesystem query) when `headroom_enforced` hasn't been
    /// turned on — see that field's doc comment for why a bare/test session
    /// doesn't enforce this by default.
    pub(crate) fn preflight_disk_headroom(
        &self,
        group_id: &str,
        target_path: &Path,
        additional_bytes: u64,
    ) -> Result<(), PeerSessionError> {
        if !self.headroom_enforced() {
            return Ok(());
        }
        Ok(check_disk_headroom(
            &self.sync_root(group_id)?,
            target_path,
            additional_bytes,
            self.headroom_override_bytes(),
        )?)
    }
}

impl super::LocalConvergenceExecutor {
    /// One bounded reconciliation attempt: acquires
    /// `MaterializationAuditGuard` for `group_id`, runs
    /// `reconcile_group_paths(paths)` under it, and releases the guard
    /// before returning — never holds it across more than one
    /// `reconcile_group_paths` call. Returns `Ok(None)` if the guard could
    /// not be acquired (another attempt for this group is already in
    /// flight) or the group is not `LinkGate::Live` — the caller decides
    /// what "could not run this attempt right now" means for its own
    /// retry/backoff.
    pub(crate) async fn reconcile_group_paths_guarded(
        &self,
        group_id: &str,
        paths: std::collections::BTreeSet<String>,
        origin_device_id: &str,
        prefetched: &HashMap<String, BlockRequirement>,
        audit_attempt_id: u64,
        call_timer: &crate::local_convergence::call_timer::ReconcileCallTimer,
    ) -> Result<Option<ProjectionAttempt>, PeerSessionError> {
        if !matches!(self.state.link_gate_for_group(group_id)?, LinkGate::Live { .. }) {
            return Ok(None);
        }
        let Some(_guard) = MaterializationAuditGuard::try_acquire(&self.state, group_id) else {
            return Ok(None);
        };
        Ok(Some(
            self.reconcile_group_paths(
                group_id,
                paths,
                origin_device_id,
                prefetched,
                audit_attempt_id,
                call_timer,
            )
            .await?,
        ))
    }

    /// Best-effort, lock-free preparation of an "ordinary" content
    /// upsert (a plain regular file: not a symlink, not hazardous, eager-
    /// admitted, every block fetchable, and not already content-identical
    /// to what's indexed) for batched publish via [`Self::
    /// try_commit_ordinary_batch`]. Returns `Ok(None)` for every other
    /// shape -- the caller falls back to the unbatched, per-path
    /// `materialize_dag_content_head` for those, completely unchanged.
    ///
    /// This function's classification is advisory, not authoritative: it
    /// runs with no path lock held (so its slow block-fetch/reconstruct
    /// work never blocks, or is blocked by, any other path), and
    /// `try_commit_ordinary_batch` re-validates every candidate fresh
    /// under its batch's locks before actually committing anything --
    /// exactly mirroring `materialize_dag_content_head`'s own CONV-7
    /// freshness re-resolution, just deferred to the batched commit step
    /// instead of running inline here.
    // ~10 call sites across this module and its tests; grouping these into
    // a params struct is out of scope for a lint cleanup.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn prepare_ordinary_projected_upsert<'a>(
        &self,
        group_id: &str,
        target_path: &str,
        demand_path: &str,
        head: &PathHead,
        policy: MaterializationPolicy,
        derived_head: Option<&PathHead>,
        activity_provider: &'a dyn BlockWriteActivityProvider,
        reconcile_batch: &ReconcileProvenanceBatch,
        call_timer: &crate::local_convergence::call_timer::ReconcileCallTimer,
    ) -> Result<
        Option<(Box<dyn Send + 'a>, yadorilink_peer_session::ports::PreparedProjectedUpsert)>,
        PeerSessionError,
    > {
        let Some(content) = head.content.as_ref() else {
            return Ok(None);
        };
        // Same ordering `materialize_dag_content_head` uses before its own
        // path-lock acquisition: force a same-path (or case-fold sibling)
        // pending local edit to become visible in the DAG now, so `try_
        // commit_ordinary_batch`'s later under-lock re-resolution can
        // actually see it and correctly drop a candidate this flush
        // superseded, rather than racing an edit this call itself could
        // have surfaced.
        //
        // A local edit the guard could not capture disqualifies this
        // candidate; the per-path fallback runs the same guard again and
        // declines the write there.
        if self.flush_local_changes_before_reconcile(group_id, target_path).await
            == PendingLocalFlushOutcome::RetryRequired
        {
            return Ok(None);
        }
        // This device's own capture of the path is never an ordinary write:
        // whether it may touch the disk at all is decided in one place,
        // `materialize_dag_content_head` (see `own_capture_on_disk`).
        if head.device_id == self.local_device_id
            && self.state.is_local_capture(group_id, target_path, &ChangeHash(head.change_hash))?
        {
            return Ok(None);
        }

        let version_hash = VersionHash(content.version_hash);
        let Some(version) = self.state.dag_get_file_version(group_id, &version_hash)? else {
            return Ok(None);
        };
        let record = file_record_from_version(target_path, &version);
        if record.deleted {
            return Ok(None);
        }

        // Content-identical fast path: if this exact block list is already
        // what's indexed, this is (at most) a cheap metadata-only update --
        // not worth batching, and not safe to decide unlocked (it can
        // itself write). Fall back and let the existing per-path code
        // handle it under its own lock, exactly as today.
        if let Some(local) = self.state.get_file(group_id, target_path)? {
            let same_content = !local.deleted
                && local.blocks.len() == record.blocks.len()
                && local.blocks.iter().zip(&record.blocks).all(|(b, vb)| b.hash == vb.hash);
            if same_content {
                return Ok(None);
            }
        }

        if self.hazard_reason_for(group_id, &record)?.is_some() {
            return Ok(None);
        }
        // The INCOMING version's own kind, not the index's current
        // `get_record_kind` -- for a path this device has never indexed
        // before, the index has no kind recorded yet (defaults away from
        // `Symlink`) until `apply_incoming_wire_metadata` writes one, which
        // in the unbatched path always runs before `materialize()`'s own
        // (index-based) symlink check, but which this batched path defers
        // to `revalidate_ordinary_upsert`. Checking the wire-carried kind
        // directly here is the correct check regardless of index state.
        // Only a regular file is ever an ordinary batch write: a symlink or
        // a directory has no content to reconstruct and takes its own lane.
        if version.meta.record_kind != RecordKind::File {
            return Ok(None);
        }

        // The path that DEMANDS this content, not the path it lands at --
        // see `materialize_dag_content_head`'s own check.
        let pinned = self.state.is_pinned(group_id, demand_path)?;
        let eager_admitted = pinned
            || (policy == MaterializationPolicy::Eager
                && self.admit_eager_blocks(group_id, record.blocks.len() as u64));
        if !eager_admitted {
            return Ok(None);
        }

        // From here on this candidate WILL fetch/reconstruct blocks unless
        // something below still disqualifies it (a genuinely transient
        // condition -- an unreachable peer, a timeout) -- only now is it
        // correct to enter the block-write-activity gate.
        // `materialize_dag_content_head` enters this same gate at its own
        // very top and holds it across its WHOLE call, including the
        // eventual row commit; this split-phase path preserves that exact
        // "one guard, held from before the fetch through the commit" shape
        // by having the caller (`reconcile_group_paths`) own the activity-
        // provider reference for its whole call and threading the SAME
        // guard returned here all the way to `try_commit_ordinary_batch`'s
        // own commit step, rather than taking a second, independent guard
        // there. Entering it any earlier than this would call it even for
        // a candidate this function is about to reject as not "ordinary"
        // at all (e.g. an on-demand, non-pinned policy) -- which falls
        // back to the unbatched `materialize_dag_content_head`, which
        // would then enter the SAME gate a second time for the same path.
        let write_activity = activity_provider.begin_block_write_activity();

        let ensure_blocks_started = std::time::Instant::now();
        // Is this candidate's content already here? Preparation does not
        // obtain it: acquiring a block is the one part of convergence that
        // needs a peer, and it happens before this pass runs, once, for every
        // path the pass is about to consider. A candidate whose content did
        // not arrive is simply not an ordinary candidate this pass -- it falls
        // back to the per-path route, which records a retriable placeholder
        // and leaves the obligation open for an explicit wake.
        let all_present =
            !self.blocks_missing_locally_in_batch(group_id, &record, Some(reconcile_batch))?;
        let newly_fetched_block_hashes: Vec<Vec<u8>> = Vec::new();
        let ensure_blocks_elapsed = ensure_blocks_started.elapsed();
        call_timer.add_ensure_blocks_present(ensure_blocks_elapsed);
        if !all_present {
            return Ok(None);
        }

        let out_path = self.local_file_path(group_id, target_path)?;
        self.verify_write_target(group_id, &out_path)?;
        self.preflight_disk_headroom(group_id, &out_path, record.size)?;
        let intent_target_hash = yadorilink_local_storage::intent_target_hash(&record.blocks);
        let tmp_path = reconstruct_file_to_temp_off_runtime(
            self.store.clone(),
            &out_path,
            &record.blocks,
            record.mtime_unix_nanos,
        )
        .await?;
        let metadata = yadorilink_replica_domain::session_state::LocalFileMetaColumns {
            record_kind: version.meta.record_kind,
            symlink_target: version.meta.symlink_target.clone(),
            symlink_out_of_root: false,
            unix_mode: version.meta.unix_mode,
            xattrs: version.meta.xattrs.clone(),
        };
        Ok(Some((
            write_activity,
            yadorilink_peer_session::ports::PreparedProjectedUpsert {
                rel_path: target_path.to_string(),
                tmp_path,
                out_path,
                record,
                origin_device_id: head.device_id.clone(),
                authoring_change_hash: Some(ChangeHash(head.change_hash)),
                target_version_hash: intent_target_hash,
                metadata,
                derived_head: derived_head.cloned(),
                newly_fetched_block_hashes,
                // The version the temp file was reconstructed from, a few
                // lines above -- `record` itself is derived from it.
                written_version: version.clone(),
                // Filled in by `revalidate_ordinary_upsert`, under the
                // committing batch's own path lock. Nothing resolved here
                // would still be the frontier by then: this prepare step
                // runs unlocked, before the fetch.
                realized_causal_basis: Vec::new(),
            },
        )))
    }

    /// Commits `pending` in chunks of at most `ORDINARY_BATCH_MAX_PATHS`
    /// -- bounded the same way the Convergence Engine's own direct per-tick
    /// reconcile is, whatever the size of the pass that deferred them.
    async fn commit_pending_batch(
        &self,
        group_id: &str,
        origin_device_id: &str,
        pending: Vec<OrdinaryBatchItem<'_>>,
        call_timer: &crate::local_convergence::call_timer::ReconcileCallTimer,
    ) -> Result<
        (
            std::collections::BTreeMap<String, SettlementEvidence>,
            std::collections::BTreeSet<String>,
        ),
        PeerSessionError,
    > {
        let mut settled = std::collections::BTreeMap::new();
        let mut retry = std::collections::BTreeSet::new();
        let mut pending = pending.into_iter();
        loop {
            let chunk: Vec<OrdinaryBatchItem> =
                (&mut pending).take(Self::ORDINARY_BATCH_MAX_PATHS).collect();
            if chunk.is_empty() {
                break;
            }
            let commit_started = std::time::Instant::now();
            let (chunk_settled, chunk_retry) = self
                .try_commit_ordinary_batch(group_id, origin_device_id, chunk, call_timer)
                .await?;
            call_timer.add_ordinary_commit(commit_started.elapsed());
            settled.extend(chunk_settled);
            retry.extend(chunk_retry);
        }
        Ok((settled, retry))
    }

    /// Diagnostic-only: correlates a conflict-copy output back to the seed
    /// path that produced it and the losing change it carries, so an
    /// intermittently stalled conflict-copy obligation can be traced to its
    /// seed. Silent for an output the fixpoint had `already_derived`.
    fn trace_conflict_copy_discovered(
        &self,
        group_id: &str,
        audit_attempt_id: u64,
        derived_from_path: &str,
        resolved_output_path: &str,
        loser: &PathHead,
        already_derived: bool,
    ) {
        if already_derived {
            return;
        }
        tracing::debug!(
            local_device_id = %self.local_device_id,
            group_id,
            audit_attempt_id,
            derived_from_path = %derived_from_path,
            resolved_output_path = %resolved_output_path,
            conflict_loser_change_hash = %hex::encode(loser.change_hash),
            conflict_loser_device_id = %loser.device_id,
            "conflict-copy output discovered by resolution fixpoint"
        );
    }

    /// Commits a bounded batch of ordinary upserts/deletes (each
    /// already classified as batch-eligible by the per-path loop in
    /// `reconcile_group_paths`) with just two `write_immediate` DB
    /// transactions total, instead of one per path per DB write. Acquires
    /// every item's path lock up front (canonical, sorted order -- the
    /// same discipline every other multi-path lock site in this crate
    /// uses), re-validates each candidate fresh under those locks (see
    /// `revalidate_ordinary_upsert`/the inline delete check below),
    /// commits the surviving upserts' rows/intents in one transaction
    /// (`open_projected_upserts_batch`), publishes each survivor's already-
    /// prepared temp file (or removes a delete's target) per path, then
    /// commits every survivor's completion (fingerprint/intent-clear for
    /// upserts, tombstone row/held-clear for deletes) in one final
    /// transaction (`finalize_projected_mutations_batch`) -- preserving
    /// the exact row-before-file (intent-protected) and disk-first-for-
    /// deletes crash orderings a single unbatched `materialize()` call
    /// already guarantees, just batched across up to
    /// `ORDINARY_BATCH_MAX_PATHS` paths at once.
    ///
    /// Every item in `items` lands in exactly one of the two returned sets
    /// -- same invariant `reconcile_group_paths` itself keeps for every
    /// path it examines.
    #[allow(
        clippy::too_many_lines,
        reason = "the batch's lock, revalidate, commit, publish and finalize phases share \
              one lock set and must keep the crash orderings documented above; they \
              are kept in one body so that ordering stays reviewable in one place"
    )]
    pub(crate) async fn try_commit_ordinary_batch(
        &self,
        group_id: &str,
        origin_device_id: &str,
        items: Vec<OrdinaryBatchItem<'_>>,
        call_timer: &crate::local_convergence::call_timer::ReconcileCallTimer,
    ) -> Result<
        (
            std::collections::BTreeMap<String, SettlementEvidence>,
            std::collections::BTreeSet<String>,
        ),
        PeerSessionError,
    > {
        let mut settled = std::collections::BTreeMap::new();
        let mut retry = std::collections::BTreeSet::new();
        if items.is_empty() {
            return Ok((settled, retry));
        }

        let mut sorted = items;
        sorted.sort_by(|a, b| a.path().cmp(b.path()));
        let mut _guards = Vec::with_capacity(sorted.len());
        // Index-based, not `for item in &sorted`: a borrowing iterator over
        // `OrdinaryBatchItem` would need `OrdinaryBatchItem: Sync` to stay
        // `Send` across the `.await` below, and the `Box<dyn Send + '_>`
        // activity guard it carries is (correctly) not `Sync`.
        #[allow(clippy::needless_range_loop)]
        for i in 0..sorted.len() {
            let path_lock = self.state.path_lock(group_id, sorted[i].path());
            _guards.push(path_lock.lock_owned().await);
        }

        let authority = self.root_lease_for(group_id)?;
        let authority_op = authority.begin_operation()?;
        let permit = authority_op.permit();

        // Kept alive (never inspected) until this whole batch's commit
        // work below finishes -- each is the SAME per-candidate block-
        // write-activity guard `prepare_ordinary_projected_upsert` already
        // acquired, so dropping it only now (rather than per-candidate,
        // right after its own commit) still satisfies "held from before
        // the fetch through the commit" and errs toward holding slightly
        // longer, never shorter.
        let mut _upsert_activity_guards: Vec<Box<dyn Send + '_>> = Vec::new();
        let mut candidate_upserts: Vec<yadorilink_peer_session::ports::PreparedProjectedUpsert> =
            Vec::new();
        let mut candidate_deletes: Vec<(String, ChangeHash)> = Vec::new();
        // Cross-file provenance batching: every hash ANY Upsert
        // candidate in this bounded chunk newly fetched, deduplicated --
        // collected regardless of whether that candidate survives
        // revalidation below, since its blocks are already durably
        // `store.put` either way and deserve provenance whether or not
        // THIS particular row ends up published this round.
        let mut pending_provenance_hashes: std::collections::HashSet<Vec<u8>> =
            std::collections::HashSet::new();
        for item in sorted {
            match item {
                OrdinaryBatchItem::Upsert(write_activity, prepared) => {
                    _upsert_activity_guards.push(write_activity);
                    pending_provenance_hashes
                        .extend(prepared.newly_fetched_block_hashes.iter().cloned());
                    if let Some(basis) =
                        self.revalidate_ordinary_upsert(group_id, &prepared, call_timer).await?
                    {
                        let mut prepared = *prepared;
                        prepared.realized_causal_basis = basis;
                        candidate_upserts.push(prepared);
                    } else {
                        // A rejected candidate's
                        // already-assembled temp file is otherwise never
                        // cleaned up (`reconstruct_file_to_temp` only
                        // removes it on an assembly failure, not on a
                        // caller later deciding not to publish it) --
                        // repeated staleness races would leak full-size
                        // temp files into the sync directory indefinitely.
                        let _ = std::fs::remove_file(&prepared.tmp_path);
                        retry.insert(prepared.rel_path);
                    }
                }
                OrdinaryBatchItem::Delete(path, _stale_tombstone_author, derived_head) => {
                    // Re-resolve fresh, now under this
                    // batch's lock, instead of trusting `stale_tombstone_
                    // author` or treating "a live row still exists" as
                    // proof the tombstone still wins. The unbatched Absent
                    // branch's own safety comes from holding the lock
                    // CONTINUOUSLY from its resolution through its delete
                    // (a near-zero window) -- deferring into a batch
                    // reopens that window to however long this batch spent
                    // preparing its OTHER candidates, during which a
                    // concurrent local create or a newer peer change can
                    // supersede this tombstone. `still_live` alone cannot
                    // detect that: a racing create also leaves the row
                    // live, so checking only liveness (not who currently
                    // wins) would delete the new content just as readily
                    // as the genuinely-still-deleted case. Mirrors
                    // `revalidate_ordinary_upsert`'s identical reasoning
                    // for the upsert side.
                    let dag_started = std::time::Instant::now();
                    let fresh = self.combined_heads(group_id, &path, derived_head.as_ref())?;
                    call_timer.add_dag_resolution(dag_started.elapsed());
                    if fresh.is_empty() {
                        retry.insert(path);
                        continue;
                    }
                    let tombstone_author = match resolve_path_heads(&path, &fresh) {
                        PathResolution::Present { .. } => {
                            // Superseded by new content since the unlocked
                            // classification pass -- must not delete;
                            // retry so the next pass resolves it as
                            // Present and materializes the real winner.
                            retry.insert(path);
                            continue;
                        }
                        PathResolution::Absent => ChangeHash(
                            fresh
                                .iter()
                                .map(|h| h.change_hash)
                                .max()
                                .expect("Absent resolution has at least one head"),
                        ),
                    };
                    let record = FileRecord {
                        path: path.clone(),
                        size: 0,
                        mtime_unix_nanos: 0,
                        blocks: Vec::new(),
                        deleted: true,
                    };
                    if self.hazard_reason_for(group_id, &record)?.is_some() {
                        // Extremely rare (hazard appearing between this
                        // path's unlocked classification and this locked
                        // recheck): simplest safe response is to retry --
                        // the next reconcile pass's own unlocked
                        // classification will see the hazard and route it
                        // through the existing serial `materialize()` call,
                        // which handles holding it correctly.
                        retry.insert(path);
                        continue;
                    }
                    let still_live =
                        self.state.get_file(group_id, &path)?.map(|r| !r.deleted).unwrap_or(false);
                    if still_live {
                        candidate_deletes.push((path, tombstone_author));
                    } else if let Some(evidence) =
                        self.settle_directory_at_deleted_path(group_id, &path)?
                    {
                        // A directory still stands at an already-deleted
                        // path. Decided now, never retried: see
                        // `settle_directory_at_deleted_path`.
                        settled.insert(path, evidence);
                    } else if !self.observably_absent_on_disk(group_id, &path)? {
                        // The row says deleted, but something is at this
                        // name. This attempt has observed no absence and
                        // may not claim one. Not deleted here either:
                        // those bytes may be a local edit nobody has
                        // indexed yet, and deciding that is local
                        // capture's job.
                        retry.insert(path);
                    } else {
                        // A genuinely already-settled tombstone
                        // (row exists, already deleted, authoring hash
                        // already this exact tombstone) must cost zero
                        // writer_gate acquisitions, same principle as the
                        // content-identical fast path -- an
                        // unconditional `set_authoring_change_hash` here
                        // re-examines every re-driven tombstone's change
                        // (roughly 2x per path across a storm) into a real
                        // write even when nothing differs.
                        if self.state.get_file(group_id, &path)?.is_some()
                            && self.state.get_authoring_change_hash(group_id, &path)?.as_ref()
                                != Some(&tombstone_author)
                        {
                            self.state.set_authoring_change_hash(
                                group_id,
                                &path,
                                &tombstone_author,
                            )?;
                        }
                        let evidence = self.already_absent(group_id, &path)?;
                        settled.insert(path, evidence);
                    }
                }
            }
        }

        // Cross-file provenance batching: ONE `record_group_block_
        // provenance` call for this whole bounded commit chunk, BEFORE any
        // publish below -- crash-ordering requirement: fetch -> verify ->
        // store.put durable -> provenance batch durable -> publish. A
        // failure here fails every surviving upsert candidate in this
        // chunk closed (never published/settled this round, cleaned up
        // and left for retry) -- deletes in the same chunk are unaffected,
        // since they never depended on block provenance.
        if !pending_provenance_hashes.is_empty() {
            let hashes: Vec<Vec<u8>> = pending_provenance_hashes.into_iter().collect();
            if let Err(e) = self.flush_provenance_hashes(group_id, hashes, Some(call_timer)).await {
                tracing::warn!(
                    group_id,
                    error = %e,
                    "ordinary-batch cross-file provenance flush failed; leaving every \
                     surviving upsert in this chunk unapplied for retry"
                );
                for prepared in candidate_upserts.drain(..) {
                    let _ = std::fs::remove_file(&prepared.tmp_path);
                    retry.insert(prepared.rel_path);
                }
            }
        }

        if !candidate_upserts.is_empty() {
            let open_batch_started = std::time::Instant::now();
            let gate_before = yadorilink_sqlite_runtime::writer_gate_stats::stats().1;
            self.state.open_projected_upserts_batch(group_id, &candidate_upserts, &permit)?;
            let open_batch_elapsed = open_batch_started.elapsed();
            let gate_wait =
                yadorilink_sqlite_runtime::writer_gate_stats::stats().1.saturating_sub(gate_before);
            call_timer.add_sqlite_write(open_batch_elapsed, gate_wait);
        }

        // No batch-wide basis is read here any more. Each candidate
        // carries the frontier its own revalidation resolved, captured
        // under that path's lock immediately before this loop writes it --
        // which is the frontier the write realizes. One shared read taken
        // here would instead name the group's frontier at the moment the
        // first path in the batch started, for every path in it.
        let mut finished_upserts = Vec::with_capacity(candidate_upserts.len());
        for prepared in &candidate_upserts {
            // This is a mutator in its own right: this batched path
            // bypasses `materialize()` entirely, writing real content
            // directly -- `path_lock` is held for every path in this
            // batch via `_guards`, acquired above. Bump before the real
            // write below.
            // The version this publish is about comes from the payload it
            // is publishing, fixed when the temp file was built. Reading
            // it from the row -- even before the write -- would ask about
            // the row instead of about the bytes, and a supersession that
            // keeps the authoring identity moves the row's version
            // without moving anything this write can see.
            let mutation_generation = self.state.dag_bump_mutation_fence(
                group_id,
                &prepared.rel_path,
                "ordinary_batch_upsert_write",
            )?;
            let persist_result =
                persist_reconstructed_file_off_runtime(&prepared.tmp_path, &prepared.out_path)
                    .await;
            match persist_result {
                Ok(()) => {
                    // From `written_version`, the same payload version
                    // the proof below names and the temp file above was
                    // built from -- not from the row, which this batch
                    // has already upserted and which a concurrent
                    // supersession can move out from under this loop
                    // between one candidate and the next.
                    let kind = prepared.written_version.meta.record_kind;
                    let evidence = match self.finish_ordinary_batch_write(
                        group_id,
                        prepared,
                        kind,
                        mutation_generation,
                    ) {
                        Ok(Some(evidence)) => evidence,
                        // Superseded while this batch was writing. The
                        // finalizer's own guard would refuse it too; not
                        // adding it to `finished_upserts` keeps the two
                        // decisions from disagreeing, and not adding it to
                        // `settled` keeps evidence for a version this path
                        // has left from reaching the engine at all.
                        Ok(None) => {
                            retry.insert(prepared.rel_path.clone());
                            continue;
                        }
                        // This path's own file could not take its metadata
                        // or prove what it is. That is this path's problem:
                        // it keeps its intent open (repair or the retry
                        // reconstructs it, as after a failed rename above),
                        // and the rest of the batch still finalizes. A
                        // database, invariant or root failure is not, and
                        // still aborts the whole batch below.
                        Err(e) if ordinary_batch_error_is_path_local(&e) => {
                            tracing::warn!(
                                group_id,
                                path = %prepared.rel_path,
                                error = %e,
                                "ordinary-batch metadata or evidence failed for one path; \
                                 leaving its intent open and its change unapplied for retry"
                            );
                            retry.insert(prepared.rel_path.clone());
                            continue;
                        }
                        Err(e) => return Err(e),
                    };
                    // The finalizer publishes the proof for exactly what
                    // this evidence claims, under exactly the epoch this
                    // write produced -- so it is built from the same values,
                    // not re-derived later.
                    let version_hash = match &evidence {
                        SettlementEvidence::ExactObject { version, .. } => *version,
                        other => {
                            return Err(PeerSessionError::CorruptState(format!(
                                "{}: an ordinary batch write produced non-exact settlement \
                                 evidence: {other:?}",
                                prepared.rel_path
                            )))
                        }
                    };
                    finished_upserts.push(
                        yadorilink_peer_session::ports::FinishedProjectedUpsert {
                            rel_path: prepared.rel_path.clone(),
                            kind,
                            version_hash,
                            mutation_generation,
                            observed_identity:
                                yadorilink_root_authority::fs_identity::FileIdentity::observe_path(
                                    &prepared.out_path,
                                )
                                .ok(),
                            causal_basis: prepared.realized_causal_basis.clone(),
                            // What the row must still look like for this
                            // write's proof to be the truth about it: the
                            // authoring identity this candidate was
                            // revalidated against, and the state the
                            // open-batch transaction left it in.
                            expected_authoring: prepared.authoring_change_hash,
                            expected_state:
                                yadorilink_peer_session::ports::MATERIALIZATION_IN_FLIGHT_STATE,
                        },
                    );
                    settled.insert(prepared.rel_path.clone(), evidence);
                }
                Err(e) => {
                    // The row+intent were already committed above -- a
                    // publish failure here is safe to just retry: the
                    // intent is still open, so restart/periodic repair
                    // reconstructs from the locally-present blocks exactly
                    // as an unbatched crash-after-intent-open would.
                    tracing::warn!(
                        group_id,
                        path = %prepared.rel_path,
                        error = %e,
                        "ordinary-batch disk publish failed; leaving its intent open for \
                         repair and its change unapplied for retry"
                    );
                    retry.insert(prepared.rel_path.clone());
                }
            }
        }

        let mut finished_deletes = Vec::with_capacity(candidate_deletes.len());
        let mut retained_directories: Vec<(
            String,
            &'static str,
            Option<Box<yadorilink_root_authority::fs_identity::FileIdentity>>,
        )> = Vec::new();
        // Deepest first: every descendant of a path sorts after it, so in
        // reverse order a directory's deleted children are gone before the
        // directory's own `rmdir` runs, and an `rm -rf` arriving as point
        // deletes empties each directory before removing it.
        candidate_deletes.sort_by(|(a, _), (b, _)| b.cmp(a));
        for (path, tombstone_author) in candidate_deletes {
            let out_path = self.local_file_path(group_id, &path)?;
            if let Err(e) = self.verify_delete_target(group_id, &out_path) {
                tracing::warn!(
                    group_id, path = %path, error = %e,
                    "ordinary-batch delete target verification failed; leaving unapplied \
                     for retry"
                );
                retry.insert(path);
                continue;
            }
            // Bump before the real delete syscall below (same mutator
            // reasoning as the upsert side above).
            let mutation_generation =
                self.state.dag_bump_mutation_fence(group_id, &path, "ordinary_batch_delete")?;
            let removal = match self.remove_for_tombstone(group_id, &path, &out_path) {
                Ok(removal) => removal,
                Err(e) => {
                    tracing::warn!(
                        group_id, path = %path, error = %e,
                        "ordinary-batch delete failed; leaving unapplied for retry"
                    );
                    retry.insert(path);
                    continue;
                }
            };
            let record = FileRecord {
                path: path.clone(),
                size: 0,
                mtime_unix_nanos: 0,
                blocks: Vec::new(),
                deleted: true,
            };
            finished_deletes.push(yadorilink_peer_session::ports::PreparedProjectedDelete {
                rel_path: path.clone(),
                out_path,
                record,
                origin_device_id: origin_device_id.to_string(),
                authoring_change_hash: Some(tombstone_author),
            });
            match removal {
                super::types::TombstoneRemoval::Removed => {
                    settled.insert(path, SettlementEvidence::ExactAbsent { mutation_generation });
                }
                super::types::TombstoneRemoval::Retained { reason, removable } => {
                    retained_directories.push((path.clone(), reason, removable));
                    settled
                        .insert(path, SettlementEvidence::Retained { reason: reason.to_string() });
                }
            }
        }

        if !finished_upserts.is_empty() || !finished_deletes.is_empty() {
            let finalize_started = std::time::Instant::now();
            let gate_before = yadorilink_sqlite_runtime::writer_gate_stats::stats().1;
            let published = self.state.finalize_projected_mutations_batch(
                group_id,
                &finished_upserts,
                &finished_deletes,
                &permit,
            )?;
            // A candidate the finalizer refused published nothing, so it
            // is not settled either. Its evidence names the version this
            // write realized, and the path has since moved off it --
            // leaving it in `settled` hands that evidence to the engine,
            // which publishes CASing only on the fence and would land the
            // very proof the finalizer just declined to write.
            for upsert in &finished_upserts {
                if !published.contains(&upsert.rel_path) {
                    settled.remove(&upsert.rel_path);
                    retry.insert(upsert.rel_path.clone());
                }
            }
            // Recorded once the deletes are: the record is what a retained
            // settlement closes against, and it must not outlive a finalize
            // that failed.
            for (path, reason, removable) in &retained_directories {
                self.keep_directory_a_delete_found_not_empty(
                    group_id,
                    path,
                    reason,
                    removable.as_deref(),
                )?;
            }
            let finalize_elapsed = finalize_started.elapsed();
            let gate_wait =
                yadorilink_sqlite_runtime::writer_gate_stats::stats().1.saturating_sub(gate_before);
            call_timer.add_sqlite_write(finalize_elapsed, gate_wait);
        }

        Ok((settled, retry))
    }

    /// Projects a set of touched paths into the materialized index through one
    /// conflict-copy-aware fixpoint fold — the engine's counterpart to the
    /// property suite's `fold_materialize`, so the two cannot disagree on
    /// nested-overlap corners.
    ///
    /// A conflict copy is content the *losing* change materializes at a derived
    /// path; that path is first-class, so it is folded together with any change
    /// that directly touches it (with cross-supersession), and it is only
    /// (re)materialized if it survives — a delete of a conflict copy sticks, and
    /// a conflict-copy path independently edited resolves as an ordinary path.
    /// The fixpoint discovers derived copy paths (bounded: copy names embed the
    /// losing version hash), then a single pass materializes each path's result:
    /// *absent* → a deletion (the no-resurrection guarantee), *present* → the
    /// winning content head via the session's block-fetch machinery.
    #[allow(
        clippy::too_many_lines,
        reason = "the conflict-copy fixpoint and the single materialize pass that consumes \
              it share every map the fixpoint builds; the fold mirrors the property \
              suite's `fold_materialize` and is kept whole so the two can be compared"
    )]
    async fn reconcile_group_paths(
        &self,
        group_id: &str,
        mut seed_paths: std::collections::BTreeSet<String>,
        // Who to attribute an adopted record to. Genuinely a peer's identity
        // when a peer drove this pass, and this device's own when nothing but
        // this device did.
        origin_device_id: &str,
        // What the pre-pass observed for each path whose content it went and
        // obtained, by path. A path with no entry was never asked for.
        prefetched: &HashMap<String, BlockRequirement>,
        audit_attempt_id: u64,
        // The whole attempt's timer, owned by the caller. Not created here:
        // an attempt that obtains content does that BEFORE this function is
        // entered, so a timer created here can never see this attempt's
        // block fetching -- see `reconcile_paths_directly`'s own comment.
        call_timer: &crate::local_convergence::call_timer::ReconcileCallTimer,
    ) -> Result<ProjectionAttempt, PeerSessionError> {
        let call_started = std::time::Instant::now();
        // A copy name with no head of its own is placed by its source's
        // resolution -- a conflict copy of a losing head, or a leaf moved
        // aside for a directory -- so it is decided with its source. Asked
        // for alone (an installed base places rows at copy names, and
        // releasing the install's hold on one raises its obligation), it
        // would resolve from no heads and never settle.
        let mut copy_sources = Vec::new();
        for path in &seed_paths {
            if yadorilink_replica_domain::conflict::is_conflict_copy_path(path)
                && self.store_live_heads_for_path(group_id, path)?.is_empty()
            {
                copy_sources
                    .push(yadorilink_replica_domain::conflict::conflict_copy_source_path(path));
            }
        }
        seed_paths.extend(copy_sources);
        // The namespace closure. A path is decided with its ancestors: one
        // whose own heads name a File or Symlink has to move aside while
        // anything lives below it and comes back once nothing does, and
        // only a pass over a descendant ever learns either. Ancestors with
        // no leaf of their own are directories or nothing; the mkdir of a
        // write and the prune after a delete decide those.
        //
        // On a volume that folds names, an ancestor the tree needs as a
        // directory can have its name held by a tracked file spelled
        // differently (`A` for `a`): that file has to step aside on this
        // device alone, so it joins the pass too. And an entry held aside
        // that way joins every pass over its level, so it takes its name
        // back once the directory is gone.
        let mut ancestors_with_leaves = std::collections::BTreeSet::new();
        let mut folded_leaves = std::collections::BTreeSet::new();
        let held_beside_folded = self
            .state
            .entries_held_beside_folded_directories(group_id)
            .map_err(crate::sync_error::SyncError::from)?;
        let mut held_aside = std::collections::BTreeSet::new();
        for path in &seed_paths {
            if self.is_locally_ignored(group_id, path) {
                continue;
            }
            for ancestor in self.ancestors_holding_leaves(group_id, path)? {
                if !self.is_locally_ignored(group_id, &ancestor) {
                    ancestors_with_leaves.insert(ancestor);
                }
            }
            for ancestor in super::namespace_steps::proper_ancestors(path) {
                let Some(leaf) = self.folded_leaf_in_the_way(group_id, ancestor)? else {
                    continue;
                };
                if self.is_locally_ignored(group_id, &leaf)
                    || !self.namespace_needs_directory(group_id, ancestor)?
                {
                    continue;
                }
                folded_leaves.insert(leaf);
            }
            for level_mate in
                std::iter::once(path.as_str()).chain(super::namespace_steps::proper_ancestors(path))
            {
                let level = super::namespace_steps::parent_of(level_mate);
                held_aside.extend(
                    held_beside_folded
                        .iter()
                        .filter(|held| super::namespace_steps::parent_of(held) == level)
                        .filter(|held| !self.is_locally_ignored(group_id, held))
                        .cloned(),
                );
            }
        }
        seed_paths.extend(ancestors_with_leaves);
        seed_paths.extend(folded_leaves.iter().cloned());
        seed_paths.extend(held_aside);
        let fixpoint_started = std::time::Instant::now();
        // What the namespace requires of each path on its own account, read
        // once. `None` when it cannot be decided locally yet (a live
        // version this replica does not hold): the path then takes its
        // per-path resolution, and materializing it fails closed on the
        // same missing version.
        let mut desired_of: std::collections::BTreeMap<
            String,
            Option<yadorilink_sync_sqlite::desired_state::DesiredPathState>,
        > = std::collections::BTreeMap::new();
        // path -> the copy names its relocated File or Symlink winner takes
        // because the path has to be a directory.
        let mut relocations: std::collections::BTreeMap<String, Vec<String>> =
            std::collections::BTreeMap::new();
        // copy_path -> the losing content head that materializes there.
        let mut derived: std::collections::BTreeMap<String, PathHead> =
            std::collections::BTreeMap::new();
        // copy_path -> the path whose resolution DEMANDS that copy's content.
        //
        // A conflict copy is never something anyone asks for by name: it
        // exists only because resolving a source path produced it, at a name
        // only the resolution knows. Every gate that asks "did something
        // request this content" has to ask about the source, or an on-demand
        // folder refuses the copy forever and the source can never settle.
        // Inherited transitively, so a copy derived from a copy still names
        // the seed path that ultimately demanded it.
        let mut demand_of: std::collections::BTreeMap<String, String> =
            std::collections::BTreeMap::new();
        loop {
            let mut next = derived.clone();
            let paths: std::collections::BTreeSet<String> =
                seed_paths.iter().cloned().chain(derived.keys().cloned()).collect();
            for path in &paths {
                // Derive nothing from a path this device ignores. A conflict
                // copy carries the losing head's content to a *different* name
                // (it embeds the version hash), and that derived name will not
                // generally match the pattern that excluded the original — a
                // literal `secret.log` rule does not match
                // `secret (conflict …).log`. Resolving an ignored path here
                // would therefore launder its content past the user's own
                // filter under a name they never wrote a rule for. Skipping it
                // in the fixpoint is what keeps the exclusion airtight; the
                // materialize pass below re-checks each derived name on its own
                // merits, so a copy path that is itself ignored is dropped too.
                if self.is_locally_ignored(group_id, path) {
                    continue;
                }
                let dag_started = std::time::Instant::now();
                let inputs = self.combined_heads(group_id, path, derived.get(path))?;
                call_timer.add_dag_resolution(dag_started.elapsed());
                if inputs.is_empty() {
                    continue;
                }
                if let PathResolution::Present { winner, conflict_copies } =
                    resolve_path_heads(path, &inputs)
                {
                    if !derived.contains_key(path) && !desired_of.contains_key(path) {
                        let (desired, relocated) =
                            self.namespace_relocation(group_id, path, &inputs[winner])?;
                        desired_of.insert(path.clone(), desired);
                        let copies = relocated.clone().unwrap_or_default();
                        let demand = demand_of.get(path).cloned().unwrap_or_else(|| path.clone());
                        next.extend(
                            copies.iter().map(|copy| (copy.clone(), inputs[winner].clone())),
                        );
                        demand_of.extend(copies.iter().map(|copy| (copy.clone(), demand.clone())));
                        relocations.extend(relocated.map(|copies| (path.clone(), copies)));
                    }
                    // A Directory loses its metadata to the winning
                    // directory's and is owed no copy: an empty directory
                    // beside the path carries nothing.
                    let conflict_copies =
                        self.leaf_conflict_copies(group_id, &inputs, conflict_copies)?;
                    for cc in conflict_copies {
                        self.trace_conflict_copy_discovered(
                            group_id,
                            audit_attempt_id,
                            path,
                            &cc.path,
                            &inputs[cc.head],
                            derived.contains_key(&cc.path),
                        );
                        let demand = demand_of.get(path).cloned().unwrap_or_else(|| path.clone());
                        demand_of.entry(cc.path.clone()).or_insert(demand);
                        next.insert(cc.path.clone(), inputs[cc.head].clone());
                    }
                }
            }
            // `derived` only ever grows, so a stable size means a fixpoint.
            if next.len() == derived.len() {
                break;
            }
            derived = next;
        }
        let fixpoint_elapsed = fixpoint_started.elapsed();
        if fixpoint_elapsed > std::time::Duration::from_secs(1) {
            tracing::warn!(
                group_id,
                audit_attempt_id,
                elapsed_ms = fixpoint_elapsed.as_millis(),
                seed_path_count = seed_paths.len(),
                derived_path_count = derived.len(),
                "reconcile_group_paths conflict-copy fixpoint took unusually long"
            );
        }
        // Permanent guard against an unbounded `MaterializationAuditGuard`
        // hold (the reason every caller of this function is bounded to
        // a small seed-path window in the first place, most notably the
        // Convergence Engine's own `MAX_PATHS_PER_RECONCILE_ATTEMPT`-bounded
        // `reconcile_paths_directly`): a small seed-path window can still
        // expand into a much larger materialize workload below if its
        // paths happen to have many concurrent conflict-copy losers, since
        // this fixpoint's own derived-path discovery has no independent
        // bound. Confirmed NOT the cause of that incident (the actual call
        // logged `seed_path_count=993, derived_path_count=0`), so not
        // truncated/deferred here -- doing that safely would need to
        // preserve `resolve_path_heads`'s per-path winner/loser
        // classification, which needs every live head for a path in view
        // at once, and warrants its own careful design if this ever fires
        // for real. Logged so a real occurrence is visible rather than
        // silently repeating that incident via a different path.
        if derived.len() > UNUSUALLY_LARGE_CONFLICT_COPY_FIXPOINT_THRESHOLD {
            tracing::warn!(
                group_id,
                audit_attempt_id,
                seed_path_count = seed_paths.len(),
                derived_path_count = derived.len(),
                "reconcile_group_paths: conflict-copy fixpoint derived significantly more paths \
                 than this call's own seed-path window bound; the materialize step below may \
                 still take a long time while holding MaterializationAuditGuard"
            );
        }
        let materialize_started = std::time::Instant::now();

        let paths: std::collections::BTreeSet<String> =
            seed_paths.iter().cloned().chain(derived.keys().cloned()).collect();
        // Fail closed on the link table rather than defaulting the policy: a
        // missing row used to resolve to `Eager`, so an unlinked folder was the
        // *most* aggressive materialization target in the system.
        //
        // Report every path as unprojected rather than returning "none failed":
        // this function's result is the set the caller must NOT mark applied, so
        // an empty set here would record the batch as projected into a folder
        // that was never written to, and a later relink would never re-project
        // it.
        let LinkGate::Live { policy, .. } = self.state.link_gate_for_group(group_id)? else {
            return Ok(ProjectionAttempt { settled: Default::default(), retry: paths });
        };
        // A path under a paused item is not written while the pause lasts.
        // The projection scheduler already leaves such a path unclaimed;
        // this covers every other way into this pass (the hazard recheck,
        // an attempt claimed just before the pause landed). `retry`, never
        // `settled`: the change stays outstanding, and resume re-arms it.
        //
        // A path a snapshot install holds is held back the same way: its
        // disk still carries what the replaced row placed, or an uncaptured
        // edit of it, and projecting over that would destroy it unexamined.
        // Releasing the hold schedules the projection again.
        let mut paused = self
            .state
            .paused_item_repository()
            .list(group_id)
            .map_err(crate::sync_error::SyncError::from)
            .map_err(PeerSessionError::from)?;
        paused.extend(
            self.state
                .snapshot_install_hold_repository()
                .held_paths(group_id)
                .map_err(crate::sync_error::SyncError::from)
                .map_err(PeerSessionError::from)?,
        );
        // Every path this call resolves lands in exactly one of these two
        // sets by the end of the loop below — see `ProjectionAttempt`'s own
        // doc comment for why that invariant matters. A per-path write
        // failure (disk-full, missing block, I/O, materialize error) goes to
        // `retry` and the sweep continues, rather than `?`-aborting the
        // whole batch: the caller marks only changes whose paths are ALL in
        // `settled` as applied, and the rest re-project later.
        // Non-path-specific errors (a DAG/DB read failing) still propagate
        // via `?`, since they are not attributable to one path and mean
        // nothing projected reliably.
        let mut settled: std::collections::BTreeMap<String, SettlementEvidence> =
            std::collections::BTreeMap::new();
        let mut retry: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        // Paths classified as batch-eligible ("ordinary": no hazard,
        // no symlink, eager-admitted, every block fetchable) below are
        // accumulated here instead of materializing immediately one at a
        // time -- committed in bounded chunks via `try_commit_ordinary_
        // batch` after this loop. Every other path (including every
        // classification failure) still materializes immediately, inline,
        // exactly as before this batching existed.
        //
        // Declared once, here, so every batched candidate's block-write-
        // activity guard (acquired in `prepare_ordinary_projected_upsert`)
        // borrows from this SAME long-lived reference and can be kept alive
        // all the way to `try_commit_ordinary_batch`'s own commit step --
        // see that guard's own doc comment.
        let activity_provider = self.block_write_activity_provider();
        // Cross-file provenance batching: see `ReconcileProvenance
        // Batch`'s own doc comment. One instance for this whole call's
        // per-path preparation loop (so dedup evidence is visible across
        // every ordinary candidate this call prepares), but the actual SQL
        // flush stays bounded to `try_commit_ordinary_batch`'s own
        // ORDINARY_BATCH_MAX_PATHS-sized commit chunks, not this call's
        // (potentially conflict-copy-expanded) full `paths` set.
        let reconcile_provenance_batch = ReconcileProvenanceBatch::new();
        let mut pending_batch: Vec<OrdinaryBatchItem<'_>> = Vec::new();
        // Plan order: every removal first, deepest first, so a directory is
        // emptied before anything is decided about its own name; then
        // everything else shallowest first, so a directory exists before
        // anything is written into it, and a relocated file's copy is
        // written before the name it leaves is turned into a directory.
        let (order, phase_two_start) =
            self.namespace_order(group_id, &paths, &derived, &desired_of)?;
        // Paths the namespace could not shape in this pass and that are not
        // a directory on disk. Nothing below one is written until a later
        // pass shapes it: writing a descendant would create the directory
        // itself, under a name whose index row may still claim the leaf that
        // was being moved aside -- which repair then reads as a directory
        // standing where a tracked file belongs, and moves aside.
        let mut unshaped: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for (index, path) in order.iter().enumerate() {
            if index == phase_two_start {
                // The removals are done before anything is written: commit
                // them, and prune the directories they emptied.
                let (removed, failed) = self
                    .commit_pending_batch(
                        group_id,
                        origin_device_id,
                        std::mem::take(&mut pending_batch),
                        call_timer,
                    )
                    .await?;
                settled.extend(removed);
                retry.extend(failed);
                self.remove_emptied_retained_ancestors(
                    group_id,
                    settled
                        .iter()
                        .filter(|(_, evidence)| {
                            matches!(evidence, SettlementEvidence::ExactAbsent { .. })
                        })
                        .map(|(path, _)| path),
                )
                .await;
            }
            // Without this the DAG path — which every pair of
            // current-build peers negotiates — writes and indexes a peer's
            // file that matches this device's `.yadorilinkignore`.
            // Deliberately NOT added to `failed`: `failed` means "retry
            // this", and an ignored path is a decision, not a fault.
            // Recording it as a failure would hold its change unprojected
            // forever, so the reprojection backstop would re-drive it
            // every cycle and the change would never retire. Skipping as a
            // *success* lets the change mark applied and this device's
            // heads advance past it — so the next heads exchange shows the
            // peer we already hold it and it is never re-sent. The DAG
            // settles; the bytes just never land. Uniform across Present
            // and Absent (tombstone) alike, matching the legacy filter,
            // which dropped the record before ever reading its `deleted`
            // flag: an ignored path is simply not a path this device
            // accepts peer decisions about, in either direction. A
            // tombstone for a path ignored from the start is a no-op
            // anyway (nothing was ever indexed to delete); for a path
            // materialized *before* it became ignored, declining the
            // delete leaves the user's local copy intact, which is the
            // safe half of an unavoidable ambiguity — the ignore set is
            // device-local, so no peer can know to stop sending, and
            // honoring a remote delete against a locally-excluded path
            // would let a purely local config edit turn into
            // remote-triggered data loss. Nothing is evicted here for the
            // same reason: an already- materialized file that later
            // becomes ignored keeps its bytes and its index row (they
            // agree — the file really is on disk), so it never takes the
            // "index row for a file the user does not have" shape that
            // gets misread as an offline delete.
            if self.is_locally_ignored(group_id, path) {
                tracing::debug!(
                    group_id,
                    path = %path,
                    "not projecting a change-DAG path matching this device's ignore patterns"
                );
                settled.insert(path.clone(), SettlementEvidence::IgnoreExcluded);
                continue;
            }
            if yadorilink_sync_sqlite::paused_items::path_is_covered(&paused, path) {
                tracing::debug!(group_id, path = %path, "not projecting a path under a paused item or an unreconciled snapshot install");
                retry.insert(path.clone());
                continue;
            }
            let dag_started = std::time::Instant::now();
            let mut inputs = self.combined_heads(group_id, path, derived.get(path))?;
            call_timer.add_dag_resolution(dag_started.elapsed());
            if inputs.is_empty() {
                // An installed base carries only present heads: a path the
                // base and everything written on it leave absent has no head
                // at all, where retained history would still hold the
                // removal that ended it. Absent in the index and on disk,
                // there is nothing left to do at it.
                if self.absent_under_installed_base(group_id, path)? {
                    settled.insert(path.clone(), self.already_absent(group_id, path)?);
                    continue;
                }
                // No live heads at all for a path this call was asked to
                // resolve — genuinely ambiguous (this device's own DAG
                // state may simply be behind), not a positive proof of
                // anything. Fail closed: `retry`, never `settled` (see
                // `ProjectionAttempt`'s own doc comment).
                retry.insert(path.clone());
                continue;
            }
            let mut resolution = resolve_path_heads(path, &inputs);
            if matches!(resolution, PathResolution::Absent) {
                // A path resolves Absent only when every live head is a
                // tombstone (no content head survives). Before acting on that
                // as a delete, capture any local edit to this path that is
                // still sitting undispatched in this link's debounce
                // accumulator. The admission loop in `handle_change_batch`
                // flushes only the paths in the *triggering* change's own ops;
                // a path folded into this projection by a promoted orphan
                // (whose parent touched a different path) is never flushed
                // there. Left unflushed, a genuine concurrent local edit is
                // invisible to the resolution above, which then reads the path
                // as Absent and deletes it — losing the edit with no conflict
                // copy. Flush it now (before any delete and before any path
                // lock — the flush dispatches through the ordinary local-change
                // path, which takes the path lock itself, and this branch holds
                // no lock here, so there is no deadlock), then re-resolve. The
                // now-live local content head turns the resolution into
                // Present, so the file is kept instead of deleted — exactly the
                // same flush `materialize_dag_content_head` performs for the
                // Present branch, hoisted ahead of the resolution so it can
                // still flip a delete decision. (Because Absent means there was
                // no content head at all, a flushed edit adds exactly one, so
                // the re-resolution never yields a conflict copy here.)
                if self.flush_local_changes_before_reconcile(group_id, path).await
                    == PendingLocalFlushOutcome::RetryRequired
                {
                    // A local edit to this path could not be captured, so
                    // the Absent verdict may be missing it: never delete
                    // on it. Leave the obligation for a later pass.
                    retry.insert(path.clone());
                    continue;
                }
                let dag_started = std::time::Instant::now();
                inputs = self.combined_heads(group_id, path, derived.get(path))?;
                call_timer.add_dag_resolution(dag_started.elapsed());
                if inputs.is_empty() {
                    // Same reasoning as the first `inputs.is_empty()` check
                    // above: ambiguous, not a positive proof — `retry`.
                    retry.insert(path.clone());
                    continue;
                }
                resolution = resolve_path_heads(path, &inputs);
            }
            yadorilink_peer_session::dst_trace(path, || {
                let heads: Vec<String> = inputs
                    .iter()
                    .map(|h| {
                        format!(
                            "{}@{}{}",
                            hex::encode(&h.change_hash[..4]),
                            h.device_id,
                            if h.content.is_some() { "" } else { ":tomb" }
                        )
                    })
                    .collect();
                let outcome = match &resolution {
                    PathResolution::Absent => "Absent".to_string(),
                    PathResolution::Present { winner, conflict_copies } => format!(
                        "Present winner={} copies={}",
                        hex::encode(&inputs[*winner].change_hash[..4]),
                        conflict_copies.len()
                    ),
                };
                format!("reconcile on {}: heads={heads:?} -> {outcome}", self.local_device_id)
            });
            match resolution {
                PathResolution::Absent => {
                    let tombstone_author = ChangeHash(
                        inputs
                            .iter()
                            .map(|head| head.change_hash)
                            .max()
                            .expect("Absent resolution has at least one head"),
                    );
                    // Every live head removed the path — materialize the deletion
                    // if the index still shows it live. A stale content change
                    // that is an ancestor of the tombstone never reaches the live
                    // set, so this can never resurrect a deleted file.
                    //
                    // Held across the still-live check AND the materialize call
                    // below, matching `materialize_dag_content_head`'s identical
                    // discipline for the Present branch (see its own comment on
                    // why). Without this, a concurrent local write to this same
                    // path -- e.g. the filename being reused by a brand-new
                    // local create shortly after this device's own earlier
                    // delete, which `local_change.rs`'s own commit path takes
                    // this same lock for -- can interleave between the check and
                    // the previously-unlocked materialize() below: the new
                    // create's content and index row land first, then this
                    // stale tombstone's materialize() removes that brand-new
                    // file and overwrites its live index row with `deleted:
                    // true` -- an index-says-deleted/disk-had-content mismatch
                    // that no later re-resolution can detect, since every
                    // device involved already believes it is consistent.
                    // Confirmed as the actual cause of a real, reproduced
                    // divergence: four devices with byte-identical DAG heads
                    // each ended up with their own un-merged local tombstone
                    // for the same repeatedly-recreated path.
                    //
                    // An ordinary (non-hazardous) delete needs none of
                    // `materialize()`'s slow work -- defer it into the
                    // bounded batch below instead of taking this path's lock
                    // and materializing immediately. `try_commit_ordinary_
                    // batch` re-resolves this path's DAG heads fresh (and
                    // reruns the hazard check) under its own lock before
                    // acting -- not just a `still_live` recheck, which
                    // cannot by itself distinguish a genuinely-still-deleted
                    // path from one a concurrent local recreate revived in
                    // the window this deferral reopens (see its own doc
                    // comment).
                    // A hazardous tombstone is NOT deferred: its
                    // hold-handling stays on the existing serial path below,
                    // matching every other hazard case's scoping.
                    let synthetic_tombstone_for_hazard_check = FileRecord {
                        path: path.clone(),
                        size: 0,
                        mtime_unix_nanos: 0,
                        blocks: Vec::new(),
                        deleted: true,
                    };
                    if self
                        .hazard_reason_for(group_id, &synthetic_tombstone_for_hazard_check)?
                        .is_none()
                    {
                        pending_batch.push(OrdinaryBatchItem::Delete(
                            path.clone(),
                            tombstone_author,
                            derived.get(path).cloned(),
                        ));
                        continue;
                    }
                    let lock_wait_started = std::time::Instant::now();
                    let path_lock = self.state.path_lock(group_id, path);
                    let _guard = path_lock.lock().await;
                    let lock_wait_elapsed = lock_wait_started.elapsed();
                    if lock_wait_elapsed > std::time::Duration::from_secs(1) {
                        tracing::warn!(
                            group_id,
                            path = %path,
                            lock_wait_elapsed_ms = lock_wait_elapsed.as_millis(),
                            "absent-branch path-lock wait took unusually long"
                        );
                    }
                    let still_live =
                        self.state.get_file(group_id, path)?.map(|r| !r.deleted).unwrap_or(false);
                    if !still_live && !self.observably_absent_on_disk(group_id, path)? {
                        // Same as the batch lane: a tombstoned row is not
                        // an observation of absence, and this attempt has
                        // made none.
                        retry.insert(path.clone());
                        continue;
                    }
                    if still_live {
                        let record = FileRecord {
                            path: path.clone(),
                            size: 0,
                            mtime_unix_nanos: 0,
                            blocks: Vec::new(),
                            deleted: true,
                        };
                        // A DAG tombstone is a materialization operation, not
                        // merely an index update.  Going straight to
                        // `upsert_file` leaves the old bytes on disk while the
                        // index says they are deleted; route through the same
                        // removal path as legacy peer reconciliation so an I/O
                        // failure keeps the change unapplied for retry.
                        let materialize_started = std::time::Instant::now();
                        // A tombstone names no content, so this can only
                        // conclude -- it has nothing to ask a peer for.
                        // A tombstone names no content, so its payload
                        // version is simply the one this empty record
                        // derives -- there is nothing on disk for it to
                        // disagree with.
                        let payload = MaterializationPayload::tombstone(record.clone());
                        let materialize_result = self
                            .materialize_local(
                                group_id,
                                &payload,
                                &record.path,
                                policy,
                                origin_device_id,
                                Some(&tombstone_author),
                                None,
                            )
                            .await
                            .map(|outcome| match outcome {
                                LocalMaterializeOutcome::Concluded(result) => result,
                                LocalMaterializeOutcome::NeedBlocks(_) => {
                                    MaterializeResult::RetryRequired
                                }
                            });
                        let materialize_elapsed = materialize_started.elapsed();
                        if materialize_elapsed > std::time::Duration::from_secs(1) {
                            tracing::warn!(
                                group_id,
                                path = %path,
                                elapsed_ms = materialize_elapsed.as_millis(),
                                "absent-branch materialize() call took unusually long"
                            );
                        }
                        match materialize_result {
                            Ok(MaterializeResult::Settled(evidence)) => {
                                settled.insert(path.clone(), evidence);
                            }
                            // Matches the `Present` branch's identical
                            // distinction just below: a hazard-collision
                            // tombstone that dropped without applying
                            // anything reports `RetryRequired`, and this
                            // branch must not fold that into `settled` --
                            // this was the only caller of `materialize` for
                            // a deletion that collapsed every `Ok(_)` into
                            // "done", silently discarding the distinction
                            // `MaterializeResult` exists to preserve.
                            Ok(MaterializeResult::RetryRequired) => {
                                retry.insert(path.clone());
                            }
                            Err(e) => {
                                tracing::warn!(
                                    group_id,
                                    path = %path,
                                    error = %e,
                                    "failed to project a deletion; leaving its change(s) unapplied"
                                );
                                retry.insert(path.clone());
                            }
                        }
                    } else {
                        // Already not live -- the deletion is already
                        // reflected, nothing to do this attempt.
                        //
                        // Same principle as the ordinary batch
                        // delete branch's identical fix -- an unconditional
                        // `set_authoring_change_hash` here costs a
                        // writer_gate acquisition on every re-drive of an
                        // already-fully-settled tombstone, even when the
                        // authoring hash already matches exactly.
                        if self.state.get_file(group_id, path)?.is_some()
                            && self.state.get_authoring_change_hash(group_id, path)?.as_ref()
                                != Some(&tombstone_author)
                        {
                            self.state.set_authoring_change_hash(
                                group_id,
                                path,
                                &tombstone_author,
                            )?;
                        }
                        settled.insert(path.clone(), self.already_absent(group_id, path)?);
                    }
                }
                PathResolution::Present { winner, .. } => {
                    if super::namespace_steps::proper_ancestors(path)
                        .any(|ancestor| unshaped.contains(ancestor))
                    {
                        tracing::debug!(
                            group_id,
                            path = %path,
                            "an ancestor did not take the shape its namespace requires in this \
                             pass; not writing below it yet"
                        );
                        retry.insert(path.clone());
                        continue;
                    }
                    // The namespace first: a path a live descendant needs
                    // is a directory whatever its own heads say, and an
                    // entry cannot take a name a directory holds.
                    if !derived.contains_key(path) {
                        match self
                            .namespace_step(
                                group_id,
                                path,
                                demand_of.get(path).map_or(path.as_str(), String::as_str),
                                &inputs,
                                winner,
                                desired_of.get(path).cloned().flatten(),
                                &derived,
                                &settled,
                                folded_leaves.contains(path),
                                policy,
                                prefetched.get(path.as_str()),
                            )
                            .await
                        {
                            Ok(None) => {}
                            Ok(Some(MaterializeResult::Settled(evidence))) => {
                                settled.insert(path.clone(), evidence);
                                continue;
                            }
                            Ok(Some(MaterializeResult::RetryRequired)) => {
                                unshaped.extend(
                                    (!self.directory_on_disk(group_id, path)).then(|| path.clone()),
                                );
                                retry.insert(path.clone());
                                continue;
                            }
                            Err(e) => {
                                tracing::warn!(
                                    group_id,
                                    path = %path,
                                    error = %e,
                                    "failed to give a path the shape its namespace requires; \
                                     leaving its change(s) unapplied for retry"
                                );
                                unshaped.extend(
                                    (!self.directory_on_disk(group_id, path)).then(|| path.clone()),
                                );
                                retry.insert(path.clone());
                                continue;
                            }
                        }
                    }
                    // A relocated file's copy is written unbatched: the
                    // name it leaves becomes a directory later in this same
                    // pass, and only once the copy is known to be in place.
                    let relocated_copy = relocations.values().flatten().any(|copy| copy == path);
                    // Best-effort, lock-free classification of this
                    // path as an "ordinary" content upsert -- see `prepare_
                    // ordinary_projected_upsert`'s own doc comment for
                    // exactly what qualifies. A `None` (any hazard/symlink/
                    // placeholder/content-identical/not-eager-admitted
                    // shape, or a classification error) falls straight
                    // through to the exact same unbatched `materialize_dag_
                    // content_head` call this branch has always made --
                    // nothing below this `if let` changes for that case.
                    let prepare_result = if relocated_copy {
                        Ok(None)
                    } else {
                        self.prepare_ordinary_projected_upsert(
                            group_id,
                            path,
                            demand_of.get(path).map_or(path.as_str(), String::as_str),
                            &inputs[winner],
                            policy,
                            derived.get(path),
                            activity_provider.as_ref(),
                            &reconcile_provenance_batch,
                            call_timer,
                        )
                        .await
                    };
                    match prepare_result {
                        Ok(Some((write_activity, prepared))) => {
                            pending_batch.push(OrdinaryBatchItem::Upsert(
                                write_activity,
                                Box::new(prepared),
                            ));
                            continue;
                        }
                        Ok(None) => {}
                        Err(e) => {
                            tracing::debug!(
                                group_id,
                                path = %path,
                                error = %e,
                                "ordinary-upsert classification failed; falling back to \
                                 the unbatched materialize path for this attempt"
                            );
                        }
                    }
                    let head_started = std::time::Instant::now();
                    let head_result = self
                        .materialize_dag_content_head(
                            group_id,
                            path,
                            demand_of.get(path).map_or(path.as_str(), String::as_str),
                            &inputs[winner],
                            policy,
                            derived.get(path),
                            prefetched.get(path.as_str()),
                        )
                        .await;
                    let head_elapsed = head_started.elapsed();
                    if head_elapsed > std::time::Duration::from_secs(1) {
                        tracing::warn!(
                            group_id,
                            path = %path,
                            elapsed_ms = head_elapsed.as_millis(),
                            "materialize_dag_content_head call took unusually long"
                        );
                    }
                    match head_result {
                        Ok(MaterializeResult::Settled(evidence)) => {
                            settled.insert(path.clone(), evidence);
                        }
                        Ok(MaterializeResult::RetryRequired) => {
                            retry.insert(path.clone());
                        }
                        Err(e) => {
                            tracing::warn!(
                                group_id,
                                path = %path,
                                error = %e,
                                "failed to project a path; leaving its change(s) unapplied for retry"
                            );
                            retry.insert(path.clone());
                        }
                    }
                }
            }
        }
        // Commit every path deferred into `pending_batch` above, in
        // chunks of at most `ORDINARY_BATCH_MAX_PATHS` -- bounded the same
        // way the Convergence Engine's own direct per-tick reconcile is,
        // regardless of whether this call's own `paths` came from an 8-path
        // engine call or a larger backstop window.
        let (committed, failed) = self
            .commit_pending_batch(group_id, origin_device_id, pending_batch, call_timer)
            .await?;
        settled.extend(committed);
        retry.extend(failed);
        // A directory whose delete ran before its last child's was retained
        // and is never reconciled again on its own: re-examine the retained
        // directories above every path this pass removed. No path lock is
        // held here.
        self.remove_emptied_retained_ancestors(
            group_id,
            settled
                .iter()
                .filter(|(_, evidence)| matches!(evidence, SettlementEvidence::ExactAbsent { .. }))
                .map(|(path, _)| path),
        )
        .await;
        // Every path examined above must land in exactly one of the two
        // sets — see `ProjectionAttempt`'s own doc comment. This should be
        // unreachable given the match above is exhaustive and every arm
        // inserts into one set or the other; kept as a loud, visible signal
        // (not a silent "treat as settled") in case a future edit
        // reintroduces a branch that forgets to record an outcome.
        for path in &paths {
            if !settled.contains_key(path) && !retry.contains(path) {
                tracing::error!(
                    local_device_id = %self.local_device_id,
                    group_id,
                    audit_attempt_id,
                    path = %path,
                    "reconcile_group_paths examined a path but recorded neither settled nor retry \
                     for it; treating as retry, never as an accidental success"
                );
                retry.insert(path.clone());
            }
        }
        if !retry.is_empty() {
            // Diagnostic-only: splits `retry` into direct (a raw seed path)
            // vs. derived (a synthetic conflict-copy path), for diagnosing
            // intermittently stalled obligations.
            let retry_direct: Vec<&String> =
                retry.iter().filter(|p| seed_paths.contains(*p)).collect();
            let retry_derived: Vec<&String> =
                retry.iter().filter(|p| !seed_paths.contains(*p)).collect();
            tracing::debug!(
                local_device_id = %self.local_device_id,
                group_id,
                audit_attempt_id,
                retry_direct = ?retry_direct,
                retry_derived = ?retry_derived,
                "reconcile_group_paths finished with unresolved paths this attempt"
            );
        }
        let materialize_elapsed = materialize_started.elapsed();
        if materialize_elapsed > std::time::Duration::from_secs(1) {
            tracing::warn!(
                group_id,
                audit_attempt_id,
                elapsed_ms = materialize_elapsed.as_millis(),
                path_count = paths.len(),
                settled_count = settled.len(),
                retry_count = retry.len(),
                "reconcile_group_paths materialization loop took unusually long"
            );
        }
        call_timer.finish(
            group_id,
            paths.len(),
            settled.len(),
            retry.len(),
            call_started.elapsed(),
        );
        Ok(ProjectionAttempt { settled, retry })
    }

    /// Materializes one resolved content head at `target_path`: resolves its
    /// version hash to the stored `FileVersion`, builds a `FileRecord` from the
    /// version's block list/size/metadata, persists the record's kind/symlink/
    /// exec metadata (so `materialize`'s symlink dispatch and metadata-only
    /// fast path see it), then hands the record to `materialize`.
    ///
    /// The `FileVersion` records each block's content hash and real size
    /// (canonical encoding v2), so the built `FileRecord`'s blocks carry real
    /// sizes and prefix-sum offsets and block fetch validates by both size and
    /// content hash before materialization.
    // One argument per input of a head's projection; see `_under`.
    #[allow(clippy::too_many_arguments)]
    pub async fn materialize_dag_content_head(
        &self,
        group_id: &str,
        target_path: &str,
        demand_path: &str,
        head: &PathHead,
        policy: MaterializationPolicy,
        derived: Option<&PathHead>,
        satisfied: Option<&BlockRequirement>,
    ) -> Result<MaterializeResult, PeerSessionError> {
        self.materialize_dag_content_head_under(
            group_id,
            target_path,
            demand_path,
            head,
            policy,
            derived,
            satisfied,
            OwnCaptureRule::RecaptureFirst,
        )
        .await
    }

    /// Captures what `target_path` holds now, for an own captured head the
    /// disk has moved on from, and says whether that superseded `head`.
    /// Called without the path lock, which capture takes itself.
    async fn recapture_instead_of_projecting(
        &self,
        group_id: &str,
        target_path: &str,
        head: &PathHead,
        derived: Option<&PathHead>,
    ) -> Result<Recapture, PeerSessionError> {
        yadorilink_peer_session::dst_trace(target_path, || {
            format!(
                "own capture {} not written back on {}: disk moved on, recapturing",
                hex::encode(&head.change_hash[..4]),
                self.local_device_id,
            )
        });
        let flushed =
            self.pending_local_change_flush.capture_local_path_state(group_id, target_path).await;
        if flushed == PendingLocalFlushOutcome::RetryRequired {
            tracing::info!(
                group_id,
                path = target_path,
                "declined to project this device's own captured change over newer local state; \
                 the newer state could not be captured yet (still changing)"
            );
            return Ok(Recapture::StillChanging);
        }
        let fresh = self.combined_heads(group_id, target_path, derived)?;
        let still_elected = matches!(
            resolve_path_heads(target_path, &fresh),
            PathResolution::Present { winner, .. } if fresh[winner].change_hash == head.change_hash
        );
        if still_elected {
            tracing::warn!(
                group_id,
                path = target_path,
                head = %hex::encode(&head.change_hash[..4]),
                "disk no longer holds this device's own captured change, but capturing the path \
                 authored nothing newer: capture finds no local state it has not recorded"
            );
            return Ok(Recapture::NothingNewer);
        }
        tracing::info!(
            group_id,
            path = target_path,
            "declined to project this device's own captured change over newer local state; \
             captured the newer state, which supersedes it"
        );
        Ok(Recapture::Superseded)
    }

    // The public entry point's parameters plus the recapture rule it runs
    // under; bundling them would only rename the same list.
    #[allow(clippy::too_many_arguments)]
    #[allow(
        clippy::too_many_lines,
        reason = "one DAG head's projection, from version lookup through recapture to \
              the proof, as a single ordered sequence sharing one permit"
    )]
    async fn materialize_dag_content_head_under(
        &self,
        group_id: &str,
        target_path: &str,
        demand_path: &str,
        head: &PathHead,
        policy: MaterializationPolicy,
        derived: Option<&PathHead>,
        satisfied: Option<&BlockRequirement>,
        own_capture_rule: OwnCaptureRule,
    ) -> Result<MaterializeResult, PeerSessionError> {
        let activity_provider = self.block_write_activity_provider();
        let _write_activity = activity_provider.begin_block_write_activity();
        // A removing head (tombstone / move-away source) lands no content; only
        // content heads reach here, but guard defensively. This reports
        // `RetryRequired`, never `Settled` -- this branch verifies nothing
        // about the path's actual state (no write, no fence observation), so
        // it must not report a settlement the publication step could ever be asked to
        // publish evidence for; a caller reaching here at all is already
        // outside this function's own documented contract, and the safe
        // response to an unexpected state is to defer, not to claim success.
        let Some(_) = head.content.as_ref() else {
            return Ok(MaterializeResult::RetryRequired);
        };
        // Flush any same-path (and case-fold sibling) local edit still sitting
        // in this link's debounce accumulator *before* taking the path lock —
        // the same ordering the legacy reconcile relies on so a not-yet-indexed
        // local write is captured (into the index and the DAG) rather than
        // silently overwritten by this materialize.
        let flush_started = std::time::Instant::now();
        let flushed = self.flush_local_changes_before_reconcile(group_id, target_path).await;
        let flush_elapsed = flush_started.elapsed();
        if flushed == PendingLocalFlushOutcome::RetryRequired {
            // A local edit at this path could not be captured -- most often
            // a file still being written. Writing now would put this
            // device's older view of the path over bytes it never
            // authored. Leave the obligation for a later pass; the capture
            // that eventually succeeds moves the path's head anyway.
            yadorilink_peer_session::dst_trace(target_path, || {
                format!(
                    "materialize deferred on {}: pending local edit not captured",
                    self.local_device_id
                )
            });
            return Ok(MaterializeResult::RetryRequired);
        }
        // Held across the whole materialize (including its block-fetch awaits),
        // closing the local-save-vs-incoming-version race exactly as the legacy
        // path does.
        let lock_wait_started = std::time::Instant::now();
        let path_lock = self.state.path_lock(group_id, target_path);
        let _guard = path_lock.lock().await;
        let lock_wait_elapsed = lock_wait_started.elapsed();
        if flush_elapsed > std::time::Duration::from_secs(1)
            || lock_wait_elapsed > std::time::Duration::from_secs(1)
        {
            tracing::warn!(
                group_id,
                path = target_path,
                flush_elapsed_ms = flush_elapsed.as_millis(),
                lock_wait_elapsed_ms = lock_wait_elapsed.as_millis(),
                "materialize_dag_content_head flush/lock-wait took unusually long"
            );
        }
        // CONV-7's freshness principle applied INSIDE the path lock: the
        // resolution that elected `head` ran before this lock was acquired,
        // and a newer change for this path can land in between — most
        // dangerously this device's OWN local tombstone (a user deleting or
        // renaming the file away), whose emission removes the file, writes
        // the deleted index row, and admits the change already `applied`.
        // Writing the pre-lock winner anyway resurrects content the newer
        // change just removed on this very device, and because a locally
        // authored change is never reprojected, nothing re-examines the path
        // afterwards — captured live (single-path DST trace, three-device
        // mesh chaos seed 1000005) as a deterministic terminal divergence:
        // the device that authored a rename's tombstone re-materialized the
        // pre-rename winner an instant later and kept, forever, a live file
        // every peer had deleted, under byte-identical DAG heads. Re-resolve
        // under the lock (with the caller's derived-copy context, so a
        // fixpoint-derived conflict copy re-validates against the same
        // inputs that elected it) and decline a head that is no longer the
        // current winner; `RetryRequired` keeps the caller from recording
        // the path as settled on the strength of a write that did not
        // happen, and whichever change superseded `head` drives (or already
        // drove) the path's real projection through its own admission.
        let fresh = self.combined_heads(group_id, target_path, derived)?;
        let elected = self.namespace_winner(group_id, target_path, &fresh, derived.is_some())?;
        let effective_head = match elected {
            Some(winner) if fresh[winner].change_hash == head.change_hash => head.clone(),
            Some(winner) => {
                // The winner moved to a NEWER content head while this call
                // waited for the lock. Rather than declining and paying a
                // whole retry round-trip (decline → caller marks retry →
                // next audit re-resolves → re-materializes — measurable
                // churn under exactly the contention that produces these
                // races), upgrade in place: this call already holds the
                // path lock, so materializing the fresh winner here is the
                // same write the retry would eventually perform, minus the
                // window in which the path sits stale.
                yadorilink_peer_session::dst_trace(target_path, || {
                    format!(
                        "stale materialize upgraded on {}: head {} superseded by winner {}",
                        self.local_device_id,
                        hex::encode(&head.change_hash[..4]),
                        hex::encode(&fresh[winner].change_hash[..4]),
                    )
                });
                tracing::debug!(
                    local_device_id = %self.local_device_id,
                    group_id,
                    path = %target_path,
                    stale_head = %hex::encode(&head.change_hash[..4]),
                    fresh_head = %hex::encode(&fresh[winner].change_hash[..4]),
                    "materialize upgraded under the path lock to the current winner"
                );
                fresh[winner].clone()
            }
            None => {
                yadorilink_peer_session::dst_trace(target_path, || {
                    format!(
                        "stale materialize declined on {}: head {} is now fully removed",
                        self.local_device_id,
                        hex::encode(&head.change_hash[..4]),
                    )
                });
                tracing::debug!(
                    local_device_id = %self.local_device_id,
                    group_id,
                    path = %target_path,
                    stale_head = %hex::encode(&head.change_hash[..4]),
                    "declining a materialize whose path a newer tombstone removed before \
                     the path lock was acquired"
                );
                return Ok(MaterializeResult::RetryRequired);
            }
        };
        // Same reclassification and reasoning as the analogous guard above:
        // this branch verifies nothing about the path's actual state.
        let Some(content) = effective_head.content.as_ref() else {
            return Ok(MaterializeResult::RetryRequired);
        };
        let version_hash = VersionHash(content.version_hash);
        let Some(version) = self.state.dag_get_file_version(group_id, &version_hash)? else {
            // Admission gated on the version being present, so this only
            // happens if it was pruned in between — skip; a later heads
            // exchange re-drives this path once the version is re-supplied.
            // NOT settled: content was never verified/written, so a caller
            // must not treat this as done (see `MaterializeResult`'s own
            // doc comment).
            tracing::warn!(
                group_id,
                path = target_path,
                version = %version_hash.to_hex(),
                "file version for a resolved content head is missing; skipping materialize"
            );
            return Ok(MaterializeResult::RetryRequired);
        };
        let record = file_record_from_version(target_path, &version);
        let meta = IncomingWireMeta {
            record_kind: version.meta.record_kind,
            symlink_target: version.meta.symlink_target.clone(),
            // A version does not carry the out-of-root flag (it is advisory,
            // never gated on); default it, matching a legacy record whose
            // sender predates the field.
            symlink_out_of_root: false,
            unix_mode: version.meta.unix_mode,
            xattrs: version.meta.xattrs.clone(),
            origin_device_id: Some(effective_head.device_id.clone()),
            authoring_change_hash: Some(ChangeHash(effective_head.change_hash)),
        };
        // If this path already holds exactly this version's content, there is
        // nothing to fetch or rewrite. Skipping here matters beyond saving
        // work: re-running the projection, or resolving to a version this
        // device itself authored, must not overwrite an existing, richer index
        // row (real version vector, real per-block sizes) with the projection's
        // placeholder metadata.
        //
        // A plain regular file gets a richer classification
        // than symlink/directory records below -- not just "is the content
        // already right" (which still costs two writer_gate acquisitions
        // even on a genuine no-op re-examination: one for the metadata
        // columns, one for the full row upsert), but "is EVERYTHING already
        // right" (content, row identity, authoring, origin), in which case
        // this candidate costs zero DB writes at all. Content-identical
        // re-examination dominates writer_gate load under a large change
        // burst once ordinary batching removes the bigger per-path write
        // sources, and most of those re-examinations are genuinely fully
        // settled, not merely content-identical. Scoped to `RecordKind::
        // File` only -- symlink/directory records keep the exact prior
        // behavior below, matching every other scoping choice in
        // this file (placeholder/hazard/conflict-copy stay on the existing
        // path too).
        // Before any "is this already materialized?" shortcut below, and
        // before any write: a name this device refuses to write is held,
        // and holding it is a durable outcome, not a reason to skip the
        // path silently.
        //
        // The order matters specifically on a case-insensitive volume, and
        // getting it wrong was a real, reproduced defect (confirmed on real
        // APFS): every shortcut below asks its question by opening
        // `sync_root/target_path`, which such a volume resolves to whatever
        // existing file case-folds to that name -- a DIFFERENT file than
        // the record being materialized. Consulting it at all for a
        // colliding name means deciding this record's fate by inspecting
        // another record's bytes, and the observed effect was that an
        // incoming "photo.jpg" colliding with an already-materialized
        // "Photo.jpg" was reported `Settled` -- marked converged, with no
        // hold ever recorded, so nothing re-examined it and the collision
        // was silently forgotten. (The first file's content was correctly
        // left intact throughout; the damage was to the bookkeeping, not
        // the data.)
        //
        // `prepare_ordinary_projected_upsert`'s own hazard check stays a
        // pure batch-eligibility test that declines to batch: this is the
        // path that decides what actually happens to a hazardous record,
        // and the batched route defers here precisely so there is one such
        // place rather than two.
        if let Some(reason) = self.hazard_reason_for(group_id, &record)? {
            let authority = self.root_lease_for(group_id)?;
            let authority_op = authority.begin_operation()?;
            let permit = authority_op.permit();
            hold_record(
                self.state.as_ref(),
                group_id,
                &record,
                &reason,
                &effective_head.device_id,
                meta.authoring_change_hash.as_ref(),
                &permit,
            )?;
            // Durable: `hold_record` upserts the incoming record with its
            // own authoring identity, so this projection is genuinely
            // concluded rather than owed another attempt. The path is
            // re-examined when the hazard itself clears, through the
            // hazard-recheck sweep, not by re-driving this change.
            //
            // `HazardHeld`, not `ExactAbsent`. This lane used to claim
            // exact absence for a path `hold_record` had just given a
            // live, non-deleted row with a `held_reason` -- the opposite
            // of absent. The engine published that as an exact `Absent`
            // proof and then closed the obligation through the exact
            // completion, which checks the proof's hash and the
            // obligation's generation but never asks the `files` row
            // whether the path is really a tombstone. So a held path
            // settled as proven-absent.
            //
            // `materialize()`'s own three hazard branches have always
            // returned `HazardHeld`, and the engine's non-exact
            // completion re-checks `held_reason IS NOT NULL` inside its
            // own transaction. That is the route this lane belongs on.
            //
            // The fence bump goes with it: a hold performs no physical
            // mutation, and this one existed only to carry an epoch for
            // the proof that should never have been published.
            return Ok(MaterializeResult::Settled(SettlementEvidence::HazardHeld { reason }));
        }
        if version.meta.record_kind == RecordKind::File {
            if let Some(current) = self.state.get_current_version_record(group_id, target_path)? {
                let blocks_match = !current.deleted
                    && current.blocks.len() == version.blocks.len()
                    && current
                        .blocks
                        .iter()
                        .zip(&version.blocks)
                        .all(|(b, vb)| b.hash == vb.hash.0);
                // Unlike the symlink/directory
                // branch below, a `RecordKind::File` with an empty block
                // list is a genuinely verifiable on-disk state (an existing,
                // exactly-empty regular file) -- `disk_bytes_match_indexed_
                // blocks` (via `disk_content_comparison`) correctly proves
                // that even for zero blocks (open the path, read zero
                // blocks, then require exactly zero trailing bytes), so
                // this branch must not take the "no content blocks to
                // verify" shortcut the symlink/directory branch legitimately
                // does. Skipping it here would let an index row survive a
                // local deletion of the underlying empty file the watcher/
                // debounce pipeline hasn't caught up to yet -- the old
                // path's own `try_apply_metadata_only_update` never had this
                // gap because it unconditionally rejected an empty block
                // list outright. A verification failure (including "file
                // vanished") falls through to the slow path below, same as
                // `blocks_match` being false.
                //
                // A file whose owner cannot read it has neither verifiable
                // bytes nor readable or settable replicated metadata. It is
                // held, before anything is mutated, rather than failing this
                // pass with a raw permission error or falling through to a
                // path that could replace it.
                let content_matches = blocks_match
                    && match yadorilink_local_storage::disk_bytes_match_indexed_blocks(
                        &self.sync_root(group_id)?.join(target_path),
                        &record.blocks,
                    ) {
                        Ok(matches) => matches,
                        Err(yadorilink_local_storage::StorageError::Io(error))
                            if error.kind() == std::io::ErrorKind::PermissionDenied =>
                        {
                            let reason = self.state.hold_metadata_unprovable(
                                group_id,
                                target_path,
                                &self.sync_root(group_id)?.join(target_path),
                                &version_hash,
                            )?;
                            return Ok(MaterializeResult::Settled(
                                SettlementEvidence::HazardHeld { reason },
                            ));
                        }
                        Err(error) => return Err(error.into()),
                    };
                // This device's own capture of the path whose bytes still
                // match but whose mode or replicated attributes do not:
                // "repairing" them would write the captured metadata back
                // over a newer local edit, which capture records as one. It
                // is left to the recapture below, like a content change.
                let own_capture = own_capture_rule == OwnCaptureRule::RecaptureFirst
                    && effective_head.device_id == self.local_device_id
                    && self.state.is_local_capture(
                        group_id,
                        target_path,
                        &ChangeHash(effective_head.change_hash),
                    )?;
                let content_matches = content_matches
                    && (!own_capture
                        || mode_and_xattrs_match_disk(
                            &self.sync_root(group_id)?.join(target_path),
                            &version,
                        )?);
                if content_matches {
                    // `current` was read as one atomic statement, so this
                    // reconstructs the exact `FileVersion` identity that row
                    // describes -- equal to `version_hash` iff every column
                    // `FileVersion` identity covers (blocks/size/mtime/
                    // record_kind/symlink_target/unix_mode/xattrs) already
                    // agrees. `authoring_change_hash`/`origin_device_id`/
                    // `symlink_out_of_root` are not part of that identity,
                    // so they need their own checks to rule out a truly
                    // no-op DB write.
                    let index_fully_matches = current.to_file_version().version_hash
                        == version_hash
                        && self.state.get_authoring_change_hash(group_id, target_path)?
                            == meta.authoring_change_hash
                        && self.state.get_origin_device_id(group_id, target_path)?.as_deref()
                            == Some(effective_head.device_id.as_str())
                        && self.state.get_symlink_out_of_root(group_id, target_path)?
                            == meta.symlink_out_of_root;
                    if !index_fully_matches {
                        let columns =
                            yadorilink_replica_domain::session_state::LocalFileMetaColumns {
                                record_kind: meta.record_kind,
                                symlink_target: meta.symlink_target.clone(),
                                symlink_out_of_root: meta.symlink_out_of_root,
                                unix_mode: meta.unix_mode,
                                xattrs: meta.xattrs.clone(),
                            };
                        let authority = self.root_lease_for(group_id)?;
                        let authority_op = authority.begin_operation()?;
                        let permit = authority_op.permit();
                        self.state.apply_projected_row_atomic(
                            group_id,
                            &record,
                            &effective_head.device_id,
                            meta.authoring_change_hash.as_ref(),
                            &columns,
                            &permit,
                        )?;
                    }
                    // Never skipped, even when `index_fully_matches`: the DB
                    // matching the target version only proves the RECORDED
                    // mode/xattrs are right, not that the actual on-disk
                    // file's mode/xattrs still are (e.g. a local chmod this
                    // device's own watcher hasn't reconciled yet) -- keeping
                    // this repair semantics is why this is not a naive early
                    // return.
                    //
                    // Re-verify root identity
                    // and this path's containment immediately before these
                    // disk mutations, matching every other write path in
                    // this module (`self.verify_write_target` -- see its own
                    // doc comment) -- the block hashing above (`disk_bytes_
                    // match_indexed_blocks`) can take real time, and a root
                    // swap or an intermediate-symlink substitution during
                    // that window must not go undetected right up to the
                    // point this function mutates whatever is now at
                    // `out_path`.
                    let out_path = self.sync_root(group_id)?.join(target_path);
                    self.verify_write_target(group_id, &out_path)?;
                    // See
                    // `terminal_object_is_a_regular_file`'s own doc
                    // comment: `verify_write_target` only confirms the
                    // PARENT directory chain, and every call below this
                    // point follows a terminal symlink. Refuse to settle
                    // this fast path at all rather than chmod/xattr-ing
                    // through a symlink this branch never checked for --
                    // a later tick re-resolves from scratch, and the
                    // ordinary reconstruct path it may then take is the
                    // temp-then-rename primitive, which is safe.
                    if !terminal_object_is_a_regular_file(&out_path) {
                        return Ok(MaterializeResult::RetryRequired);
                    }
                    // `apply_unix_mode`/`apply_xattrs` are NOT a cheap no-op
                    // when nothing has actually drifted: `apply_xattrs` unconditionally issues a real
                    // `fsetxattr` for every desired name regardless of
                    // whether the value already matches, which the mutation
                    // fence's own "bump before the first mutating syscall"
                    // invariant treats as a real mutation -- the same class
                    // of gap `try_apply_metadata_only_update` handles.
                    // Determine first, then decide snapshot vs. bump, mirroring
                    // that function exactly.
                    // See `try_apply_metadata_only_update`'s identical
                    // handling for why mtime must be folded into this same
                    // decision -- a same-content, mtime-only-changed
                    // version must still attempt the stamp (mtime is
                    // retained-only, never blocking, but not "never even
                    // attempted" either), and attempting it is a real
                    // mutating syscall needing the same preceding bump.
                    let mode_and_xattrs_match = mode_and_xattrs_match_disk(&out_path, &version)?;
                    // An own capture whose mode or attributes moved on never
                    // got here (see `content_matches` above). An mtime that
                    // alone differs is not an edit capture records, and not
                    // that change's to undo either: it is left as it is,
                    // and mtime is retained-only in the settlement.
                    let metadata_already_matches_disk = mode_and_xattrs_match
                        && (own_capture
                            || yadorilink_local_storage::mtime_already_matches_disk(
                                &out_path,
                                version.meta.mtime_unix_nanos,
                            )?);
                    let (mutation_generation, xattr_evidence) = if metadata_already_matches_disk {
                        // This path's bytes were verified (not written)
                        // identical to the desired version above
                        // (`content_matches`), and metadata already matches
                        // too -- a genuine *snapshot*, never a bump, since
                        // no mutating syscall occurs here. Nothing written,
                        // so the xattrs are proved from disk.
                        (
                            self.state.dag_snapshot_mutation_fence(group_id, target_path)?,
                            XattrEvidence::ReproveFromDisk,
                        )
                    } else {
                        let fence = self.state.dag_bump_mutation_fence(
                            group_id,
                            target_path,
                            "metadata_repair",
                        )?;
                        // Before the final mode, which may deny the owner
                        // the read access the stamp's open needs.
                        yadorilink_local_storage::stamp_mtime_at_path(
                            &out_path,
                            version.meta.mtime_unix_nanos,
                        )?;
                        let applied = yadorilink_local_storage::apply_file_metadata_verified(
                            &out_path,
                            version.meta.unix_mode,
                            &version.meta.xattrs,
                        )?;
                        (fence, XattrEvidence::from(applied))
                    };
                    require_xattr_evidence(
                        target_path,
                        &out_path,
                        &version.meta.xattrs,
                        &xattr_evidence,
                    )?;
                    // A path held because its file was unreadable settles
                    // here once it is readable again; the hold goes with it.
                    self.state.clear_metadata_unprovable_hold(group_id, target_path)?;
                    return Ok(MaterializeResult::Settled(SettlementEvidence::ExactObject {
                        kind: RecordKind::File,
                        version: version_hash,
                        identity: Box::new(
                            yadorilink_root_authority::fs_identity::FileIdentity::observe_path(
                                &out_path,
                            )
                            .ok(),
                        ),
                        mutation_generation,
                    }));
                }
            }
        } else if let Some(local) = self.state.get_file(group_id, target_path)? {
            let same_content = !local.deleted
                && local.blocks.len() == version.blocks.len()
                && local.blocks.iter().zip(&version.blocks).all(|(b, vb)| b.hash == vb.hash.0);
            // The index alone is not proof the fast path is safe: it only
            // means this device's LAST INDEXING pass produced a record whose
            // block list happens to match the winner's. A raw filesystem
            // write to this same path (e.g. a concurrent local edit) changes
            // the actual bytes on disk immediately, but is only reflected in
            // the index once the watcher/debounce pipeline processes it —
            // which can lag behind an incoming remote materialize attempt
            // that runs in the meantime. Trusting a stale index here would
            // silently skip the real write, permanently leaving the wrong
            // bytes on disk with the index and DAG both agreeing the path is
            // "done" — nothing else would ever re-examine it. Verify actual
            // disk bytes hash-match the winner's blocks before trusting this
            // fast path; skip the check only for record kinds with no
            // content blocks to verify (symlink/directory), where it would
            // be meaningless (and `disk_bytes_match_indexed_blocks` assumes
            // a regular file). A verification failure (including "file
            // vanished") falls through to the real write below, same as
            // `same_content` being false to begin with.
            let same_content = same_content
                && (version.blocks.is_empty()
                    || yadorilink_local_storage::disk_bytes_match_indexed_blocks(
                        &self.sync_root(group_id)?.join(target_path),
                        &record.blocks,
                    )?);
            if same_content {
                // Content equality does not imply version equality: exec-bit,
                // symlink, or mtime-only changes are part of FileVersion
                // identity, so the DAG winner's metadata still has to be
                // applied here. Returning without this step leaves replicas
                // with the same bytes but permanently divergent permissions.
                let metadata_record = record.clone();
                let authority = self.root_lease_for(group_id)?;
                let authority_op = authority.begin_operation()?;
                let permit = authority_op.permit();
                apply_incoming_wire_metadata(
                    self.state.as_ref(),
                    group_id,
                    &metadata_record,
                    &meta,
                    &permit,
                )?;
                // The version is already known here -- it came from the
                // projection being applied -- so this site never had the
                // re-inference problem. It takes the generation and
                // ignores the helper's own reading of the row.
                let update = match try_apply_metadata_only_update(
                    self.state.as_ref(),
                    &self.sync_root(group_id)?,
                    group_id,
                    &metadata_record,
                    &effective_head.device_id,
                    meta.authoring_change_hash.as_ref(),
                    // The projection's own resolved version -- the same
                    // one this metadata came from.
                    &version,
                    &permit,
                ) {
                    // See the regular-file branch above: held, not retried.
                    Err(PeerSessionError::MetadataUnprovable(_)) => {
                        let reason = self.state.hold_metadata_unprovable(
                            group_id,
                            target_path,
                            &self.sync_root(group_id)?.join(target_path),
                            &version_hash,
                        )?;
                        return Ok(MaterializeResult::Settled(SettlementEvidence::HazardHeld {
                            reason,
                        }));
                    }
                    other => other?,
                };
                if let Some(MetadataOnlyUpdate { mutation_generation, .. }) = update {
                    // `try_apply_metadata_only_update` itself already
                    // decided snapshot vs. bump based on whether applying
                    // metadata actually changed anything on disk -- see its
                    // own doc comment.
                    let out_path = self.sync_root(group_id)?.join(target_path);
                    return Ok(MaterializeResult::Settled(SettlementEvidence::ExactObject {
                        kind: version.meta.record_kind,
                        version: version_hash,
                        identity: Box::new(
                            yadorilink_root_authority::fs_identity::FileIdentity::observe_path(
                                &out_path,
                            )
                            .ok(),
                        ),
                        mutation_generation,
                    }));
                }
            }
        }
        // Everything above that could settle this path without writing it
        // has declined: disk does not hold this head. For this device's own
        // capture of the path that means disk moved on after the capture --
        // other bytes, another link target, or no file at all -- and what
        // is there is newer local state. Writing the capture back would
        // destroy it (or bring back a file the user deleted), and merely
        // retrying would leave the older change standing as the path's head
        // with nothing to supersede it. Capture the disk instead, its
        // absence included -- outside the path lock, which capture takes
        // itself -- so the newer state becomes a newer change and this
        // obligation is superseded by it. A file still changing is left for
        // a later pass by the same capture.
        //
        // Capture compares disk with the index row, not with this head, so
        // it can find nothing newer to author: disk holds what this device
        // last recorded for the path, and there is no uncaptured local
        // state to protect. The path is then projected exactly as it was
        // before this rule existed, from the top (the lock was released for
        // the capture), rather than declined on every pass. A deletion is
        // the exception: bringing a file back is never that projection's to
        // make, so it waits for the watcher's own capture of it.
        let on_disk = match own_capture_rule {
            OwnCaptureRule::RecaptureFirst => {
                self.own_capture_on_disk(group_id, target_path, &effective_head, &version)?
            }
            OwnCaptureRule::ProjectAsBefore => OwnCaptureOnDisk::NotACapture,
        };
        if on_disk.superseded() {
            drop(_guard);
            return match self
                .recapture_instead_of_projecting(group_id, target_path, &effective_head, derived)
                .await?
            {
                Recapture::NothingNewer if on_disk != OwnCaptureOnDisk::Removed => {
                    Box::pin(self.materialize_dag_content_head_under(
                        group_id,
                        target_path,
                        demand_path,
                        head,
                        policy,
                        derived,
                        satisfied,
                        OwnCaptureRule::ProjectAsBefore,
                    ))
                    .await
                }
                _ => Ok(MaterializeResult::RetryRequired),
            };
        }
        {
            let authority = self.root_lease_for(group_id)?;
            let authority_op = authority.begin_operation()?;
            let permit = authority_op.permit();
            apply_incoming_wire_metadata(self.state.as_ref(), group_id, &record, &meta, &permit)?;
        }
        // Return `materialize`'s own result unchanged: it reports
        // `RetryRequired` for every "not done yet" shape (blocks not
        // fetchable this attempt, decline under the path lock, or a
        // hazardous TOMBSTONE holding a genuine live row rather than
        // deleting it — see the `if record.deleted` branch's own doc
        // comment for why that specific case is not durable), and
        // collapsing any of those to `Settled` here marks the change
        // applied with content that never landed — a live index row with
        // no file on disk that nothing ever re-examines. A CREATE/symlink
        // hazard hold for a content record like this one is different:
        // `hold_record` fully upserts the incoming record (including its
        // own authoring identity), so that case is a genuinely durable
        // `Settled` outcome, not one this comment needs to call out. The
        // authoring identity needs no follow-up write either: `materialize`
        // persists it atomically with the row in every branch that writes
        // one.
        // `satisfied` is what the pre-pass observed for this path before the
        // blocks were requested, so the racing-local-write guard still has
        // something to compare against, and so a path whose content never
        // arrived records its retriable placeholder rather than asking again.
        // A path with no entry -- one that appeared after the pass was planned
        // -- is left unsettled for the next one.
        // The version that resolved this head IS the payload's version --
        // the record above is derived from it. Nothing here reads the row
        // to find out what is being written.
        let payload = MaterializationPayload::from_version(target_path, version.clone());
        match self
            .materialize_local(
                group_id,
                &payload,
                demand_path,
                policy,
                &effective_head.device_id,
                meta.authoring_change_hash.as_ref(),
                satisfied,
            )
            .await?
        {
            LocalMaterializeOutcome::Concluded(result) => Ok(result),
            LocalMaterializeOutcome::NeedBlocks(_) => Ok(MaterializeResult::RetryRequired),
        }
    }
}

/// Whether an error from one ordinary-batch path's post-rename finish
/// belongs to that path alone, so the batch may retry that path and
/// finalize the rest: its file could not be opened, chmodded or observed
/// (`apply_unix_mode`/`apply_xattrs` fail as `Storage`), it does not
/// hold the xattrs or the kind its version claims, or its existing file is
/// not readable by its owner.
/// Everything else aborts the batch: `CorruptState` (a database or
/// invariant failure), disk pressure, a lost root, a transport or engine
/// error -- and also the bare `Io` and `NotFound`, which is how a SQLite
/// I/O or not-found error arrives here, so they cannot be told from a
/// database failure.
///
/// `PathEscapesRoot` is batch-wide too. `sync_root` reports a group with
/// no live link that way, and a storage-level escape is converted into the
/// same variant, so a lost root cannot be told from one escaping path;
/// treating it as path-local would retry every path in turn while the rest
/// of the batch finalized against a root that is gone.
fn ordinary_batch_error_is_path_local(error: &PeerSessionError) -> bool {
    use yadorilink_local_storage::StorageError as S;
    match error {
        PeerSessionError::ReplicatedXattrsNotExact(_)
        | PeerSessionError::PhysicalKindMismatch(_)
        | PeerSessionError::MetadataUnprovable(_) => true,
        PeerSessionError::Storage(storage) => {
            matches!(storage, S::Io(_) | S::InvalidPath(_) | S::PathEscapesRoot(_))
        }
        PeerSessionError::PathEscapesRoot(_)
        | PeerSessionError::Io(_)
        | PeerSessionError::NotFound(_)
        | PeerSessionError::CorruptState(_)
        | PeerSessionError::InvalidInput(_)
        | PeerSessionError::HydrationFailed(_)
        | PeerSessionError::ReservedNamespaceCollision(_)
        | PeerSessionError::NonPortablePath(_)
        | PeerSessionError::DiskPressure { .. }
        | PeerSessionError::Hex(_)
        | PeerSessionError::Transport(_)
        | PeerSessionError::RootAuthority(_)
        | PeerSessionError::ReplicaEngine(_)
        | PeerSessionError::Decode(_) => false,
    }
}
