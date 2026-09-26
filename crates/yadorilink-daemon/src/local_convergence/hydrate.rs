use futures_util::stream::{FuturesUnordered, StreamExt};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use yadorilink_peer_session::PeerSessionError;
use yadorilink_replica_domain::admission::ChangeOrdering;
use yadorilink_replica_domain::file::FileVersion;
use yadorilink_replica_domain::file::{FileRecord, RecordKind};
use yadorilink_replica_domain::ids::{ChangeHash, VersionHash};
use yadorilink_replica_domain::session_state::LinkGate;
use yadorilink_replica_domain::session_state::{MaterializationPolicy, MaterializationState};

use super::types::*;
use yadorilink_peer_session::peer_session::*;
use yadorilink_root_authority::fs_identity::{disk_race_fingerprint, disk_race_fingerprint_of};

impl super::LocalConvergenceExecutor {
    pub async fn reconcile_paths_directly(
        self: &Arc<Self>,
        driver: &Arc<dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver>,
        group_id: &str,
        paths: std::collections::BTreeSet<String>,
    ) -> Result<Option<ProjectionAttempt>, yadorilink_peer_session::PeerSessionError> {
        // ONE timer for the whole attempt -- see the inner function's own
        // comment for why it cannot be created further down.
        let call_timer = crate::local_convergence::call_timer::ReconcileCallTimer::new();
        self.reconcile_paths_directly_with_timer(driver, group_id, paths, &call_timer).await
    }

    pub(crate) async fn reconcile_paths_directly_with_timer(
        self: &Arc<Self>,
        driver: &Arc<dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver>,
        group_id: &str,
        paths: std::collections::BTreeSet<String>,
        call_timer: &crate::local_convergence::call_timer::ReconcileCallTimer,
    ) -> Result<Option<ProjectionAttempt>, yadorilink_peer_session::PeerSessionError> {
        let audit_attempt_id = next_audit_attempt_id();
        tracing::debug!(
            local_device_id = %self.local_device_id,
            group_id,
            audit_attempt_id,
            path_count = paths.len(),
            paths = ?paths,
            "direct path reconciliation attempt starting"
        );
        // Obtain what this pass will need, once, before it runs.
        //
        // The pass itself is local: it decides everything from this device's
        // disk, index and DAG, and it is entered from the top with the content
        // already here rather than being suspended in the middle of a decision
        // while a peer answers. Which peer, how many blocks at once, what a
        // `DontHave` means and what to do with a transport error are all
        // settled here, on the side that has a peer.
        //
        // A plan that goes stale between the request and the pass costs a
        // wasted fetch and nothing else: the pass re-resolves every path
        // itself, and what it observed before the request is carried in so the
        // guard against a local editor writing during the fetch still has its
        // before-picture.
        // `call_timer` spans BOTH halves below and is owned by the caller,
        // because the block fetching this attempt does happens in
        // `obtain_missing_content` -- strictly before `reconcile_group_
        // paths` is entered. A timer created down there cannot observe any
        // of it, so every block-fetch counter the reported line carries
        // (`blocks_fetched`, `block_fetch_wait_ms`) was structurally pinned
        // at zero on this path regardless of what actually happened on the
        // wire: measured against a real two-device run, 13,340 genuine
        // block round trips all reported as `blocks_fetched=0
        // block_fetch_wait_ms=0`. Threading one timer through both halves
        // is what makes the reported line describe the whole attempt --
        // the "constructed once per call and threaded by reference through
        // every function that call touches" property this module's own doc
        // comment already claims.
        let prefetched = self.obtain_missing_content(driver, group_id, &paths, call_timer).await?;
        self.reconcile_group_paths_guarded(
            group_id,
            paths,
            driver.peer_device_id(),
            &prefetched,
            audit_attempt_id,
            call_timer,
        )
        .await
    }

    /// Applies one committed batch. Only here does a hash become
    /// provenance-eligible, which is what keeps "provenance is recorded
    /// strictly after the durable write it attests to" true under batching.
    fn absorb_commit_result(
        &self,
        driver: &Arc<dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver>,
        joined: Result<CommittedBatch, tokio::task::JoinError>,
        pool: &mut ReceiveCommitPool,
        call_timer: Option<&crate::local_convergence::call_timer::ReconcileCallTimer>,
    ) {
        let committed = match joined {
            Ok(committed) => committed,
            Err(join_err) => {
                if pool.fatal.is_none() {
                    pool.fatal = Some(PeerSessionError::from(std::io::Error::other(format!(
                        "block store write task panicked: {join_err}"
                    ))));
                }
                pool.lost_content = true;
                return;
            }
        };
        if let (Some(timer), Some(elapsed)) = (call_timer, committed.elapsed) {
            timer.add_store_put(elapsed);
        }
        for rejected in &committed.rejected {
            tracing::warn!(
                local_device_id = %self.local_device_id,
                candidate_peer_id = %driver.peer_device_id(),
                hash = %hex::encode(rejected),
                "peer returned bytes that do not hash to the requested block; discarding them"
            );
            pool.lost_content = true;
        }
        if let Some(e) = committed.error {
            if pool.fatal.is_none() {
                pool.fatal = Some(e.into());
            }
            // The batch is all-or-nothing, so nothing in it is durable and
            // nothing in it may be provenanced.
            pool.lost_content = true;
            return;
        }
        for hash in committed.hashes {
            if let Some(batch) = &pool.reconcile_batch {
                batch.record(hash.clone());
            }
            pool.durable.push(hash);
        }
    }

    /// Routes one completed fetch into the pool, or into the
    /// give-up/fatal state. Deliberately does NOT touch `pool.durable`: a
    /// fetched block is not yet a durable one, and that field is what
    /// provenance is drawn from.
    ///
    /// Takes the per-file loop state as explicit `&mut` arguments rather
    /// than a wrapper struct: each is genuinely per-invocation state the
    /// two call sites (mid-loop drain and final drain) share, and a struct
    /// whose only purpose is to satisfy an argument count would obscure
    /// that they are separate concerns.
    #[allow(clippy::too_many_arguments)]
    async fn absorb_fetch_result(
        &self,
        driver: &Arc<dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver>,
        result: Result<yadorilink_peer_session::convergence_driver::FetchedBlock, PeerSessionError>,
        pool: &mut ReceiveCommitPool,
        group_id: &str,
        file_path: &str,
        version_hex: &str,
        all_present: &mut bool,
        give_up: &mut bool,
        fatal_error: &mut Option<PeerSessionError>,
        call_timer: Option<&crate::local_convergence::call_timer::ReconcileCallTimer>,
    ) {
        let result = result.map(|fetched| {
            // The session reports the wire wait; attributing it is this
            // side's business, which is exactly why it is a `Duration` at
            // the boundary and not a timer the session writes into.
            if let Some(timer) = call_timer {
                timer.add_block_fetch_wait(fetched.wire_wait);
            }
            fetched.outcome
        });
        match result {
            Ok(yadorilink_peer_session::convergence_driver::BlockFetch::Fetched { hash, data }) => {
                if let Some(timer) = call_timer {
                    timer.add_block_fetched();
                }
                self.pool_push(
                    driver,
                    pool,
                    PendingBlock {
                        hash,
                        data,
                        path: file_path.to_string(),
                        version_hex: version_hex.to_string(),
                    },
                    call_timer,
                )
                .await;
            }
            Ok(yadorilink_peer_session::convergence_driver::BlockFetch::Missing) => {
                *all_present = false;
                *give_up = true;
            }
            Ok(yadorilink_peer_session::convergence_driver::BlockFetch::VerifiedRefusal {
                reason,
            }) => {
                // The one fetch answer worth keeping. Written here because
                // this is the side that owns this device's durable state --
                // the session reports what the peer said and does not
                // record it. Bound to the exact version asked for, so a
                // later version of the same path is not held back by an
                // older one's refusal (see `block_fetch_refusals`'s schema
                // doc). Best-effort: losing the evidence must not fail the
                // fetch, which failed on its own terms anyway.
                if let Err(e) = self.state.record_block_fetch_refusal(
                    group_id,
                    file_path,
                    version_hex,
                    driver.peer_device_id(),
                    &reason,
                    crate::local_convergence::types::now_unix_nanos(),
                ) {
                    tracing::warn!(
                        candidate_peer_id = %driver.peer_device_id(),
                        file_path,
                        error = %e,
                        "failed to record a block fetch refusal"
                    );
                }
                *all_present = false;
                *give_up = true;
            }
            Err(e) => {
                if fatal_error.is_none() {
                    *fatal_error = Some(e);
                }
                *give_up = true;
            }
        }
    }

    /// Physically reapplies incoming wire metadata that diverged from an
    /// equal-authoring local row, after `apply_locked_record` has already
    /// written it to the index columns. `Some` ends that dispatch with the
    /// returned outcome.
    fn reapply_equal_authoring_metadata(
        &self,
        group_id: &str,
        local: &FileRecord,
        meta: &IncomingWireMeta,
        incoming_author: &ChangeHash,
        incoming_origin: &str,
        root_commit_permit: &yadorilink_root_authority::root_commit::RootCommitPermit<'_>,
    ) -> Result<Option<LockedRecordOutcome>, PeerSessionError> {
        match meta.record_kind {
            RecordKind::File => {
                let root = self.sync_root(group_id)?;
                let out_path = root.join(&local.path);
                self.verify_write_target(group_id, &out_path)?;
                // This was the one metadata-repair call site
                // in this module that skipped the "bump before the
                // first mutating syscall, no exceptions"
                // fence discipline every other
                // `apply_unix_mode`/`apply_xattrs` call site
                // follows (see `try_apply_metadata_only_
                // update`'s and the equivalent-content
                // `Equal`-arm's own doc comments for the
                // identical fix, mirrored here exactly).
                // `apply_xattrs` unconditionally issues a
                // real `fsetxattr`/`fremovexattr` for every
                // desired name and silently swallows a
                // syscall failure by its own documented
                // contract -- without a preceding fence
                // bump, a real write failure here leaves the
                // live mutation fence unchanged, so an
                // already-published stale proof for this
                // path (published under the OLD fence
                // value) stays wrongly "current" and a later
                // consumer is told disk matches evidence it
                // does not.
                let mode_matches = yadorilink_local_storage::unix_mode_already_matches_disk(
                    &out_path,
                    meta.unix_mode,
                )?;
                let xattrs_match =
                    yadorilink_local_storage::xattrs_already_match_disk(&out_path, &meta.xattrs)?;
                // Asked before the bump, not after: a file
                // its owner cannot read can have its
                // attributes neither read back nor set, so
                // the repair could only bump the fence and
                // fail, on every pass. It is held instead,
                // with nothing on disk touched.
                if !xattrs_match && existing_file_is_owner_unreadable(&out_path)? {
                    self.state.hold_metadata_unprovable(
                        group_id,
                        &local.path,
                        &out_path,
                        &MaterializationPayload::from_wire(local.clone(), meta)
                            .version()
                            .version_hash,
                    )?;
                    return Ok(Some(LockedRecordOutcome::Settled));
                }
                let metadata_already_matches_disk = mode_matches && xattrs_match;
                let mutation_generation = if metadata_already_matches_disk {
                    // A true zero-mutation verification --
                    // no syscall below will change anything,
                    // so this is a snapshot, never a bump.
                    // The proof step below re-reads disk.
                    self.state.dag_snapshot_mutation_fence(group_id, &local.path)?
                } else {
                    let fence = self.state.dag_bump_mutation_fence(
                        group_id,
                        &local.path,
                        "equal_authoring_metadata_repair",
                    )?;
                    // Surfaces a real `fsetxattr`/`fremovexattr`
                    // failure as a retriable error instead of
                    // letting `apply_xattrs`'s own
                    // silently-swallowed-failure contract
                    // fold it into a false settle. Checked
                    // inside the attempt, before the final
                    // mode: a mode such as 0o200 makes the
                    // attributes unreadable afterwards
                    // without changing them.
                    let applied = yadorilink_local_storage::apply_file_metadata_verified(
                        &out_path,
                        meta.unix_mode,
                        &meta.xattrs,
                    )?;
                    require_xattr_evidence(
                        &local.path,
                        &out_path,
                        &meta.xattrs,
                        &XattrEvidence::from(applied),
                    )?;
                    fence
                };
                self.prove_equal_authoring_file_repair(
                    group_id,
                    local,
                    meta,
                    &out_path,
                    incoming_author,
                    mutation_generation,
                    root_commit_permit,
                )?;
                self.state.clear_metadata_unprovable_hold(group_id, &local.path)?;
            }
            RecordKind::Symlink => {
                let windows_opt_in = self.state.windows_symlink_opt_in_for_group(group_id)?;
                // This call site used to discard
                // `materialize_symlink_at`'s
                // returned outcome entirely, unlike the
                // ordinary `materialize()` symlink dispatch
                // (see this crate's own `SymlinkMaterializeOutcome::
                // PolicySkipped` handling there). A
                // `PolicySkipped` outcome here left the row
                // at whatever `materialization_state` it
                // already had -- reachable via this Equal-
                // authoring repair path independent of that
                // other call site's own fix.
                if matches!(
                    materialize_symlink_at(
                        SymlinkMaterialization {
                            state: self.state.as_ref(),
                            root: &self.sync_root(group_id)?,
                            group_id,
                            windows_opt_in,
                            origin_device_id: incoming_origin,
                            authoring_change_hash: Some(incoming_author),
                            permit: root_commit_permit,
                        },
                        local,
                        // The payload this repair arm is
                        // applying: `local`'s content
                        // (proven equal-authoring above)
                        // plus the incoming wire metadata
                        // this arm exists to reapply.
                        //
                        // NOT `tombstone(local)`, which
                        // was here before and is wrong
                        // now that the link target comes
                        // from the version: `tombstone`
                        // hardcodes `record_kind: File`
                        // and `symlink_target: None`, so
                        // this arm would have skipped
                        // every symlink write as "no
                        // target recorded" -- the repair
                        // would have become a no-op that
                        // demoted the row to
                        // `Placeholder` forever.
                        MaterializationPayload::from_wire(local.clone(), meta).version(),
                    )?,
                    SymlinkMaterializeOutcome::PolicySkipped
                ) {
                    self.state.set_materialization_state(
                        group_id,
                        &local.path,
                        MaterializationState::Placeholder,
                        root_commit_permit,
                    )?;
                }
            }
            // Nothing physical to reapply for a
            // directory beyond the index columns
            // `apply_incoming_wire_metadata` above
            // already fixed.
            RecordKind::Directory => {}
        }
        Ok(None)
    }

    pub async fn apply_locked_record(
        &self,
        driver: &Arc<dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver>,
        group_id: &str,
        incoming: FileRecord,
        meta: IncomingWireMeta,
        policy: MaterializationPolicy,
    ) -> Result<LockedRecordOutcome, PeerSessionError> {
        let incoming_author = meta.authoring_change_hash.as_ref().ok_or_else(|| {
            PeerSessionError::InvalidInput(format!(
                "incoming record {group_id}/{} has no valid authoring_change_hash",
                incoming.path
            ))
        })?;
        let root_commit_authority = self.root_lease_for(group_id)?;
        let root_commit_authority_op = root_commit_authority.begin_operation()?;
        let root_commit_permit = root_commit_authority_op.permit();
        if !self.state.dag_is_verified_authoring_change(group_id, incoming_author)? {
            return Err(PeerSessionError::InvalidInput(format!(
                "incoming record {group_id}/{} references an unverified authoring change",
                incoming.path
            )));
        }
        // The device that
        // actually produced `incoming`'s content, per the sending peer's
        // own `SyncState::get_origin_device_id` lookup (`file_info_for_
        // record`) — not necessarily `driver.peer_device_id()` if this peer
        // is relaying a *third* device's content rather than sending its
        // own. Falls back to `driver.peer_device_id()` for a peer that
        // predates this field (empty/absent on the wire).
        let incoming_origin =
            meta.origin_device_id.clone().unwrap_or_else(|| driver.peer_device_id().to_string());

        let local = self.state.get_file(group_id, &incoming.path)?;

        let Some(local) = local else {
            // Persist the peer's
            // advertised kind/target/exec-bit into the index *before*
            // `materialize` runs — its own symlink dispatch reads
            // `SyncState::get_record_kind` for this exact path, so this
            // must land first, not after. Skipped for a tombstone: a
            // delete has no kind/target/exec-bit to dispatch on (the
            // `record.deleted` branch in `materialize` runs unconditionally
            // first, before any kind-based dispatch), and bootstrapping a
            // `version_seq = 0` scaffold row here just to immediately drop
            // it (a hazard-collision tombstone for a path this device has
            // no genuine content at settles without upserting anything —
            // see `materialize`'s tombstone branch) left the scaffold
            // behind with a NULL `authoring_change_hash`: the next record
            // for this same path took the `Some(local)` branch above
            // instead of this never-seen branch, and `get_authoring_
            // change_hash` returning `Ok(None)` for that column turned into
            // `PeerSessionError::CorruptState` at its `ok_or_else` a few lines up.
            if !incoming.deleted {
                apply_incoming_wire_metadata(
                    self.state.as_ref(),
                    group_id,
                    &incoming,
                    &meta,
                    &root_commit_permit,
                )?;
            }
            // We've never seen this path: adopt it outright (`materialize`
            // now handles a tombstone-for-a-file-we-never-had correctly
            // too — — recording the row without ever touching
            // a file that was never on disk here in the first place).
            // The payload is the incoming record AND the wire metadata that
            // came with it -- both halves of what will be written. The
            // version is derived from them once, here, rather than read
            // back off the row after the write.
            let payload = MaterializationPayload::from_wire(incoming.clone(), &meta);
            let outcome = self
                .materialize(
                    driver,
                    group_id,
                    &payload,
                    policy,
                    &incoming_origin,
                    Some(incoming_author),
                )
                .await?;
            // Full mesh: this device's *other* peers need to learn about
            // this file too, not just the one that sent it (see
            // `forward_tx`'s doc comment). Forwarded regardless of
            // `outcome`: even a not-yet-settled record's identity is worth
            // this device's other peers learning about, and `materialize`
            // itself is what actually gates whatever content lands where.
            driver.forward(group_id, &incoming);
            return Ok(match outcome {
                MaterializeResult::Settled(_) => LockedRecordOutcome::Settled,
                MaterializeResult::RetryRequired => LockedRecordOutcome::RetryRequired,
            });
        };

        let local_author =
            self.state.get_authoring_change_hash(group_id, &local.path)?.ok_or_else(|| {
                PeerSessionError::CorruptState(format!(
                    "current row {group_id}/{} has no authoring change identity",
                    local.path
                ))
            })?;
        let ordering = self
            .state
            .dag_compare_authoring(group_id, &local_author, incoming_author)?
            .ok_or_else(|| {
                PeerSessionError::CorruptState(format!(
                    "current or incoming row {group_id}/{} references an unverified authoring change",
                    local.path
                ))
            })?;
        // Unconditional trace
        // of the dispatch decision itself, since the eager-rehydrate arms
        // below only log when they actually attempt a hydrate -- see the
        // tracked comment on `randomized_soak_converges_with_no_leaks_or_
        // stuck_state` in `topology_soak_lane.rs`.
        tracing::debug!(
            local_device_id = %self.local_device_id,
            group_id,
            path = %local.path,
            peer = %driver.peer_device_id(),
            ?ordering,
            needs_rehydrate = ?self.live_record_needs_rehydrate(group_id, &local, policy),
            "materialization audit: apply_locked_record dispatch"
        );

        match ordering {
            ChangeOrdering::Equal => {
                if !same_record_content(&local, &incoming) {
                    return Err(PeerSessionError::CorruptState(format!(
                        "authoring change identity maps to different content for {group_id}/{}",
                        local.path
                    )));
                }
                // `same_record_content` only proves content (deleted/
                // size/mtime/blocks) matches -- the same gap
                // `authoring_proves_redundant`'s own `Equal` branch
                // handles (see that function's doc comment): this device's own `record_kind`/
                // `symlink_target`/`unix_mode` can still have diverged
                // from what the identical authoring change actually
                // specifies (an interrupted materialization, or manual
                // local drift), and reaching this branch at all means
                // that OTHER fix already decided this record needs a
                // real look, not a skip -- so this is the one place
                // left that must actually repair the divergence, not
                // just detect it and fall through to a no-op.
                if !incoming.deleted {
                    let local_kind =
                        self.state.get_record_kind(group_id, &local.path)?.unwrap_or_default();
                    let local_symlink_target =
                        self.state.get_symlink_target(group_id, &local.path)?;
                    let local_unix_mode = self.state.get_unix_mode(group_id, &local.path)?;
                    let local_xattrs = self.state.get_xattrs(group_id, &local.path)?;
                    let metadata_diverged = local_kind != meta.record_kind
                        || local_symlink_target != meta.symlink_target
                        || local_unix_mode != meta.unix_mode
                        || local_xattrs != meta.xattrs;
                    if metadata_diverged {
                        apply_incoming_wire_metadata(
                            self.state.as_ref(),
                            group_id,
                            &local,
                            &meta,
                            &root_commit_permit,
                        )?;
                        if let Some(outcome) = self.reapply_equal_authoring_metadata(
                            group_id,
                            &local,
                            &meta,
                            incoming_author,
                            &incoming_origin,
                            &root_commit_permit,
                        )? {
                            return Ok(outcome);
                        }
                    }
                }
                if self.live_record_needs_rehydrate(group_id, &local, policy)? {
                    // `_locked`: this branch's only caller
                    // (`rematerialize_one_record`) already holds
                    // `path_lock` for `local.path` -- see
                    // `hydrate_file_with_timeout_locked`'s own doc
                    // comment for why the lock-acquiring public wrapper
                    // would deadlock here.
                    //
                    // This outcome must not be discarded: `Held`
                    // (blocks fetched, physical write withheld by a
                    // filename hazard) is not `Hydrated`, and reporting
                    // `Settled` for it would be wrong while the row is
                    // still `Placeholder`.
                    // See the tracked comment on `randomized_soak_
                    // converges_with_no_leaks_or_stuck_state` in
                    // `topology_soak_lane.rs`.
                    let outcome = self
                        .hydrate_file_with_timeout_locked(
                            driver,
                            group_id,
                            &local.path,
                            DEFAULT_HYDRATION_TIMEOUT,
                        )
                        .await?;
                    tracing::debug!(
                        local_device_id = %self.local_device_id,
                        group_id,
                        path = %local.path,
                        peer = %driver.peer_device_id(),
                        ?outcome,
                        "materialization audit: eager rehydrate outcome (Equal arm)"
                    );
                }
                Ok(LockedRecordOutcome::Settled)
            }
            ChangeOrdering::After => {
                if self.live_record_needs_rehydrate(group_id, &local, policy)? {
                    // `_locked`: this branch's only caller
                    // (`rematerialize_one_record`) already holds
                    // `path_lock` for `local.path` -- see
                    // `hydrate_file_with_timeout_locked`'s own doc
                    // comment for why the lock-acquiring public wrapper
                    // would deadlock here.
                    let outcome = self
                        .hydrate_file_with_timeout_locked(
                            driver,
                            group_id,
                            &local.path,
                            DEFAULT_HYDRATION_TIMEOUT,
                        )
                        .await?;
                    tracing::debug!(
                        local_device_id = %self.local_device_id,
                        group_id,
                        path = %local.path,
                        peer = %driver.peer_device_id(),
                        ?outcome,
                        "materialization audit: eager rehydrate outcome (After arm)"
                    );
                }
                Ok(LockedRecordOutcome::Settled)
            }
            ChangeOrdering::Before => {
                // Peer is ahead: adopt their version. this used to
                // ignore `remove_file`'s result (`let _ =...`) — if the
                // file was locked/open (a real occurrence on Windows) or
                // otherwise couldn't be removed, the index still recorded
                // `deleted=true` while the file remained; the next scan
                // then saw an on-disk file with no matching *not-deleted*
                // index entry, treated it as a brand-new local edit
                // (self-echo suppression is gated on `!existing.deleted`),
                // and resurrected + re-propagated it. `materialize` now
                // surfaces a real removal failure as an error instead of
                // silently discarding it.
                //
                // Same as the
                // never-seen branch above — must land before `materialize`,
                // and is skipped for a tombstone for the same reason (see
                // that branch's comment): applying kind/target/exec-bit
                // metadata onto the still-existing row moments before a
                // hazard-hold decision would leave a "mixed" row behind —
                // old content and authoring, but the incoming tombstone's
                // pre-delete metadata — if `materialize` decides to hold
                // rather than delete.
                if !incoming.deleted {
                    apply_incoming_wire_metadata(
                        self.state.as_ref(),
                        group_id,
                        &incoming,
                        &meta,
                        &root_commit_permit,
                    )?;
                }
                let payload = MaterializationPayload::from_wire(incoming.clone(), &meta);
                let outcome = self
                    .materialize(
                        driver,
                        group_id,
                        &payload,
                        policy,
                        &incoming_origin,
                        Some(incoming_author),
                    )
                    .await?;
                driver.forward(group_id, &incoming);
                Ok(match outcome {
                    MaterializeResult::Settled(_) => LockedRecordOutcome::Settled,
                    MaterializeResult::RetryRequired => LockedRecordOutcome::RetryRequired,
                })
            }
            ChangeOrdering::Concurrent => Ok(LockedRecordOutcome::Concurrent { local }),
        }
    }

    /// Returns true only when retained, group-matching DAG history proves
    /// that `incoming` is already represented by `local`. Any missing or
    /// unverifiable identity forces the locked path instead of falling back
    /// to the passive version-vector field.
    fn authoring_proves_redundant(
        &self,
        group_id: &str,
        local: &FileRecord,
        incoming: &FileRecord,
        meta: &IncomingWireMeta,
    ) -> Result<bool, PeerSessionError> {
        let Some(incoming_hash) = meta.authoring_change_hash.as_ref() else {
            return Ok(false);
        };
        match self.state.current_authoring_relation(group_id, &local.path, incoming_hash)? {
            Some(ChangeOrdering::Equal) => {
                // `same_record_content` only compares `FileRecord`'s own
                // fields (deleted/size/mtime/blocks) -- but under the identical authoring change,
                // this device's own `record_kind`/`symlink_target`/
                // `unix_mode`/`xattrs` can still have diverged from what
                // that change actually specifies (a regular file that got
                // reclassified as a symlink or vice versa, a different
                // symlink target, a lost exec bit, a dropped replicated
                // xattr, or an interrupted materialization that left the
                // index ahead of disk for one of these fields
                // specifically). Content equality alone must not
                // short-circuit reconciliation for a path whose
                // non-content metadata still needs repairing.
                //
                // ONE read for all four, and all four compared. The
                // xattrs were missing from this list while the `Equal`
                // arm this skip is deciding for DOES compare them, so a
                // path whose only divergence was an xattr was skipped
                // here and never reached the repair that would have
                // fixed it.
                let Some(row) = self.state.current_row_snapshot(group_id, &local.path)? else {
                    return Ok(false);
                };
                Ok(same_record_content(local, incoming)
                    && row.record_kind == meta.record_kind
                    && row.symlink_target == meta.symlink_target
                    && row.unix_mode == meta.unix_mode
                    && row.xattrs == meta.xattrs)
            }
            Some(ChangeOrdering::After) => Ok(true),
            Some(ChangeOrdering::Before | ChangeOrdering::Concurrent) | None => Ok(false),
        }
    }

    /// Fetches only the blocks not already held locally (
    /// missing-block computation; local dedup — a block already
    /// present, from any file/version, is never re-requested). Returns
    /// whether every block ended up present locally — `false` if this
    /// peer reported any as not found, which `hydrate_file` uses to know a
    /// fetch is incomplete, not just to log it.
    ///
    /// Retries a bounded number of
    /// times (`NOT_FOUND_RETRY_ATTEMPTS`) before accepting a
    /// `FetchOutcome::NotFound` as final — see `FetchOutcome`'s own doc
    /// comment for why this specifically retries `NotFound` and not
    /// `Unusable` (a decompression failure or similar). Two devices
    /// independently resolving the same conflict compute the same
    /// deterministic conflict-copy path (`conflict::resolve_conflict_names`)
    /// and can each request the other's content for it directly — one
    /// side's request can legitimately arrive before the other side's own
    /// `resolve_and_apply_conflict` has finished materializing/upserting
    /// that exact record locally, so `block_request_is_referenced` finds
    /// nothing yet and refuses with `not_found`. That's a transient race
    /// at the file-record/index layer, not a real content absence — the
    /// requested block's bytes are typically already sitting in the
    /// responding peer's own block store the whole time (it's that
    /// device's own prior edit); what's missing is the index entry
    /// linking the new conflict-copy path to those bytes. Since this
    /// retry is bounded (not indefinite), a block genuinely absent from
    /// every peer still fails — just after a few hundred milliseconds of
    /// retries instead of on the first attempt — so
    /// `a_block_missing_from_every_peer_fails_hydration_cleanly` is
    /// unaffected in outcome, only in exact timing. This intentionally
    /// does NOT retry inside `fetch_block`/`fetch_block_raw` itself: the
    /// *other* caller of `fetch_block` (`yadorilink-daemon`'s multi-peer
    /// hydration dispatcher, `hydration.rs`) already has its own, faster
    /// "this peer doesn't have it — reassign to a different candidate
    /// peer" strategy for the exact same signal, and stacking a same-peer
    /// retry underneath that would only slow down an already-correct
    /// fallback.
    /// Immediate-flush form, unchanged for every caller outside the
    /// ordinary-reconciliation preparation path (`materialize_dag_content_
    /// head`/`materialize`, hydration, etc.): fetches this file's blocks
    /// and flushes their provenance in ONE batched `record_group_block_
    /// provenance` call scoped to this file alone, exactly as before
    /// cross-file batching existed. See `ensure_blocks_present_collecting`
    /// for the reconciliation-only form that defers this flush so several
    /// files can share one transaction.
    pub(crate) async fn ensure_blocks_present(
        &self,
        driver: &Arc<dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver>,
        group_id: &str,
        file_path: &str,
        record: &FileRecord,
        // The version `record` is, from the caller's payload -- see
        // `ensure_blocks_present_core`.
        version_hash: &VersionHash,
        block_response_timeout: std::time::Duration,
    ) -> Result<bool, PeerSessionError> {
        // A pool of its own, drained before returning: this caller is
        // about one file, so there is no sibling file to share a barrier
        // with and nothing to gain from deferring. Its `all_present` keeps
        // exactly the meaning it always had -- every block durable -- which
        // is why the drain happens here rather than being left to a caller
        // that has no pool.
        let mut pool = ReceiveCommitPool::new(group_id, None);
        let core_result = self
            .ensure_blocks_present_core(
                driver,
                group_id,
                file_path,
                record,
                version_hash,
                block_response_timeout,
                None,
                None,
                &mut pool,
            )
            .await;
        self.pool_drain(driver, &mut pool, None).await;
        let hashes = std::mem::take(&mut pool.durable);
        let flush_result = self.flush_provenance_hashes(group_id, hashes, None).await;
        match core_result.and_then(|all_present| match pool.fatal.take() {
            // A commit that failed after every fetch succeeded is still
            // this call's failure: the blocks are not held.
            Some(e) => Err(e),
            None => Ok(all_present && !pool.lost_content),
        }) {
            // The fetch/store outcome (or its own fatal error) takes
            // precedence over a flush failure, matching this fn's
            // original (pre-split) first-error-wins behavior -- the flush
            // is still attempted either way so a fetch error never
            // discards already-durable siblings' provenance.
            Err(e) => Err(e),
            Ok(all_present) => flush_result.map(|()| all_present),
        }
    }

    /// Cross-file provenance batching: identical fetch/store behavior
    /// to `ensure_blocks_present`, but for the ordinary-reconciliation
    /// preparation path ONLY (`prepare_ordinary_projected_upsert`). Newly-
    /// fetched hashes are NOT flushed here -- returned to the caller
    /// instead, which attaches them to this candidate's own `Prepared
    /// ProjectedUpsert` so `try_commit_ordinary_batch` can flush every
    /// contributing file's hashes (deduplicated) in ONE `record_group_
    /// block_provenance` call per bounded (`ORDINARY_BATCH_MAX_PATHS`)
    /// commit chunk, instead of one call per file.
    ///
    /// The deferral applies ONLY when this call itself succeeds
    /// (`all_present`): a candidate that does NOT reach the batched commit
    /// path (some block missing, or a fatal fetch/store error) flushes its
    /// own partial progress immediately here, exactly like `ensure_blocks_
    /// present` would -- see requirement 6's own reasoning: a hash this
    /// call already durably `store.put` must never be left stranded
    /// unflushed just because ITS OWN candidate never reaches a commit
    /// batch.
    ///
    /// `reconcile_batch` is consulted (in addition to the DB-confirmed
    /// provenance set) so a LATER file in the same bounded reconciliation
    /// window that references a block an EARLIER file already fetched
    /// this same window never re-fetches it merely because that earlier
    /// file's own flush (deferred to the batch boundary) hasn't committed
    /// yet -- see `ReconcileProvenanceBatch`'s own doc comment.
    #[allow(clippy::too_many_arguments)]
    async fn ensure_blocks_present_collecting(
        &self,
        driver: &Arc<dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver>,
        group_id: &str,
        file_path: &str,
        record: &FileRecord,
        version_hash: &VersionHash,
        block_response_timeout: std::time::Duration,
        reconcile_batch: &ReconcileProvenanceBatch,
        call_timer: &crate::local_convergence::call_timer::ReconcileCallTimer,
        pool: &mut ReceiveCommitPool,
    ) -> Result<bool, PeerSessionError> {
        // No drain, and no per-file provenance flush. Both belong to the
        // pass that owns `pool`: draining here would put a barrier between
        // every pair of files, which for a one-block-per-file workload is
        // the barrier-per-block behaviour this pooling exists to remove.
        //
        // The hashes this file contributed are not returned either --
        // `pool.durable` accumulates every committed hash for the whole
        // pass, and the pass flushes provenance once from it. The previous
        // per-file split (return hashes when the file fully arrived, flush
        // them immediately when it did not) had the same net effect as
        // that single flush, just spread over one transaction per file.
        self.ensure_blocks_present_core(
            driver,
            group_id,
            file_path,
            record,
            version_hash,
            block_response_timeout,
            Some(reconcile_batch),
            Some(call_timer),
            pool,
        )
        .await
    }

    /// Shared fetch/store body for `ensure_blocks_present`/`ensure_blocks_
    /// present_collecting`: always returns every hash this call newly
    /// fetched and durably `store.put`, alongside the fetch/store outcome
    /// (or its own fatal error) -- NEVER flushes provenance itself, that
    /// is entirely the two callers' own responsibility, which is exactly
    /// what lets one defer it and the other not.
    #[allow(clippy::too_many_arguments)]
    async fn ensure_blocks_present_core(
        &self,
        driver: &Arc<dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver>,
        group_id: &str,
        file_path: &str,
        record: &FileRecord,
        // The version `record` is, from the caller's payload. NOT
        // recomputed from the index row here: `block_fetch_refusals`
        // evidence is bound to the exact version it is about, and a
        // refusal recorded against a hash stitched out of this record
        // plus four live row reads names a version no incarnation of the
        // row ever had -- so it matches nothing later and the refusal is
        // simply lost. The caller holding `path_lock` was the old
        // justification for the stitching, and it is the same one
        // `repair_row_snapshot` rejects: a base install
        // (`rebootstrap_store::install_base_rows`) rewrites a group's rows
        // without taking it.
        version_hash: &VersionHash,
        block_response_timeout: std::time::Duration,
        reconcile_batch: Option<&ReconcileProvenanceBatch>,
        call_timer: Option<&crate::local_convergence::call_timer::ReconcileCallTimer>,
        pool: &mut ReceiveCommitPool,
    ) -> Result<bool, PeerSessionError> {
        let blocks = &record.blocks;
        let hashes: Vec<_> = blocks.iter().map(|b| hex::encode(&b.hash)).collect();
        // Batched presence check rather than probing one
        // hash at a time — most of a hydration's blocks are typically
        // already-known-missing (that's the point of a placeholder), so
        // this collapses what would otherwise be N separate local-storage
        // calls interleaved with network fetches into one upfront query.
        let present = match self.store.present_blocks(&hashes) {
            Ok(present) => present,
            Err(e) => return Err(e.into()),
        };
        // Batched alongside `present_blocks` above, for the same reason --
        // calling the single-hash `group_has_block_provenance` once per
        // block would cost up to hundreds of separate SQLite round-trips
        // for one large file's worth of already-present blocks. `provenance_hashes` holds
        // the SUBSET of `block.hash` values with recorded provenance for
        // this group; a block whose hash isn't in this set has none (same
        // meaning as the single-hash call returning `false`).
        let provenance_hashes: std::collections::HashSet<Vec<u8>> =
            match self.state.group_has_block_provenance_batch(
                group_id,
                &blocks.iter().map(|b| b.hash.clone()).collect::<Vec<_>>(),
            ) {
                Ok(set) => set,
                Err(e) => return Err(e),
            };
        // Durability evidence:
        // `block_fetch_refusals` evidence must be bound to the EXACT
        // version it is about, not just the path -- a refusal recorded
        // against an older version must never be read as evidence about a
        // newer one that superseded it. That version is the caller's, and
        // arrives as `version_hash`.
        let current_version_hash_hex = version_hash.to_hex();
        let mut all_present = true;
        let concurrency = block_fetch_concurrency();
        // Bounded-concurrency block fetch rather than a strictly
        // one-at-a-time loop: per-block round-trip latency
        // (not transport throughput) dominates end-to-end time once bulk
        // bytes move fast: `DEFAULT_BLOCK_SIZE` (128 KiB) means a 1 GiB
        // file is up to ~8192 blocks, and even a few milliseconds of
        // unavoidable per-block control-plane/stream overhead compounds
        // linearly across that many strictly-sequential round-trips
        // (a 1 GiB transfer measured ~4.5ms/block sequentially).
        // `fetch_and_store_one_block` below is the per-block body (bounded
        // retry, fail-fast on `TimedOut`/`Redirect`/`Rejected`,
        // durability-fact recording); only how many run at once is
        // bounded here. `FuturesUnordered` of plain borrowed futures
        // (not `tokio::spawn`ed tasks) is deliberate: these are pure I/O-
        // bound awaits, need no separate task/thread, and dropping the
        // whole `FuturesUnordered` (e.g. on this function's own early
        // `Err` return below) cleanly cancels every still-in-flight fetch
        // with no detached background work left behind.
        // Factored out of the `FuturesUnordered` type below (clippy
        // type_complexity): a pinned, boxed, borrowed block-fetch future.
        type BlockFetchFuture<'a> = std::pin::Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<
                            yadorilink_peer_session::convergence_driver::FetchedBlock,
                            PeerSessionError,
                        >,
                    > + Send
                    + 'a,
            >,
        >;
        let mut in_flight: FuturesUnordered<BlockFetchFuture<'_>> = FuturesUnordered::new();
        // Set once a block is confirmed missing after its own bounded
        // retries -- the equivalent of a sequential loop's `break`: this peer
        // has already shown it cannot supply this path's content, so
        // launching further fetches against it only adds latency for a
        // result already known to be `false`. Blocks already in flight
        // when this flips are still awaited to completion in the drain
        // loop below -- only launching NEW ones stops.
        let mut give_up = false;
        // Hashes are no longer collected per call. They accumulate in `pool.durable`
        // as batches commit -- across every file of the pass, not just this
        // one -- and the pass owner flushes them through ONE batched
        // `record_group_block_provenance` call. A hash reaches that field
        // only from a batch that already returned `Ok`, so provenance still
        // trails durability; and it is kept regardless of whether THIS
        // file's attempt ends `Ok(false)` or `Err`, so a block already made
        // durable is never re-fetched because one of its siblings failed.
        //
        // A hard per-block error (transport failure, a panicked
        // `store.put`/index-write task) used to `return Err(e)` immediately
        // -- now deferred until after the provenance flush below, so
        // sibling blocks that already succeeded in THIS call keep their
        // provenance rather than losing it to an unrelated later failure.
        // First error wins; `give_up` is also set so no further NEW
        // fetches launch, matching `Missing`'s own fail-fast behavior.
        let mut fatal_error: Option<PeerSessionError> = None;
        for (block, already_present) in blocks.iter().zip(present) {
            // A physical hit may belong only to another group. Treat it as
            // missing until this group has independently obtained the
            // bytes -- OR an earlier file in this SAME bounded
            // reconciliation window already fetched it this call (durably
            // committed, provenance flush merely deferred to the batch
            // boundary): see `ReconcileProvenanceBatch`'s own doc comment
            // for why that is provenance-equivalent for this attempt.
            let pending_provenance = reconcile_batch.is_some_and(|b| b.already_known(&block.hash));
            if already_present && (provenance_hashes.contains(&block.hash) || pending_provenance) {
                continue; // already held — dedup, no network round-trip
            }
            // An earlier file in THIS pass already pulled these exact bytes
            // and they are sitting in the pool, committed or not. Fetching
            // them again would cost a second network round-trip for content
            // this device already has in hand. Not treated as "held": the
            // hash still becomes provenance-eligible only through its
            // batch, so a failed commit leaves both files unpublishable and
            // re-fetched, rather than one of them believing it holds bytes
            // that were never written.
            if pool.fetched.contains(&block.hash) {
                continue;
            }
            if give_up {
                all_present = false;
                continue;
            }
            if in_flight.len() >= concurrency {
                if let Some(result) = in_flight.next().await {
                    self.absorb_fetch_result(
                        driver,
                        result,
                        pool,
                        group_id,
                        file_path,
                        &current_version_hash_hex,
                        &mut all_present,
                        &mut give_up,
                        &mut fatal_error,
                        call_timer,
                    )
                    .await;
                }
            }
            if give_up {
                continue;
            }
            in_flight.push(driver.fetch_block(group_id, file_path, block, block_response_timeout));
        }
        while let Some(result) = in_flight.next().await {
            self.absorb_fetch_result(
                driver,
                result,
                pool,
                group_id,
                file_path,
                &current_version_hash_hex,
                &mut all_present,
                &mut give_up,
                &mut fatal_error,
                call_timer,
            )
            .await;
        }

        // Nothing is drained here, deliberately. Whatever this file's
        // blocks did not fill stays pending so the NEXT file's blocks can
        // share the same barrier -- which is the entire point, since a
        // tiny-file workload is one block per file and a pool drained per
        // file could never batch anything. The pass owner drains once, and
        // only hashes from batches that already returned `Ok` become
        // provenance-eligible, so the ordering contract is unchanged.
        //
        // `all_present` here therefore means "every block is either already
        // held or has been fetched and handed to the pool", not "every
        // block is durable". The caller reconciles that against the drain's
        // own outcome; `ensure_blocks_present` does it immediately, the
        // cross-file pass at the end of its loop.
        match fatal_error {
            Some(e) => Err(e),
            None => Ok(all_present),
        }
    }

    /// Everything between "the bytes are down" and "a proof may be
    /// taken", for the peer hydration lane: stamp the payload's metadata
    /// onto the file, confirm the replicated xattrs really landed, and
    /// observe the finished object.
    ///
    /// Together, because they are one claim. `version.version_hash` is a
    /// hash over the mode and the xattrs as well as the block list, so a
    /// proof naming it asserts all three; taking the identity before the
    /// metadata is applied describes a state the same attempt is about to
    /// change; and `apply_xattrs` swallows a `fsetxattr`/`fremovexattr`
    /// failure by its own documented contract, so without
    /// `require_xattr_evidence` nothing upstream would ever see one.
    ///
    /// Every value written comes from `version` -- the payload -- never
    /// from the row. Re-reading the row here would let a supersession
    /// mid-hydration dress V1's bytes in V2's mode and xattrs under a
    /// proof naming V1.
    fn finish_hydration_write_before_proof(
        &self,
        path: &str,
        out_path: &Path,
        version: &FileVersion,
    ) -> Result<yadorilink_root_authority::fs_identity::FileIdentity, PeerSessionError> {
        // Test-only failure-injection seam standing in for a real,
        // repeatable chmod `EPERM` or xattr `EOPNOTSUPP`. Compiled out
        // entirely in production.
        #[cfg(any(test, feature = "test-support"))]
        if self
            .force_hydration_failure_during_metadata_apply
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(PeerSessionError::HydrationFailed(path.to_string()));
        }
        let applied = yadorilink_local_storage::apply_file_metadata_verified(
            out_path,
            version.meta.unix_mode,
            &version.meta.xattrs,
        )?;
        require_xattr_evidence(
            path,
            out_path,
            &version.meta.xattrs,
            &XattrEvidence::from(applied),
        )?;
        // A failed observation abandons the attempt rather than falling
        // through to the claim: the fence bump earlier already made any
        // previous proof stale, so claiming `Hydrated` with no proof
        // would leave the state the hydration reader refuses to
        // reconstruct over, wedging the path.
        yadorilink_root_authority::fs_identity::FileIdentity::observe_path(out_path).map_err(
            |error| {
                tracing::warn!(
                    %path,
                    %error,
                    "could not observe the file just reconstructed; abandoning this hydration \
                     attempt rather than claiming Hydrated without a proof"
                );
                PeerSessionError::HydrationFailed(path.to_string())
            },
        )
    }

    /// Hands `record` to `forward_tx`, if set — a full mesh needs every
    /// peer session to relay what it learns to this device's other peers.
    /// Hydrates one path, taking `path_lock` for the whole attempt.
    ///
    /// This is the entry point the session used to expose and forward here;
    /// it belongs to the executor, because the lock it takes is the one
    /// every other writer for this path takes, and all of those writers are
    /// this type's. Two concurrent attempts on one path would otherwise
    /// interleave their temp-then-rename writes, and an authoring-identity
    /// refusal does not undo a rename that already landed.
    pub async fn hydrate_file(
        self: &Arc<Self>,
        driver: &Arc<dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver>,
        group_id: &str,
        path: &str,
    ) -> Result<HydrationOutcome, PeerSessionError> {
        self.hydrate_file_with_timeout(
            driver,
            group_id,
            path,
            yadorilink_peer_session::peer_session::DEFAULT_HYDRATION_TIMEOUT,
        )
        .await
    }

    /// [`hydrate_file`](Self::hydrate_file) with an explicit ceiling.
    /// Production callers use the default; tests use a much shorter one so
    /// the "no reachable peer" case does not make a suite slow.
    pub async fn hydrate_file_with_timeout(
        self: &Arc<Self>,
        driver: &Arc<dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver>,
        group_id: &str,
        path: &str,
        timeout: std::time::Duration,
    ) -> Result<HydrationOutcome, PeerSessionError> {
        let path_lock = self.state.path_lock(group_id, path);
        let _guard = path_lock.lock().await;
        self.hydrate_file_with_timeout_locked(driver, group_id, path, timeout).await
    }

    /// The actual hydration body, assuming the caller already holds
    /// `SyncState::path_lock` for `path` -- used directly by
    /// `apply_locked_record`'s `Equal`/`After` rehydrate branches, whose
    /// only caller (`rematerialize_one_record`) already holds that same
    /// lock for its whole body; calling the public, lock-acquiring
    /// `hydrate_file_with_timeout` from there would deadlock on
    /// `tokio::sync::Mutex`'s non-reentrant lock.
    pub(crate) async fn hydrate_file_with_timeout_locked(
        &self,
        driver: &Arc<dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver>,
        group_id: &str,
        path: &str,
        timeout: std::time::Duration,
    ) -> Result<HydrationOutcome, PeerSessionError> {
        // Hydration places the row it was asked to place, so its payload
        // IS that row -- fixed here, at entry, and used for the fetch, the
        // reconstruct, the exactness gate and the commit alike. Reading
        // the version again after the write would ask a different
        // question at a different moment: a supersession that keeps the
        // authoring identity moves the row while the bytes this attempt
        // assembled do not move at all.
        //
        // ONE read, and this time actually one. An earlier draft took the
        // version from `get_current_version_record` and the record from a
        // separate `get_file`, which is the very ABA this comment claims
        // to prevent. Deriving the record from the version fixed that
        // half -- and left the other half in place: the authoring hash
        // was still a second read, in a second transaction, under a
        // comment that said "ONE read". The row could move between them,
        // and then this attempt held V1's bytes beside A2's identity,
        // which is a pair that never existed. The pre-write authoring
        // re-check compares A2 against A2 and passes; the final commit's
        // expected_version refuses, but only after V1's bytes are on
        // disk; and the rehydration guard, bound to A2, would revert V2's
        // row.
        //
        // `current_row_snapshot` returns the version, the record and the
        // authoring identity from one statement, so none of that is
        // expressible.
        let Some(current) = self.state.current_row_snapshot(group_id, path)? else {
            return Err(PeerSessionError::NotFound(format!("file {group_id}/{path}")));
        };
        // Not over a path a snapshot install holds: what is on disk there
        // belongs to the replaced row, or is an uncaptured edit of it, and
        // only the install's reconciliation may decide which.
        if self
            .state
            .snapshot_install_hold_repository()
            .is_held(group_id, path)
            .map_err(crate::sync_error::SyncError::from)
            .map_err(PeerSessionError::from)?
        {
            return Err(PeerSessionError::HydrationFailed(path.to_string()));
        }
        if current.record.deleted {
            return Err(PeerSessionError::NotFound(format!("file {group_id}/{path}")));
        }
        let payload = MaterializationPayload::from_current_row(path, current.to_file_version());
        let record = payload.record().clone();
        let target_version = payload.version().clone();
        // From the same statement as `target_version`, so the guard below
        // and the commit at the end are about one incarnation of the row.
        let authoring_change_hash = current.authoring_change_hash;
        let out_path = self.local_file_path(group_id, path)?;
        // Captured BEFORE the (possibly multi-second) block fetch below,
        // for the identical reason the daemon's own `hydrate_inner`
        // captures `initial_disk_identity`: re-verifying the authoring
        // identity before the physical write is not enough without also
        // checking disk identity. A `Placeholder` row already has a real sparse file on disk
        // (`chunker::write_placeholder`, written when the row was first
        // set to `Placeholder`); if an external editor writes real
        // content into that same-named file while this attempt is mid-
        // fetch -- `path_lock` is held for this whole attempt, but an
        // editor writing directly to the file does not go through
        // `path_lock` at all -- the authoring-hash re-check alone cannot
        // detect it (the index row's authoring identity hasn't changed,
        // only the bytes on disk have). Re-checked just before
        // `reconstruct_file` below; a mismatch means this attempt must
        // not overwrite what's now on disk.
        //
        // The same `lstat` is what the attempt's starting point is judged
        // from: that re-check only proves the file did not change DURING
        // the attempt, and an edit made before it started (or a delete)
        // would otherwise be the baseline itself.
        let initial_lstat = std::fs::symlink_metadata(&out_path).ok();
        let initial_disk_identity = initial_lstat.as_ref().map(disk_race_fingerprint_of);
        let root_commit_authority = self.root_lease_for(group_id)?;
        let root_commit_authority_op = root_commit_authority.begin_operation()?;
        let root_commit_permit = root_commit_authority_op.permit();
        // A CAS, not a blind write. `path_lock` serializes this device's
        // own materializers, and does not exclude a DAG-side supersession
        // at all -- so between the snapshot above and this line the row
        // can become V2, and an unconditional set stamps V2's row
        // `Hydrating` on behalf of an attempt that is about V1. The
        // rollback guard is bound to V1 and will then correctly decline
        // to touch it, which leaves V2 stuck `Hydrating` forever.
        //
        // The state is part of the guard, not just the version and the
        // authoring hash: another attempt for this same version may have
        // already finished and stamped `Hydrated`, and an older attempt
        // must not drag that back to `Hydrating`.
        //
        // The guard it returns reverts the row back on drop unless `commit`ed
        // -- every `?` between here and the end of this function used to
        // leave the row stuck at `Hydrating` forever on a real error
        // (a hazard-check I/O/DB failure, `clear_held`, root/containment
        // verification, disk-headroom preflight, the reconstruct itself,
        // or the exec-bit apply). The two outcomes that already had their
        // own explicit revert (fetch failure, hazard-hold) construct and
        // immediately drop their own guard too, so every exit path is
        // covered by exactly one mechanism instead of some exits
        // remembering to revert and others not. Its revert target is
        // exactly what the CAS moved away from, so an abandoned attempt
        // leaves the row as it found it.
        // Anything but a `Hydrated` row: the file is supposed to be this
        // device's placeholder, and the attempt may only replace it if it
        // still is -- the judgement access hydration makes too, see
        // `admit_hydration_start`. Before the entry CAS, which moves the row
        // off `Placeholder` and with it the recorded placeholder identity
        // the judgement reads. Not under a filename hazard: what answers
        // to `out_path` there may be a case-folding sibling, which is
        // neither this row's placeholder nor a local change to it, and the
        // hazard exit after the fetch writes nothing there anyway.
        if current.materialization_state != Some(MaterializationState::Hydrated)
            && self.hazard_reason_for(group_id, &record)?.is_none()
            && !crate::daemon_state::run_blocking_sweep_offloaded(|| {
                self.state.admit_hydration_start(
                    group_id,
                    path,
                    &out_path,
                    initial_lstat.as_ref(),
                    &current.record,
                    current.unix_mode,
                    &current.xattrs,
                    &root_commit_permit,
                )
            })
            .map_err(PeerSessionError::from)?
        {
            tracing::warn!(
                %path,
                group_id,
                "the file is no longer the placeholder this device wrote; leaving the local \
                 change for local capture and hydrating nothing"
            );
            return Err(PeerSessionError::HydrationFailed(path.to_string()));
        }
        let Some(mut hydrating_guard) = self.state.begin_convergence_hydration(
            group_id,
            path,
            current.materialization_state,
            authoring_change_hash,
            target_version.version_hash,
        )?
        else {
            return Err(PeerSessionError::HydrationFailed(path.to_string()));
        };

        let outcome = tokio::time::timeout(
            timeout,
            self.ensure_blocks_present(
                driver,
                group_id,
                path,
                &record,
                &target_version.version_hash,
                Tuning::FETCH_RESPONSE_TIMEOUT,
            ),
        )
        .await;

        let all_present = match outcome {
            Ok(Ok(all_present)) => all_present,
            Ok(Err(e)) => return Err(e),
            Err(_timed_out) => false,
        };

        if !all_present {
            return Err(PeerSessionError::HydrationFailed(path.to_string()));
        }

        // Same hazard short-circuit as
        // `materialize` — every block was just fetched into this device's
        // block store above regardless (so it can still serve them onward
        // to another peer), but the atomic reconstruct-to-disk
        // write below must never run for a hazardous name. Reverts back
        // to `Placeholder` (content genuinely isn't on disk under this
        // name) rather than leaving the row stuck at `Hydrating`, and
        // returns `Ok(Held)` rather than an error — the blocks really were
        // hydrated successfully; only local materialization was withheld,
        // and the caller must not read this as indistinguishable from a
        // genuine `Hydrated`.
        if let Some(reason) = self.hazard_reason_for(group_id, &record)? {
            hydrating_guard.hold_for_hazard(&reason)?;
            tracing::info!(
                path = %path,
                group_id,
                reason = %reason,
                "hydration fetched all blocks but the file is held due to a filename hazard; \
                 not materialized on this device"
            );
            // The guard's own drop reverts to `Placeholder` -- this is
            // exactly that "hazard, not error" exit, not a rollback of
            // something that failed.
            return Ok(HydrationOutcome::Held { reason });
        }
        // The owner step reads the held marker first -- a read, not itself
        // a writer-gate write -- to decide whether the intent guard is
        // worth opening at all. Only an actual
        // transition OUT of a hold needs it; for the overwhelmingly common
        // case (this path was never held), its `clear_held` is
        // already a documented safe no-op, and opening the extra intent
        // guard unconditionally on every ordinary hydration would add a
        // real per-call write to the hot path for zero protective benefit
        // -- an unheld path was never relying on `held_reason` for
        // tombstone-loop protection in the first place. Same reasoning as
        // `materialize`'s own symlink branch's identical gating.
        //
        // Opened BEFORE `clear_held`, not after -- same reasoning as
        // `materialize`'s own symlink branch (see that call site's own
        // comment for the full argument). `held_reason` being set is
        // itself what protects a held row from the tombstone loop; the
        // instant `clear_held` clears it, the row looks like an ordinary,
        // unprotected `Placeholder`/`Hydrating` row until this function
        // either commits a genuine `Hydrated` write or fails. Every exit
        // between here and that commit (`?`-propagated or an explicit
        // early `return Err`) drops this guard without clearing it,
        // automatically, via Rust's own scope-exit semantics -- no
        // separate handling needed at each of the several fallible steps
        // below (authoring-hash CAS, disk-race re-check, root/containment
        // verification, disk-headroom preflight, the reconstruct itself,
        // the fingerprint recording). A dangling intent left by any of
        // those failures is exactly the fail-safe outcome this guard
        // exists to guarantee, matching this whole file's established "an
        // intent left dangling is fail-safe" discipline -- explicitly
        // cleared only at the one point below where the row is confirmed
        // to have actually transitioned to `Hydrated`.
        let hold_transition_intent_guard = hydrating_guard.release_hold_under_intent(
            &yadorilink_local_storage::intent_target_hash(&record.blocks),
            &root_commit_permit,
        )?;
        // Test-only failure-injection seam, proving the guard just opened
        // above genuinely survives an arbitrary failure anywhere in the
        // remainder of this function (representative of any of the several
        // real fallible steps below -- they all rely on the identical
        // "drop without clearing" mechanism, so exercising one exercises
        // all of them). Compiled out entirely in production.
        #[cfg(any(test, feature = "test-support"))]
        if self
            .force_hydration_failure_after_hold_cleared
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(PeerSessionError::HydrationFailed(path.to_string()));
        }

        // Re-validate this attempt's captured authoring identity BEFORE
        // the physical write below -- the rollback above alone is not
        // enough: a concurrent
        // peer update can supersede this row with a genuinely newer
        // version at any point during the (up to `timeout`-long) block
        // fetch above, and this attempt is still working off `record`,
        // the OLD version read at the very start. Without this check,
        // reconstructing and committing here would write the OLD
        // version's bytes to disk and then mark the NOW-current (newer)
        // row `Hydrated` -- index says the new version is fully
        // materialized while disk actually holds the old one. Failing
        // here is not a real hydration failure (the blocks this attempt
        // fetched are still valid and stored for the version it started
        // with); the caller retries and a fresh call picks up the
        // current version correctly.
        // Both halves, from one read. The authoring hash alone was the
        // check here, and it cannot see a supersession that keeps the
        // hash while moving the content columns -- which is precisely the
        // shape this whole arc is about. A version mismatch means this
        // attempt's blocks are for a version the path has left.
        let live = self.state.current_row_snapshot(group_id, path)?;
        let still_this_version = live.as_ref().is_some_and(|row| {
            row.authoring_change_hash == authoring_change_hash
                && row.to_file_version().version_hash == target_version.version_hash
        });
        if !still_this_version {
            return Err(PeerSessionError::HydrationFailed(path.to_string()));
        }
        // The authoring-identity re-check above catches a concurrent PEER
        // update superseding this row; it says nothing about a concurrent
        // LOCAL edit, which never touches the index's authoring column at
        // all until the watcher gets around to processing it (and the
        // watcher's own DAG-authoring path is itself serialized behind
        // this same `path_lock`, so it cannot even run until this attempt
        // finishes). Re-checking disk identity here closes that gap: if
        // an external editor wrote real content into the placeholder
        // file while this attempt was mid-fetch, disk no longer matches
        // what this attempt captured before starting, and reconstructing
        // now would silently discard that edit the moment the watcher is
        // finally unblocked and reads it as already-gone.
        if disk_race_fingerprint(&out_path) != initial_disk_identity {
            return Err(PeerSessionError::HydrationFailed(path.to_string()));
        }
        // defense-in-depth — see `materialize`'s matching call
        // for what this does and does not close.
        self.verify_write_target(group_id, &out_path)?;
        // Preflight before the
        // temp-then-rename write below begins — see
        // `preflight_disk_headroom`'s doc comment.
        self.preflight_disk_headroom(group_id, &out_path, record.size)?;
        // Every mutation below (reconstruct_file_off_runtime,
        // apply_file_metadata) runs under a mutation-fence bump, like
        // every sibling physical mutator (`materialize`'s own
        // hydration/placeholder/content writes just below, the daemon's `hydration.rs::hydrate_inner`
        // for its equivalent on-demand-hydration write). Same reasoning as
        // those: this write has no DAG-frontier proof of its own to
        // publish under -- the authoring-hash CAS below
        // (`transition_materialization_state_if_same_authoring`) guards
        // this attempt's OWN commit against a concurrent supersession, but
        // says nothing to any OTHER, unrelated reader about whether an
        // existing `path_materialized_generations` proof for this path is
        // still current -- so this only ever bumps/invalidates the fence,
        // inside `path_lock` (held for this whole attempt), before the
        // real write below.
        let mutation_generation = hydrating_guard.begin_physical_write()?;
        // Off the async runtime -- see `reconstruct_file_off_
        // runtime`'s own doc comment for the failure mode this closes
        // (large-file reconstruction blocking this process's tokio worker
        // pool long enough to starve this same peer's own channel actor).
        reconstruct_file_off_runtime(
            self.store.clone(),
            &out_path,
            &record.blocks,
            record.mtime_unix_nanos,
        )
        .await?;
        // Everything the proof below is about has to be on disk BEFORE
        // the proof is taken, and `version_hash` is a hash over the mode
        // and the replicated xattrs as much as over the bytes. These
        // three steps used to run AFTER the commit, on the reasoning that
        // a failure in them was survivable because the content was
        // already right -- but that reasoning is about the content, and
        // the claim is about the version. A chmod EPERM or an xattr
        // EOPNOTSUPP left `ExactObject(version = V1)` and `Hydrated`
        // durably committed for a disk state that was not V1, and
        // `pin_and_hydrate_file` reads exactly that pair as "already
        // hydrated". The recorded `FileIdentity` was taken early too, so
        // even the identity described a state this attempt then changed.
        //
        // Ordering is now: write the bytes, dress them, prove they are
        // exact, observe them, and only then claim anything.
        let identity =
            match self.finish_hydration_write_before_proof(path, &out_path, &target_version) {
                Ok(identity) => identity,
                Err(error) => {
                    // The intent is cleared here, explicitly, rather than
                    // left to dangle. Its job is to stop a later scan reading
                    // "no file" as an offline delete while a write was in
                    // flight; the bytes are on disk and no write is in flight
                    // any more, so it has nothing left to protect -- and
                    // leaving it would be a REACHABLE steady state, not a
                    // crash window, because this row is about to revert to
                    // `Placeholder` and nothing clears an intent on that path.
                    //
                    // That danger is real, and it is what the previous
                    // ordering was reaching for. It is not a reason to
                    // publish a proof that is false: a dangling intent is
                    // repaired by clearing it, which is what this does.
                    if let Some(guard) = hold_transition_intent_guard {
                        if let Err(clear_error) = guard.clear() {
                            tracing::warn!(
                                %path,
                                error = %clear_error,
                                "could not clear the held-transition intent after an abandoned \
                                 hydration; a later offline delete of this path may be misread as \
                                 an interrupted write"
                            );
                        }
                    }
                    // The rehydration guard still reverts the row to
                    // `Placeholder` on the way out, so the path stays a
                    // repair candidate and this attempt is re-driven.
                    return Err(error);
                }
            };
        // Everything this reconstruct proved, in one durable commit: the
        // versioned proof under the epoch bumped above, the `Hydrated`
        // stamp, and the intent clear.
        //
        // This used to go through the EXTERNAL-adoption path
        // (`adopt_local_capture_actual_state`), which mints a fresh epoch
        // of its own.
        // For an internal mutator that already bumped the fence before
        // its own write, that advanced it again on the way to recording
        // what the write did, and published `version: None` besides.
        // Since the resolved-path-state hash encodes version presence,
        // such a proof matches no desired resolution, so it could never
        // settle anything.
        //
        // The author-binding is not lost by moving off
        // `transition_materialization_state_if_same_authoring` -- it is
        // strengthened. It was a separate statement from the publish, so
        // a supersession could land between them; passing it as the
        // commit's own guard makes the re-check and the write one step.
        // Its purpose is unchanged: if the row has moved on, this
        // attempt's bytes are stale for whatever version is current now,
        // and it must not claim `Hydrated` for a version it never
        // materialized.
        // The guard commits the version fixed at entry, alongside the
        // record these bytes were assembled from, and expects `Hydrating`
        // with the authoring identity and version it captured then: the
        // re-read just above ran in a different transaction from this
        // commit, so the check still closes a real window. It disarms the
        // revert only when the commit published.
        if !hydrating_guard.commit_exact_file(identity, mutation_generation, &root_commit_permit)? {
            return Err(PeerSessionError::HydrationFailed(path.to_string()));
        }
        // The commit above cleared the intent in the same transaction
        // that published the proof, so there is nothing left for this
        // guard to do. Dropping it is inert -- it has no `Drop`
        // behaviour -- and the clear can no longer land in a separate
        // statement from the proof it is supposed to follow.
        drop(hold_transition_intent_guard);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        self.state.touch_last_accessed(group_id, path, now)?;
        Ok(HydrationOutcome::Hydrated)
    }

    /// The equal-authoring metadata repair's File settle, after the metadata
    /// step. That step moved the row's version, and a bump also made its
    /// proof unusable, so a `Hydrated` row has to be proven again or access hydration refuses
    /// it as `CorruptState`. Only bytes, mode and xattrs compared against
    /// the version are proven, under `mutation_generation` (the value the
    /// step's bump or snapshot returned): anything else on disk (an edit
    /// not yet journalled) leaves the row unproven, which fails closed. A
    /// `Placeholder` has no content to prove.
    #[allow(clippy::too_many_arguments)]
    fn prove_equal_authoring_file_repair(
        &self,
        group_id: &str,
        local: &FileRecord,
        meta: &IncomingWireMeta,
        out_path: &Path,
        authoring: &ChangeHash,
        mutation_generation: i64,
        permit: &yadorilink_root_authority::root_commit::RootCommitPermit<'_>,
    ) -> Result<(), PeerSessionError> {
        // A disk read that fails is a mismatch, not an error: the version
        // this step just applied may itself leave the file unreadable to
        // its owner (a write-only mode), and failing here would fail the
        // record on every pass. The row stays unproven, which fails closed.
        // The xattrs use the strict reader, not the best-effort
        // `xattrs_already_match_disk`, which reads a failed attribute read
        // as "no attributes" and so could prove a version whose attributes
        // it never read.
        let disk_is_the_version = || {
            matches!(
                yadorilink_local_storage::disk_bytes_match_indexed_blocks(out_path, &local.blocks),
                Ok(true)
            ) && matches!(
                yadorilink_local_storage::unix_mode_already_matches_disk(out_path, meta.unix_mode),
                Ok(true)
            ) && matches!(
                yadorilink_local_storage::verify_replicated_xattrs_exact(out_path, &meta.xattrs),
                Ok(true)
            )
        };
        if self.state.get_materialization_state(group_id, &local.path)?
            != Some(MaterializationState::Hydrated)
            || !disk_is_the_version()
        {
            return Ok(());
        }
        let version = MaterializationPayload::from_wire(local.clone(), meta).version().version_hash;
        if !self.state.settle_equal_authoring_metadata_repair(
            group_id,
            &local.path,
            out_path,
            version,
            authoring,
            mutation_generation,
            permit,
        )? {
            tracing::debug!(
                group_id,
                path = %local.path,
                "equal-authoring metadata repair could not prove its row (fence or row moved); \
                 it stays unproven"
            );
        }
        Ok(())
    }

    fn live_record_needs_rehydrate(
        &self,
        group_id: &str,
        record: &FileRecord,
        policy: MaterializationPolicy,
    ) -> Result<bool, PeerSessionError> {
        if record.deleted {
            return Ok(false);
        }
        if self.state.get_record_kind(group_id, &record.path)?.unwrap_or_default()
            != RecordKind::File
        {
            return Ok(false);
        }
        let materialization_state = self.state.get_materialization_state(group_id, &record.path)?;
        // This has to agree with `list_materialization_repair_candidates`,
        // which is what selected this path in the first place. That query
        // takes a placeholder under an `eager` policy, a placeholder that
        // is PINNED whatever the policy, and any row left `hydrating`.
        //
        // This gate used to ask only `policy == Eager`, so on an OnDemand
        // group the audit picked a pinned placeholder or a stuck
        // `Hydrating` row as a repair candidate and then dropped it here
        // -- the storage layer naming a path as needing content and the
        // session's own fast-skip cancelling it out. A pinned placeholder
        // after a transient failure is exactly the case a user notices:
        // pinning is documented as forcing hydration, and nothing else
        // re-drives it.
        let wants_content = policy == MaterializationPolicy::Eager
            || materialization_state == Some(MaterializationState::Hydrating)
            || self.state.is_pinned(group_id, &record.path)?;
        if !wants_content {
            return Ok(false);
        }
        if materialization_state != Some(MaterializationState::Hydrated) {
            return Ok(true);
        }
        // The stamp is a claim, and a claim with nothing behind it is what
        // this question exists to catch. A size match cannot substitute:
        // it is satisfied by the PREVIOUS version's bytes whenever the two
        // versions happen to be the same length, and by any edit that
        // preserved length. So require the row's own proof -- usable
        // against the live fence, and about the version this row names --
        // and fail closed to "needs rehydrating" without it. The cost of
        // being wrong in that direction is work already done; the cost in
        // the other direction is a path that never gets its content.
        if !self.state.dag_usable_proof_names_current_version(group_id, &record.path)? {
            return Ok(true);
        }

        let out_path = self.local_file_path(group_id, &record.path)?;
        let on_disk_size = std::fs::metadata(&out_path).ok().map(|m| m.len());
        Ok(on_disk_size != Some(record.size))
    }

    /// The local materialization-repair path's payload producer
    /// (`reconcile_local_materialization_audit` /
    /// `rematerialize_local_records`).
    ///
    /// The single read behind [`materialization_audit_candidate`], which
    /// takes the row rather than reading it. Every audit payload this
    /// device produces comes through here, so this one statement is the
    /// whole of what "produced from one incarnation of the row" rests on.
    pub fn materialization_audit_candidate(
        &self,
        group_id: &str,
        path: &str,
    ) -> Result<AuditCandidate, PeerSessionError> {
        Ok(materialization_audit_candidate(self.state.current_row_snapshot(group_id, path)?))
    }

    pub async fn materialize(
        &self,
        driver: &Arc<dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver>,
        group_id: &str,
        payload: &MaterializationPayload,
        policy: MaterializationPolicy,
        origin_device_id: &str,
        authoring_change_hash: Option<&ChangeHash>,
    ) -> Result<MaterializeResult, PeerSessionError> {
        let record = payload.record();
        let mut satisfied: Option<BlockRequirement> = None;
        loop {
            let outcome = self
                .materialize_local(
                    group_id,
                    payload,
                    // This entry point materializes the path it is handed and
                    // derives nothing, so the path demands its own content.
                    &record.path,
                    policy,
                    origin_device_id,
                    authoring_change_hash,
                    satisfied.as_ref(),
                )
                .await?;
            let requirement = match outcome {
                LocalMaterializeOutcome::Concluded(result) => return Ok(result),
                LocalMaterializeOutcome::NeedBlocks(requirement) => requirement,
            };
            debug_assert!(
                satisfied.is_none(),
                "the local core asked for blocks twice; it must settle or decline after one                  attempt, or this loop would poll the block lane"
            );
            if satisfied.is_some() {
                return Ok(MaterializeResult::RetryRequired);
            }
            // Every block this attempt does obtain is stored durably and keeps
            // its provenance, whatever happens to its siblings -- so a partial
            // result is progress the next attempt does not repeat, not work
            // thrown away.
            tokio::time::timeout(
                Tuning::BULK_MATERIALIZE_TIMEOUT,
                self.ensure_blocks_present(
                    driver,
                    group_id,
                    &record.path,
                    record,
                    &requirement.version_hash,
                    Tuning::BULK_FETCH_RESPONSE_TIMEOUT,
                ),
            )
            .await
            .map_err(|_elapsed| PeerSessionError::HydrationFailed(record.path.clone()))??;
            satisfied = Some(requirement);
        }
    }

    /// Fetch every block this pass is going to want, and record what was
    /// observed for each path before its request went out.
    ///
    /// One bounded attempt per path. A path whose content does not arrive is
    /// still returned: the pass needs its before-picture either way, and it is
    /// what tells the pass to record a retriable placeholder rather than ask
    /// again. Provenance for everything obtained is flushed once, here, so the
    /// pass never publishes a row whose blocks this group cannot prove it
    /// holds.
    ///
    /// `call_timer` is the caller's own whole-attempt timer, not one created
    /// here: this is where an attempt's block fetching actually happens, so
    /// a timer scoped to this function alone is dropped before anything
    /// reports it (see `reconcile_paths_directly`'s own comment).
    pub(crate) async fn obtain_missing_content(
        &self,
        driver: &Arc<dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver>,
        group_id: &str,
        paths: &std::collections::BTreeSet<String>,
        call_timer: &crate::local_convergence::call_timer::ReconcileCallTimer,
    ) -> Result<HashMap<String, BlockRequirement>, PeerSessionError> {
        // On-demand is a promise about bytes: track every path and version a
        // peer publishes, fetch content only when something asks. This pass
        // is not something asking -- it runs on every reconnect and after
        // every unrelated commit, for every path in the group, so fetching
        // here would fill an on-demand folder up simply by staying connected.
        //
        // `materialize_local` already respects the policy and lands these
        // rows at `Placeholder`, which is why the state is right even today
        // and only the block store gives the bypass away. It is the one
        // remaining content fetch that never consults the policy at all.
        //
        // An explicit hydration is unaffected: it enters through
        // `hydration.rs` and `ensure_blocks_present`, not through this pass.
        // A group with no link row at all is left to fetch, matching every
        // other consumer's reading of `None` as "not on-demand" rather than
        // as a refusal.
        //
        // A PIN is something asking, so it still fetches. That exception is
        // not optional here: the pass maps `NeedBlocks` to `RetryRequired`
        // and never reaches for the transport itself, so a pinned record it
        // did not prefetch would retry forever without ever being obtained.
        // `materialize_local` makes the same exception in the same order --
        // `pinned || (policy == Eager && ..)` -- and this keeps the two
        // readings of "on-demand does not fetch" identical.
        let on_demand = matches!(
            self.state.materialization_policy_for_group(group_id),
            Ok(Some(MaterializationPolicy::OnDemand))
        );
        let mut wanted = self.content_missing_locally(group_id, paths)?;
        if on_demand {
            let mut pinned = Vec::new();
            for requirement in wanted {
                if self.state.is_pinned(group_id, &requirement.demand_path)? {
                    pinned.push(requirement);
                }
            }
            wanted = pinned;
        }
        if wanted.is_empty() {
            return Ok(HashMap::new());
        }
        let batch = Arc::new(ReconcileProvenanceBatch::new());
        // ONE pool for the whole pass, not one per file. A tiny-file
        // workload is exactly one block per file, so a pool that drained at
        // each file boundary could never batch anything: 2000 one-block
        // files produced 2000 batches of one, and therefore 2000 durability
        // barriers, measured end to end on two real daemons. Pooling across
        // the pass is what lets the block store's group commit do the job
        // it was built for -- the local capture side reached the same
        // conclusion, which is why `ScanBlockStaging` pools across files
        // rather than per file.
        let mut pool = ReceiveCommitPool::new(group_id, Some(Arc::clone(&batch)));
        for requirement in &wanted {
            // Bounded per path. An unreachable or unhelpful peer leaves this
            // path's content absent, which the pass then records durably --
            // it never becomes a wait.
            let fetched = tokio::time::timeout(
                Tuning::BULK_MATERIALIZE_TIMEOUT,
                self.ensure_blocks_present_collecting(
                    driver,
                    group_id,
                    &requirement.path,
                    &requirement.record,
                    &requirement.version_hash,
                    Tuning::BULK_FETCH_RESPONSE_TIMEOUT,
                    &batch,
                    call_timer,
                    &mut pool,
                ),
            )
            .await;
            match fetched {
                // Hashes are not collected here any more: they land in
                // `pool.durable` when the batch carrying them commits,
                // which may be during a LATER file's fetching or not until
                // the drain below. That deferral is the point -- and it is
                // also what keeps provenance strictly behind durability,
                // since a hash cannot reach `pool.durable` before the write
                // it attests to returned `Ok`.
                Ok(Ok(_all_present)) => {}
                // Neither a timeout nor a fetch error is this pass's failure:
                // every other path still converges, and this one is absent,
                // which the pass already knows how to record.
                Ok(Err(error)) => {
                    tracing::debug!(
                        group_id,
                        path = %requirement.path,
                        %error,
                        "could not obtain this path's content from this peer; leaving it for a \
                         later pass"
                    );
                }
                Err(_elapsed) => {
                    tracing::debug!(
                        group_id,
                        path = %requirement.path,
                        "timed out obtaining this path's content from this peer; leaving it for \
                         a later pass"
                    );
                }
            }
        }
        // Everything still pending becomes durable here, and only now is
        // anything provenance-eligible. A file whose blocks are still in an
        // uncommitted batch has no provenance, so the pass cannot publish a
        // row for it -- which is exactly the ordering requirement, expressed
        // through the gate that already existed rather than a second one.
        self.pool_drain(driver, &mut pool, Some(call_timer)).await;
        if let Some(error) = &pool.fatal {
            // Not this pass's failure any more than a per-path fetch error
            // is: the paths whose blocks did commit still converge, and the
            // rest are absent, which the pass already knows how to record.
            tracing::debug!(
                group_id,
                %error,
                "a receive-side durability commit failed; leaving the affected paths for a \
                 later pass"
            );
        }
        // Before the pass publishes anything: a block this device holds but
        // cannot prove this group obtained is not this group's to serve.
        let obtained = std::mem::take(&mut pool.durable);
        if !obtained.is_empty() {
            self.flush_provenance_hashes(group_id, obtained, Some(call_timer)).await?;
        }
        Ok(wanted.into_iter().map(|r| (r.path.clone(), r)).collect())
    }

    /// Hands whatever is pending to the store as one batch, first making
    /// room by settling commits down to `MAX_COMMITS_IN_FLIGHT - 1`.
    ///
    /// Settling before launching rather than after is what keeps fetching
    /// overlapped with flushing: an in-flight `FuturesUnordered` makes no
    /// progress while its driving task is parked, so a design that awaited
    /// each commit inline would stall every concurrent fetch for the length
    /// of an fsync.
    async fn pool_commit_pending(
        &self,
        driver: &Arc<dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver>,
        pool: &mut ReceiveCommitPool,
        call_timer: Option<&crate::local_convergence::call_timer::ReconcileCallTimer>,
    ) {
        if pool.pending.is_empty() {
            return;
        }
        while pool.commits.len() >= Tuning::MAX_COMMITS_IN_FLIGHT {
            match pool.commits.next().await {
                Some(joined) => self.absorb_commit_result(driver, joined, pool, call_timer),
                None => break,
            }
        }
        let batch = std::mem::take(&mut pool.pending);
        pool.pending_bytes = 0;
        let commit = self.spawn_commit(driver, batch, &pool.group_id, call_timer);
        pool.commits.push(commit);
    }

    /// Flushes everything still pending and waits for every commit to
    /// land. After this returns, `pool.durable` names exactly the blocks
    /// this pass made durable -- which is what makes it safe to record
    /// provenance for them and not before.
    async fn pool_drain(
        &self,
        driver: &Arc<dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver>,
        pool: &mut ReceiveCommitPool,
        call_timer: Option<&crate::local_convergence::call_timer::ReconcileCallTimer>,
    ) {
        self.pool_commit_pending(driver, pool, call_timer).await;
        while let Some(joined) = pool.commits.next().await {
            self.absorb_commit_result(driver, joined, pool, call_timer);
        }
    }

    /// Takes one fetched block into the pool, and commits a batch if that
    /// filled one.
    ///
    /// Called from inside a file's fetch loop but operating on a pool that
    /// outlives that file, which is what lets one barrier serve blocks from
    /// many files.
    async fn pool_push(
        &self,
        driver: &Arc<dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver>,
        pool: &mut ReceiveCommitPool,
        block: PendingBlock,
        call_timer: Option<&crate::local_convergence::call_timer::ReconcileCallTimer>,
    ) {
        pool.pending_bytes += block.data.len() as u64;
        pool.fetched.insert(block.hash.clone());
        pool.pending.push(block);
        if pool.pending.len() >= Tuning::RECEIVE_COMMIT_BATCH_BLOCKS
            || pool.pending_bytes >= Tuning::RECEIVE_COMMIT_BATCH_BYTES
        {
            self.pool_commit_pending(driver, pool, call_timer).await;
        }
    }

    /// Periodic DAG resync's local repair backstop. A heads announce keeps
    /// network catch-up proportional to divergence, but it carries no file
    /// metadata when both sides already know the same heads. Re-run the
    /// ordinary reconcile path only for locally tracked repair candidates so
    /// eager live records demoted to placeholders/hydrating still rehydrate
    /// without making every peer session scan and re-query the whole group.
    /// Returns `Ok(true)` if this call actually ran the audit (whether or
    /// not it found anything to do), `Ok(false)` if it was skipped because
    /// another audit for the same group is already in flight
    /// (`MaterializationAuditGuard` contention). Callers that use a skip as
    /// a signal for their own bookkeeping (the Convergence Engine's
    /// `run_once`, see `engine.rs`) need this distinction: a caller that
    /// cannot tell a skip from "ran and made no progress" would otherwise
    /// treat a contended tick as a failed materialization attempt and apply
    /// backoff for it, needlessly delaying a job that never actually got a
    /// chance to run this tick.
    pub async fn reconcile_local_materialization_audit(
        self: Arc<Self>,
        driver: &Arc<dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver>,
        group_id: &str,
    ) -> Result<bool, PeerSessionError> {
        let audit_attempt_id = next_audit_attempt_id();
        tracing::debug!(
            local_device_id = %self.local_device_id,
            group_id,
            audit_attempt_id,
            "materialization audit attempt starting"
        );
        // This audit re-drives materialization, so it needs the same
        // fail-closed link gate the incoming-batch path uses: for an unlinked
        // group there is no folder to repair towards, and re-projecting into
        // one would be exactly the write the unlink was meant to stop.
        if !matches!(self.state.link_gate_for_group(group_id)?, LinkGate::Live { .. }) {
            return Ok(true);
        }
        // Ordinary desired-state projection has exactly one scheduling
        // source (`projection_obligations`) and one driver (the
        // Convergence Engine's own claim/reconcile loop) -- this periodic
        // audit no longer independently re-projects unprojected history.
        // What remains here are the genuinely distinct maintenance
        // responsibilities: conflict-copy retirement and explicit
        // repair-candidate re-materialization. Held for the whole
        // remainder of this audit -- unlike the old reproject-backstop
        // era, nothing here runs an unbounded number of
        // `reconcile_group_paths` calls, so there is no reason to release
        // and re-acquire between steps.
        let Some(_guard) = MaterializationAuditGuard::try_acquire(&self.state, group_id) else {
            return Ok(false);
        };

        if let Err(e) =
            self.retire_unjustified_ephemeral_conflict_copies(group_id, audit_attempt_id).await
        {
            tracing::warn!(
                group_id,
                error = %e,
                "failed to retire unjustified ephemeral conflict copies during audit"
            );
        }

        let paths = self.state.list_materialization_repair_candidates(group_id)?;
        // Names every candidate
        // path this device's own audit considered repair-eligible this
        // attempt -- see the tracked comment on `randomized_soak_converges_
        // with_no_leaks_or_stuck_state` in `topology_soak_lane.rs`.
        tracing::debug!(
            local_device_id = %self.local_device_id,
            group_id,
            audit_attempt_id,
            ?paths,
            "materialization audit: repair-candidate paths"
        );
        if paths.is_empty() {
            return Ok(true);
        }

        // One read per candidate path, and only one: each payload below
        // is a single incarnation of its row. This used to be a batched
        // `get_files_by_paths` for the content followed by seven point
        // queries per path for the metadata and the authoring identity,
        // which is how a payload could end up holding the blocks of one
        // incarnation beside the mode and authoring hash of another --
        // see `materialization_audit_candidate`.
        let mut fetched_count = 0usize;
        let mut file_infos = Vec::with_capacity(paths.len());
        let mut dropped_as_deleted = Vec::new();
        let mut dropped_as_not_yet_paired = Vec::new();
        for path in &paths {
            match self.materialization_audit_candidate(group_id, path)? {
                // Not counted as fetched: there is no row behind it at
                // all any more.
                AuditCandidate::NoRow => {}
                AuditCandidate::Deleted => {
                    fetched_count += 1;
                    dropped_as_deleted.push(path.clone());
                }
                AuditCandidate::NotYetPaired => {
                    fetched_count += 1;
                    dropped_as_not_yet_paired.push(path.clone());
                }
                AuditCandidate::Payload(record, meta) => {
                    fetched_count += 1;
                    file_infos.push((record, meta));
                }
            }
        }
        if !dropped_as_not_yet_paired.is_empty() {
            // A visible (not just debug-level) signal: any occurrence is
            // uncommon in steady state, and if the same path keeps
            // reappearing here across repeated audit passes, that is
            // exactly the "authoring identity never arrives" case worth an
            // operator's attention -- this audit itself has no durable
            // per-path retry counter to distinguish a fleeting, expected
            // instance from a genuinely stuck one, so it surfaces every
            // occurrence rather than silently downgrading them all.
            tracing::warn!(
                local_device_id = %self.local_device_id,
                group_id,
                audit_attempt_id,
                ?dropped_as_not_yet_paired,
                "materialization audit: skipped candidate path(s) with no authoring identity yet"
            );
        }
        tracing::debug!(
            local_device_id = %self.local_device_id,
            group_id,
            audit_attempt_id,
            candidate_count = paths.len(),
            fetched_count,
            file_infos_count = file_infos.len(),
            ?dropped_as_deleted,
            ?dropped_as_not_yet_paired,
            "materialization audit: candidate paths resolved to files"
        );
        if file_infos.is_empty() {
            return Ok(true);
        }
        self.rematerialize_local_records(driver, group_id, file_infos).await?;
        Ok(true)
    }

    /// The materialization-audit driver. Each record is re-driven through
    /// `rematerialize_one_record` (materialize-only, no conflict resolver). Used by
    /// `reconcile_local_materialization_audit` to repair missing on-disk
    /// materializations for records this device already holds without changing
    /// DAG conflict state.
    pub async fn rematerialize_local_records(
        self: Arc<Self>,
        driver: &Arc<dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver>,
        group_id: &str,
        incoming: Vec<(FileRecord, IncomingWireMeta)>,
    ) -> Result<(), PeerSessionError> {
        // Fail closed rather than defaulting a missing link row to `Eager` —
        // see `reconcile_group_paths`. There is nothing to rematerialize into
        // for a group this device holds no live link for.
        let LinkGate::Live { policy, .. } = self.state.link_gate_for_group(group_id)? else {
            return Ok(());
        };

        // Decode and apply the
        // cheap, purely-local path-safety/ignore filters for the whole
        // incoming batch first (unchanged from before — neither check
        // touches `SyncState`), then issue *one* batched index lookup
        // (`get_files_by_paths`) for every surviving path, in place of
        // what used to be a `get_file` point query per record buried
        // inside `reconcile_one_file`. `authoring_proves_redundant` then
        // decides, from that single batched snapshot, which records are
        // provably already in sync and can be skipped outright — turning
        // the common "an audit batch is mostly already-synced records" case
        // from O(records) store round-trips
        // into one, while every record that might actually need adopting
        // or conflict-resolving still goes through the exact same
        // correctly-locked `reconcile_one_file` path as before (see that
        // function's and `authoring_proves_redundant`'s doc comments for why the
        // batched snapshot can only ever cause a *safe* skip, never an
        // incorrect one).
        let mut retained: Vec<(FileRecord, IncomingWireMeta)> = Vec::with_capacity(incoming.len());
        for (incoming_record, incoming_meta) in incoming {
            if !is_safe_relative_path(&incoming_record.path) {
                tracing::warn!(
                    path = %incoming_record.path,
                    peer = %driver.peer_device_id(),
                    "ignoring file record with an unsafe path (absolute or containing '..') — \
                     folder-group authorization does not grant filesystem-wide write access"
                );
                continue;
            }

            // A record for a path matching
            // this device's own ignore patterns is dropped here, before
            // any materialization/indexing/forwarding work — it is never
            // written to disk, never added to the local index, and never
            // re-announced to this device's other peers. This is purely
            // local: the sending peer, and this device's other peers, are
            // unaffected — they may still hold and continue to sync this
            // same path with each other.
            if self.is_locally_ignored(group_id, &incoming_record.path) {
                tracing::debug!(
                    path = %incoming_record.path,
                    group_id,
                    peer = %driver.peer_device_id(),
                    "dropping incoming record for a path matching this device's ignore patterns"
                );
                continue;
            }

            retained.push((incoming_record, incoming_meta));
        }

        let paths: Vec<String> = retained.iter().map(|(record, _)| record.path.clone()).collect();
        let prefetched = self.state.get_files_by_paths(group_id, &paths)?;

        // `FuturesUnordered<JoinHandle<_>>`: each pushed `tokio::spawn(..)`
        // runs as its own independently-scheduled task, and
        // `FuturesUnordered` only does the "poll whichever join handle
        // finishes first" bookkeeping.
        let mut in_flight: FuturesUnordered<tokio::task::JoinHandle<()>> = FuturesUnordered::new();
        let mut in_flight_count = 0usize;
        for (incoming_record, incoming_meta) in retained {
            let causally_redundant = match prefetched.get(&incoming_record.path) {
                Some(local) => self.authoring_proves_redundant(
                    group_id,
                    local,
                    &incoming_record,
                    &incoming_meta,
                )?,
                None => false,
            };
            let needs_repair_backstop = match prefetched.get(&incoming_record.path) {
                Some(local) if causally_redundant => {
                    self.live_record_needs_rehydrate(group_id, local, policy)?
                }
                _ => false,
            };
            if !needs_repair_backstop && causally_redundant {
                continue;
            }

            if in_flight_count >= MAX_CONCURRENT_RECONCILES && in_flight.next().await.is_some() {
                in_flight_count -= 1;
            }

            let this = self.clone();
            let driver = driver.clone();
            let group_id = group_id.to_string();
            in_flight.push(tokio::spawn(async move {
                // A
                // transient error here — historically a `SyncState` write
                // hitting `SQLITE_BUSY`/`DatabaseLocked` under real
                // concurrent load (this reconcile loop's own
                // `MAX_CONCURRENT_RECONCILES` in-flight tasks, the local
                // debounce executor, and the periodic materialization-
                // repair task all contending for the same device's
                // connection pool) even past `retry_on_database_locked`'s
                // bounded retries; `SyncState`'s writer gate has since made
                // that own-process shape structurally impossible, but the
                // retry stays for every other transient failure here
                // (block fetch over a flapping transport, filesystem I/O).
                // Such a failure used to
                // be a silent, single-attempt, permanent drop: this
                // specific incoming record would simply never be applied,
                // with no retry and no requeue, leaving this device's
                // index permanently stuck at whatever it had before. Same
                // shape as `ensure_blocks_present`'s own
                // bounded-retry fix: a bounded retry with jitter
                // for a transient condition that resolves shortly after,
                // not an indefinite one.
                let mut attempt = 0;
                loop {
                    attempt += 1;
                    match this
                        .rematerialize_one_record(
                            &driver,
                            &group_id,
                            incoming_record.clone(),
                            incoming_meta.clone(),
                            policy,
                        )
                        .await
                    {
                        Ok(()) => break,
                        Err(e) if attempt < RECONCILE_RETRY_ATTEMPTS => {
                            tokio::time::sleep(reconcile_retry_delay()).await;
                            tracing::debug!(
                                error = %e,
                                attempt,
                                group_id = %group_id,
                                path = %incoming_record.path,
                                "retrying a failed reconcile of one file from peer index"
                            );
                        }
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                attempts = attempt,
                                group_id = %group_id,
                                path = %incoming_record.path,
                                "error reconciling a file from peer index after retrying"
                            );
                            break;
                        }
                    }
                }
            }));
            in_flight_count += 1;
        }
        while in_flight.next().await.is_some() {}
        Ok(())
    }

    /// Because `incoming` is a snapshot of this device's own committed
    /// row, its version vector can only equal or trail the local row it is
    /// compared against, so the `Concurrent` arm is unreachable here; it
    /// is treated as a hard invariant violation rather than silently
    /// resolved, keeping the mtime resolver off the audit path.
    async fn rematerialize_one_record(
        &self,
        driver: &Arc<dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver>,
        group_id: &str,
        incoming: FileRecord,
        meta: IncomingWireMeta,
        policy: MaterializationPolicy,
    ) -> Result<(), PeerSessionError> {
        let activity_provider = self.block_write_activity_provider.clone();
        let _write_activity = activity_provider.begin_block_write_activity();
        // Must run *before*
        // `path_lock` below is acquired (see
        // `flush_pending_local_change_before_reconcile`'s doc comment for
        // why) — this is what makes sure `local` (read further down, once
        // the lock is held) already reflects a same-path local edit that
        // was still sitting undispatched in this link's debounce
        // accumulator a moment ago, so the version-vector `compare` below
        // correctly sees it as `Concurrent` rather than missing it
        // entirely, and every `materialize` call downstream of this
        // function never overwrites its on-disk content ahead of it being
        // captured. The case-fold sibling half runs with it, for a
        // differently-cased sibling path this device may have its own
        // not-yet-indexed local write for — see this method's own doc
        // comment for why the exact-path flush alone isn't enough on a
        // case-insensitive filesystem.
        if self.flush_local_changes_before_reconcile(group_id, &incoming.path).await
            == yadorilink_peer_session::peer_session::PendingLocalFlushOutcome::RetryRequired
        {
            // A local edit at this path could not be captured; re-writing
            // the path now could put this device's older view over it. The
            // path stays a repair candidate, so a later audit pass retries.
            tracing::debug!(
                group_id,
                path = %incoming.path,
                "deferring a rematerialization: a local edit at this path is not captured yet"
            );
            return Ok(());
        }

        // held for this whole function, including the `.await`s
        // inside `materialize` (a block fetch can take real time) — see
        // `SyncState::path_lock`'s doc comment for the local-save-vs-
        // incoming-peer-version race this closes. `local` is read here,
        // *after* acquiring the lock, not before, so a concurrent local
        // save that ran while this device was waiting for the lock is
        // reflected in the comparison below rather than compared against
        // stale state.
        let path_lock = self.state.path_lock(group_id, &incoming.path);
        let _guard = path_lock.lock().await;
        // Captured before
        // `incoming` is moved into `apply_locked_record` below, so the
        // `RetryRequired` arm can name exactly which path/version didn't
        // settle -- see the tracked comment on `randomized_soak_converges_
        // with_no_leaks_or_stuck_state` in `topology_soak_lane.rs`.
        let audited_path = incoming.path.clone();
        let audited_size = incoming.size;
        let audited_block_count = incoming.blocks.len();
        match self.apply_locked_record(driver, group_id, incoming, meta, policy).await? {
            LockedRecordOutcome::Settled => Ok(()),
            // Not silently folded into `Ok(())` as `Settled` was before:
            // this audit's own re-candidacy for `path` next tick is driven
            // by `SyncState::list_materialization_repair_candidates`'s own
            // `materialization_state` column, not by this return value, so
            // a genuinely-still-placeholder path is naturally re-picked-up
            // regardless -- but logging this as an unqualified success
            // would have made a real, still-unresolved repair attempt
            // indistinguishable from one that actually completed.
            LockedRecordOutcome::RetryRequired => {
                tracing::debug!(
                    local_device_id = %self.local_device_id,
                    group_id,
                    peer = %driver.peer_device_id(),
                    path = %audited_path,
                    audited_size,
                    audited_block_count,
                    "materialization audit re-drive did not settle this record this attempt; \
                     it stays a repair candidate for the next audit tick"
                );
                Ok(())
            }
            LockedRecordOutcome::Concurrent { local, .. } => {
                debug_assert!(
                    false,
                    "materialization audit reached the concurrent-conflict path for a record \
                     built from this device's own index rows; incoming must never be concurrent \
                     with local here"
                );
                tracing::warn!(
                    group_id,
                    path = %local.path,
                    peer = %driver.peer_device_id(),
                    "materialization audit unexpectedly saw a concurrent record; skipping \
                     without legacy conflict resolution"
                );
                Ok(())
            }
        }
    }

    /// Hands one batch of fetched blocks to the block store off the async
    /// runtime, as a single durability barrier.
    ///
    /// The hash check here is not redundant with the wire checks: the
    /// receive path compares the peer's ECHOED header hash against the one
    /// it asked for, which is only the peer's own claim about its payload.
    /// `LocallyHashedBlock` hashes the bytes that actually arrived, and
    /// this is the first point where those two can be compared. Before
    /// batching, the per-block `store.put` computed the same hash and
    /// simply discarded it, so a peer returning the wrong bytes had them
    /// stored under their own (different) key while this device recorded
    /// provenance for the key it had asked for -- attesting to a block it
    /// did not hold. Mismatches are dropped from the batch and reported as
    /// `rejected`, never stored and never provenanced.
    ///
    /// The stale-refusal clears ride along in this same blocking hop, one
    /// per distinct `(path, version)` the batch carried rather than one per
    /// block. Those keys hold no hash, so the old per-block version issued
    /// the byte-for-byte identical SQLite write once for every block of a
    /// file; deduplicating them is the same meaning for a fraction of the
    /// writes, and it is what lets a batch span files without either
    /// dropping a clear or repeating one.
    fn spawn_commit(
        &self,
        driver: &Arc<dyn yadorilink_peer_session::convergence_driver::ConvergenceDriver>,
        batch: Vec<PendingBlock>,
        group_id: &str,
        call_timer: Option<&crate::local_convergence::call_timer::ReconcileCallTimer>,
    ) -> BlockingHandle<CommittedBatch> {
        let store = self.store.clone();
        let blocks = batch.len();
        let attributed = call_timer.is_some();
        let index_state = self.state.clone();
        let refusal_peer = driver.peer_device_id().to_string();
        let refusal_group_id = group_id.to_string();
        spawn_blocking(move || {
            let started = std::time::Instant::now();
            let mut prepared = Vec::with_capacity(blocks);
            let mut hashes = Vec::with_capacity(blocks);
            let mut rejected = Vec::new();
            let mut refusal_keys: Vec<(String, String)> = Vec::new();
            for block in batch {
                let hashed =
                    yadorilink_local_storage::LocallyHashedBlock::from_bytes(block.data.to_vec());
                if hashed.hash().as_bytes() != hex::encode(&block.hash).as_bytes() {
                    rejected.push(block.hash);
                    continue;
                }
                let key = (block.path, block.version_hex);
                if !refusal_keys.contains(&key) {
                    refusal_keys.push(key);
                }
                hashes.push(block.hash);
                prepared.push(hashed);
            }
            let error = store.put_prepared_batch(&prepared).err();
            let elapsed = started.elapsed();
            // Only after a successful commit: a batch that failed proves
            // nothing about what this peer holds.
            if error.is_none() {
                for (path, version) in &refusal_keys {
                    let cleared = index_state.clear_block_fetch_refusal(
                        &refusal_group_id,
                        path,
                        version,
                        &refusal_peer,
                    );
                    // Same disposition as before: a failed refusal clear is
                    // logged and tolerated, never fatal to this fetch.
                    if let Err(e) = cleared {
                        tracing::warn!(
                            file_path = %path,
                            error = %e,
                            "failed to clear a stale block fetch refusal after a successful fetch"
                        );
                    }
                }
            }
            CommittedBatch {
                hashes,
                rejected,
                error,
                elapsed: if attributed { Some(elapsed) } else { None },
            }
        })
    }
}
