use std::path::PathBuf;

use yadorilink_peer_session::ports::OpenMaterializationIntent;
use yadorilink_peer_session::PeerSessionError;
use yadorilink_replica_domain::file::{FileVersion, RecordKind};
use yadorilink_replica_domain::session_state::MaterializationState;

use super::super::types::*;
use super::MaterializationPlan;
use yadorilink_root_authority::fs_identity::disk_race_fingerprint;

// The eager/pinned lane is a pipeline. Each stage consumes the value the
// previous one produced, so a stage can only run once everything before it
// has: a write needs a revalidated target, a verification needs a written
// object whose payload metadata is applied, and the commit needs the
// verified evidence.

/// This path as it stood on disk before this pass asked for any blocks.
struct ObservedTarget {
    race_check_path: PathBuf,
    pre_fetch_disk_state: Option<(u64, Option<std::time::SystemTime>, i64, i64)>,
}

/// The answer to "is this record's content on this device?".
enum ContentLocation {
    /// Not all of it, and the session has not yet had its attempt at the
    /// block lane: hand the requirement to the session.
    NeedBlocks(BlockRequirement),
    /// Either all present, or the session already had its bounded attempt.
    Located(LocatedContent),
}

/// This record's content, located locally as far as it could be.
struct LocatedContent {
    race_check_path: PathBuf,
    all_present: bool,
}

/// A target that passed both pre-write revalidations -- nothing wrote to it
/// while blocks were fetched, and its bytes still match what this device
/// has indexed. Every write below consumes one.
struct RevalidatedTarget {
    all_present: bool,
}

/// The row is committed under an open materialization intent, the target is
/// verified and preflighted, and the mutation fence is bumped for the
/// content write. The bytes are not written yet.
struct PendingContentWrite<'a> {
    intent_guard: Box<dyn OpenMaterializationIntent + Send + 'a>,
    out_path: PathBuf,
    written_version: FileVersion,
    mutation_generation: i64,
}

/// The outcome of the content write: the payload's bytes are durably
/// renamed into place, or the attempt was demoted to a retriable
/// placeholder.
enum Reconstruction {
    Written(WrittenObject),
    DemotedToPlaceholder,
}

/// The payload's bytes on disk at `out_path`, written under
/// `mutation_generation`.
struct WrittenObject {
    out_path: PathBuf,
    written_version: FileVersion,
    mutation_generation: i64,
}

/// The written object with this payload's mode and xattrs applied.
struct AppliedObject {
    written: WrittenObject,
    /// The strict xattr check this attempt made before applying the final
    /// mode; the exactness gate uses it instead of re-reading a file the
    /// mode may have made unreadable.
    xattrs: super::super::types::XattrEvidence,
}

/// The applied object verified as the exact desired object, with the
/// evidence that says so. Only this is committed.
struct VerifiedObject {
    written: WrittenObject,
    evidence: SettlementEvidence,
}

impl super::super::LocalConvergenceExecutor {
    /// The eager/pinned lane of [`Self::materialize_local`]: this record's
    /// content is wanted on disk now.
    pub(super) async fn materialize_eager_lane(
        &self,
        plan: &MaterializationPlan<'_>,
    ) -> Result<LocalMaterializeOutcome, PeerSessionError> {
        let observed = self.observe_target(plan)?;
        let located = match self.locate_content(plan, observed)? {
            ContentLocation::NeedBlocks(requirement) => {
                return Ok(LocalMaterializeOutcome::NeedBlocks(requirement));
            }
            ContentLocation::Located(located) => located,
        };
        // Blocks are requested before this check, hazardous or not, and
        // that ordering is deliberate: this device may be another peer's
        // only currently-reachable source for these blocks even though it
        // cannot write them to disk under this name itself ("blocks still
        // requested/served to peers"). Only the write step below is
        // skipped for a held record.
        if let Some(reason) = &plan.hazard_reason {
            return self.hold_for_hazard(plan, reason);
        }
        let Some(target) = self.revalidate_target(plan, located)? else {
            return Ok(MaterializeResult::RetryRequired.into());
        };
        // Do not record unfetched content as hydrated:
        // `ensure_blocks_present` returns `false` (not an error) when a
        // peer could not supply one or more of this record's blocks
        // (reported not-found/unusable, or returned bytes failing
        // integrity verification). Committing a `Hydrated` row and
        // running `reconstruct_file` here would then fail at
        // `store.get(<missing block>)` mid-loop, orphaning its temp file
        // and leaving a live-but-fileless `Hydrated` row — which
        // `repair_interrupted_materializations` (blocks still absent)
        // demotes to an empty placeholder, silently destroying a
        // still-pending write (for a losing conflict copy, its only
        // preservation). Instead record a retriable `Placeholder` — the
        // exact `all_present == false` handling `hydrate_file_with_timeout`
        // already uses — so the fetch is retried on a later reconcile
        // (`live_record_needs_rehydrate`) and recovery never
        // clobbers it. Reuses the not-admitted branch's placeholder path.
        if !target.all_present {
            return self.write_incomplete_content_placeholder(plan, target);
        }
        let pending = self.begin_content_write(plan, target)?;
        let written = match self.reconstruct_content(plan, pending).await? {
            Reconstruction::Written(written) => written,
            Reconstruction::DemotedToPlaceholder => {
                return Ok(MaterializeResult::RetryRequired.into());
            }
        };
        // The proof, the `Hydrated` stamp and the intent clear are
        // committed HERE, in one transaction, under exactly the epoch
        // this write bumped -- and the evidence is still returned, so
        // the engine can close the obligation as it always has. Its
        // own publication re-publishes the same row under the same
        // epoch, which replaces it with an identical value.
        //
        // Publishing here is not what was reverted before. That was
        // the EXTERNAL-capture lane (`adopt_local_capture_actual_state`),
        // which mints a fresh epoch on its way to recording what it
        // was told: it moved the fence from `N` to `N+1` and
        // published a versionless proof under `N+1`, so the engine's
        // own CAS on `N` lost every time on the healthy path. The
        // internal commit used here mints nothing -- it CASes on the
        // epoch it is given, and publishes the version it is given.
        //
        // A crash before this commit leaves no proof at all, which is
        // the correct outcome: the intent is still open and the
        // obligation untouched, so the work is re-driven.
        tracing::debug!("phase T_recv_hydrated_commit: Hydrated state-machine commit completed");
        let applied = self.apply_written_metadata(plan, written)?;
        let Some(verified) = self.verify_written_object(plan, applied)? else {
            // The bytes landed, but the path has moved on to a version
            // they are not. There is no exact claim to make about
            // them, so re-drive rather than settle -- and leave the
            // intent open, since nothing has been proven.
            return Ok(MaterializeResult::RetryRequired.into());
        };
        self.commit_verified_object(plan, verified)
    }

    /// Stage 1: fingerprint the target before any block is requested.
    fn observe_target(
        &self,
        plan: &MaterializationPlan<'_>,
    ) -> Result<ObservedTarget, PeerSessionError> {
        let MaterializationPlan { group_id, record, origin_device_id, .. } = *plan;
        // Snapshot this path's on-disk state before asking for blocks, so
        // it can be re-checked on re-entry, right before this
        // materialization writes anything.
        //
        // This is the one observation that has to cross the request
        // boundary, and the reason is that re-reading cannot recover it.
        // `path_lock` is held for this whole call, but it only serializes
        // *this device's own* SyncState-mediated writes -- it is not, and
        // cannot be, an OS file lock, so a genuine local edit (a real
        // user's editor, or this scenario's `solo-write`) can still land
        // directly on disk while the session is fetching. Confirmed,
        // reproduced: a local write that races into exactly this window is
        // silently clobbered by this materialization's own later rename,
        // then permanently invisible to every later check --
        // `flush_pending_local_change_before_reconcile` (already run by
        // every caller before taking `path_lock`) only catches an edit
        // that was *already* pending at that moment; it cannot see one
        // that has not happened yet, and calling it again from inside this
        // locked call would deadlock (see its own doc comment). Read
        // fresh, the fingerprint would simply describe the racing write as
        // if it had always been there; only a comparison against what was
        // on disk before the request went out can tell the two apart.
        let out_path_for_race_check = self.local_file_path(group_id, &record.path)?;
        let pre_fetch_disk_state = disk_race_fingerprint(&out_path_for_race_check);
        // The second fork: by the time an incoming change is about to be
        // written, are this device's own local bytes still on disk? If a
        // local write is lost despite the flush guard running, the length
        // here says whether the guard looked too late (bytes already
        // replaced) or the guard looked in the wrong place (bytes still
        // present and about to be overwritten by this call).
        yadorilink_peer_session::dst_trace(&record.path, || {
            format!(
                "materialize about to write on {} (origin={}): on_disk_len={:?} incoming_len={}",
                self.local_device_id,
                origin_device_id,
                pre_fetch_disk_state.as_ref().map(|(len, ..)| *len),
                record.size
            )
        });
        Ok(ObservedTarget { race_check_path: out_path_for_race_check, pre_fetch_disk_state })
    }

    /// Stage 2: ask local storage whether this record's content is here, and
    /// hand the session a block requirement if it is not and the session has
    /// not yet had its attempt.
    fn locate_content(
        &self,
        plan: &MaterializationPlan<'_>,
        observed: ObservedTarget,
    ) -> Result<ContentLocation, PeerSessionError> {
        let MaterializationPlan { group_id, payload, record, satisfied, .. } = *plan;
        let ObservedTarget { race_check_path, pre_fetch_disk_state } = observed;
        // Is this record's content already on this device? Two local
        // questions, both of them the same ones `ensure_blocks_present`
        // itself asks before it fetches anything: are the bytes in the
        // block store, and has this group independently obtained them.
        // A physical hit belonging only to another group is not this
        // group's to use, so both must hold for every block.
        let missing_blocks = self.blocks_missing_locally(group_id, record)?;
        if missing_blocks && satisfied.is_none() {
            // Stop here. Which peer to ask, how many blocks at once, what
            // a `DontHave` means, how long to wait and what to do with a
            // transport error are all the session's business, and none of
            // them belong on this side of the boundary.
            return Ok(ContentLocation::NeedBlocks(BlockRequirement {
                path: record.path.clone(),
                // This path IS what is being materialized, so it demands
                // its own content; only the prefetch path derives copies.
                demand_path: record.path.clone(),
                version_hash: payload.version().version_hash,
                record: record.clone(),
                observed_disk: pre_fetch_disk_state,
            }));
        }
        // `satisfied` says the session had its bounded attempt at the
        // block lane. Whether that attempt worked is answered the same
        // way it is answered on a first pass: by asking local storage.
        // If content is still absent the obligation stays unsettled --
        // recorded as a retriable placeholder below, re-driven by an
        // explicit wake. Nothing here polls.
        let all_present = !missing_blocks;
        Ok(ContentLocation::Located(LocatedContent { race_check_path, all_present }))
    }

    /// Stage 3: revalidate the target right before anything is written.
    /// `None` declines this pass for retry.
    fn revalidate_target(
        &self,
        plan: &MaterializationPlan<'_>,
        located: LocatedContent,
    ) -> Result<Option<RevalidatedTarget>, PeerSessionError> {
        let MaterializationPlan { group_id, record, satisfied, .. } = *plan;
        let LocatedContent { race_check_path: out_path_for_race_check, all_present } = located;
        // Re-check the snapshot taken before the blocks were requested: if
        // this path's on-disk state changed while the session was
        // fetching, something wrote to it independently of this
        // materialization. Proceeding would silently overwrite that write
        // with no error, no conflict copy, and (once the watcher's own
        // flush eventually runs against the post-overwrite bytes, which
        // now match exactly what this materialization is about to commit)
        // no trace at all -- the confirmed mechanism behind a
        // materialize-vs-local-edit race this check exists to close.
        // Decline instead: `RetryRequired` sends this back through the
        // ordinary reconcile retry path, by which point `path_lock` has
        // been released, the racing write has committed its own change,
        // and the next resolution correctly sees both as concurrent.
        //
        // Only meaningful on a re-entry that a fetch stands behind. On a
        // first pass the fingerprint was taken moments ago by this same
        // call with the lock already held, so there is no window for it to
        // describe and nothing to compare it against.
        let post_fetch_disk_state = disk_race_fingerprint(&out_path_for_race_check);
        if satisfied.is_some_and(|r| post_fetch_disk_state != r.observed_disk) {
            tracing::info!(
                group_id,
                path = %record.path,
                "declining a materialize whose target changed on disk while this device \
                 fetched blocks from a peer; leaving it for retry so the racing local edit \
                 is not silently overwritten"
            );
            return Ok(None);
        }
        // LAST LINE OF DEFENCE BEFORE THE BYTES ARE GONE.
        //
        // Everything upstream of here tries to get a local edit
        // *authored* before an incoming change lands on the same path:
        // `flush_pending_local_change_before_reconcile` force-flushes the
        // debounce accumulator, `capture_undiscovered_local_change` falls
        // back to reading the path off disk, and the metadata CAS above
        // catches a write that slips in during the block fetch. Each is
        // scheduling-dependent, and measurably none of them closes the
        // case where the write lands on disk *before* this materialize
        // started and its watcher event has not been processed yet.
        //
        // This check is not scheduling-dependent: it asks the bytes
        // themselves. If the file on disk no longer matches the content
        // this device has indexed for it, someone wrote to it outside the
        // index -- an unauthored local edit -- and overwriting it destroys
        // it permanently. Permanently is not hyperbole: after the rename
        // the edit exists nowhere (not on disk, not in the block store),
        // and the watcher's own flush then chunks the *remote* bytes,
        // finds them equal to what was just indexed, and suppresses the
        // whole thing as a self-echo (`local_change.rs`'s block-equality
        // check). No error, no conflict copy, no trace. That is why no
        // fix on the flush side can work -- there is nothing left to
        // recover by then.
        //
        // Compare against `local_row` (what this device believes is on
        // disk right now), NOT `record` (the incoming content this call
        // is about to install).
        //
        // Reproduced and traced on `dst_network_fault_chaos` seed
        // 3298840609: a solo write landed while the previous round's race
        // winner was still materialising over it, was overwritten before
        // it could author, and left the harness reading back the previous
        // round's authoring hash -- two ops sharing one hash, which
        // `oracle::supersedes` refuses to treat as superseding, surfacing
        // as `[NoLoss]`.
        //
        // Cost: one content hash of the destination (two for an unproven
        // `Placeholder` row), and only for a path that already exists as a
        // regular file. Skipped for an untouched placeholder and for
        // `Hydrating`/`Evicting` rows, whose whole point is to disagree
        // with their file, and for tombstones. Deliberately paid: the
        // alternative is silently destroying user data.
        //
        // A narrow TOCTOU window remains between this hash and the rename
        // below -- there is no portable "rename only if the destination
        // still hashes to X". The metadata CAS above is kept precisely as
        // a second, cheaper net across that window. Closing it fully
        // would mean preserving the displaced bytes before replacing them
        // (quarantine-on-divergence), which changes conflict semantics
        // and needs its own crash-recovery design; noted, not attempted.
        //
        // A path that no longer exists at all is NOT the same finding as
        // one whose bytes diverge, and must not be declined the same
        // way. A missing `out_path_for_race_check` is not proof anyone
        // wrote an unauthored edit -- it is equally consistent with this
        // path's *parent* having been renamed or removed by a local
        // operation whose watcher event has not reached this device's
        // local pipeline yet (confirmed, reproduced:
        // `dst_directory_move_edit_race.rs`'s `CbBeforeDirDispatch`
        // ordering hung forever on exactly this call site treating
        // `Absent` the same as `PresentButDifferent`, permanently
        // declining a legitimate fast-forward materialize with nothing
        // left to ever change the outcome). Declining forever on an
        // absent path is safe to avoid here specifically because
        // `flush_pending_local_change_before_reconcile` (called on
        // `record.path` above, before `path_lock` was even taken) has
        // already force-flushed any debounce entry keyed on this exact
        // path -- so a genuine, still-unflushed single-file local
        // deletion of THIS path cannot be what produced the absence; the
        // only thing an exact-path flush structurally cannot discover
        // and dispatch first is an ancestor-directory-level event, which
        // is exactly the case this guard must let through. Resurrecting
        // a file whose deletion truly wasn't caught by any of that is
        // still recoverable, unlike destroying divergent bytes: the
        // local pipeline's own Removed-event handling re-stats before
        // dispatch and will still author the deletion once it runs.
        //
        // Which rows this covers -- including a row with no blocks, and a
        // `Placeholder` row this device never wrote a placeholder for -- is
        // `disk_holds_uncaptured_local_bytes`'s own doc. Both were once
        // skipped, and both are how a file still being written (a `git
        // clone`'s pack) got this device's own older version of it written
        // back over it.
        if self.disk_holds_uncaptured_local_bytes(
            group_id,
            &record.path,
            &out_path_for_race_check,
            Some(&record.blocks),
        )? {
            tracing::info!(
                group_id,
                path = %record.path,
                "declining a materialize whose target no longer matches this \
                 device's indexed content; an unauthored local edit is on disk \
                 and overwriting it would destroy it silently"
            );
            yadorilink_peer_session::dst_trace(&record.path, || {
                format!(
                    "materialize DECLINED on {}: on-disk bytes diverge from \
                     indexed content -- unauthored local edit protected",
                    self.local_device_id
                )
            });
            return Ok(None);
        }
        Ok(Some(RevalidatedTarget { all_present }))
    }

    /// Stage 3b, when not every block is present: record a retriable
    /// placeholder instead of unfetched content.
    fn write_incomplete_content_placeholder(
        &self,
        plan: &MaterializationPlan<'_>,
        _target: RevalidatedTarget,
    ) -> Result<LocalMaterializeOutcome, PeerSessionError> {
        let MaterializationPlan { group_id, record, permit: root_commit_permit, .. } = *plan;
        // Same journaled-write seam the sibling "demoted after a
        // failed reconstruct" arm below uses, and for the identical
        // reason: `persist_row_under_
        // fresh_operation`'s underlying `upsert_file_with_origin` INSERTs a
        // fresh row that DEFAULTS to `Hydrated` before the explicit
        // `set_materialization_state(..., Placeholder, ...)` below
        // runs, and even once demoted, `create_or_defer_
        // placeholder` (the actual on-disk write) has not run yet
        // either. A crash/restart in EITHER window leaves an
        // indexed, not-deleted row with no local file and no
        // protecting intent -- exactly what the startup "full
        // reconciliation" scan (`local_change.rs`'s `reconcile_
        // disk_with_ignore`) reads as an offline deletion, silently
        // tombstoning a file this device never actually lost.
        // Exercised by a restart-mid-relay-sync integration test.
        // Opening the guard before the row commit
        // and clearing it right before the placeholder disk write
        // (mirroring the sibling arm exactly) closes both windows.
        let intent_guard = self.state.open_placeholder_write(
            group_id,
            record,
            plan.origin_device_id,
            plan.authoring_change_hash,
            &|| self.root_lease_for(group_id),
            root_commit_permit,
        )?;
        let out_path = self.local_file_path(group_id, &record.path)?;
        // A placeholder is a real on-disk write -- bump before it,
        // same as any other physical mutator, so any stale
        // exact-object proof for this path is invalidated even
        // though this attempt itself never publishes one (it
        // returns `RetryRequired`, carrying no evidence).
        let placeholder_deferred =
            self.write_placeholder(plan, &out_path, "eager_placeholder_write")?;
        // Clear the intent right after the placeholder write is
        // confirmed, BEFORE `apply_unix_mode`/`apply_xattrs` below
        // -- correcting an earlier version of this fix that
        // cleared BEFORE `create_or_defer_placeholder` instead
        // (see the OnDemand branch below for the fuller
        // reasoning). Those are real, fallible syscalls (a
        // repeatable chmod EPERM or xattr EOPNOTSUPP is not
        // hypothetical), and clearing only after them would leak
        // this guard permanently were a failure to hit there: the
        // placeholder is already durably on disk (this device's
        // own write, not a peer's content), so nothing would ever
        // re-drive materialization for this exact path again to
        // clean the intent up. Also skipped entirely when Windows
        // deferred the write to `cfapi-host.exe`: nothing is
        // actually on disk yet in that case, so the intent must
        // stay open -- this call already returns `RetryRequired`
        // below regardless, so a later retry naturally
        // re-examines this path.
        if !placeholder_deferred {
            intent_guard.clear()?;
            // Also skipped when deferred: nothing was actually
            // written under `out_path` yet on Windows, so there is
            // no real file to apply the exec bit/xattrs to -- both
            // are real syscalls against a path that does not exist
            // in that case.
            // Payload metadata, like every other lane -- see the
            // eager `Hydrated` branch's own comment below.
            plan.apply_payload_metadata(&out_path)?;
        }
        // Eager/pinned wanted real content but not every block was
        // available -- this is a retriable Placeholder, not a
        // settled outcome (the confirmed bug this type exists to
        // close: see `MaterializeResult`'s own doc comment).
        Ok(MaterializeResult::RetryRequired.into())
    }

    /// Stage 4: commit the row under an open intent and bump the fence for
    /// the content write that follows.
    fn begin_content_write<'p>(
        &'p self,
        plan: &'p MaterializationPlan<'p>,
        _target: RevalidatedTarget,
    ) -> Result<PendingContentWrite<'p>, PeerSessionError> {
        let MaterializationPlan { group_id, payload, record, permit: root_commit_permit, .. } =
            *plan;
        // Receiver-side phase marker: every block this file's
        // record lists is now present (already-local, or freshly
        // fetched-and-committed by `ensure_blocks_present` above) in
        // this device's own block store -- the eager-materialize
        // path's own completeness check, the counterpart of
        // `hydration.rs`'s identically-tagged `T_recv_all_blocks_
        // available` on the on-demand-sync path.
        tracing::debug!(
            "phase T_recv_all_blocks_available: every block this file needs is now local"
        );
        // Open the single sanctioned materialization-intent seam BEFORE
        // committing the brand-new row below. This branch deliberately
        // stamps the row `Hydrated` optimistically, before the temp-
        // write-then-rename even begins (see the explicit stamp right
        // after `persist_row_under_fresh_operation` below -- `upsert_file_
        // with_origin` itself no longer defaults a fresh row to
        // `Hydrated`; the schema's own default is `Placeholder` as of
        // v25, see `SCHEMA_VERSION`'s doc comment), and that commit is
        // durable (`PRAGMA synchronous = FULL`) — so a crash *after* it
        // but before the temp-write-then-rename lands would otherwise leave
        // a `Hydrated` row with no file on disk, its blocks present, and no
        // intent. Startup/periodic repair reads exactly that state as an
        // offline deletion and tombstones the path, destroying a
        // just-received file group-wide. `MaterializationIntentGuard::open`
        // writes a durable intent first — the same seam
        // `reconstruct_file_journaled` uses for repair's own writes — so
        // repair instead sees the intent and reconstructs from the
        // locally-present blocks. The guard is cleared the instant the
        // rename is durable (below) or when this write is demoted to a
        // `Placeholder`; an early `?` return on a failed write drops it
        // without clearing, leaving the intent for repair.
        //
        // The owner operation below opens that intent, commits the row
        // under it, stamps the row with the in-flight state -- explicitly
        // NOT `Hydrated`: the intent is what makes the row-before-file
        // ordering safe across a crash, not what makes the exact claim
        // true, and the bytes are still nowhere at this point (the batched
        // receive this branch was modelled on moved to the in-flight state
        // for the same reason, and left this one behind) -- and clears any
        // hazard hold, each in its own transaction.
        let intent_guard = self.state.open_content_write(
            group_id,
            record,
            plan.origin_device_id,
            plan.authoring_change_hash,
            &|| self.root_lease_for(group_id),
            root_commit_permit,
        )?;
        let out_path = self.local_file_path(group_id, &record.path)?;
        // defense-in-depth: `is_safe_relative_path` (in
        // `reconcile_files`) already blocks `..`/absolute components,
        // but a *symlink* at an intermediate path component is
        // followed by the plain `create`/`rename` calls inside
        // `reconstruct_file`, which could otherwise land the write
        // outside `group_id`'s sync root. See `verify_write_target_
        // within_root`'s doc comment for what this does and does not
        // close.
        self.verify_write_target(group_id, &out_path)?;
        // Preflight before the
        // temp-then-rename write below begins — see
        // `preflight_disk_headroom`'s doc comment.
        self.preflight_disk_headroom(group_id, &out_path, record.size)?;
        // Off the async runtime -- see `reconstruct_file_off_
        // runtime`'s own doc comment for the failure mode this closes
        // (large-file reconstruction blocking this process's tokio
        // worker pool long enough to starve this same peer's own
        // channel actor). This retry loop is the eager-fetch path's
        // OWN reconstruct call (distinct from `hydrate_file_with_
        // timeout_locked`'s single attempt above), so it gets the
        // identical treatment here too.
        //
        // Receiver-side phase marker: about to begin
        // reconstructing the real file from CAS blocks -- the
        // eager-materialize path's counterpart of `hydration.rs`'s
        // identically-tagged `T_recv_materialize_start` on the
        // on-demand-sync path. Fired once even though a transient
        // read failure below can retry the reconstruct attempt itself
        // -- that retry re-reads already-local, already-verified
        // blocks, not a second "begins receiving" event.
        tracing::debug!(
            "phase T_recv_materialize_start: begins reconstructing the real file from CAS blocks"
        );
        // Bump before the real content write below (the retry loop
        // that follows is all one logical
        // write attempt, so one bump covers it -- a bump is
        // safe-but-pessimistic, never a lock: see the tombstone-delete
        // branch above for the identical reasoning). Captured now so
        // the eventual `Settled` evidence CASes on the value this
        // specific write invalidated the path's prior proof under, not
        // a value re-read later that some other mutator could have
        // already advanced past.
        // The payload's own version -- what these bytes ARE. Reading
        // it from the row, even before the write, asked about the row
        // instead: a supersession that keeps the authoring identity
        // moves the row's version while the payload does not move at
        // all, and every check downstream then agreed with itself
        // while the bytes disagreed.
        let written_version = payload.version().clone();
        let content_write_mutation_generation =
            self.state.dag_bump_mutation_fence(group_id, &record.path, "eager_content_write")?;
        Ok(PendingContentWrite {
            intent_guard,
            out_path,
            written_version,
            mutation_generation: content_write_mutation_generation,
        })
    }

    /// Stage 5: reconstruct the payload's bytes into place,
    /// retrying a transient failure, and demote to a retriable placeholder
    /// if it never succeeds.
    async fn reconstruct_content(
        &self,
        plan: &MaterializationPlan<'_>,
        pending: PendingContentWrite<'_>,
    ) -> Result<Reconstruction, PeerSessionError> {
        let MaterializationPlan { group_id, record, permit: root_commit_permit, .. } = *plan;
        let PendingContentWrite {
            intent_guard,
            out_path,
            written_version,
            mutation_generation: content_write_mutation_generation,
        } = pending;
        // Guard the one-shot reconstruct. `reconstruct_file` reads every
        // block back through `store.get` mid-loop, so a *transient* block-
        // store read error (an EIO) fails the whole assembly *after* the
        // live row was already committed at the top of this branch — which,
        // left unhandled, orphans the temp file and leaves a live+Hydrated
        // row with no file on disk (a losing conflict copy would then be
        // permanently lost, since `repair_interrupted_materializations` /
        // the reconcile re-drive do not reliably revisit a same-device
        // conflict copy the peer never echoes back). The bytes are always
        // durably present in *this* device's own block store by now (the
        // eager fetch above stored them, or — for a losing conflict copy —
        // they are this device's own prior edit, per this function's
        // "content is always already present" invariant), so the correct
        // response to a transient read error is to retry the assembly in
        // place: a retry re-reads those same content-addressed blocks on a
        // later, non-faulting read. Retry a bounded number of times, then
        // fall back to the same retriable `Placeholder` the `all_present ==
        // false` branch uses (so a genuinely-stuck read still never leaves a
        // fileless Hydrated row).
        const MAX_RECONSTRUCT_RETRIES: u32 = 20;
        const RECONSTRUCT_RETRY_BACKOFF: std::time::Duration = std::time::Duration::from_millis(50);
        let mut recon = reconstruct_file_off_runtime(
            self.store.clone(),
            &out_path,
            &record.blocks,
            record.mtime_unix_nanos,
        )
        .await;
        let mut attempts = 0u32;
        while recon.is_err() && attempts < MAX_RECONSTRUCT_RETRIES {
            attempts += 1;
            // Short backoff before re-reading the already-present blocks.
            // Under the deterministic simulator this advances virtual time
            // (letting any interfering condition clear) at no real cost.
            tokio::time::sleep(RECONSTRUCT_RETRY_BACKOFF).await;
            // Re-verify root identity before EVERY retry, not just the
            // single check before the first attempt above: up to
            // `MAX_RECONSTRUCT_RETRIES * RECONSTRUCT_RETRY_BACKOFF`
            // (~1s) elapses across this loop, during which the same
            // unmount-and-replace window `verify_write_target`'s own
            // re-check exists to close could still open between two
            // retries. A verify failure here surfaces as a real error
            // (not a demotion to `Placeholder`) since a replaced root
            // is not a transient, retriable condition.
            self.verify_write_target(group_id, &out_path)?;
            recon = reconstruct_file_off_runtime(
                self.store.clone(),
                &out_path,
                &record.blocks,
                record.mtime_unix_nanos,
            )
            .await;
        }
        if let Err(e) = recon {
            tracing::warn!(
                group_id,
                path = %record.path,
                error = %e,
                attempts,
                "reconstruct after eager fetch still failing; demoting to retriable placeholder"
            );
            self.state.set_materialization_state(
                group_id,
                &record.path,
                MaterializationState::Placeholder,
                root_commit_permit,
            )?;
            // This is a DIFFERENT physical write than the failed
            // reconstruct above (a placeholder instead of
            // real content) -- its own bump, same reasoning as the
            // `!all_present` branch's identical placeholder write.
            let placeholder_deferred = self.write_placeholder(
                plan,
                &out_path,
                "eager_reconstruct_failed_placeholder_write",
            )?;
            // Clear the intent right after the placeholder write is
            // confirmed, BEFORE `apply_unix_mode`/`apply_xattrs` below
            // -- those are real, fallible syscalls (a repeatable chmod
            // EPERM or xattr EOPNOTSUPP is not hypothetical), and
            // clearing only after them would leak this guard
            // permanently on a REACHABLE steady state were a failure
            // to hit there: the placeholder is already durably on
            // disk (this device's own write, not a peer's content),
            // so nothing would ever re-drive materialization for this
            // exact path again to clean the intent up. Also skipped
            // entirely when Windows deferred the write to
            // `cfapi-host.exe`: nothing is actually on disk yet in
            // that case, so the intent must stay open (see the
            // OnDemand branch below for the fuller reasoning, identical
            // here).
            if !placeholder_deferred {
                intent_guard.clear()?;
                // Also skipped when deferred: nothing was actually
                // written under `out_path` yet on Windows, so there is
                // no real file to apply the exec bit/xattrs to.
                // Payload metadata, like every other lane -- see the
                // eager `Hydrated` branch's own comment below.
                plan.apply_payload_metadata(&out_path)?;
            }
            // Reconstruct never actually succeeded despite the blocks
            // being fetched -- demoted to a retriable Placeholder, not
            // a settled outcome (same reasoning as the `!all_present`
            // branch above).
            return Ok(Reconstruction::DemotedToPlaceholder);
        }
        // Captured immediately
        // after this device's own successful reconstruct -- see
        // `MaterializationStateRepository::record_materialized_
        // fingerprint`'s own doc comment for what the daemon's
        // already-`Hydrated` fast path (`hydration.rs::hydrate_inner`)
        // The temp-write-then-rename completed durably — clear the intent
        // NOW, before the post-write metadata touch below. Clearing only
        // after `apply_unix_mode` would leak the intent whenever reading or
        // applying the exec bit errored (a real `chmod` on POSIX) even though
        // the file is durably on disk and `Hydrated`; a later genuine offline
        // delete of that path would then read `missing + intent present` and
        // wrongly resurrect it from the blocks. This is exactly
        // `reconstruct_file_journaled`'s "clear right after the rename"
        // ordering.
        // The intent is cleared by the commit below, not here:
        // clearing first leaves a window in which the bytes exist,
        // nothing records that a write was in flight, and no proof has
        // landed. Dropping the guard unclear is inert -- it has no
        // `Drop` behaviour of its own, and the commit owns the clear.
        drop(intent_guard);
        Ok(Reconstruction::Written(WrittenObject {
            out_path,
            written_version,
            mutation_generation: content_write_mutation_generation,
        }))
    }

    /// Stage 6: apply this payload's mode and xattrs to the written object.
    fn apply_written_metadata(
        &self,
        plan: &MaterializationPlan<'_>,
        written: WrittenObject,
    ) -> Result<AppliedObject, PeerSessionError> {
        // Apply the owner-executable bit and xattrs THIS PAYLOAD
        // specifies (POSIX: real chmod; no-op, no error, on Windows).
        //
        // From the payload, not the row -- the sharpest instance of
        // the split this commit closes. The content above was
        // reconstructed from the payload's blocks and the proof
        // below names the payload's version, but these two lines used
        // to read the row, so a supersession during the (arbitrarily
        // long) fetch and reconstruct produced exactly:
        //     content bytes    <- payload V1
        //     mode/xattrs      <- row V2
        //     proof version    <- payload V1
        // and V1's `version_hash` bakes in V1's mode and xattrs. The
        // `require_replicated_xattrs_exact` gate inside
        // `exact_object_evidence_after_write` compares disk against
        // the version, so this was a false `ExactObject` claim that
        // the exactness check itself could not catch -- it was
        // verifying against the same row that supplied the wrong
        // values.
        let xattrs = plan.apply_payload_metadata(&written.out_path)?;
        Ok(AppliedObject { written, xattrs })
    }

    /// Stage 7: verify disk holds the exact object the payload names.
    /// `None` when the path has moved on to a version these bytes are not.
    fn verify_written_object(
        &self,
        plan: &MaterializationPlan<'_>,
        applied: AppliedObject,
    ) -> Result<Option<VerifiedObject>, PeerSessionError> {
        let AppliedObject { written, xattrs } = applied;
        Ok(self
            .exact_object_evidence_after_write(
                plan.group_id,
                &plan.record.path,
                RecordKind::File,
                &written.written_version,
                written.mutation_generation,
                &xattrs,
            )?
            .map(|evidence| VerifiedObject { written, evidence }))
    }

    /// Stage 8: commit the proof, the `Hydrated` stamp and the intent clear
    /// under the fence this write bumped, and settle with the evidence.
    fn commit_verified_object(
        &self,
        plan: &MaterializationPlan<'_>,
        verified: VerifiedObject,
    ) -> Result<LocalMaterializeOutcome, PeerSessionError> {
        let MaterializationPlan {
            group_id,
            record,
            authoring_change_hash,
            permit: root_commit_permit,
            ..
        } = *plan;
        let VerifiedObject {
            written:
                WrittenObject {
                    out_path,
                    written_version,
                    mutation_generation: content_write_mutation_generation,
                },
            evidence,
        } = verified;
        if !self.state.commit_internal_materialized_state_if_fence_current(
            group_id,
            &record.path,
            yadorilink_peer_session::ports::ExactActualState::Object {
                kind: RecordKind::File,
                version: written_version.version_hash,
                identity: Box::new(
                    yadorilink_root_authority::fs_identity::FileIdentity::observe_path(&out_path)
                        .ok(),
                ),
            },
            content_write_mutation_generation,
            Some(yadorilink_peer_session::ports::ExpectedAuthoring {
                state: yadorilink_peer_session::ports::MATERIALIZATION_IN_FLIGHT_STATE,
                authoring_change_hash,
                expected_version: Some(&written_version.version_hash),
            }),
            root_commit_permit,
        )? {
            return Ok(MaterializeResult::RetryRequired.into());
        }
        Ok(MaterializeResult::Settled(evidence).into())
    }
}
