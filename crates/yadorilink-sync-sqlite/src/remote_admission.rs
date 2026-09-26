//! Promotion from verified possession into the canonical Published DAG.
//!
//! # Plan outside the writer, revalidate inside it
//!
//! Everything expensive happens with no writer transaction held: decoding the
//! staged Change, working out which parents it needs, reading the local
//! capture fences of the paths it touches. What runs under `BEGIN IMMEDIATE`
//! is only a revalidation of the facts the plan assumed, followed by the
//! inserts. If any of those facts moved, nothing is written and the promotion
//! is re-driven from a fresh plan.
//!
//! This is the same shape the retroactive-repair planner needs, and for the
//! same reason: planning a retroactive merge under the writer gate can hold
//! it for tens of seconds at a time on a large folder. Planning under the writer gate is what turns
//! an expensive computation into
//! a system-wide stall.
//!
//! # Two different things guard the local capture barrier
//!
//! The first is the barrier itself. A path with a row in `local_dirty_paths`
//! has a local edit that has been observed but not yet turned into a Change.
//! Promoting a remote Change that touches such a path would order it causally
//! after content this device has not yet expressed as history — the local edit
//! would be sequenced as though it came first, or be lost. So a Change whose
//! touched paths include an open barrier is not promotable at all, and stays
//! staged until the barrier settles.
//!
//! The second is a race guard. Even with the barrier closed at planning time,
//! a local mutation could be captured between planning and committing. So the
//! plan records each touched path's `path_actual_mutation_fences` generation,
//! and the commit refuses unless every one is still exactly what was planned.
//!
//! Both are derived from current state at the moment they are asked. Neither
//! is stored as a reason, a status or a retry count.
//!
//! # What promotion does not do
//!
//! No signature is checked here, no checkpoint is verified, no Merkle proof is
//! recomputed. All of that happened before the Change was ever staged, and
//! re-doing it under the writer gate is precisely the cost this design
//! removes. Promotion is a state transition over facts already established.

use rusqlite::Connection;
use yadorilink_replica_domain::change::Change;
use yadorilink_replica_domain::ids::{ChangeHash, FolderGroupId};

use crate::dag_store;
use crate::error::SyncSqliteError;
use crate::verified_change_store::{self, VerifiedChangeBundle};

/// The local-capture state a promotion plan was built against.
///
/// One entry per path the Change touches, holding that path's mutation-fence
/// generation as read during planning. A path with no fence row yet reads as
/// generation 0, matching `snapshot_mutation_fence`'s own semantics for a
/// never-mutated path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalCaptureToken {
    fences: Vec<(String, i64)>,
}

impl LocalCaptureToken {
    pub fn paths(&self) -> impl Iterator<Item = &str> {
        self.fences.iter().map(|(path, _)| path.as_str())
    }
}

/// A promotion worked out with no writer transaction held.
#[derive(Clone, Debug)]
pub struct AdmissionPlan {
    pub change_hash: ChangeHash,
    pub group: FolderGroupId,
    pub bundle: VerifiedChangeBundle,
    pub capture_token: LocalCaptureToken,
}

/// Why a plan was refused at commit time.
///
/// None of these is an error. Each says the world moved between planning and
/// committing, and the answer to every one of them is to plan again — not to
/// retry the same plan, and not to record a failure anywhere.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Stale {
    /// The object is no longer staged: something else promoted it first.
    NoLongerStaged,
    /// A parent this plan required is not canonical any more, or never became
    /// canonical.
    ParentNotCanonical(ChangeHash),
    /// A local mutation to one of the Change's paths was captured after this
    /// plan read that path's fence.
    CaptureFenceMoved { path: String, planned: i64, current: i64 },
    /// One of the Change's paths has a local edit that has been observed but
    /// not yet captured into a Change. Promoting now would order this remote
    /// Change after content this device has not expressed as history.
    CaptureBarrierOpen { path: String },
    /// The canonical DAG refused to apply the Change directly, which at this
    /// point can only mean its parent shape changed under the plan.
    ParentShapeChanged,
}

/// What a commit attempt did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdmissionOutcome {
    /// The Change is canonical.
    ///
    /// Exactly one Change, always. Nothing this promotion unblocked is swept
    /// in alongside it: a child earns its own plan, its own capture-token
    /// revalidation and its own commit.
    Promoted { newly_admitted: Vec<ChangeHash> },
    /// The Change was already held here before this attempt: canonical, or
    /// a pruned witness of the history a base absorbed.
    AlreadyCanonical,
    /// Nothing was written; plan again.
    Stale(Stale),
    /// The Change's own author chain refuses it. Nothing was written, the
    /// staged bundle is gone, and the hash is recorded as permanently
    /// rejected: unlike `Stale`, there is nothing to plan again.
    RefusedAuthorChain(yadorilink_replica_domain::admission::AuthorChainRefusal),
    /// The Change was written on a different history than this replica's.
    /// Nothing was written, the staged bundle is gone, and the hash is
    /// recorded as permanently rejected: like `RefusedAuthorChain` there is
    /// nothing to plan again, and unlike it the way forward for the author
    /// is a re-bootstrap onto this replica's base.
    RefusedForeignHistoryBase {
        local: yadorilink_replica_domain::rebootstrap::HistoryEpoch,
        incoming: yadorilink_replica_domain::rebootstrap::HistoryEpoch,
    },
    /// The Change names a path no replica may store. Nothing was written
    /// for it, the staged bundle is gone, and the hash is recorded as
    /// permanently rejected: there is nothing to plan again.
    RefusedPath(yadorilink_replica_domain::admission::PathRefusal),
    /// One of the Change's DAG parents is permanently refused here, so it
    /// can never be installed. Nothing was written for it, the staged
    /// bundle is gone, and the hash is recorded as permanently rejected.
    RefusedBehindRejectedParent { parent: ChangeHash },
    /// The staged Change names an observed base head this replica's base
    /// does not carry at any path it touches. Recorded and discarded like
    /// `RefusedForeignHistoryBase`: no re-plan makes it installable while
    /// the replica stays on its base.
    RefusedInvalidObservedBaseHead {
        local: yadorilink_replica_domain::rebootstrap::HistoryEpoch,
        head: ChangeHash,
    },
}

/// Build a promotion plan. Read-only: safe to run with no writer gate held.
///
/// Returns `None` if the hash is not staged — it may never have been received,
/// or it may already be canonical.
pub fn plan_admission(
    conn: &Connection,
    change_hash: &ChangeHash,
) -> Result<Option<AdmissionPlan>, SyncSqliteError> {
    let Some(bundle) = verified_change_store::load_staged(conn, change_hash)? else {
        return Ok(None);
    };

    let mut paths: Vec<&str> =
        bundle.change.ops.iter().flat_map(dag_store::op_touched_paths).collect();
    paths.sort_unstable();
    paths.dedup();

    let group = bundle.change.group_id.clone();
    let mut fences = Vec::with_capacity(paths.len());
    for path in paths {
        fences.push((path.to_owned(), read_mutation_fence(conn, group.as_str(), path)?));
    }

    Ok(Some(AdmissionPlan {
        change_hash: *change_hash,
        group,
        bundle,
        capture_token: LocalCaptureToken { fences },
    }))
}

/// Commit a plan. Must be called inside the caller's `BEGIN IMMEDIATE`,
/// which this checks rather than merely documenting: `&Connection` and
/// `&Transaction` are the same type to the compiler (`Transaction` derefs
/// to `Connection`), so a caller that passed a plain pooled connection
/// compiled and ran exactly like one that opened a transaction -- and this
/// function's ten-odd write statements then each committed on their own.
/// That was not only slow (`synchronous = FULL` fsyncs the WAL per commit,
/// measured at ~3.6ms per statement on real storage, ~60x the same
/// statement against tmpfs, and ~63ms of the ~67ms a promotion cost); it
/// silently broke the atomicity
/// `dag_store::retained_history_integrity::record_admission_time_index` documents as
/// guaranteed, since a crash between two of those statements leaves a
/// change row whose head-set update or time-index row never landed.
///
/// Everything below is a comparison or an insert; nothing here decodes,
/// verifies or traverses.
pub fn commit_admission(
    conn: &Connection,
    plan: &AdmissionPlan,
) -> Result<AdmissionOutcome, SyncSqliteError> {
    if conn.is_autocommit() {
        return Err(SyncSqliteError::CorruptState(
            "commit_admission requires an open transaction: a promotion must be all-or-nothing"
                .to_owned(),
        ));
    }
    // Already canonical. Clear the staged copy so the possession union does
    // not carry the hash twice, and report it: this is a benign race, not a
    // failure.
    if verified_change_store::is_canonical(conn, &plan.change_hash)? {
        verified_change_store::discard_staged(conn, &plan.change_hash)?;
        return Ok(AdmissionOutcome::AlreadyCanonical);
    }
    // Held here as a pruned witness of the history a base absorbed: not
    // canonical, and never going to be, but not foreign either -- it is
    // history this replica already holds. A peer still keeping the old
    // history can send it again. Its staged copy is dropped the same way,
    // or it would be selected on every pass and never settle.
    if dag_store::has_change_or_pruned(conn, plan.group.as_str(), &plan.change_hash)? {
        verified_change_store::discard_staged(conn, &plan.change_hash)?;
        return Ok(AdmissionOutcome::AlreadyCanonical);
    }

    if !verified_change_store::is_staged(conn, &plan.change_hash)? {
        return Ok(AdmissionOutcome::Stale(Stale::NoLongerStaged));
    }

    // The history the Change was written on, before anything about its
    // parents. A Change from another history is refused for that whatever
    // its parents are: waiting on them would keep it staged -- possessed and
    // servable -- for parents that belong to that other history, and
    // refusing it as behind a refused parent would name the wrong remedy.
    // `admissible_now` selects such a Change for exactly this reason.
    if let Some(refusal) = dag_store::refuse_foreign_history_base(conn, &plan.bundle.change)? {
        let yadorilink_replica_domain::admission::AdmissionRefusal::ForeignHistoryBase {
            local,
            incoming,
        } = refusal
        else {
            return Err(SyncSqliteError::CorruptState(format!(
                "a history check on {:?} returned {refusal:?}",
                plan.change_hash
            )));
        };
        verified_change_store::discard_staged(conn, &plan.change_hash)?;
        return Ok(AdmissionOutcome::RefusedForeignHistoryBase { local, incoming });
    }

    // A refused parent before a missing one. A parent that is refused here
    // is also not canonical, and will never be; reported as a stale plan,
    // this Change would be re-planned for as long as it stayed staged, and
    // it would stay staged forever -- possessed, so never asked for again,
    // and never promotable. Refused, it is recorded under its parent's
    // verdict and its staged copy goes with this transaction; whatever was
    // staged behind it is then itself a Change behind a refused parent,
    // and is selected and refused the same way on the next pass.
    if let Some(refusal) = dag_store::refuse_behind_rejected_parent(conn, &plan.bundle.change)? {
        let yadorilink_replica_domain::admission::AdmissionRefusal::BehindRejectedParent { parent } =
            refusal
        else {
            return Err(SyncSqliteError::CorruptState(format!(
                "a rejected-parent check on {:?} returned {refusal:?}",
                plan.change_hash
            )));
        };
        verified_change_store::discard_staged(conn, &plan.change_hash)?;
        return Ok(AdmissionOutcome::RefusedBehindRejectedParent { parent });
    }

    for parent in &plan.bundle.change.parents {
        if !verified_change_store::is_canonical(conn, parent)? {
            return Ok(AdmissionOutcome::Stale(Stale::ParentNotCanonical(*parent)));
        }
    }

    for (path, planned) in &plan.capture_token.fences {
        if has_uncaptured_local_edit(conn, plan.group.as_str(), path)? {
            return Ok(AdmissionOutcome::Stale(Stale::CaptureBarrierOpen { path: path.clone() }));
        }

        let current = read_mutation_fence(conn, plan.group.as_str(), path)?;
        if current != *planned {
            return Ok(AdmissionOutcome::Stale(Stale::CaptureFenceMoved {
                path: path.clone(),
                planned: *planned,
                current,
            }));
        }
    }

    // Exactly this Change, and nothing else.
    //
    // `dag_store::admit_change` would also recursively promote every buffered
    // `orphan_changes` row this Change completes. Those children would then be
    // installed inside this transaction, against local capture fences nobody
    // read and nobody revalidated — bypassing the whole plan/revalidate
    // sequence this function exists to enforce. Every Change earns its own
    // promotion; whatever this one unblocks is picked up by the coordinator's
    // next pass.
    //
    // Order matches the existing atomic remote-admission path: the Change
    // lands first, then the evidence that publishes it. Both commit with the
    // staged copy's removal, so no reader observes the hash as neither staged
    // nor canonical.
    // A stale plan is a distinct outcome, not an error. Matching on an error
    // variant here would conflate "a parent moved under the plan" with "the
    // database is inconsistent" — the append path can raise the latter too —
    // and a genuine corruption would then be re-driven forever as though it
    // were a race.
    // The metadata the Change refers to, installed before the Change itself
    // because the DAG append validates that every referenced version is
    // present. These came with the bundle and were staged in the same
    // transaction that made the Change possessed, so this is a copy across a
    // boundary inside one database -- not a fetch, and not something that can
    // fail for want of a peer.
    //
    // `put_file_version` re-verifies each version's hash against its own bytes
    // and is idempotent on the content address, so a version already installed
    // by an earlier promotion (or by local capture) is a no-op rather than a
    // conflict.
    for version in &plan.bundle.versions {
        dag_store::put_file_version(conn, plan.bundle.change.group_id.as_str(), version)?;
    }

    match dag_store::install_canonical_change_only(conn, &plan.bundle.change)? {
        dag_store::InstallCanonicalOutcome::Installed
        | dag_store::InstallCanonicalOutcome::AlreadyPresent => {}
        dag_store::InstallCanonicalOutcome::ParentsNotPresent => {
            return Ok(AdmissionOutcome::Stale(Stale::ParentShapeChanged));
        }
        dag_store::InstallCanonicalOutcome::RefusedAuthorChain(refusal) => {
            // Not stale: no re-plan makes this installable, so the staged
            // bundle is discarded. Leaving it staged would have the
            // coordinator plan and refuse it again on every wake. The
            // durable "never ask for this again" record is the admission
            // boundary's, written before this outcome was returned, so
            // every path that refuses a change records it the same way.
            verified_change_store::discard_staged(conn, &plan.change_hash)?;
            return Ok(AdmissionOutcome::RefusedAuthorChain(refusal));
        }
        dag_store::InstallCanonicalOutcome::RefusedForeignHistoryBase { local, incoming } => {
            // Same disposal as an author-chain refusal, and for the same
            // reason: no re-plan makes a change from another history
            // installable here. The durable record, with its own wording
            // saying which history it came from rather than accusing its
            // author of forking, was written at the admission boundary.
            verified_change_store::discard_staged(conn, &plan.change_hash)?;
            return Ok(AdmissionOutcome::RefusedForeignHistoryBase { local, incoming });
        }
        dag_store::InstallCanonicalOutcome::RefusedPath(refusal) => {
            // Same disposal again: the path is part of the Change's own
            // signed bytes, so no re-plan changes the verdict. The refusal
            // is returned rather than raised so that this transaction
            // commits, carrying the durable record and the discard with it.
            verified_change_store::discard_staged(conn, &plan.change_hash)?;
            return Ok(AdmissionOutcome::RefusedPath(refusal));
        }
        dag_store::InstallCanonicalOutcome::RefusedBehindRejectedParent { parent } => {
            // No parent that is refused ever becomes canonical, so no
            // re-plan makes this installable.
            verified_change_store::discard_staged(conn, &plan.change_hash)?;
            return Ok(AdmissionOutcome::RefusedBehindRejectedParent { parent });
        }
        dag_store::InstallCanonicalOutcome::RefusedInvalidObservedBaseHead { local, head } => {
            // The names are part of the Change's signed bytes and measured
            // against the base this replica is on, so no re-plan changes
            // the verdict while it stays there.
            verified_change_store::discard_staged(conn, &plan.change_hash)?;
            return Ok(AdmissionOutcome::RefusedInvalidObservedBaseHead { local, head });
        }
    }

    dag_store::published_view::attach_authorization_evidence_on_conn(
        conn,
        &plan.bundle.checkpoint.checkpoint_hash,
        plan.bundle.change.group_id.as_str(),
        plan.bundle.checkpoint.device_id.as_str(),
        plan.bundle.checkpoint.checkpoint_seq,
        &plan.bundle.checkpoint.encoded,
        &plan.bundle.checkpoint.signature,
        &plan.bundle.checkpoint.author_signing_public_key,
        &[(plan.change_hash, plan.bundle.merkle_proof.clone())],
    )?;

    verified_change_store::discard_staged(conn, &plan.change_hash)?;

    Ok(AdmissionOutcome::Promoted { newly_admitted: vec![plan.change_hash] })
}

/// Whether `path` has a local edit that has been observed but not yet turned
/// into a Change.
///
/// This is the local capture barrier. It is read fresh every time it is asked;
/// there is no cached "blocked" flag anywhere, so a barrier that settles needs
/// nothing invalidated for the next attempt to see it settled.
///
/// A dirty conflict-copy name of `path` holds it too: an edit of a copy the
/// namespace placed `path`'s leaf under is journaled at the copy name but
/// authored at `path` (see [`crate::write_through`]). Held for any such
/// name, placed or authored, since which one it is is decided only when the
/// edit is captured.
fn has_uncaptured_local_edit(
    conn: &Connection,
    group_id: &str,
    path: &str,
) -> Result<bool, SyncSqliteError> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM local_dirty_paths WHERE group_id = ?1 AND path = ?2",
        rusqlite::params![group_id, path],
        |row| row.get(0),
    )?;
    if count > 0 {
        return Ok(true);
    }
    // Every copy name of `path` starts with its stem and the marker; the
    // range is that prefix's (the marker's last byte, a space, bumped).
    let (dir, filename) = path.rsplit_once('/').map_or(("", path), |(dir, name)| (dir, name));
    let stem = match filename.rsplit_once('.') {
        Some((stem, _)) if !stem.is_empty() => stem,
        _ => filename,
    };
    let dir = if dir.is_empty() { String::new() } else { format!("{dir}/") };
    let low = format!("{dir}{stem} (conflicted copy, ");
    let high = format!("{dir}{stem} (conflicted copy,!");
    let mut stmt = conn.prepare_cached(
        "SELECT path FROM local_dirty_paths WHERE group_id = ?1 AND path >= ?2 AND path < ?3",
    )?;
    let rows =
        stmt.query_map(rusqlite::params![group_id, low, high], |row| row.get::<_, String>(0))?;
    for dirty in rows {
        let dirty = dirty?;
        if yadorilink_replica_domain::conflict::conflict_copy_source_path(&dirty) == path {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Read a path's mutation-fence generation without writing.
///
/// `materialized_generation::snapshot_mutation_fence` inserts a
/// generation-zero row for a path it has never seen, which makes it a write
/// and so unusable during planning. A missing row means the path has never
/// been mutated, which is generation 0 — the same value that function would
/// have created and returned.
fn read_mutation_fence(
    conn: &Connection,
    group_id: &str,
    path: &str,
) -> Result<i64, SyncSqliteError> {
    conn.query_row(
        "SELECT mutation_generation FROM path_actual_mutation_fences \
          WHERE group_id = ?1 AND path = ?2",
        rusqlite::params![group_id, path],
        |row| row.get(0),
    )
    .or_else(|error| match error {
        rusqlite::Error::QueryReturnedNoRows => Ok(0),
        other => Err(SyncSqliteError::from(other)),
    })
}

/// Convenience for a caller that wants the decoded Change of a plan without
/// reaching through the bundle.
impl AdmissionPlan {
    pub fn change(&self) -> &Change {
        &self.bundle.change
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod epoch_first_tests;

#[cfg(test)]
mod author_hold_tests;
