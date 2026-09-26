//! Sealing a group's history into a new history base.
//!
//! A seal replaces everything this replica holds of a group's history with
//! a signed base that carries two things: the materialized files that
//! history produced, and the bounded causal summary `Q = (W, L, Gamma)` of
//! the history itself. `W` is every author's position (watermark and the
//! change that reached it), `L` is the greatest Lamport the history reached,
//! and `Gamma` is, per path, every causally maximal present entry head --
//! a file's, a symlink's or a directory's. A structural directory, one
//! that exists only to hold a descendant, has no head: it is derived from
//! the tree, never written. The base derives from a checkpoint whose
//! snapshot hash covers both halves, so the base is bound to the summary
//! as tightly as to the files.
//!
//! The files are the namespace projection of `Gamma`, not its per-path
//! winners. A path that has to be a directory -- because a directory head
//! is live there, or because something lives below it -- holds that
//! directory, and a file the per-path resolver would have put there sits
//! at its conflict-copy name beside it. That is the shape the index has
//! once the reconcile pass has caught up, and the shape a joiner's install
//! leaves, so a seal carries the rows where the index holds them and a
//! joiner reads a copy-name row back as the displaced path's head, which
//! `Gamma` names, rather than as a path of its own.
//!
//! A seal does not wait for other devices. A device that was away while the
//! history was sealed comes back with changes written on the history the
//! base replaced; those are not missing parents of anything here, they are
//! another history, and they are merged by joining the two summaries rather
//! than by holding every seal until every device has acknowledged it.
//!
//! What a seal must hold before it is allowed to happen is checked in
//! [`verify_seal_preconditions`]; [`prepare_seal`] and [`seal_group`] are
//! the only paths that produce and commit a seal, and both go through it.

use std::collections::{BTreeMap, HashMap, HashSet};

use rusqlite::{Connection, OptionalExtension};
use yadorilink_replica_domain::base_negotiation::SummaryIdentity;
use yadorilink_replica_domain::change::Change;
use yadorilink_replica_domain::file::FileVersion;
use yadorilink_replica_domain::file::RecordKind;
use yadorilink_replica_domain::ids::{AuthorSeq, ChangeHash, FolderGroupId, VersionHash};
use yadorilink_replica_domain::rebootstrap::{HistoryBase, HistoryEpoch};
use yadorilink_replica_engine::compaction::{Checkpoint, PrunePlan};
use yadorilink_replica_engine::conflict::{path_effects_of_change, PathHead};
use yadorilink_replica_engine::namespace::{project, DirectoryNode, PhysicalNode, Placement};
use yadorilink_replica_engine::rebootstrap_snapshot::{
    RebootstrapSnapshot, SnapshotAuthorState, SnapshotPathHead, SnapshotVersionState,
};

use super::{build_compaction_snapshot, GroupHistorySummary};
use crate::SyncSqliteError;

/// Why a seal was refused. Each is a state in which the base the seal would
/// produce would not describe the history it replaces, or would lose
/// something the history still holds.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SealRefusal {
    /// Nothing has been admitted on the current history epoch since the
    /// base below it, so a seal would only restate that base.
    #[error("nothing has been written on the current history epoch")]
    NothingToSeal,
    /// The seal was planned against a frontier the group no longer has.
    #[error("the group's frontier moved after the seal was planned")]
    FrontierMoved,
    /// A change is admitted but not yet published: the files it will
    /// produce are not in the store yet, so a snapshot taken now would not
    /// contain them while the summary would.
    #[error("change {} is admitted but not yet published", .change.to_hex())]
    UnpublishedChange { change: ChangeHash },
    /// Another subsystem has registered a change the seal would absorb as
    /// one it still needs retained.
    #[error("change {} is held by a retention root", .change.to_hex())]
    RetentionRootHeld { change: ChangeHash },
    /// A path's projection has not caught up with the history, so the
    /// files the snapshot would carry are not what the history resolves to.
    #[error("{path} has an outstanding projection obligation")]
    ProjectionPending { path: String },
    /// A path replaced by an earlier snapshot install has not been
    /// reconciled on disk yet.
    #[error("{path} is held by an unreconciled snapshot install")]
    InstallHoldPending { path: String },
    /// A current file row whose authoring change has no authorization
    /// evidence. The snapshot carries only evidenced rows, so this one
    /// would silently vanish from it.
    #[error("{path} has a current row with no authorization evidence")]
    FileWithoutEvidence { path: String },
    /// A path whose content or explicit directory the projection of the
    /// summary places somewhere -- at the path, or at the copy name a
    /// directory displaced it to -- where no current row holds it.
    #[error("{path} does not hold the content its heads resolve to")]
    WinnerNotMaterialized { path: String },
    /// A live row at a path the namespace projection makes a structural
    /// directory. A structural directory is derived, never replicated.
    #[error("{path} is a structural directory but holds a live row")]
    RowAtStructuralDirectory { path: String },
    /// A live directory row at a path where no head holds a directory.
    #[error("{path} holds a directory row no head accounts for")]
    DirectoryWithoutHead { path: String },
    /// A live row below a live File or Symlink row. The rows a base
    /// carries form a tree; a joiner would move the leaf out of the way.
    #[error("{path} holds a live row below the live leaf {leaf}")]
    RowBelowLeaf { path: String, leaf: String },
    /// A losing content class at a path has no durable conflict copy.
    #[error("{path} has a losing content head with no durable conflict copy at {copy_path}")]
    ConflictCopyNotDurable { path: String, copy_path: String },
    /// A content head the summary carries whose version the snapshot does
    /// not carry, so the base would name content it cannot reproduce.
    #[error("{path} has a head at version {} the snapshot does not carry", hex::encode(.version.0))]
    ContentNotCarried { path: String, version: VersionHash },
    /// A retained change written on an earlier history that the installed
    /// base does not account for.
    #[error("retained change {} belongs to an earlier history the installed base does not carry", .change.to_hex())]
    RetainedChangeOutsideBase { change: ChangeHash },
    /// A retained change names a parent this replica does not hold.
    #[error("retained change {} names a parent this replica does not hold", .change.to_hex())]
    HistoryNotClosed { change: ChangeHash },
    /// An author's retained changes do not form one unbroken chain above
    /// the position the base carried for it.
    #[error("author {device_id}'s chain is broken: {detail}")]
    AuthorChainBroken { device_id: String, detail: String },
    /// An author's stored anchor disagrees with where its chain stands.
    #[error("author {device_id}'s stored anchor disagrees with its retained history")]
    AuthorAnchorInconsistent { device_id: String },
    /// Two live content heads of one path by one author.
    #[error("author {device_id} holds two live heads of {path}")]
    TwoHeadsFromOneAuthor { path: String, device_id: String },
    /// The summary the store maintains disagrees with the one recomputed
    /// from the signed changes it retains.
    #[error("the maintained summary disagrees with retained history: {detail}")]
    SummaryDisagreesWithHistory { detail: String },
    /// The snapshot does not survive its own canonical encoding.
    #[error("the snapshot does not round-trip through its canonical encoding")]
    SnapshotNotCanonical,
}

pub(crate) fn refuse(group_id: &str, refusal: SealRefusal) -> SyncSqliteError {
    SyncSqliteError::SealRefused { group_id: group_id.to_owned(), refusal }
}

/// A seal whose preconditions have been checked: the checkpoint, the
/// snapshot it commits to, and which retained changes it replaces.
///
/// Only [`prepare_seal`] makes one, so holding one means every
/// precondition in [`verify_seal_preconditions`] held against the state
/// it was built from.
#[derive(Clone, Debug)]
pub struct VerifiedSeal {
    checkpoint: Checkpoint,
    snapshot: RebootstrapSnapshot,
    frontier: Vec<ChangeHash>,
    pruned: Vec<ChangeHash>,
}

impl VerifiedSeal {
    pub fn checkpoint(&self) -> &Checkpoint {
        &self.checkpoint
    }

    pub fn snapshot(&self) -> &RebootstrapSnapshot {
        &self.snapshot
    }

    /// The base this seal produces.
    pub fn history_base(&self) -> HistoryBase {
        HistoryBase::from_checkpoint(&self.checkpoint)
    }

    /// The retained changes the base's checkpoint names as its frontier.
    pub fn frontier(&self) -> &[ChangeHash] {
        &self.frontier
    }

    /// The retained changes below the frontier.
    pub fn pruned(&self) -> &[ChangeHash] {
        &self.pruned
    }

    /// Every retained change the base absorbs: the frontier and everything
    /// below it.
    pub fn absorbed(&self) -> Vec<ChangeHash> {
        let mut all: Vec<ChangeHash> =
            self.frontier.iter().chain(self.pruned.iter()).copied().collect();
        all.sort();
        all
    }

    /// The causal summary this seal's base carries.
    pub fn summary(&self) -> GroupHistorySummary {
        GroupHistorySummary {
            author_state: self.snapshot.author_state.clone(),
            path_heads: self.snapshot.path_heads.clone(),
            lamport_ceiling: self.snapshot.lamport_ceiling,
        }
    }

    /// The identity of [`summary`](Self::summary), as the base
    /// advertisement states it.
    pub fn summary_identity(&self) -> SummaryIdentity {
        crate::base_advertisement::summary_identity(&self.summary())
    }
}

/// What a seal of `group_id` would absorb: every change this replica
/// retains for the group, with the group's current heads as the frontier.
///
/// Planned from this replica's own history and nothing else. No other
/// device's acknowledged frontier is consulted, because a seal does not
/// wait for any device: one that has not seen this history returns with its
/// own, and the two are merged by summary.
pub fn plan_seal(conn: &Connection, group_id: &str) -> Result<PrunePlan, SyncSqliteError> {
    let mut frontier = crate::dag_store::group_heads(conn, group_id)?;
    frontier.sort();
    let in_frontier: HashSet<ChangeHash> = frontier.iter().copied().collect();
    let mut pruned: Vec<ChangeHash> = retained_change_hashes(conn, group_id)?
        .into_iter()
        .filter(|hash| !in_frontier.contains(hash))
        .collect();
    pruned.sort();
    Ok(PrunePlan {
        group_id: FolderGroupId(group_id.to_owned()),
        checkpoint_frontier: frontier,
        pruned,
        blocking_devices: Vec::new(),
    })
}

pub(crate) fn retained_change_hashes(
    conn: &Connection,
    group_id: &str,
) -> Result<Vec<ChangeHash>, SyncSqliteError> {
    let mut stmt = conn.prepare("SELECT change_hash FROM changes WHERE group_id = ?1")?;
    let rows = stmt.query_map([group_id], |row| row.get::<_, Vec<u8>>(0))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(ChangeHash(super::hash_32(&row?, "changes.change_hash")?));
    }
    Ok(out)
}

/// The history a seal absorbs, read once and checked for the properties the
/// rest of the seal relies on.
struct AbsorbedHistory {
    group_id: String,
    /// The epoch the retained changes above the installed base were
    /// written on.
    epoch: HistoryEpoch,
    /// The installed base's summary, or `None` on the original history.
    base: Option<GroupHistorySummary>,
    /// Every retained change, decoded.
    changes: Vec<(ChangeHash, Change)>,
    /// Each author's position over the whole history: the base's, advanced
    /// by the author's retained changes on the current epoch.
    positions: BTreeMap<String, (AuthorSeq, ChangeHash)>,
}

/// Checks everything a seal of `plan` into `snapshot` must hold.
///
/// Of the history:
///
/// * the plan is still the group's frontier and covers exactly what the
///   group retains;
/// * every retained change is published, and something has been written
///   on the current epoch;
/// * no other subsystem holds a retention root on anything it absorbs;
/// * projection has caught up and no install hold is outstanding;
/// * every current row carries authorization evidence the snapshot can
///   carry with it;
/// * every retained change is either on the current epoch or absorbed by
///   the installed base, and each author's changes on the current epoch
///   continue its position in one unbroken chain; each author's stored
///   anchor agrees.
///
/// Of the snapshot:
///
/// * it survives its own canonical encoding;
/// * its `W`, `Gamma` and `L` are exactly what the retained signed changes
///   and the installed base's summary produce, recomputed here without the
///   derived state the builder read;
/// * it carries every head's content;
/// * the current rows are the namespace projection of its `Gamma`: every
///   placed entry at the name the projection gives it (a displaced
///   winner at its copy name, every losing content class as a durable
///   conflict copy), every explicit directory's row at its path, no live
///   row at a structural directory, and no directory row the projection
///   does not hold.
pub fn verify_seal_preconditions(
    conn: &Connection,
    plan: &PrunePlan,
    snapshot: &RebootstrapSnapshot,
) -> Result<(), SyncSqliteError> {
    let history = check_history(conn, plan)?;
    check_snapshot(&history, snapshot)
}

/// Plans, builds and verifies a seal of `group_id`, without committing it.
///
/// The history is checked before the snapshot is built as well as after,
/// so a history that cannot be sealed is refused for the reason it cannot,
/// rather than for whichever symptom building a snapshot of it hits first.
pub fn prepare_seal(conn: &Connection, group_id: &str) -> Result<VerifiedSeal, SyncSqliteError> {
    let plan = plan_seal(conn, group_id)?;
    let history = check_history(conn, &plan)?;
    let snapshot = build_compaction_snapshot(conn, &plan)?;
    check_snapshot(&history, &snapshot)?;
    let checkpoint = Checkpoint::new(
        plan.group_id.clone(),
        plan.checkpoint_frontier.clone(),
        snapshot.snapshot_hash(),
    );
    Ok(VerifiedSeal {
        checkpoint,
        snapshot,
        frontier: plan.checkpoint_frontier,
        pruned: plan.pruned,
    })
}

/// Seals `group_id` in the caller's transaction: plans, builds, verifies
/// and commits in one step, so what is committed is exactly what was
/// verified.
///
/// The commit is the atomic epoch reset
/// (`super::reset_group_epoch`): the base and its summary are
/// installed and the whole absorbed history -- [`VerifiedSeal::absorbed`],
/// frontier included -- is retired, so afterwards the group retains no
/// change at all. Every author is anchored on the new base: its next change
/// sits at the position the base carries plus one, names no predecessor,
/// is signed on the new epoch and is clocked from the base's ceiling. The
/// seal carries every author's position exactly as the store holds it, so
/// every position matches; one that did not would be left anchored on a
/// change the base absorbed, and is reported rather than left behind.
pub fn seal_group(
    tx: &rusqlite::Transaction<'_>,
    group_id: &str,
) -> Result<VerifiedSeal, SyncSqliteError> {
    seal_group_until(tx, group_id, None)
}

fn seal_group_until(
    tx: &rusqlite::Transaction<'_>,
    group_id: &str,
    interrupt_after: Option<EpochResetStep>,
) -> Result<VerifiedSeal, SyncSqliteError> {
    // A seal deletes the whole retained history and moves the group onto an
    // epoch no peer accepts yet, so it stays off with the rest of history
    // compaction. Test fixtures seal regardless: they exercise the seal
    // itself, not whether one may run.
    #[cfg(not(any(test, feature = "test-support")))]
    require_compaction_ready(yadorilink_replica_engine::rebootstrap::COMPACTION_SCHEDULING_READY)?;
    let seal = prepare_seal(tx, group_id)?;
    super::reset_group_epoch(
        tx,
        &seal.checkpoint,
        &seal.snapshot,
        &seal.absorbed(),
        interrupt_after,
    )?;
    let base = seal.history_base();
    for author in crate::dag_store::author_chain::all_author_state(tx, group_id)? {
        let anchored_on =
            crate::dag_store::author_chain::author_chain_state(tx, group_id, &author.device_id)?
                .and_then(|state| state.anchored_on);
        if anchored_on != Some(base) {
            return Err(SyncSqliteError::CorruptState(format!(
                "sealing group {group_id} left author {} anchored on {:?} rather than on the \
                 base it sealed",
                author.device_id, anchored_on
            )));
        }
    }
    if !retained_change_hashes(tx, group_id)?.is_empty() {
        return Err(SyncSqliteError::CorruptState(format!(
            "sealing group {group_id} left changes retained beside the base it sealed"
        )));
    }
    // The absorbed history's evidence goes with it, except what a row, a
    // version or the summary the base carries still names.
    crate::authorization_witness_gc::collect_authorization_witnesses(tx, group_id)?;
    interrupt_if_reached(interrupt_after, EpochResetStep::WitnessesCollected, || {
        format!("the seal of group {group_id}")
    })?;
    Ok(seal)
}

/// Stops the caller's reset with an error when `step` is the one it is to
/// be interrupted after, as a crash right there would stop it.
pub(super) fn interrupt_if_reached(
    interrupt_after: Option<EpochResetStep>,
    step: EpochResetStep,
    what: impl FnOnce() -> String,
) -> Result<(), SyncSqliteError> {
    if interrupt_after == Some(step) {
        return Err(SyncSqliteError::Io(std::io::Error::new(
            std::io::ErrorKind::Interrupted,
            format!("{} was interrupted after {step:?}", what()),
        )));
    }
    Ok(())
}

/// Refuses a seal while history compaction is not ready to run.
#[cfg_attr(any(test, feature = "test-support"), allow(dead_code))]
pub(super) fn require_compaction_ready(ready: bool) -> Result<(), SyncSqliteError> {
    if ready {
        return Ok(());
    }
    Err(SyncSqliteError::CorruptState(
        "history compaction is disabled until the R3.3 re-bootstrap pipeline is \
         production-ready"
            .into(),
    ))
}

/// A point inside the transaction that commits a seal, after which a crash
/// could stop it before it commits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EpochResetStep {
    /// The checkpoint and the snapshot carrying the summary are written;
    /// the group has not switched to the new base yet.
    SummaryRecorded,
    /// The new base is the group's history and every author is anchored on
    /// it; the history it absorbed is still retained.
    BaseSwitched,
    /// The absorbed history and everything derived from it are gone.
    HistoryRetired,
    /// The authorization witnesses nothing retained still needs are
    /// collected (P7); the reset has not committed yet.
    WitnessesCollected,
}

impl EpochResetStep {
    /// Every step, in the order a seal passes them.
    pub const ALL: [Self; 4] =
        [Self::SummaryRecorded, Self::BaseSwitched, Self::HistoryRetired, Self::WitnessesCollected];
}

/// [`seal_group`], stopped with an error right after `step`, as a crash
/// there would stop it. The caller's transaction then never commits.
#[cfg(any(test, feature = "test-support"))]
pub fn seal_group_interrupted_after(
    tx: &rusqlite::Transaction<'_>,
    group_id: &str,
    step: EpochResetStep,
) -> Result<VerifiedSeal, SyncSqliteError> {
    seal_group_until(tx, group_id, Some(step))
}

fn check_history(conn: &Connection, plan: &PrunePlan) -> Result<AbsorbedHistory, SyncSqliteError> {
    let group_id = plan.group_id.as_str();
    let refused = |refusal| refuse(group_id, refusal);

    let mut heads = crate::dag_store::group_heads(conn, group_id)?;
    heads.sort();
    let mut planned_frontier = plan.checkpoint_frontier.clone();
    planned_frontier.sort();
    let mut planned: Vec<ChangeHash> =
        plan.checkpoint_frontier.iter().chain(plan.pruned.iter()).copied().collect();
    planned.sort();
    let mut retained = retained_change_hashes(conn, group_id)?;
    retained.sort();
    if heads != planned_frontier || retained != planned {
        return Err(refused(SealRefusal::FrontierMoved));
    }

    if let Some(change) = first_hash(
        conn,
        "SELECT c.change_hash FROM changes c WHERE c.group_id = ?1 AND NOT EXISTS \
         (SELECT 1 FROM change_authorization ca WHERE ca.change_hash = c.change_hash) \
         ORDER BY c.change_hash LIMIT 1",
        group_id,
    )? {
        return Err(refused(SealRefusal::UnpublishedChange { change }));
    }

    let epoch = super::current_history_epoch(conn, group_id)?;
    let mut changes = Vec::with_capacity(retained.len());
    {
        let mut stmt = conn.prepare(
            "SELECT change_hash, encoded FROM changes WHERE group_id = ?1 ORDER BY change_hash",
        )?;
        let rows = stmt.query_map([group_id], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;
        for row in rows {
            let (hash, encoded) = row?;
            let hash = ChangeHash(super::hash_32(&hash, "changes.change_hash")?);
            let change = super::decode_stored_change(&encoded)?;
            if change.compute_hash() != hash {
                return Err(SyncSqliteError::CorruptState(format!(
                    "retained change {} of group {group_id} is stored under another hash",
                    hash.to_hex()
                )));
            }
            changes.push((hash, change));
        }
    }
    if !changes.iter().any(|(_, change)| change.history_epoch == epoch) {
        return Err(refused(SealRefusal::NothingToSeal));
    }

    if let Some(change) = first_hash(
        conn,
        "SELECT r.change_hash FROM dag_retention_roots r \
         JOIN changes c ON c.change_hash = r.change_hash \
         WHERE r.group_id = ?1 AND c.group_id = ?1 ORDER BY r.change_hash LIMIT 1",
        group_id,
    )? {
        return Err(refused(SealRefusal::RetentionRootHeld { change }));
    }

    if let Some(path) = first_path(
        conn,
        "SELECT path FROM projection_obligations \
         WHERE group_id = ?1 AND state != 'ignore_blocked' ORDER BY path LIMIT 1",
        group_id,
    )? {
        return Err(refused(SealRefusal::ProjectionPending { path }));
    }
    if let Some(path) = first_path(
        conn,
        "SELECT path FROM snapshot_install_holds WHERE group_id = ?1 ORDER BY path LIMIT 1",
        group_id,
    )? {
        return Err(refused(SealRefusal::InstallHoldPending { path }));
    }
    // The same rows the snapshot's file set is read from, minus the join
    // that silently drops a row with no evidence behind it. `version_seq`
    // 0 is a scaffold for a path never indexed, which carries no content.
    if let Some(path) = first_path(
        conn,
        "SELECT f.path FROM files f WHERE f.group_id = ?1 AND f.state = 'current' \
           AND f.version_seq > 0 AND NOT EXISTS \
           (SELECT 1 FROM change_authorization ca WHERE ca.change_hash = f.authoring_change_hash) \
         ORDER BY f.path LIMIT 1",
        group_id,
    )? {
        return Err(refused(SealRefusal::FileWithoutEvidence { path }));
    }

    let base = match epoch {
        HistoryEpoch::Genesis => None,
        HistoryEpoch::Base(_) => {
            Some(super::history_base_summary(conn, group_id)?.ok_or_else(|| {
                SyncSqliteError::CorruptState(format!(
                    "group {group_id} has an installed history base with no summary"
                ))
            })?)
        }
    };
    let positions = author_positions(group_id, epoch, base.as_ref(), &changes)?;
    check_anchors(conn, group_id, epoch, &positions, &changes)?;

    Ok(AbsorbedHistory { group_id: group_id.to_owned(), epoch, base, changes, positions })
}

/// Each author's position over the whole history, from the installed
/// base's positions and the retained changes, checking on the way that the
/// retained changes are a history the base can stand under.
///
/// A retained change written on an earlier epoch must be one the base
/// absorbed: at or below the base's position for its author, and the very
/// change the base names when it is at that position. Changes on the
/// current epoch must continue each author's position in one unbroken
/// chain: consecutive sequences from the base's position plus one, the
/// first naming no predecessor, each after that naming the one before.
fn author_positions(
    group_id: &str,
    epoch: HistoryEpoch,
    base: Option<&GroupHistorySummary>,
    changes: &[(ChangeHash, Change)],
) -> Result<BTreeMap<String, (AuthorSeq, ChangeHash)>, SyncSqliteError> {
    let mut positions: BTreeMap<String, (AuthorSeq, ChangeHash)> = base
        .map(|base| {
            base.author_state
                .iter()
                .map(|author| {
                    (author.device_id.clone(), (author.watermark, author.tip_change_hash))
                })
                .collect()
        })
        .unwrap_or_default();
    let mut current: BTreeMap<&str, Vec<&(ChangeHash, Change)>> = BTreeMap::new();
    for entry in changes {
        let (hash, change) = entry;
        let device = change.device_id.as_str();
        if change.history_epoch == epoch {
            current.entry(device).or_default().push(entry);
            continue;
        }
        match positions.get(device) {
            Some((watermark, tip)) if change.author_seq <= *watermark => {
                if change.author_seq == *watermark && tip != hash {
                    return Err(refuse(
                        group_id,
                        SealRefusal::AuthorChainBroken {
                            device_id: device.to_owned(),
                            detail: format!(
                                "retained change {} and the installed base's position name two \
                                 different changes at sequence {watermark}",
                                hash.to_hex()
                            ),
                        },
                    ));
                }
            }
            _ => {
                return Err(refuse(
                    group_id,
                    SealRefusal::RetainedChangeOutsideBase { change: *hash },
                ))
            }
        }
    }
    for (device, mut chain) in current {
        chain.sort_by_key(|(_, change)| change.author_seq);
        let broken = |detail: String| {
            refuse(
                group_id,
                SealRefusal::AuthorChainBroken { device_id: device.to_owned(), detail },
            )
        };
        let first = positions.get(device).map_or(0, |(watermark, _)| watermark.get()) + 1;
        let mut predecessor: Option<ChangeHash> = None;
        for (expected, (hash, change)) in (first..).zip(chain) {
            if change.author_seq.get() != expected {
                return Err(broken(format!(
                    "expected sequence {expected} next, found {}",
                    change.author_seq
                )));
            }
            if change.author_prev != predecessor {
                return Err(broken(format!(
                    "the change at sequence {} does not name the change before it",
                    change.author_seq
                )));
            }
            predecessor = Some(*hash);
            positions.insert(device.to_owned(), (change.author_seq, *hash));
        }
    }
    Ok(positions)
}

/// Each author's stored anchor must be where its history puts it: on the
/// tip it reached on the current epoch if it wrote there, and on the
/// installed base otherwise.
fn check_anchors(
    conn: &Connection,
    group_id: &str,
    epoch: HistoryEpoch,
    positions: &BTreeMap<String, (AuthorSeq, ChangeHash)>,
    changes: &[(ChangeHash, Change)],
) -> Result<(), SyncSqliteError> {
    let wrote_on_current: HashSet<&str> = changes
        .iter()
        .filter(|(_, change)| change.history_epoch == epoch)
        .map(|(_, change)| change.device_id.as_str())
        .collect();
    for author in crate::dag_store::author_chain::all_author_state(conn, group_id)? {
        let device = author.device_id.as_str();
        let Some(state) =
            crate::dag_store::author_chain::author_chain_state(conn, group_id, device)?
        else {
            continue;
        };
        let consistent = if wrote_on_current.contains(device) {
            state.anchored_on.is_none()
                && positions.get(device).is_some_and(|(_, tip)| *tip == state.tip)
        } else {
            matches!(epoch, HistoryEpoch::Base(base) if state.anchored_on == Some(base))
        };
        if !consistent {
            return Err(refuse(
                group_id,
                SealRefusal::AuthorAnchorInconsistent { device_id: author.device_id },
            ));
        }
    }
    Ok(())
}

fn check_snapshot(
    history: &AbsorbedHistory,
    snapshot: &RebootstrapSnapshot,
) -> Result<(), SyncSqliteError> {
    let group_id = history.group_id.as_str();
    let refused = |refusal| refuse(group_id, refusal);

    if snapshot.group_id.as_str() != group_id
        || RebootstrapSnapshot::decode(&snapshot.canonical_encoding()).ok().as_ref()
            != Some(snapshot)
    {
        return Err(refused(SealRefusal::SnapshotNotCanonical));
    }

    let recomputed = recompute_summary(history)?;
    compare_summaries(group_id, snapshot, &recomputed)?;
    check_namespace(group_id, snapshot)
}

/// A base's rows against the summary it carries: every head's content is
/// carried, and the current rows are the namespace projection of `Gamma`
/// -- every placed entry at the name the projection gives it, every
/// explicit directory's row at its path, no live row at a structural
/// directory, no directory row the projection does not hold, and nothing
/// below a leaf.
///
/// The same comparison whether the summary is a seal's or the join of two
/// histories: a merged base's rows must be exactly as installable as a
/// sealed one's.
pub(super) fn check_namespace(
    group_id: &str,
    snapshot: &RebootstrapSnapshot,
) -> Result<(), SyncSqliteError> {
    let refused = |refusal| refuse(group_id, refusal);
    let kinds: HashMap<VersionHash, RecordKind> = snapshot
        .file_versions
        .iter()
        .map(|encoded| {
            FileVersion::from_canonical_encoding(encoded)
                .map(|version| (version.version_hash, version.meta.record_kind))
                .map_err(|error| {
                    SyncSqliteError::CorruptState(format!(
                        "seal snapshot for group {group_id} carries an invalid version: {error}"
                    ))
                })
        })
        .collect::<Result<_, _>>()?;
    let current_rows: BTreeMap<&str, (VersionHash, RecordKind)> = snapshot
        .files
        .iter()
        .filter(|file| file.state == SnapshotVersionState::Current && !file.record.deleted)
        .map(|file| {
            let version = FileVersion::from_index_row(
                file.record.blocks.clone(),
                file.record.size,
                file.record.mtime_unix_nanos,
                file.record_kind,
                file.unix_mode,
                file.symlink_target.clone(),
                file.xattrs.clone(),
            );
            (file.record.path.as_str(), (version.version_hash, file.record_kind))
        })
        .collect();
    let holds = |path: &str, version: [u8; 32]| {
        current_rows.get(path).map(|(held, _)| *held) == Some(VersionHash(version))
    };

    for head in &snapshot.path_heads {
        if !kinds.contains_key(&head.version_hash) {
            return Err(refused(SealRefusal::ContentNotCarried {
                path: head.path.clone(),
                version: head.version_hash,
            }));
        }
    }

    // The rows must be the namespace projection of `Gamma`, placed exactly
    // as the projection-driven reconcile places them: a path that has to
    // be a directory holds its explicit directory's row or, structural,
    // none at all, and a file it displaced sits at its copy name.
    let projection = super::heads_by_path(&snapshot.path_heads);
    let projection = project(&projection, |version| kinds.get(&VersionHash(*version)).copied())
        .map_err(|error| {
            SyncSqliteError::CorruptState(format!(
                "seal snapshot for group {group_id} cannot be projected: {error}"
            ))
        })?;
    for (name, node) in projection.nodes() {
        match node {
            PhysicalNode::Entry(entry) if !holds(name, entry.version_hash) => {
                return Err(refused(match entry.placement {
                    Placement::ConflictCopy => SealRefusal::ConflictCopyNotDurable {
                        path: entry.source.clone(),
                        copy_path: name.clone(),
                    },
                    Placement::AtPath | Placement::Relocated => {
                        SealRefusal::WinnerNotMaterialized { path: entry.source.clone() }
                    }
                }));
            }
            PhysicalNode::Directory(DirectoryNode::Explicit { version_hash })
                if !holds(name, *version_hash) =>
            {
                return Err(refused(SealRefusal::WinnerNotMaterialized { path: name.clone() }));
            }
            PhysicalNode::Directory(DirectoryNode::Structural)
                if current_rows.contains_key(name.as_str()) =>
            {
                return Err(refused(SealRefusal::RowAtStructuralDirectory { path: name.clone() }));
            }
            _ => {}
        }
    }
    // A directory row is only ever an explicit directory's. One the
    // projection does not hold would be installed by a joiner as a
    // directory nobody holds, and kept there. (A file row the projection
    // does not place is a conflict copy that outlived the head it copied,
    // which stays a file of its own.)
    for (path, (_, kind)) in &current_rows {
        if *kind == RecordKind::Directory
            && !matches!(
                projection.get(path),
                Some(PhysicalNode::Directory(DirectoryNode::Explicit { .. }))
            )
        {
            return Err(refused(SealRefusal::DirectoryWithoutHead { path: (*path).to_owned() }));
        }
    }
    // The rows form a tree: nothing lives below a leaf. Every leaf the
    // projection places holds its row (checked above), so this also keeps
    // an unplaced row from sitting below a placed file, which a joiner's
    // install would resolve by relocating the file.
    for path in current_rows.keys() {
        let mut ancestor = *path;
        while let Some((parent, _)) = ancestor.rsplit_once('/') {
            ancestor = parent;
            if current_rows.get(ancestor).is_some_and(|(_, kind)| *kind != RecordKind::Directory) {
                return Err(refused(SealRefusal::RowBelowLeaf {
                    path: (*path).to_owned(),
                    leaf: ancestor.to_owned(),
                }));
            }
        }
    }
    Ok(())
}

/// `Q` recomputed from the signed changes the group retains and the
/// installed base's summary, without the author-chain rows or the live path
/// frontier the builder reads.
///
/// `W` is the positions [`author_positions`] derived. `L` is the base's
/// ceiling or the greatest retained Lamport. `Gamma` for a path is the
/// current epoch's maximal writes there, by DAG ancestry among the current
/// epoch's changes, together with every head the base carried there that
/// no change of the current epoch touching the path names among its
/// observed base heads. A change on the current epoch supersedes a base
/// head only by naming it; a path the current epoch did not touch keeps
/// all of the base's heads.
fn recompute_summary(history: &AbsorbedHistory) -> Result<GroupHistorySummary, SyncSqliteError> {
    let group_id = history.group_id.as_str();
    let retained: HashSet<ChangeHash> = history.changes.iter().map(|(hash, _)| *hash).collect();
    let current: HashMap<ChangeHash, &Change> = history
        .changes
        .iter()
        .filter(|(_, change)| change.history_epoch == history.epoch)
        .map(|(hash, change)| (*hash, change))
        .collect();

    let mut effects: BTreeMap<String, Vec<(ChangeHash, PathHead)>> = BTreeMap::new();
    let mut named: HashSet<(String, ChangeHash)> = HashSet::new();
    for (hash, change) in &current {
        for parent in &change.parents {
            if !retained.contains(parent) {
                return Err(refuse(group_id, SealRefusal::HistoryNotClosed { change: *hash }));
            }
        }
        for (path, head) in path_effects_of_change(change) {
            for observed in &change.observed_base_heads {
                named.insert((path.clone(), *observed));
            }
            effects.entry(path).or_default().push((*hash, head));
        }
    }

    let mut path_heads = Vec::new();
    for (path, writes) in &effects {
        let superseded = superseded_writes(&current, writes);
        for (hash, head) in writes {
            let Some(content) = &head.content else { continue };
            if superseded.contains(hash) {
                continue;
            }
            let change = current[hash];
            path_heads.push(SnapshotPathHead {
                path: path.clone(),
                change_hash: *hash,
                device_id: change.device_id.as_str().to_owned(),
                author_seq: change.author_seq,
                lamport: change.lamport,
                version_hash: VersionHash(content.version_hash),
                naming_device_id: head.naming_device_id.clone(),
            });
        }
    }
    if let Some(base) = &history.base {
        path_heads.extend(
            base.path_heads
                .iter()
                .filter(|head| !named.contains(&(head.path.clone(), head.change_hash)))
                .cloned(),
        );
    }

    let lamport_ceiling = history
        .changes
        .iter()
        .map(|(_, change)| change.lamport)
        .chain(history.base.as_ref().map(|base| base.lamport_ceiling))
        .max()
        .unwrap_or(0);
    let author_state = history
        .positions
        .iter()
        .map(|(device_id, (watermark, tip))| SnapshotAuthorState {
            device_id: device_id.clone(),
            watermark: *watermark,
            tip_change_hash: *tip,
        })
        .collect();
    Ok(GroupHistorySummary { author_state, path_heads, lamport_ceiling })
}

/// The writes among `writes` that another of them descends from, by DAG
/// ancestry among the current epoch's changes.
///
/// One walk down from every write, sharing what it has already visited, so
/// each change is visited at most once per path however many writes the
/// path has. An ancestor's Lamport is strictly lower than its
/// descendant's, so nothing below the lowest write is walked.
fn superseded_writes(
    current: &HashMap<ChangeHash, &Change>,
    writes: &[(ChangeHash, PathHead)],
) -> HashSet<ChangeHash> {
    let mut reached: HashSet<ChangeHash> = HashSet::new();
    if writes.len() < 2 {
        return reached;
    }
    let floor = writes.iter().filter_map(|(hash, _)| current.get(hash)).map(|c| c.lamport).min();
    let Some(floor) = floor else { return reached };
    let mut stack: Vec<ChangeHash> = Vec::new();
    for (hash, _) in writes {
        let Some(change) = current.get(hash) else { continue };
        stack.extend(change.parents.iter().copied());
        while let Some(ancestor) = stack.pop() {
            let Some(change) = current.get(&ancestor) else { continue };
            if !reached.insert(ancestor) {
                continue;
            }
            if change.lamport > floor {
                stack.extend(change.parents.iter().copied());
            }
        }
    }
    let written: HashSet<ChangeHash> = writes.iter().map(|(hash, _)| *hash).collect();
    reached.retain(|hash| written.contains(hash));
    reached
}

fn compare_summaries(
    group_id: &str,
    snapshot: &RebootstrapSnapshot,
    recomputed: &GroupHistorySummary,
) -> Result<(), SyncSqliteError> {
    let disagree =
        |detail: String| refuse(group_id, SealRefusal::SummaryDisagreesWithHistory { detail });
    let mut authors = recomputed.author_state.clone();
    authors.sort();
    if snapshot.author_state != authors {
        return Err(disagree(format!(
            "author positions {:?} are not the {:?} the retained history attains",
            snapshot.author_state, authors
        )));
    }
    let mut heads = recomputed.path_heads.clone();
    heads.sort();
    if snapshot.path_heads != heads {
        return Err(disagree(format!(
            "path heads {:?} are not the {:?} the retained history produces",
            snapshot.path_heads, heads
        )));
    }
    if snapshot.lamport_ceiling != recomputed.lamport_ceiling {
        return Err(disagree(format!(
            "Lamport ceiling {} is not the {} the retained history reached",
            snapshot.lamport_ceiling, recomputed.lamport_ceiling
        )));
    }
    Ok(())
}

fn first_hash(
    conn: &Connection,
    sql: &str,
    group_id: &str,
) -> Result<Option<ChangeHash>, SyncSqliteError> {
    let bytes: Option<Vec<u8>> = conn.query_row(sql, [group_id], |row| row.get(0)).optional()?;
    bytes.map(|bytes| Ok(ChangeHash(super::hash_32(&bytes, "change_hash")?))).transpose()
}

fn first_path(
    conn: &Connection,
    sql: &str,
    group_id: &str,
) -> Result<Option<String>, SyncSqliteError> {
    Ok(conn.query_row(sql, [group_id], |row| row.get(0)).optional()?)
}

#[cfg(test)]
mod summary_scale_tests;
