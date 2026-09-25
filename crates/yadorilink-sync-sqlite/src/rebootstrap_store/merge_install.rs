//! Committing the merge of two history bases.
//!
//! [`merge_foreign_base`](super::merge_foreign_base) decides, over two
//! verified sides, which base the joined summary stands on. This module
//! makes that decision this replica's history, in the caller's transaction:
//!
//! * the current side already holds the returning history: nothing
//!   changes;
//! * the returning side holds this replica's history: its base and its
//!   snapshot are installed as they are;
//! * each side holds history the other does not: the snapshot of the
//!   joined summary is built -- its rows are the namespace projection of
//!   the joined `Gamma` -- and installed under the freshly minted base.
//!
//! An install here is the same atomic epoch reset a seal commits: the base
//! and its summary are installed, every author is anchored on the base, and
//! the history the base replaces is retired, so the active history restarts
//! empty. Nothing of either side's history is re-authored: the base carries
//! every author's position, and the next change any author writes follows
//! it by one on the new epoch.
//!
//! # What each side contributes
//!
//! A merge consumes what each side's base carries and nothing else. This
//! replica's side is verified to have no history above its base (it must
//! be sealed first), and it is re-verified inside the transaction that
//! commits the merge, so a change admitted after the merge was planned
//! refuses the commit rather than being left behind. The returning side's
//! history above its own base is that replica's to seal: when it merges in
//! turn, its sealed base joins this one, and the base that join stands on
//! absorbs this one.
//!
//! # The rows of a minted base
//!
//! A path the joined summary places holds the placed version: the row
//! either side already had there with that version, or a new row for the
//! head that placed it. A path the join makes a structural directory holds
//! no live row. Any other live row is kept unless it materialized a head
//! of its own side -- an entry the side's own projection placed, or an
//! explicit directory -- that the join dropped: the other side has seen
//! what superseded it. A conflict copy that outlived its head is not a
//! head's materialization and stays, exactly as it does on the replica
//! that holds it. Every row a side held that is not the new current row is
//! kept as history, the second side's numbered after the first's.
//!
//! # One base, one snapshot
//!
//! A minted base's id covers the two bases it joins and the joined summary,
//! not the snapshot's bytes, so every replica that mints it must build the
//! same snapshot or two replicas would stand on one base holding different
//! rows, and nothing would notice. Nothing here therefore depends on which
//! side is this replica's: the two sides are taken in the order of their
//! bases, and a tie between them always goes to the first; a witness two
//! sides carry for one change is the least of them; and a row's evidence
//! comes only from what the two sides carry, never from this replica's own
//! store.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use rusqlite::{params, OptionalExtension};
use yadorilink_replica_domain::file::{BlockInfo, FileRecord, FileVersion, RecordKind};
use yadorilink_replica_domain::ids::{ChangeHash, VersionHash};
use yadorilink_replica_domain::rebootstrap::{Checkpoint, HistoryBase, MergedFrom};
use yadorilink_replica_engine::namespace::{
    DirectoryNode, NamespaceProjection, PhysicalNode, Placement,
};
use yadorilink_replica_engine::rebootstrap_snapshot::{
    PublishedChangeWitness, RebootstrapSnapshot, SnapshotFile, SnapshotPathHead,
    SnapshotVersionState,
};

use super::seal::EpochResetStep;
use super::{
    merge_foreign_base, verify_current_base, ForeignMergeError, ForeignMergeRefusal,
    GroupHistorySummary, MergedBase, SummaryMerge, SummaryOrder, VerifiedBaseSummary,
};
use crate::SyncSqliteError;

/// A merge committed in the caller's transaction.
#[derive(Clone, Debug, PartialEq)]
pub struct CommittedMerge {
    pub order: SummaryOrder,
    pub base: MergedBase,
    /// The checkpoint now installed, or `None` when this replica kept its
    /// own base.
    pub installed: Option<Checkpoint>,
}

/// Merges `returning` into this replica's history for its group, in the
/// caller's transaction: this replica's side is verified here, the two
/// sides are merged, and the base the join stands on is installed with the
/// atomic epoch reset.
///
/// Refused, with nothing written, whenever the merge itself is refused --
/// no base installed here, history above it, equivocation, a join whose
/// rows are not an installable base, a row whose authorization evidence
/// neither side carries.
pub fn commit_foreign_merge(
    tx: &rusqlite::Transaction<'_>,
    returning: &VerifiedBaseSummary,
) -> Result<CommittedMerge, ForeignMergeError> {
    commit_foreign_merge_until(tx, returning, None)
}

/// [`commit_foreign_merge`], stopped with an error right after `step` of
/// the install, as a crash there would stop it. The caller's transaction
/// then never commits.
#[cfg(any(test, feature = "test-support"))]
pub fn commit_foreign_merge_interrupted_after(
    tx: &rusqlite::Transaction<'_>,
    returning: &VerifiedBaseSummary,
    step: EpochResetStep,
) -> Result<CommittedMerge, ForeignMergeError> {
    commit_foreign_merge_until(tx, returning, Some(step))
}

fn commit_foreign_merge_until(
    tx: &rusqlite::Transaction<'_>,
    returning: &VerifiedBaseSummary,
    interrupt_after: Option<EpochResetStep>,
) -> Result<CommittedMerge, ForeignMergeError> {
    // A merge moves the group onto a base no peer on either side stands on
    // yet, so it stays off with the rest of history compaction.
    #[cfg(not(any(test, feature = "test-support")))]
    super::seal::require_compaction_ready(
        yadorilink_replica_engine::rebootstrap::COMPACTION_SCHEDULING_READY,
    )?;
    let group_id = returning.group_id().as_str().to_owned();
    let current = verify_current_base(tx, &group_id)?;
    let merge = merge_foreign_base(&current, returning)?;
    let installed = match merge.base {
        MergedBase::Current(_) => None,
        MergedBase::Returning(_) => {
            install_base_by_reset(
                tx,
                returning.checkpoint(),
                returning.snapshot(),
                interrupt_after,
            )?;
            Some(returning.checkpoint().clone())
        }
        MergedBase::Minted(minted) => {
            let (checkpoint, snapshot) =
                build_merged_snapshot(&current, returning, &merge, minted)?;
            install_base_by_reset(tx, &checkpoint, &snapshot, interrupt_after)?;
            Some(checkpoint)
        }
    };
    Ok(CommittedMerge { order: merge.order, base: merge.base, installed })
}

/// Test fixtures only: [`install_base_by_reset`] with no merge deciding
/// it and nothing verified -- not the manifest, not the signer, not the
/// witnesses the base carries -- so a test can put any base under the rows
/// it wants to reconcile. Production reaches the install only through
/// [`commit_foreign_merge`], over a returning side that was verified first.
#[cfg(any(test, feature = "test-support"))]
pub fn install_base_for_tests(
    tx: &rusqlite::Transaction<'_>,
    checkpoint: &Checkpoint,
    snapshot: &RebootstrapSnapshot,
) -> Result<(), ForeignMergeError> {
    install_base_by_reset(tx, checkpoint, snapshot, None)
}

/// Installs `checkpoint`'s base over this replica's history with the
/// atomic epoch reset a seal commits: the checkpoint and the snapshot are
/// recorded, every author is advanced to the position the base carries
/// and anchored on it, the rows are replaced by the base's, and the whole
/// retained history is retired. Afterwards the group retains no change,
/// and every row the base carries is served on the strength of the
/// witness it carries -- no frontier body stays behind to vouch for one.
///
/// Refused, before anything is written, when the base carries no author
/// positions while claiming heads or a non-zero Lamport ceiling, when it
/// does not carry every author this replica holds at least as far as it
/// holds it, or when it carries a row with no witness.
fn install_base_by_reset(
    tx: &rusqlite::Transaction<'_>,
    checkpoint: &Checkpoint,
    snapshot: &RebootstrapSnapshot,
    interrupt_after: Option<EpochResetStep>,
) -> Result<(), ForeignMergeError> {
    let group_id = checkpoint.group_id.as_str();
    let reached = |step: EpochResetStep| -> Result<(), SyncSqliteError> {
        if interrupt_after == Some(step) {
            return Err(SyncSqliteError::Io(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                format!("the base install of group {group_id} was interrupted after {step:?}"),
            )));
        }
        Ok(())
    };
    snapshot.validate_against_checkpoint(checkpoint).map_err(SyncSqliteError::from)?;
    super::init_rebootstrap_schema(tx)?;
    let base = HistoryBase::from_checkpoint(checkpoint);

    // A base that cannot say where its own authors stand is not
    // installable. The one authorless base that is genuine was sealed over
    // an empty history: no heads and a ceiling of zero. Anything else is
    // the shape `history_base_summary` reads back as damage.
    if snapshot.author_state.is_empty()
        && !(snapshot.path_heads.is_empty() && snapshot.lamport_ceiling == 0)
    {
        return Err(ForeignMergeRefusal::SnapshotInvalid {
            detail: format!(
                "the base carries {} path head(s) and a Lamport ceiling of {} but no author \
                 positions",
                snapshot.path_heads.len(),
                snapshot.lamport_ceiling
            ),
        }
        .into());
    }
    let local = crate::dag_store::author_chain::all_author_state(tx, group_id)?;
    super::require_base_carries_local_authors(group_id, &snapshot.author_state, &local)?;
    let witnessed: HashSet<ChangeHash> =
        snapshot.published_change_witnesses.iter().map(|witness| witness.change_hash).collect();
    for file in &snapshot.files {
        if let Some(change) = file.authoring_change_hash.filter(|hash| !witnessed.contains(hash)) {
            return Err(ForeignMergeRefusal::EvidenceNotCarried {
                path: file.record.path.clone(),
                change,
            }
            .into());
        }
    }
    let absorbed = super::seal::retained_change_hashes(tx, group_id)?;
    let previous_checkpoint_hash: Option<[u8; 32]> = tx
        .query_row(
            "SELECT checkpoint_hash FROM group_history_bases WHERE group_id = ?1",
            [group_id],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?
        .map(|bytes| super::hash_32(&bytes, "group_history_bases.checkpoint_hash"))
        .transpose()?;

    // 1. The checkpoint and the snapshot carrying the summary.
    tx.execute(
        "INSERT OR REPLACE INTO change_checkpoint_snapshots \
         (checkpoint_hash, group_id, snapshot) VALUES (?1, ?2, ?3)",
        params![&checkpoint.checkpoint_hash().0[..], group_id, snapshot.canonical_encoding()],
    )?;
    super::record_checkpoint(tx, checkpoint)?;
    reached(EpochResetStep::SummaryRecorded)?;

    // 2. The switch: every author at the position the base carries, which
    // is never behind where this replica holds it, and anchored on it.
    for author in &snapshot.author_state {
        crate::dag_store::author_chain::advance_author_state(
            tx,
            group_id,
            &author.device_id,
            author.watermark,
            &author.tip_change_hash,
        )?;
    }
    super::persist_history_base(tx, checkpoint, snapshot, previous_checkpoint_hash)?;
    reached(EpochResetStep::BaseSwitched)?;

    // 3. The rows, the retirement of everything the base replaces, and the
    // evidence behind every row it carries.
    super::install_base_rows(tx, group_id, snapshot)?;
    super::retire_absorbed_history(tx, group_id, &base, &absorbed, snapshot)?;
    tx.execute("DELETE FROM pruned_published_change_versions WHERE group_id = ?1", [group_id])?;
    super::install_row_witnesses(tx, group_id, snapshot)?;
    crate::authorization_witness_gc::collect_authorization_witnesses(tx, group_id)?;
    reached(EpochResetStep::HistoryRetired)?;

    for author in crate::dag_store::author_chain::all_author_state(tx, group_id)? {
        let anchored_on =
            crate::dag_store::author_chain::author_chain_state(tx, group_id, &author.device_id)?
                .and_then(|state| state.anchored_on);
        if anchored_on != Some(base) {
            return Err(SyncSqliteError::CorruptState(format!(
                "installing base {} of group {group_id} left author {} anchored on {:?}",
                base.to_hex(),
                author.device_id,
                anchored_on
            ))
            .into());
        }
    }
    if !super::seal::retained_change_hashes(tx, group_id)?.is_empty() {
        return Err(SyncSqliteError::CorruptState(format!(
            "installing base {} of group {group_id} left changes retained beside it",
            base.to_hex()
        ))
        .into());
    }
    Ok(())
}

/// The snapshot of `merge`'s joined summary and the merged checkpoint that
/// commits to it, whose base is `minted`.
///
/// The rows are the namespace projection of the joined `Gamma` (see the
/// module documentation), checked with the same comparison a seal checks
/// its own rows with. Every row's authorization evidence travels as a
/// witness one of the two sides carries; the snapshot carries no frontier
/// changes. The result is the same whichever side is this replica's.
fn build_merged_snapshot(
    current: &VerifiedBaseSummary,
    returning: &VerifiedBaseSummary,
    merge: &SummaryMerge,
    minted: HistoryBase,
) -> Result<(Checkpoint, RebootstrapSnapshot), ForeignMergeError> {
    let group_id = current.group_id().clone();
    // The sides in the order of their bases, not by which one is local.
    let (first, second) = if current.history_base() <= returning.history_base() {
        (current, returning)
    } else {
        (returning, current)
    };
    let corrupt = |detail: String| {
        ForeignMergeError::Store(SyncSqliteError::CorruptState(format!(
            "cannot build the merged base of group {}: {detail}",
            group_id.as_str()
        )))
    };

    let mut versions: BTreeMap<VersionHash, FileVersion> = BTreeMap::new();
    for side in [first, second] {
        for encoded in &side.snapshot().file_versions {
            let version = FileVersion::from_canonical_encoding(encoded)
                .map_err(|error| corrupt(format!("a carried version does not decode: {error}")))?;
            versions.insert(version.version_hash, version);
        }
    }
    let kind_of = |hash: &[u8; 32]| versions.get(&VersionHash(*hash)).map(|v| v.meta.record_kind);
    let project = |summary: &GroupHistorySummary| {
        summary.project(kind_of).map_err(|error| corrupt(format!("{error}")))
    };
    let joined = project(&merge.summary)?;
    let own_first = project(first.summary())?;
    let own_second = project(second.summary())?;

    // A witness two sides carry for one change is the least of the two.
    let mut witnesses: BTreeMap<ChangeHash, PublishedChangeWitness> = BTreeMap::new();
    for side in [first, second] {
        for witness in &side.snapshot().published_change_witnesses {
            match witnesses.get(&witness.change_hash) {
                Some(held) if held <= witness => {}
                _ => {
                    witnesses.insert(witness.change_hash, witness.clone());
                }
            }
        }
    }

    let mut heads_at: HashMap<(&str, VersionHash), Vec<&SnapshotPathHead>> = HashMap::new();
    for head in &merge.summary.path_heads {
        heads_at.entry((head.path.as_str(), head.version_hash)).or_default().push(head);
    }
    // What the joined projection places at each name, and the heads that
    // could have written it there.
    let mut placed: BTreeMap<&str, (VersionHash, Vec<&SnapshotPathHead>)> = BTreeMap::new();
    let mut structural: BTreeSet<&str> = BTreeSet::new();
    for (name, node) in joined.nodes() {
        let (source, version) = match node {
            PhysicalNode::Entry(entry) => (entry.source.as_str(), VersionHash(entry.version_hash)),
            PhysicalNode::Directory(DirectoryNode::Explicit { version_hash }) => {
                (name.as_str(), VersionHash(*version_hash))
            }
            PhysicalNode::Directory(DirectoryNode::Structural) => {
                structural.insert(name.as_str());
                continue;
            }
        };
        let mut heads = heads_at.get(&(source, version)).cloned().unwrap_or_default();
        if heads.is_empty() {
            return Err(corrupt(format!("{name} is placed by no head")));
        }
        // A fresh row is written by the first head whose evidence a side
        // carries, if any does.
        heads.sort_by_key(|head| (!witnesses.contains_key(&head.change_hash), head.change_hash));
        placed.insert(name.as_str(), (version, heads));
    }

    let rows_of = |snapshot: &'_ RebootstrapSnapshot| {
        let mut rows: BTreeMap<String, Vec<SnapshotFile>> = BTreeMap::new();
        for file in &snapshot.files {
            rows.entry(file.record.path.clone()).or_default().push(file.clone());
        }
        rows
    };
    let first_rows = rows_of(first.snapshot());
    let second_rows = rows_of(second.snapshot());
    let paths: BTreeSet<&str> = placed
        .keys()
        .copied()
        .chain(first_rows.keys().map(String::as_str))
        .chain(second_rows.keys().map(String::as_str))
        .collect();

    let mut files = Vec::new();
    for path in paths {
        let in_first = first_rows.get(path).map(Vec::as_slice).unwrap_or_default();
        let in_second = second_rows.get(path).map(Vec::as_slice).unwrap_or_default();
        let chosen = choose_current(
            path,
            placed.get(path),
            structural.contains(path),
            (in_first, &own_first),
            (in_second, &own_second),
            &versions,
        );
        files.extend(merge_path_rows(in_first, in_second, chosen));
    }

    let mut carried_witnesses: BTreeMap<ChangeHash, PublishedChangeWitness> = BTreeMap::new();
    for file in &files {
        let Some(change) = file.authoring_change_hash else { continue };
        if carried_witnesses.contains_key(&change) {
            continue;
        }
        let witness = witnesses.get(&change).ok_or_else(|| {
            ForeignMergeRefusal::EvidenceNotCarried { path: file.record.path.clone(), change }
        })?;
        carried_witnesses.insert(change, witness.clone());
    }

    let mut file_versions: BTreeMap<VersionHash, Vec<u8>> = BTreeMap::new();
    for file in &files {
        let version = row_version(file);
        file_versions.insert(version.version_hash, version.canonical_encoding());
    }
    for head in &merge.summary.path_heads {
        let version = versions.get(&head.version_hash).ok_or_else(|| {
            ForeignMergeRefusal::ContentNotCarried {
                path: head.path.clone(),
                version: head.version_hash,
            }
        })?;
        file_versions.insert(head.version_hash, version.canonical_encoding());
    }

    let snapshot = RebootstrapSnapshot::new(
        group_id.clone(),
        files,
        Vec::new(),
        file_versions.into_values().collect(),
        carried_witnesses.into_values().collect(),
        Vec::new(),
        merge.summary.author_state.clone(),
        merge.summary.path_heads.clone(),
        merge.summary.lamport_ceiling,
    )
    .map_err(SyncSqliteError::from)?;
    let identity = crate::base_advertisement::summary_identity(&merge.summary);
    if snapshot.summary_identity() != identity {
        return Err(corrupt("the snapshot does not carry the joined summary".into()));
    }
    super::seal::check_namespace(group_id.as_str(), &snapshot).map_err(|error| match error {
        SyncSqliteError::SealRefused { refusal, .. } => {
            ForeignMergeError::Refused(ForeignMergeRefusal::MergedSnapshotRefused(refusal))
        }
        other => ForeignMergeError::Store(other),
    })?;
    let merged_from = MergedFrom::new(current.history_base(), returning.history_base(), identity)
        .map_err(|error| corrupt(error.to_string()))?;
    let checkpoint =
        Checkpoint::new_merged(group_id.clone(), Vec::new(), snapshot.snapshot_hash(), merged_from);
    if HistoryBase::from_checkpoint(&checkpoint) != minted {
        return Err(corrupt("the merged checkpoint does not derive the minted base".into()));
    }
    Ok((checkpoint, snapshot))
}

/// The row that is current at `path` in the merged base.
enum Chosen {
    /// The first side's current row, as it is.
    First,
    /// The second side's current row, as it is.
    Second,
    /// A row neither side holds: a head the join places where neither
    /// side had placed its version.
    Fresh(SnapshotFile),
    /// No current row: the join places nothing here and nothing survives.
    None,
}

fn choose_current(
    path: &str,
    placed: Option<&(VersionHash, Vec<&SnapshotPathHead>)>,
    structural: bool,
    (first, own_first): (&[SnapshotFile], &NamespaceProjection),
    (second, own_second): (&[SnapshotFile], &NamespaceProjection),
    versions: &BTreeMap<VersionHash, FileVersion>,
) -> Chosen {
    let current = |rows: &[SnapshotFile]| {
        rows.iter().find(|row| row.state == SnapshotVersionState::Current).cloned()
    };
    let (first_current, second_current) = (current(first), current(second));
    if let Some((version, heads)) = placed {
        let holds = |row: &Option<SnapshotFile>| {
            row.as_ref()
                .is_some_and(|row| !row.record.deleted && row_version(row).version_hash == *version)
        };
        if holds(&first_current) {
            return Chosen::First;
        }
        if holds(&second_current) {
            return Chosen::Second;
        }
        let head = heads[0];
        return Chosen::Fresh(fresh_row(path, &versions[version], head));
    }
    if structural {
        return Chosen::None;
    }
    // A live row the join does not place survives unless it materialized
    // a head of its own side, which the join dropped.
    let survives = |row: &Option<SnapshotFile>, own: &NamespaceProjection| {
        row.as_ref().is_some_and(|row| {
            !row.record.deleted
                && !matches!(
                    own.get(path),
                    Some(PhysicalNode::Entry(entry)) if entry.placement != Placement::ConflictCopy
                )
                && !matches!(
                    own.get(path),
                    Some(PhysicalNode::Directory(DirectoryNode::Explicit { .. }))
                )
        })
    };
    if survives(&first_current, own_first) {
        return Chosen::First;
    }
    if survives(&second_current, own_second) {
        return Chosen::Second;
    }
    let tombstone = |row: &Option<SnapshotFile>| row.as_ref().is_some_and(|row| row.record.deleted);
    if tombstone(&first_current) {
        return Chosen::First;
    }
    if tombstone(&second_current) {
        return Chosen::Second;
    }
    Chosen::None
}

/// Every row of one path in the merged base: the first side's rows at
/// their own sequence numbers, the second side's rows the first does not
/// hold numbered after them, and the chosen current row last. Every row
/// that was current on either side and is not the chosen one is history.
fn merge_path_rows(
    first: &[SnapshotFile],
    second: &[SnapshotFile],
    chosen: Chosen,
) -> Vec<SnapshotFile> {
    // Numbered from the first side that holds the path; the other side's
    // rows follow it.
    let (primary, secondary, chosen_primary, chosen_secondary) = match (&chosen, first.is_empty()) {
        (Chosen::Second, true) => (second, first, true, false),
        (Chosen::Second, false) => (first, second, false, true),
        (Chosen::First, _) => (first, second, true, false),
        (_, true) => (second, first, false, false),
        (_, false) => (first, second, false, false),
    };
    let identity = |row: &SnapshotFile| {
        (row_version(row).version_hash, row.record.deleted, row.authoring_change_hash)
    };
    let as_history = |row: &SnapshotFile| {
        let mut row = row.clone();
        if row.state == SnapshotVersionState::Current {
            row.state = SnapshotVersionState::Superseded;
        }
        row
    };

    let mut out = Vec::new();
    let mut held = HashSet::new();
    let mut next_seq = primary.iter().map(|row| row.version_seq).max().unwrap_or(0) + 1;
    let mut chosen_row = None;
    for row in primary {
        held.insert(identity(row));
        if chosen_primary && row.state == SnapshotVersionState::Current {
            chosen_row = Some(row.clone());
        } else {
            out.push(as_history(row));
        }
    }
    let mut secondary: Vec<&SnapshotFile> = secondary.iter().collect();
    secondary.sort_by_key(|row| row.version_seq);
    let mut appended = false;
    for row in secondary {
        if chosen_secondary && row.state == SnapshotVersionState::Current {
            chosen_row = Some(row.clone());
            continue;
        }
        if !held.insert(identity(row)) {
            continue;
        }
        let mut row = as_history(row);
        row.version_seq = next_seq;
        next_seq += 1;
        appended = true;
        out.push(row);
    }
    if let Chosen::Fresh(row) = chosen {
        chosen_row = Some(row);
    }
    // The current row is the path's latest: a reader that meets several
    // rows of one path installed at one instant takes the highest number
    // as the current one. The numbering side's current row keeps its
    // number unless the other side's history now follows it.
    if let Some(mut row) = chosen_row {
        if !(chosen_primary && !appended) {
            row.version_seq = next_seq;
        }
        row.state = SnapshotVersionState::Current;
        out.push(row);
    }
    out
}

/// A current row holding `version` at `path`, written by `head`.
fn fresh_row(path: &str, version: &FileVersion, head: &SnapshotPathHead) -> SnapshotFile {
    let mut offset = 0u64;
    let blocks = version
        .blocks
        .iter()
        .map(|block| {
            let info = BlockInfo { hash: block.hash.0.clone(), offset, size: block.size };
            offset += u64::from(block.size);
            info
        })
        .collect();
    let (size, mtime_unix_nanos) = match version.meta.record_kind {
        RecordKind::Directory => (0, 0),
        _ => (version.size, version.meta.mtime_unix_nanos),
    };
    SnapshotFile {
        record: FileRecord {
            path: path.to_owned(),
            size,
            mtime_unix_nanos,
            blocks,
            deleted: false,
        },
        version_seq: 0,
        state: SnapshotVersionState::Current,
        origin_device_id: Some(head.device_id.clone()),
        record_kind: version.meta.record_kind,
        symlink_target: version.meta.symlink_target.clone(),
        symlink_out_of_root: false,
        unix_mode: version.meta.unix_mode,
        xattrs: version.meta.xattrs.clone(),
        authoring_change_hash: Some(head.change_hash),
    }
}

fn row_version(file: &SnapshotFile) -> FileVersion {
    FileVersion::from_index_row(
        file.record.blocks.clone(),
        file.record.size,
        file.record.mtime_unix_nanos,
        file.record_kind,
        file.unix_mode,
        file.symlink_target.clone(),
        file.xattrs.clone(),
    )
}
