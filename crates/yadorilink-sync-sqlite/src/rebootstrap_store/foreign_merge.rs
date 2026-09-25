//! Merging a history that was written on another base.
//!
//! Two devices that sealed independently stand on two different bases, and
//! a change written above one of them is inadmissible above the other. What
//! brings them together is not a replay of either side's changes but the
//! join of the two bases' causal summaries `Q = (W, L, Gamma)`: `W` by
//! maximum, `L` by maximum, and each path's heads by union minus whatever
//! the other side's watermark already covers.
//!
//! This module is the pure core of that merge, and nothing in it writes:
//!
//! 1. [`verify_current_base`] (or [`VerifiedBaseSummary::from_seal`]) checks
//!    this replica's side: the installed base re-derived from its retained
//!    checkpoint and snapshot, the stored summary equal to the one the
//!    snapshot carries, and no history written above the base that the
//!    summary would leave out.
//! 2. [`verify_returning_base`] checks the other side: a signed manifest,
//!    a signer the group's authority lets found a base
//!    ([`BaseSignerAuthority`]), snapshot bytes that hash to its checkpoint,
//!    a summary that is internally consistent and whose every head's
//!    content travels with it, and rows that are the namespace projection
//!    of that summary's `Gamma` -- the same comparison a seal checks its
//!    own rows with, since the base id covers the summary and a merged
//!    one does not cover the rows at all.
//! 3. [`find_equivocation`] refuses two different changes at one author
//!    position.
//! 4. [`GroupHistorySummary::join`] computes the joined summary.
//! 5. [`merge_foreign_base`] runs 3 and 4 over two verified sides and
//!    decides which base the joined summary stands on: the side that already
//!    holds the other's whole history keeps its base, equal summaries settle
//!    on one of the two bases deterministically, and only a join that
//!    differs from both sides gets a freshly minted base
//!    ([`HistoryBase::mint_merged`]). It is the only way production reaches
//!    that decision; the same decision over bare, unverified summaries
//!    (`plan_summary_merge`) exists for tests alone.
//!
//! Building the snapshot a minted base carries, installing it and
//! restarting the active history above it are in `merge_install`
//! ([`commit_foreign_merge`](super::commit_foreign_merge)).
//!
//! # What the equivocation check can see
//!
//! A summary remembers which change sat at an author position only while
//! that change is some path's content head, or is the author's tip. Below
//! that it keeps a watermark, which by design has forgotten the changes it
//! covers. Two different changes at one position are therefore caught here
//! only while each is still a head or a tip on its side; once one of them
//! has been superseded, or both lie below both watermarks, the join keeps
//! one side without noticing. The merge is sound only for authors that never
//! sign two changes at one position, and that is enforced where it can be
//! enforced completely: admission refuses a second change at a known
//! position, and nothing re-signs an existing change under a new base. This
//! check is the last line, not the guarantee.
//!
//! A change's hash covers the base it was written on, so the same change
//! re-signed under another base is a different hash at the same position
//! and is refused like any other pair.

use std::collections::BTreeMap;

use rusqlite::Connection;
use yadorilink_replica_domain::base_negotiation::{AdvertisedBase, SummaryIdentity};
use yadorilink_replica_domain::change::Change;
use yadorilink_replica_domain::file::FileVersion;
use yadorilink_replica_domain::ids::{AuthorSeq, ChangeHash, FolderGroupId, VersionHash};
use yadorilink_replica_domain::rebootstrap::{
    Checkpoint, HistoryBase, RebootstrapTrust, SnapshotManifest,
};
use yadorilink_replica_engine::rebootstrap_snapshot::RebootstrapSnapshot;

use super::{GroupHistorySummary, VerifiedSeal};
use crate::base_advertisement::summary_identity;
use crate::SyncSqliteError;

/// Two different changes at one author position.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SummaryEquivocation {
    pub device_id: String,
    pub author_seq: AuthorSeq,
    pub held: ChangeHash,
    pub incoming: ChangeHash,
}

impl std::fmt::Display for SummaryEquivocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "author {} holds two changes at position {} ({} and {})",
            self.device_id,
            self.author_seq,
            self.held.to_hex(),
            self.incoming.to_hex()
        )
    }
}

/// Why a merge of two bases was refused before it produced anything.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ForeignMergeRefusal {
    /// This replica has no base installed, so there is no verified summary
    /// of its side to merge; its history has to be sealed first.
    #[error("no history base is installed for this group")]
    NoBaseInstalled,
    /// This replica has history above its installed base, which the base's
    /// summary does not describe; merging the base alone would leave that
    /// history out, so it has to be sealed first.
    #[error("history has been written above the installed base")]
    HistoryAboveBase,
    /// The two sides are histories of different groups.
    #[error("the two sides belong to different groups ({current} and {returning})")]
    GroupMismatch { current: String, returning: String },
    /// The returning side's manifest does not verify.
    #[error("the manifest does not verify: {detail}")]
    ManifestInvalid { detail: String },
    /// The returning side's manifest verifies, but its signer may not found
    /// a base for this group: not a writer under the group's policy, signing
    /// with a key the policy did not bind to it, or not a full replica.
    #[error("{signer} may not found a base for this group")]
    SignerNotAuthorized { signer: String },
    /// The returning side's snapshot is not the one its manifest commits to,
    /// or is not well formed.
    #[error("the snapshot does not verify: {detail}")]
    SnapshotInvalid { detail: String },
    /// The returning side's rows are not the namespace projection of its
    /// own summary's `Gamma`, so adopting it -- or joining it -- would
    /// install rows the summary every author is anchored on contradicts.
    #[error("the snapshot's rows are not its summary's projection: {0}")]
    SnapshotNotProjection(super::SealRefusal),
    /// A head whose content the snapshot does not carry, so a merged base
    /// could name content no replica can reproduce from it.
    #[error("{path} has a head at version {} the snapshot does not carry", hex::encode(.version.0))]
    ContentNotCarried { path: String, version: VersionHash },
    /// Two different changes at one author position, on one side or across
    /// the two.
    #[error("equivocation: {0}")]
    Equivocation(SummaryEquivocation),
    /// The two summaries have no join.
    #[error("the summaries do not join: {detail}")]
    JoinRefused { detail: String },
    /// The rows of the joined summary are not a base a seal could carry:
    /// the namespace projection of the joined `Gamma` does not fit the
    /// rows the two sides hold (see `SealRefusal`).
    #[error("the joined summary's rows are not an installable base: {0}")]
    MergedSnapshotRefused(super::SealRefusal),
    /// A row the base would carry whose authorization evidence neither
    /// side carries, so this replica could hold its content and never
    /// serve it.
    #[error("{path} is authored by {} and no side carries its evidence", .change.to_hex())]
    EvidenceNotCarried { path: String, change: ChangeHash },
}

/// A merge refused, or a store that could not be read.
#[derive(Debug, thiserror::Error)]
pub enum ForeignMergeError {
    #[error(transparent)]
    Refused(#[from] ForeignMergeRefusal),
    #[error(transparent)]
    Store(#[from] SyncSqliteError),
}

impl From<rusqlite::Error> for ForeignMergeError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Store(error.into())
    }
}

impl From<r2d2::Error> for ForeignMergeError {
    fn from(error: r2d2::Error) -> Self {
        Self::Store(error.into())
    }
}

impl yadorilink_sqlite_runtime::SqlOperationError for ForeignMergeError {
    fn is_locked(&self) -> bool {
        match self {
            Self::Store(error) => error.is_locked(),
            Self::Refused(_) => false,
        }
    }
}

/// One side of a merge: a base, the snapshot it derives from, and the
/// summary that snapshot carries, all checked against each other.
///
/// Only the verifying constructors make one.
#[derive(Clone, Debug)]
pub struct VerifiedBaseSummary {
    base: HistoryBase,
    checkpoint: Checkpoint,
    snapshot: RebootstrapSnapshot,
    summary: GroupHistorySummary,
    /// Every author position this side names a change for: tips, heads and
    /// the checkpoint's frontier changes.
    positions: BTreeMap<(String, AuthorSeq), ChangeHash>,
}

impl VerifiedBaseSummary {
    /// This replica's own side, from a seal it has prepared but not
    /// necessarily committed. The seal's preconditions are the verification.
    pub fn from_seal(seal: &VerifiedSeal) -> Result<Self, ForeignMergeRefusal> {
        Self::from_parts(seal.checkpoint().clone(), seal.snapshot().clone())
    }

    fn from_parts(
        checkpoint: Checkpoint,
        snapshot: RebootstrapSnapshot,
    ) -> Result<Self, ForeignMergeRefusal> {
        let summary = GroupHistorySummary {
            author_state: snapshot.author_state.clone(),
            path_heads: snapshot.path_heads.clone(),
            lamport_ceiling: snapshot.lamport_ceiling,
        };

        let mut positions =
            summary_positions(&summary).map_err(ForeignMergeRefusal::Equivocation)?;
        for encoded in &snapshot.frontier_changes {
            let change = Change::from_wire_bytes(encoded).map_err(|error| {
                ForeignMergeRefusal::SnapshotInvalid {
                    detail: format!("a frontier change does not decode: {error}"),
                }
            })?;
            attest(
                &mut positions,
                change.device_id.as_str(),
                change.author_seq,
                change.compute_hash(),
            )?;
        }

        let mut carried = std::collections::BTreeSet::new();
        for encoded in &snapshot.file_versions {
            let version = FileVersion::from_canonical_encoding(encoded).map_err(|error| {
                ForeignMergeRefusal::SnapshotInvalid {
                    detail: format!("a file version does not decode: {error}"),
                }
            })?;
            carried.insert(version.version_hash);
        }
        if let Some(head) =
            summary.path_heads.iter().find(|head| !carried.contains(&head.version_hash))
        {
            return Err(ForeignMergeRefusal::ContentNotCarried {
                path: head.path.clone(),
                version: head.version_hash,
            });
        }

        Ok(Self {
            base: HistoryBase::from_checkpoint(&checkpoint),
            checkpoint,
            snapshot,
            summary,
            positions,
        })
    }

    pub fn group_id(&self) -> &FolderGroupId {
        &self.checkpoint.group_id
    }

    pub fn history_base(&self) -> HistoryBase {
        self.base
    }

    pub fn checkpoint(&self) -> &Checkpoint {
        &self.checkpoint
    }

    pub fn snapshot(&self) -> &RebootstrapSnapshot {
        &self.snapshot
    }

    pub fn summary(&self) -> &GroupHistorySummary {
        &self.summary
    }

    pub fn summary_identity(&self) -> SummaryIdentity {
        summary_identity(&self.summary)
    }

    /// Whether this is the base a peer advertised: the same checkpoint and
    /// the same summary. An advertisement is only a claim; this is how a
    /// claim is tied to what was actually fetched and verified.
    pub fn matches_advertisement(&self, advertised: &AdvertisedBase) -> bool {
        match advertised {
            AdvertisedBase::Genesis => false,
            AdvertisedBase::Installed { checkpoint, summary } => {
                **checkpoint == self.checkpoint && *summary == self.summary_identity()
            }
        }
    }
}

/// This replica's side of a merge: the installed base, re-verified from
/// what the store retains.
///
/// The checkpoint must derive the installed base, the retained snapshot must
/// hash to the checkpoint, and the summary the store keeps for the base must
/// be the one the snapshot carries; any disagreement is damage and is
/// reported as such. History written above the base is refused rather than
/// merged around: the base's summary does not describe it, so it must be
/// sealed into a base of its own first.
pub fn verify_current_base(
    conn: &Connection,
    group_id: &str,
) -> Result<VerifiedBaseSummary, ForeignMergeError> {
    let Some(base) = super::history_base(conn, group_id)? else {
        return Err(ForeignMergeRefusal::NoBaseInstalled.into());
    };
    let checkpoint = crate::base_advertisement::installed_checkpoint(conn, group_id, base)?;
    let bytes =
        super::checkpoint_snapshot(conn, &checkpoint.checkpoint_hash())?.ok_or_else(|| {
            SyncSqliteError::CorruptState(format!(
                "group {group_id}'s installed base has no retained snapshot"
            ))
        })?;
    let snapshot = RebootstrapSnapshot::decode(&bytes).map_err(SyncSqliteError::from)?;
    snapshot.validate_against_checkpoint(&checkpoint).map_err(SyncSqliteError::from)?;

    let stored = super::history_base_summary(conn, group_id)?.ok_or_else(|| {
        SyncSqliteError::CorruptState(format!(
            "group {group_id} has an installed base with no summary"
        ))
    })?;
    let side = VerifiedBaseSummary::from_parts(checkpoint, snapshot)?;
    if summary_identity(&stored) != side.summary_identity() {
        return Err(SyncSqliteError::CorruptState(format!(
            "the summary stored for group {group_id}'s installed base is not the one its \
             snapshot carries"
        ))
        .into());
    }
    let whole = super::build_group_history_summary(conn, group_id)?;
    if summary_identity(&whole) != side.summary_identity() {
        return Err(ForeignMergeRefusal::HistoryAboveBase.into());
    }
    Ok(side)
}

/// Whether a signer may found a base for a group.
///
/// A valid signature proves only that the pinned key produced the manifest.
/// A base replaces the group's whole retained history, so its signer must
/// also be one the group's authority accepts for that: a writer under the
/// group's signed policy, signing with the exact key the policy bound to it,
/// and a full replica of the group. [`RebootstrapTrust`] resolves a key by
/// device alone and has no group to check any of that against, so this is
/// a separate, required gate.
///
/// `signing_key` is the key the manifest's signature was verified under.
pub trait BaseSignerAuthority {
    fn may_found_base(
        &self,
        group_id: &str,
        signer_device_id: &str,
        signing_key: &[u8; 32],
    ) -> bool;
}

impl<F> BaseSignerAuthority for F
where
    F: Fn(&str, &str, &[u8; 32]) -> bool,
{
    fn may_found_base(
        &self,
        group_id: &str,
        signer_device_id: &str,
        signing_key: &[u8; 32],
    ) -> bool {
        self(group_id, signer_device_id, signing_key)
    }
}

/// The other side of a merge: a base a peer signed, checked before anything
/// of it is believed.
///
/// The manifest must verify under the signer's pinned key and derive its base
/// from its checkpoint, the signer must be one `authority` lets found a base
/// for this group, the snapshot bytes must be canonical and hash to that
/// checkpoint, the summary they carry must be internally consistent and
/// carry every head's content, and the rows must be the namespace
/// projection of the summary's `Gamma`.
pub fn verify_returning_base<T, A>(
    group_id: &str,
    manifest: &SnapshotManifest,
    snapshot_bytes: &[u8],
    trust: &T,
    authority: &A,
) -> Result<VerifiedBaseSummary, ForeignMergeRefusal>
where
    T: RebootstrapTrust + ?Sized,
    A: BaseSignerAuthority + ?Sized,
{
    if manifest.group_id.as_str() != group_id {
        return Err(ForeignMergeRefusal::GroupMismatch {
            current: group_id.to_owned(),
            returning: manifest.group_id.as_str().to_owned(),
        });
    }
    // The key is resolved once, so the one the authority is asked about is
    // the one the signature was verified under.
    let signer = manifest.signer_device_id.as_str();
    let signing_key =
        trust.signing_key(signer).ok_or_else(|| ForeignMergeRefusal::ManifestInvalid {
            detail: format!("no pinned signing key for manifest signer {signer}"),
        })?;
    manifest
        .verify(&|device_id: &str| (device_id == signer).then_some(signing_key))
        .map_err(|error| ForeignMergeRefusal::ManifestInvalid { detail: error.to_string() })?;
    if !authority.may_found_base(group_id, signer, &signing_key) {
        return Err(ForeignMergeRefusal::SignerNotAuthorized { signer: signer.to_owned() });
    }
    let snapshot = RebootstrapSnapshot::decode(snapshot_bytes)
        .map_err(|error| ForeignMergeRefusal::SnapshotInvalid { detail: error.to_string() })?;
    if snapshot.canonical_encoding() != snapshot_bytes {
        return Err(ForeignMergeRefusal::SnapshotInvalid {
            detail: "the snapshot bytes are not its canonical encoding".into(),
        });
    }
    snapshot
        .validate_against_checkpoint(&manifest.checkpoint)
        .map_err(|error| ForeignMergeRefusal::SnapshotInvalid { detail: error.to_string() })?;
    let side = VerifiedBaseSummary::from_parts(manifest.checkpoint.clone(), snapshot)?;
    super::seal::check_namespace(group_id, side.snapshot()).map_err(|error| match error {
        SyncSqliteError::SealRefused { refusal, .. } => {
            ForeignMergeRefusal::SnapshotNotProjection(refusal)
        }
        other => ForeignMergeRefusal::SnapshotInvalid { detail: other.to_string() },
    })?;
    Ok(side)
}

/// Where the joined summary stands relative to the two it joins.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SummaryOrder {
    /// This replica's summary already holds the returning side's history.
    CurrentAbsorbsReturning,
    /// The returning side's summary already holds this replica's history.
    ReturningAbsorbsCurrent,
    /// The two summaries are the same history.
    Equal,
    /// Each side holds history the other does not.
    Incomparable,
}

/// The base the joined summary stands on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MergedBase {
    /// This replica's base, unchanged.
    Current(HistoryBase),
    /// The returning side's base, adopted with its snapshot as it is.
    Returning(HistoryBase),
    /// A base neither side holds, founded on the joined summary.
    Minted(HistoryBase),
}

impl MergedBase {
    pub fn history_base(self) -> HistoryBase {
        match self {
            Self::Current(base) | Self::Returning(base) | Self::Minted(base) => base,
        }
    }
}

/// The outcome of merging two bases' summaries.
#[derive(Clone, Debug, PartialEq)]
pub struct SummaryMerge {
    pub order: SummaryOrder,
    pub base: MergedBase,
    /// The joined summary. Equal to the adopted side's summary unless the
    /// base was minted.
    pub summary: GroupHistorySummary,
}

/// Merges two verified sides.
///
/// Every author position either side names a change for -- heads, tips and
/// frontier changes -- is compared before anything is joined.
pub fn merge_foreign_base(
    current: &VerifiedBaseSummary,
    returning: &VerifiedBaseSummary,
) -> Result<SummaryMerge, ForeignMergeRefusal> {
    if current.group_id() != returning.group_id() {
        return Err(ForeignMergeRefusal::GroupMismatch {
            current: current.group_id().as_str().to_owned(),
            returning: returning.group_id().as_str().to_owned(),
        });
    }
    // Each side's positions include every tip and head its summary names,
    // so this covers everything `find_equivocation` would compare.
    let mut positions = current.positions.clone();
    for ((device_id, author_seq), hash) in &returning.positions {
        attest(&mut positions, device_id, *author_seq, *hash)?;
    }
    plan_positions_compared(
        current.group_id(),
        (current.history_base(), current.summary()),
        (returning.history_base(), returning.summary()),
    )
}

/// [`merge_foreign_base`]'s decision over two bare summaries, with none of
/// its verification: no signature, no checkpoint, no carried content, no
/// frontier changes. Only the equivocation check the summaries themselves
/// allow. For tests, which pin the decision against the model without
/// building a store for every scenario.
#[cfg(any(test, feature = "test-support"))]
pub fn plan_summary_merge(
    group_id: &FolderGroupId,
    current: (HistoryBase, &GroupHistorySummary),
    returning: (HistoryBase, &GroupHistorySummary),
) -> Result<SummaryMerge, ForeignMergeRefusal> {
    if let Some(equivocation) = find_equivocation(current.1, returning.1) {
        return Err(ForeignMergeRefusal::Equivocation(equivocation));
    }
    plan_positions_compared(group_id, current, returning)
}

/// The join of two summaries standing on two bases, once every author
/// position both sides name has been compared, and the base the join stands
/// on.
///
/// * The join equals this replica's summary and not the returning one:
///   this replica already holds the returning history, and keeps its base.
/// * The join equals the returning summary and not this replica's: the
///   returning side holds this replica's history, and its base is adopted.
/// * Both summaries are equal: the greater of the two bases is kept, so the
///   choice does not depend on which side merges.
/// * The join equals neither: a fresh base is minted over it.
///
/// No base is minted when one side absorbs the other. No new history came
/// into existence, and minting anyway would move only the replica that
/// merged first onto a base the other side has never seen: every change
/// authored there would be foreign on the other side, and each merge that
/// brought it across would mint yet another base.
fn plan_positions_compared(
    group_id: &FolderGroupId,
    current: (HistoryBase, &GroupHistorySummary),
    returning: (HistoryBase, &GroupHistorySummary),
) -> Result<SummaryMerge, ForeignMergeRefusal> {
    let (current_base, current_summary) = current;
    let (returning_base, returning_summary) = returning;
    let summary = current_summary
        .join_positions_compared(returning_summary)
        .map_err(|error| ForeignMergeRefusal::JoinRefused { detail: error.to_string() })?;

    let joined = summary_identity(&summary);
    let absorbs_returning = joined == summary_identity(current_summary);
    let absorbs_current = joined == summary_identity(returning_summary);
    let (order, base) = match (absorbs_returning, absorbs_current) {
        (true, true) if returning_base > current_base => {
            (SummaryOrder::Equal, MergedBase::Returning(returning_base))
        }
        (true, true) => (SummaryOrder::Equal, MergedBase::Current(current_base)),
        (true, false) => (SummaryOrder::CurrentAbsorbsReturning, MergedBase::Current(current_base)),
        (false, true) => {
            (SummaryOrder::ReturningAbsorbsCurrent, MergedBase::Returning(returning_base))
        }
        (false, false) => (
            SummaryOrder::Incomparable,
            MergedBase::Minted(HistoryBase::mint_merged(
                group_id,
                current_base,
                returning_base,
                &joined,
            )),
        ),
    };
    Ok(SummaryMerge { order, base, summary })
}

/// The first author position at which `left` and `right`, taken together,
/// name two different changes.
///
/// Positions are read from each author's tip and from every content head;
/// see the module documentation for what that cannot see.
pub fn find_equivocation(
    left: &GroupHistorySummary,
    right: &GroupHistorySummary,
) -> Option<SummaryEquivocation> {
    let mut positions = match summary_positions(left) {
        Ok(positions) => positions,
        Err(equivocation) => return Some(equivocation),
    };
    record_summary_positions(&mut positions, right).err()
}

fn summary_positions(
    summary: &GroupHistorySummary,
) -> Result<BTreeMap<(String, AuthorSeq), ChangeHash>, SummaryEquivocation> {
    let mut positions = BTreeMap::new();
    record_summary_positions(&mut positions, summary)?;
    Ok(positions)
}

fn record_summary_positions(
    positions: &mut BTreeMap<(String, AuthorSeq), ChangeHash>,
    summary: &GroupHistorySummary,
) -> Result<(), SummaryEquivocation> {
    for author in &summary.author_state {
        attest_position(positions, &author.device_id, author.watermark, author.tip_change_hash)?;
    }
    for head in &summary.path_heads {
        attest_position(positions, &head.device_id, head.author_seq, head.change_hash)?;
    }
    Ok(())
}

fn attest(
    positions: &mut BTreeMap<(String, AuthorSeq), ChangeHash>,
    device_id: &str,
    author_seq: AuthorSeq,
    hash: ChangeHash,
) -> Result<(), ForeignMergeRefusal> {
    attest_position(positions, device_id, author_seq, hash)
        .map_err(ForeignMergeRefusal::Equivocation)
}

fn attest_position(
    positions: &mut BTreeMap<(String, AuthorSeq), ChangeHash>,
    device_id: &str,
    author_seq: AuthorSeq,
    hash: ChangeHash,
) -> Result<(), SummaryEquivocation> {
    match positions.insert((device_id.to_owned(), author_seq), hash) {
        Some(held) if held != hash => Err(SummaryEquivocation {
            device_id: device_id.to_owned(),
            author_seq,
            held,
            incoming: hash,
        }),
        _ => Ok(()),
    }
}
