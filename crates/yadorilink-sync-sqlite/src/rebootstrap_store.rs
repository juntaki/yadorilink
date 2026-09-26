//! HistoryBase/snapshot persistence and the production atomic
//! installer. `build_compaction_snapshot`'s current-heads
//! check previously ran as a *separate* `self.database.read` call (via
//! `SyncState::dag_group_heads`) before the snapshot-building read. Folded
//! into the same `conn` here -- both are read-only, so this can only make
//! the two reads more mutually consistent (one snapshot instead of two
//! independently-acquired ones), never less.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

use rusqlite::{params, Connection, OptionalExtension};

use yadorilink_replica_domain::change::{Change, Op};
use yadorilink_replica_domain::file::FileVersion;
use yadorilink_replica_domain::ids::{AuthorSeq, ChangeHash, VersionHash};
use yadorilink_replica_engine::compaction::{Checkpoint, CheckpointHash, PrunePlan};
use yadorilink_replica_engine::rebootstrap::{HistoryBase, HistoryEpoch};
use yadorilink_replica_engine::rebootstrap_snapshot::{
    BoundaryParentAuth, RebootstrapSnapshot, SnapshotAuthorState, SnapshotFile, SnapshotPathHead,
    SnapshotVersionState,
};
use yadorilink_sqlite_runtime::SyncDatabase;

use crate::SyncSqliteError;

mod compaction_hold;
mod foreign_merge;
mod merge_install;
mod seal;
pub use compaction_hold::{copy_holds_compaction, held_paths, seal_group_unless_held, SealAttempt};
#[cfg(any(test, feature = "test-support"))]
pub use foreign_merge::plan_summary_merge;
pub use foreign_merge::{
    find_equivocation, merge_foreign_base, verify_current_base, verify_returning_base,
    BaseSignerAuthority, ForeignMergeError, ForeignMergeRefusal, MergedBase, SummaryEquivocation,
    SummaryMerge, SummaryOrder, VerifiedBaseSummary,
};
pub use merge_install::{commit_foreign_merge, CommittedMerge};
#[cfg(any(test, feature = "test-support"))]
pub use merge_install::{commit_foreign_merge_interrupted_after, install_base_for_tests};
#[cfg(any(test, feature = "test-support"))]
pub use seal::seal_group_interrupted_after;
pub use seal::{
    plan_seal, prepare_seal, seal_group, verify_seal_preconditions, EpochResetStep, SealRefusal,
    VerifiedSeal,
};

/// Direct accessor for the six pure-forward `group_history_bases`/
/// `change_checkpoint_snapshots` reads and
/// writes below -- migrated off the former `SyncState::history_base`/
/// `checkpoint_snapshot`/
/// `compacted_parent_auth`/`build_compaction_snapshot`/
/// `commit_compaction_snapshot` one-line delegate wrappers,
/// following the [`crate::HandoffLeaseRepository`] precedent. Opens the
/// pooled connection/`IMMEDIATE` transaction itself instead of taking a
/// raw `&Connection`/`&Transaction` from the caller, so no `rusqlite` type
/// crosses this repository's own public boundary.
pub struct RebootstrapStoreRepository {
    database: Arc<SyncDatabase>,
}

impl RebootstrapStoreRepository {
    pub fn new(database: Arc<SyncDatabase>) -> Self {
        Self { database }
    }

    /// Persisted history base for a group, if this device has crossed a
    /// compaction/re-bootstrap boundary. `None` is the un-compacted genesis
    /// history, not an error.
    pub fn history_base(&self, group_id: &str) -> Result<Option<HistoryBase>, SyncSqliteError> {
        self.database.read(|conn| history_base(conn, group_id))
    }

    pub fn checkpoint_snapshot(
        &self,
        checkpoint_hash: &CheckpointHash,
    ) -> Result<Option<Vec<u8>>, SyncSqliteError> {
        self.database.read(|conn| checkpoint_snapshot(conn, checkpoint_hash))
    }

    /// The paths whose unresolved conflict `group_id`'s compaction is
    /// waiting for (see [`held_paths`]). Empty when it is not held.
    pub fn compaction_held_paths(&self, group_id: &str) -> Result<Vec<String>, SyncSqliteError> {
        self.database.read(|conn| held_paths(conn, group_id))
    }

    /// Whether the conflict copy at `copy_path` carries a version whose
    /// fork `group_id`'s compaction is waiting for (see
    /// [`copy_holds_compaction`]).
    pub fn conflict_copy_holds_compaction(
        &self,
        group_id: &str,
        copy_path: &str,
    ) -> Result<bool, SyncSqliteError> {
        self.database.read(|conn| copy_holds_compaction(conn, group_id, copy_path))
    }

    /// Builds the exact snapshot a destructive compaction will commit. See
    /// the free function of the same name for the exact contract.
    pub fn build_compaction_snapshot(
        &self,
        plan: &PrunePlan,
    ) -> Result<RebootstrapSnapshot, SyncSqliteError> {
        self.database.read(|conn| build_compaction_snapshot(conn, plan))
    }
}

fn decode_stored_change(bytes: &[u8]) -> Result<Change, SyncSqliteError> {
    Change::from_wire_bytes(bytes).map_err(|error| {
        SyncSqliteError::CorruptState(format!(
            "invalid Change in re-bootstrap persistence: {error}"
        ))
    })
}

fn decode_stored_file_version(bytes: &[u8]) -> Result<FileVersion, SyncSqliteError> {
    FileVersion::from_canonical_encoding(bytes).map_err(|error| {
        SyncSqliteError::CorruptState(format!(
            "invalid FileVersion in re-bootstrap persistence: {error}"
        ))
    })
}

const REBOOTSTRAP_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS change_checkpoint_snapshots (
    checkpoint_hash BLOB PRIMARY KEY,
    group_id        TEXT NOT NULL,
    snapshot        BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_change_checkpoint_snapshots_group
    ON change_checkpoint_snapshots(group_id);

CREATE TABLE IF NOT EXISTS group_history_bases (
    group_id                 TEXT PRIMARY KEY,
    history_base             BLOB NOT NULL,
    checkpoint_hash          BLOB NOT NULL,
    previous_checkpoint_hash BLOB
);

-- The causal summary the installed HistoryBase carries: `Q = (W, Gamma,
-- lamport ceiling)`. Keyed by the base it belongs to, beside
-- `group_history_bases` rather than inside it, because `W` has one row
-- per author and `Gamma` one per live present entry head per path.
--
-- This is the part of a base that describes the history it replaced, as
-- opposed to the files that history produced. Without it, an author
-- whose every write was superseded before the checkpoint is invisible
-- here, and this device would have no attested position to measure that
-- author's next change against -- leaving it to take the author's own
-- word for where it stands, which is the one thing a high-water mark may
-- never rest on.
CREATE TABLE IF NOT EXISTS history_base_author_state (
    group_id        TEXT NOT NULL,
    base_hash       BLOB NOT NULL,
    device_id       TEXT NOT NULL,
    watermark       INTEGER NOT NULL,
    tip_change_hash BLOB NOT NULL,
    PRIMARY KEY (group_id, base_hash, device_id)
);

-- `Gamma`: per path, the causally maximal present entry heads (a file's,
-- a symlink's or a directory's; a structural directory has none) the base
-- carries. Keyed by the change that wrote the head and never by
-- `version_hash`: two devices that wrote identical bytes concurrently
-- are two heads, and a delete descending from only one of them removes
-- only that one.
CREATE TABLE IF NOT EXISTS history_base_path_heads (
    group_id         TEXT NOT NULL,
    base_hash        BLOB NOT NULL,
    path             TEXT NOT NULL,
    change_hash      BLOB NOT NULL,
    device_id        TEXT NOT NULL,
    author_seq       INTEGER NOT NULL,
    lamport          INTEGER NOT NULL,
    version_hash     BLOB NOT NULL,
    naming_device_id TEXT NOT NULL,
    PRIMARY KEY (group_id, base_hash, path, change_hash)
);
-- The file index checks a current row's authoring change against the heads
-- the installed base carries, by change and not by path: a conflict copy's
-- row lives at another path than the head that wrote it. That check runs
-- for every row an install writes, and joins the installed base in, so the
-- index carries `base_hash` too: with only `(group_id, change_hash)` the
-- primary key's `(group_id, base_hash)` prefix looks as selective, and
-- SQLite scans every head of the base for each row -- quadratic in the
-- number of paths.
DROP INDEX IF EXISTS idx_history_base_path_heads_change;
CREATE INDEX IF NOT EXISTS idx_history_base_path_heads_change_base
    ON history_base_path_heads(group_id, change_hash, base_hash);
-- The heads of one path, as the live path frontier reads them beside its
-- own (see `history_base_named_heads`).
CREATE INDEX IF NOT EXISTS idx_history_base_path_heads_path
    ON history_base_path_heads(group_id, path);

-- The installed base's heads a change on the current epoch has superseded,
-- per path: `(path, change_hash, naming_change)` is here exactly when the
-- admitted change `naming_change`, on the current epoch, touches `path`
-- and names `change_hash` among its signed observed base heads. A base
-- head is not a DAG node, so ancestry never supersedes one; naming is the
-- only thing that does, and a base head at a path the current epoch
-- touched that nothing named is still one of that path's live heads.
--
-- Derived, and maintained in the transaction that admits each change.
-- Rows are kept per naming change so the record can be checked and
-- rebuilt: a retained change's rows are recomputed from its signed bytes,
-- and the rows of a change a checkpoint pruned -- whose bytes are gone --
-- are the only thing left that says what it named, so they are kept as
-- long as its prune record is. Not keyed by base: a new base is installed
-- only by the epoch reset, which empties this table for the group along
-- with the rest of the replaced base's summary.
CREATE TABLE IF NOT EXISTS history_base_named_heads (
    group_id      TEXT NOT NULL,
    path          TEXT NOT NULL,
    change_hash   BLOB NOT NULL,
    naming_change BLOB NOT NULL,
    PRIMARY KEY (group_id, path, change_hash, naming_change)
);
-- What one change named, as the startup check compares it.
CREATE INDEX IF NOT EXISTS idx_history_base_named_heads_naming
    ON history_base_named_heads(group_id, naming_change);

-- The authoring change of every file row the base carries. A row outlives
-- the head that wrote it: a path's removal leaves a row authored by the
-- removal, which is no content head, and a conflict copy stays current
-- after the path it was copied from is rewritten. Neither author is in
-- `Gamma` once a seal absorbs it, yet the row is still one the base
-- carries, and the file index accepts it by this set.
CREATE TABLE IF NOT EXISTS history_base_carried_authors (
    group_id    TEXT NOT NULL,
    base_hash   BLOB NOT NULL,
    change_hash BLOB NOT NULL,
    PRIMARY KEY (group_id, base_hash, change_hash)
);

-- The rest of the summary: the greatest Lamport the replaced history
-- reached. Heads are ranked by Lamport, so a base that forgot it would
-- have to restart the clock at its own root, and a restarted clock makes
-- the compaction observable.
CREATE TABLE IF NOT EXISTS history_base_meta (
    group_id        TEXT NOT NULL,
    base_hash       BLOB NOT NULL,
    lamport_ceiling INTEGER NOT NULL,
    PRIMARY KEY (group_id, base_hash)
);

-- A group whose compaction is held (see `compaction_hold`): the last seal
-- was refused because these paths each held two live heads of one author,
-- a conflict only the user can resolve. `live_heads` is the path's live
-- heads then, their sorted change hashes laid end to end; the seal is not
-- tried again until one recorded path's heads differ. Local status, never
-- replicated, and not part of any summary.
CREATE TABLE IF NOT EXISTS compaction_holds (
    group_id   TEXT NOT NULL,
    path       TEXT NOT NULL,
    live_heads BLOB NOT NULL,
    PRIMARY KEY (group_id, path)
);
"#;

/// Whether the history base `group_id` stands on carries `change` as a
/// head of its `Gamma` or as the author of a row it installed. The summary
/// tables hold the installed base's rows only (every install replaces
/// them), so a base the group has left answers nothing.
pub(crate) fn installed_base_carries_author(
    conn: &Connection,
    group_id: &str,
    change: &ChangeHash,
) -> Result<bool, SyncSqliteError> {
    init_rebootstrap_schema(conn)?;
    let carried: Option<i64> = conn
        .prepare_cached(
            "SELECT 1 FROM group_history_bases b \
              WHERE b.group_id = ?1 AND ( \
                EXISTS (SELECT 1 FROM history_base_path_heads h \
                         WHERE h.group_id = b.group_id AND h.change_hash = ?2 \
                           AND h.base_hash = b.history_base) \
                OR EXISTS (SELECT 1 FROM history_base_carried_authors a \
                            WHERE a.group_id = b.group_id AND a.change_hash = ?2 \
                              AND a.base_hash = b.history_base))",
        )?
        .query_row(params![group_id, &change.0[..]], |row| row.get(0))
        .optional()?;
    Ok(carried.is_some())
}

pub fn init_rebootstrap_schema(conn: &Connection) -> Result<(), SyncSqliteError> {
    conn.execute_batch(REBOOTSTRAP_SCHEMA)?;
    Ok(())
}

/// Persisted history base for a group, if this device has crossed a
/// compaction/re-bootstrap boundary. `None` is the un-compacted genesis
/// history, not an error.
pub fn history_base(
    conn: &Connection,
    group_id: &str,
) -> Result<Option<HistoryBase>, SyncSqliteError> {
    init_rebootstrap_schema(conn)?;
    read_history_base(conn, group_id)
}

/// The history epoch `group_id` is currently on: the epoch above its
/// installed base, or genesis when it has none.
///
/// Reads the table without creating it, unlike every other accessor here,
/// because this one is on the admission path: every incoming change is
/// measured against it, and running the schema batch per change would turn
/// a read into a write. `init_dag_schema` creates the table for exactly
/// this reason -- the DAG's admission rule now depends on which base the
/// group holds, so the row admission reads is part of the DAG's own schema.
pub fn current_history_epoch(
    conn: &Connection,
    group_id: &str,
) -> Result<HistoryEpoch, SyncSqliteError> {
    Ok(HistoryEpoch::from_installed_base(read_history_base(conn, group_id)?))
}

/// The Lamport floor a change written on `epoch` is clocked from: the
/// greatest Lamport value the history below that epoch reached. Zero on
/// the group's original history; the ceiling the base carried on an
/// epoch above one.
///
/// `None` for a base this replica holds no ceiling for, which is any base
/// other than the installed one: its ceiling was replaced along with its
/// summary when a later base was installed, or it was never held here at
/// all. A change on such an epoch is not one this replica admits, so the
/// only thing that still reads its floor is revalidation of history kept
/// from an earlier epoch, which can then check the clock only against its
/// parents. The installed base always has a ceiling -- it is written with
/// the base -- so missing one there is damage, not an unknown.
///
/// Reads without the schema batch, like [`current_history_epoch`], because
/// admission asks it for every change.
pub(crate) fn lamport_floor(
    conn: &Connection,
    group_id: &str,
    epoch: HistoryEpoch,
) -> Result<Option<u64>, SyncSqliteError> {
    let HistoryEpoch::Base(base) = epoch else { return Ok(Some(0)) };
    let ceiling: Option<i64> = conn
        .prepare_cached(
            "SELECT lamport_ceiling FROM history_base_meta WHERE group_id = ?1 AND base_hash = ?2",
        )?
        .query_row(params![group_id, &base.0[..]], |row| row.get(0))
        .optional()?;
    match ceiling {
        Some(ceiling) if ceiling < 0 => Err(SyncSqliteError::CorruptState(format!(
            "history base {} of group {group_id} claims a Lamport ceiling of {ceiling}",
            base.to_hex()
        ))),
        Some(ceiling) => Ok(Some(ceiling as u64)),
        None if read_history_base(conn, group_id)? == Some(base) => {
            Err(SyncSqliteError::CorruptState(format!(
                "group {group_id} has history base {} installed but no stored Lamport ceiling \
                 for it; the ceiling is written with the base, so its absence is damage",
                base.to_hex()
            )))
        }
        None => Ok(None),
    }
}

fn read_history_base(
    conn: &Connection,
    group_id: &str,
) -> Result<Option<HistoryBase>, SyncSqliteError> {
    let bytes: Option<Vec<u8>> = conn
        .prepare_cached("SELECT history_base FROM group_history_bases WHERE group_id = ?1")?
        .query_row([group_id], |row| row.get(0))
        .optional()?;
    bytes
        .map(|bytes| {
            let array: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                SyncSqliteError::CorruptState(format!(
                    "stored HistoryBase for group {group_id} is not 32 bytes"
                ))
            })?;
            Ok(HistoryBase(array))
        })
        .transpose()
}

pub fn checkpoint_snapshot(
    conn: &Connection,
    checkpoint_hash: &CheckpointHash,
) -> Result<Option<Vec<u8>>, SyncSqliteError> {
    init_rebootstrap_schema(conn)?;
    Ok(conn
        .query_row(
            "SELECT snapshot FROM change_checkpoint_snapshots WHERE checkpoint_hash = ?1",
            [&checkpoint_hash.0[..]],
            |row| row.get(0),
        )
        .optional()?)
}

/// The bounded causal summary of a group's history: `Q = (W, Gamma, L)`.
///
/// `W` is every retained author's `(watermark, tip)`; `Gamma` is, per
/// path, the causally maximal present entry heads -- Directory heads
/// included, a structural directory never, since nothing writes one; `L`
/// is the greatest Lamport the history reached. Bounded by the number of
/// authors and by how concurrent each path is, not by how long the history
/// is, which is what makes it something a history base can carry in place
/// of the history.
#[derive(Clone, Debug, PartialEq)]
pub struct GroupHistorySummary {
    pub author_state: Vec<SnapshotAuthorState>,
    pub path_heads: Vec<SnapshotPathHead>,
    pub lamport_ceiling: u64,
}

impl GroupHistorySummary {
    /// The namespace projection of this summary: the physical tree the
    /// explicit state it summarises places, `project(resolve(Gamma))`.
    ///
    /// `Gamma` holds every present entry head, Directory heads included,
    /// and never a structural directory, which is derived: a directory
    /// that exists only to hold a descendant comes out of the projection,
    /// not out of any head. `kind_of` names each head's version kind; a
    /// head whose kind it cannot name fails the projection.
    ///
    /// This is what a base's rows must hold for its summary, whether the
    /// summary is a seal's or the join of two, so a structural conflict
    /// that only a join brings together (a file `a` on one side, `a/x` on
    /// the other) is placed rather than left for a later seal to refuse.
    pub fn project(
        &self,
        kind_of: impl Fn(&[u8; 32]) -> Option<yadorilink_replica_domain::file::RecordKind>,
    ) -> Result<
        yadorilink_replica_engine::namespace::NamespaceProjection,
        yadorilink_replica_engine::namespace::ProjectionError,
    > {
        yadorilink_replica_engine::namespace::project(&heads_by_path(&self.path_heads), kind_of)
    }

    /// The causal join of two summaries of the same group's history: the
    /// least summary that is above both.
    ///
    /// This is what merging two histories is. It replaces asking which of
    /// them is "the" history and re-parenting the other onto it, which
    /// cannot be done without either inventing causality or throwing away
    /// one side's writes.
    ///
    /// Watermarks join by maximum, because a watermark is a prefix of one
    /// author's chain and the higher of two prefixes contains the lower.
    /// The tip travels with the watermark it belongs to, so the joined
    /// position is a position that was actually attested rather than a
    /// number paired with the wrong change.
    ///
    /// Head sets join by a union with one subtraction. A head present on
    /// both sides is in the join, and both sides must describe it the same
    /// way -- otherwise which description survived would depend on the
    /// order of the sides, and the join would not be symmetric. A head present on only one side is in
    /// the join unless the other side's watermark for that head's author
    /// already covers it -- if that side has seen this author's write and
    /// does not list it as a head, it has seen what superseded it, and
    /// carrying it forward would resurrect content a later write removed.
    /// A head the other side simply has not reached stays.
    ///
    /// Heads are never collapsed by content. Two devices that wrote
    /// identical bytes concurrently produced two writes, and a later
    /// delete descending from only one of them removes only that one; a
    /// join that had merged them could not say the other survives.
    ///
    /// Two heads of one path by one author is corrupt state on either side
    /// or a product of joining, and is reported rather than tolerated. The
    /// reason is path-local DAG ordering, not the author chain: a chain
    /// link is not a DAG parent and orders nothing in a path's own
    /// history. What orders it is that every emission touching a path
    /// either refreshes that path's materialized basis to a head set
    /// containing the emitted change or invalidates that basis, while a
    /// local edit takes exactly that basis as its parents -- so an
    /// author's second write to a path descends its first, and the earlier
    /// one cannot still be maximal. The check stays even so: it is what
    /// catches a writer that ever breaks that property.
    ///
    /// So is one position naming two different changes, which is
    /// equivocation and outside the merge domain entirely. A position is
    /// compared wherever either side still names the change at it -- an
    /// author's tip or any content head -- which is as far as a summary can
    /// see; see [`find_equivocation`].
    ///
    /// Not yet called outside tests and the foreign-base merge core
    /// ([`merge_foreign_base`]), which nothing in production calls yet.
    pub fn join(&self, other: &Self) -> Result<Self, SyncSqliteError> {
        if let Some(equivocation) = find_equivocation(self, other) {
            return Err(SyncSqliteError::CorruptState(format!(
                "cannot join histories: {equivocation}, which is equivocation and outside the \
                 merge domain"
            )));
        }
        self.join_positions_compared(other)
    }

    /// This side's heads by `(path, change)`, and each author's watermark.
    fn head_and_watermark_index(&self) -> (HashSet<(&str, ChangeHash)>, HashMap<&str, AuthorSeq>) {
        let heads =
            self.path_heads.iter().map(|head| (head.path.as_str(), head.change_hash)).collect();
        let watermarks = self
            .author_state
            .iter()
            .map(|state| (state.device_id.as_str(), state.watermark))
            .collect();
        (heads, watermarks)
    }

    /// [`Self::join`] for a caller that has already compared every author
    /// position both sides name and found no equivocation.
    fn join_positions_compared(&self, other: &Self) -> Result<Self, SyncSqliteError> {
        let author_state = Self::join_author_state(&self.author_state, &other.author_state)?;
        let (self_heads, self_watermarks) = self.head_and_watermark_index();
        let (other_heads, other_watermarks) = other.head_and_watermark_index();
        let mut heads: BTreeMap<(&str, ChangeHash), &SnapshotPathHead> = BTreeMap::new();
        for (side, (opposite_heads, opposite_watermarks)) in
            [(self, (&other_heads, &other_watermarks)), (other, (&self_heads, &self_watermarks))]
        {
            for head in &side.path_heads {
                let covered = !opposite_heads.contains(&(head.path.as_str(), head.change_hash))
                    && opposite_watermarks
                        .get(head.device_id.as_str())
                        .is_some_and(|watermark| *watermark >= head.author_seq);
                if covered {
                    continue;
                }
                // Both sides name this change as a head of this path. They
                // must say the same thing about it: which of two differing
                // descriptions the join kept would otherwise depend on the
                // order the sides were given in, and so would the joined
                // summary's identity and the base minted over it.
                if let Some(held) = heads.insert((head.path.as_str(), head.change_hash), head) {
                    if held != head {
                        return Err(SyncSqliteError::CorruptState(format!(
                            "cannot join histories: the two sides describe head {} of {:?} \
                             differently",
                            head.change_hash.to_hex(),
                            head.path,
                        )));
                    }
                }
            }
        }
        let path_heads: Vec<SnapshotPathHead> = heads.into_values().cloned().collect();
        let mut by_author: BTreeMap<(&str, &str), &SnapshotPathHead> = BTreeMap::new();
        for head in &path_heads {
            if let Some(held) =
                by_author.insert((head.path.as_str(), head.device_id.as_str()), head)
            {
                return Err(SyncSqliteError::CorruptState(format!(
                    "cannot join histories: author {} holds two heads of {:?} ({} and {}), and an \
                     author's second write to a path descends its first, so only the later one \
                     can be maximal",
                    head.device_id,
                    head.path,
                    held.change_hash.to_hex(),
                    head.change_hash.to_hex(),
                )));
            }
        }
        Ok(Self {
            author_state,
            path_heads,
            lamport_ceiling: self.lamport_ceiling.max(other.lamport_ceiling),
        })
    }

    /// The `W` half of the join on its own: each author at the maximum of
    /// the two watermarks, carrying the tip that watermark was attested
    /// with.
    ///
    /// Separate from [`join`](Self::join) because a caller that merges two
    /// histories' author positions is not always in a position to state
    /// either side's `Gamma`. A replica installing a history base is
    /// exactly that: its own head sets describe the epoch it is about to
    /// retire, they are not used by the install, and asking for them at
    /// all would mean building a summary of a state that may already sit
    /// above a base. Positions are the whole of what such a caller merges,
    /// so positions are the whole of what it asks for.
    pub fn join_author_state(
        left: &[SnapshotAuthorState],
        right: &[SnapshotAuthorState],
    ) -> Result<Vec<SnapshotAuthorState>, SyncSqliteError> {
        let mut author_state: BTreeMap<&str, &SnapshotAuthorState> = BTreeMap::new();
        for state in left.iter().chain(right.iter()) {
            match author_state.entry(state.device_id.as_str()) {
                std::collections::btree_map::Entry::Vacant(slot) => {
                    slot.insert(state);
                }
                std::collections::btree_map::Entry::Occupied(mut slot) => {
                    let held = *slot.get();
                    if held.watermark == state.watermark
                        && held.tip_change_hash != state.tip_change_hash
                    {
                        return Err(SyncSqliteError::CorruptState(format!(
                            "cannot join histories: author {} stands at position {} with two \
                             different changes ({} and {}), which is equivocation and outside \
                             the merge domain",
                            state.device_id,
                            state.watermark,
                            held.tip_change_hash.to_hex(),
                            state.tip_change_hash.to_hex(),
                        )));
                    }
                    if state.watermark > held.watermark {
                        slot.insert(state);
                    }
                }
            }
        }
        Ok(author_state.into_values().cloned().collect())
    }

    /// Where this summary puts `device_id`, if it carries a position for it
    /// at all.
    pub fn author_watermark(&self, device_id: &str) -> Option<AuthorSeq> {
        self.author_state
            .iter()
            .find(|state| state.device_id == device_id)
            .map(|state| state.watermark)
    }
}

/// Reads `Q = (W, L, Gamma)` for the whole of one group's history out of the
/// state the store already maintains: the installed base's summary, and the
/// derived state of the epoch above it.
///
/// No history is walked. The per-author positions come from the
/// author-chain state that admission advances in the same transaction as
/// the change itself; it already continues from the positions the base
/// carried, so it is `W` for the whole history as it stands. The head sets
/// come from the live path frontier, which describes only what is retained
/// here, and the base's own head sets supply the rest.
///
/// The two are composed per path:
///
/// ```text
/// Gamma_p = { x in Gamma_base(p) | no retained change of the current epoch
///                                   that touches p names x }
///         ∪ { the current epoch's live content heads of p }
/// ```
///
/// A change on the current epoch does not descend from the whole base: it
/// supersedes exactly the base heads it names among its signed observed
/// base heads, at the paths it touches (see
/// `yadorilink_replica_domain::change::Change::observed_base_heads`). A base
/// head it does not name stays a head beside it, whatever its DAG parents
/// say -- they cannot say anything about a base head, which is not a DAG
/// node. Naming only ever adds, so the result does not depend on the order
/// changes were admitted in. A path the current epoch has not touched has
/// exactly the heads the base carried. A live head retained from an
/// earlier epoch is part of what the base absorbed and is never read from
/// the frontier.
///
/// `L` is the base's ceiling, or the greatest Lamport any retained change
/// reached if that is higher.
///
/// On a group with no installed base all of this reduces to the live
/// frontier as it is: every retained change is on the original history.
pub fn build_group_history_summary(
    conn: &Connection,
    group_id: &str,
) -> Result<GroupHistorySummary, SyncSqliteError> {
    let epoch = current_history_epoch(conn, group_id)?;
    let base = match epoch {
        HistoryEpoch::Genesis => None,
        HistoryEpoch::Base(_) => Some(history_base_summary(conn, group_id)?.ok_or_else(|| {
            SyncSqliteError::CorruptState(format!(
                "group {group_id} has an installed history base with no summary"
            ))
        })?),
    };
    let author_state = crate::dag_store::author_chain::all_author_state(conn, group_id)?;

    // Which live heads were written on the current epoch.
    let mut epoch_of: HashMap<ChangeHash, HistoryEpoch> = HashMap::new();
    for (path, hash) in crate::dag_store::path_frontier::live_heads_for_group(conn, group_id)? {
        if epoch_of.contains_key(&hash) {
            continue;
        }
        let encoded = crate::dag_store::get_encoded(conn, &hash)?.ok_or_else(|| {
            SyncSqliteError::CorruptState(format!(
                "live head {} of {path:?} in group {group_id} is not a retained change",
                hash.to_hex()
            ))
        })?;
        epoch_of.insert(hash, decode_stored_change(&encoded)?.history_epoch);
    }
    let mut path_heads: Vec<SnapshotPathHead> =
        crate::dag_store::path_frontier::live_content_heads_for_group(conn, group_id)?
            .into_iter()
            .filter(|head| epoch_of.get(&head.change_hash) == Some(&epoch))
            .collect();
    if let Some(base) = &base {
        let named = named_base_heads(conn, group_id)?;
        path_heads.extend(
            base.path_heads
                .iter()
                .filter(|head| !named.contains(&(head.path.clone(), head.change_hash)))
                .cloned(),
        );
    }

    let retained_ceiling: i64 = conn.query_row(
        "SELECT COALESCE(MAX(lamport), 0) FROM changes WHERE group_id = ?1",
        [group_id],
        |row| row.get(0),
    )?;
    if retained_ceiling < 0 {
        return Err(SyncSqliteError::CorruptState(format!(
            "group {group_id} has a stored Lamport value of {retained_ceiling}, which no change \
             can carry"
        )));
    }
    let lamport_ceiling =
        (retained_ceiling as u64).max(base.as_ref().map_or(0, |base| base.lamport_ceiling));
    Ok(GroupHistorySummary { author_state, path_heads, lamport_ceiling })
}

/// The installed base's heads the current epoch has named, as
/// `(path, change)`: the ones no longer live at that path.
fn named_base_heads(
    conn: &Connection,
    group_id: &str,
) -> Result<HashSet<(String, ChangeHash)>, SyncSqliteError> {
    let mut stmt =
        conn.prepare("SELECT path, change_hash FROM history_base_named_heads WHERE group_id = ?1")?;
    let rows = stmt
        .query_map([group_id], |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)))?;
    let mut named = HashSet::new();
    for row in rows {
        let (path, hash) = row?;
        named.insert((path, ChangeHash(hash_32(&hash, "history_base_named_heads.change_hash")?)));
    }
    Ok(named)
}

/// The causal summary the currently installed HistoryBase carries, or
/// `None` when this group has no installed base (its history is its own,
/// un-compacted, from genesis).
///
/// Read back by base hash, not merely by group, so a summary left behind
/// by a base this device has since replaced can never be returned as if
/// it described the current one.
///
/// Not yet called outside tests: negotiating a common base with a peer and
/// merging a foreign base are what will read it.
pub fn history_base_summary(
    conn: &Connection,
    group_id: &str,
) -> Result<Option<GroupHistorySummary>, SyncSqliteError> {
    init_rebootstrap_schema(conn)?;
    let Some(base) = history_base(conn, group_id)? else { return Ok(None) };
    let base_hash = &base.0[..];

    let mut stmt = conn.prepare(
        "SELECT device_id, watermark, tip_change_hash FROM history_base_author_state \
         WHERE group_id = ?1 AND base_hash = ?2 ORDER BY device_id",
    )?;
    let rows = stmt.query_map(params![group_id, base_hash], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?, row.get::<_, Vec<u8>>(2)?))
    })?;
    let mut author_state = Vec::new();
    for row in rows {
        let (device_id, watermark, tip) = row?;
        if watermark < 1 {
            return Err(SyncSqliteError::CorruptState(format!(
                "installed base for group {group_id} puts author {device_id} at watermark \
                 {watermark}, which is not a position in any author chain"
            )));
        }
        author_state.push(SnapshotAuthorState {
            device_id,
            watermark: AuthorSeq(watermark as u64),
            tip_change_hash: ChangeHash(hash_32(&tip, "history_base_author_state.tip")?),
        });
    }

    let mut stmt = conn.prepare(
        "SELECT path, change_hash, device_id, author_seq, lamport, version_hash, \
                naming_device_id \
         FROM history_base_path_heads WHERE group_id = ?1 AND base_hash = ?2 \
         ORDER BY path, change_hash",
    )?;
    let rows = stmt.query_map(params![group_id, base_hash], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, Vec<u8>>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, i64>(4)?,
            row.get::<_, Vec<u8>>(5)?,
            row.get::<_, String>(6)?,
        ))
    })?;
    let mut path_heads = Vec::new();
    for row in rows {
        let (path, change_hash, device_id, author_seq, lamport, version_hash, naming_device_id) =
            row?;
        if author_seq < 1 || lamport < 0 {
            return Err(SyncSqliteError::CorruptState(format!(
                "installed base for group {group_id} carries a head of {path:?} at author \
                 sequence {author_seq} and Lamport {lamport}, which no change can hold"
            )));
        }
        path_heads.push(SnapshotPathHead {
            path,
            change_hash: ChangeHash(hash_32(&change_hash, "history_base_path_heads.change_hash")?),
            device_id,
            author_seq: AuthorSeq(author_seq as u64),
            lamport: lamport as u64,
            version_hash: VersionHash(hash_32(
                &version_hash,
                "history_base_path_heads.version_hash",
            )?),
            naming_device_id,
        });
    }

    // The ceiling is required, not defaulted. An install writes the meta
    // row, the author state and the head set in the same transaction as
    // the base itself, so a base with no meta row is a damaged database,
    // not a history that reached Lamport 0 -- and answering 0 would be
    // the worse of the two outcomes, because the Lamport anchor resumes
    // from the ceiling and a zeroed one changes the order two replicas
    // resolve a path into without anything looking wrong. At most one row
    // can exist to read: the table is keyed by (group_id, base_hash).
    let lamport_ceiling: i64 = conn
        .query_row(
            "SELECT lamport_ceiling FROM history_base_meta WHERE group_id = ?1 AND base_hash = ?2",
            params![group_id, base_hash],
            |row| row.get(0),
        )
        .optional()?
        .ok_or_else(|| {
            SyncSqliteError::CorruptState(format!(
                "group {group_id} has an installed history base but no stored Lamport ceiling \
                 for it; the base's summary rows are written with the base itself, so their \
                 absence is damage rather than an empty history"
            ))
        })?;
    // Likewise the author positions. A base carries them or it is not
    // installable at all (`install_base_by_reset` refuses it), so no rows
    // where the base claims heads or a non-zero ceiling is the same
    // damage. The one state that genuinely reads as empty is a base
    // sealed over a history that had nothing in it: no authors, no heads,
    // and a ceiling of zero. That stays an empty summary, and is
    // distinguished here rather than conflated with the damaged case.
    if author_state.is_empty() && !(path_heads.is_empty() && lamport_ceiling == 0) {
        return Err(SyncSqliteError::CorruptState(format!(
            "group {group_id} has an installed history base that carries {} path head(s) and a \
             Lamport ceiling of {lamport_ceiling} but no author positions; a base that cannot \
             say where its own authors stand is not installable, so this is damage",
            path_heads.len()
        )));
    }
    if lamport_ceiling < 0 {
        return Err(SyncSqliteError::CorruptState(format!(
            "installed base for group {group_id} claims a Lamport ceiling of {lamport_ceiling}"
        )));
    }
    Ok(Some(GroupHistorySummary {
        author_state,
        path_heads,
        lamport_ceiling: lamport_ceiling as u64,
    }))
}

/// `Gamma`'s heads grouped by path, as the per-path resolver and the
/// namespace projection take them. A summary head carries no mtime stamp,
/// exactly as the live path frontier carries none, so conflict-copy names
/// come out the same as the live projection's.
pub(crate) fn heads_by_path(
    heads: &[SnapshotPathHead],
) -> BTreeMap<String, Vec<yadorilink_replica_engine::conflict::PathHead>> {
    use yadorilink_replica_engine::conflict::{PathHead, PathHeadContent};
    let mut by_path: BTreeMap<String, Vec<PathHead>> = BTreeMap::new();
    for head in heads {
        by_path.entry(head.path.clone()).or_default().push(PathHead {
            change_hash: head.change_hash.0,
            lamport: head.lamport,
            device_id: head.device_id.clone(),
            naming_device_id: head.naming_device_id.clone(),
            content: Some(PathHeadContent {
                version_hash: head.version_hash.0,
                mtime_unix_nanos: 0,
            }),
        });
    }
    by_path
}

/// A stored 32-byte hash column, or a corruption report naming it.
fn hash_32(bytes: &[u8], what: &str) -> Result<[u8; 32], SyncSqliteError> {
    <[u8; 32]>::try_from(bytes).map_err(|_| {
        SyncSqliteError::CorruptState(format!(
            "{what} is {} bytes, not a 32-byte hash",
            bytes.len()
        ))
    })
}

/// Builds the exact snapshot a destructive compaction will commit.
///
/// The first production implementation deliberately only compacts at the
/// current DAG frontier. That makes the SQLite materialized/version-history
/// rows an exact snapshot of the checkpoint cut; compacting to an older cut
/// would require deterministic historical replay and is rejected rather than
/// silently hashing the wrong state.
pub fn build_compaction_snapshot(
    conn: &Connection,
    plan: &PrunePlan,
) -> Result<RebootstrapSnapshot, SyncSqliteError> {
    let group_id = plan.group_id.as_str();
    init_rebootstrap_schema(conn)?;
    // Published, not raw, heads: compaction may only ever run against a
    // fully-published frontier. A Pending head here would mean this
    // device is about to build a snapshot some receiver installs and
    // trusts outright -- refusing outright (rather than merely omitting
    // the Pending head's own content) keeps "compaction runs on the
    // Published world only" true by construction, not by every caller
    // remembering to filter first.
    let mut current_heads =
        crate::dag_store::published_view::published_group_heads(conn, group_id)?;
    current_heads.sort();
    let mut checkpoint_frontier = plan.checkpoint_frontier.clone();
    checkpoint_frontier.sort();
    if current_heads != checkpoint_frontier {
        return Err(SyncSqliteError::CorruptState(format!(
            "refusing compaction for group {group_id}: checkpoint frontier is not the current \
             fully-published materialized frontier"
        )));
    }
    // An empty prune is still a seal: a base replaces the history it
    // absorbs whether or not anything below its frontier is deleted yet.
    // Whether there is anything to seal at all is a precondition of the
    // seal, not of the snapshot (see `seal::verify_seal_preconditions`).

    // Published, not raw, file rows: a snapshot builder that could ever
    // include a Pending row would defeat the entire point of gating
    // compaction on a published frontier above -- see
    // `published_view::published_snapshot_files`'s own doc comment.
    let files = crate::dag_store::published_view::published_snapshot_files(conn, group_id)?;

    let mut versions: BTreeMap<VersionHash, Vec<u8>> = BTreeMap::new();
    for file in &files {
        let version = FileVersion::from_index_row(
            file.record.blocks.clone(),
            file.record.size,
            file.record.mtime_unix_nanos,
            file.record_kind,
            file.unix_mode,
            file.symlink_target.clone(),
            file.xattrs.clone(),
        );
        versions.insert(version.version_hash, version.canonical_encoding());
    }

    let pruned: HashSet<ChangeHash> = plan.pruned.iter().copied().collect();
    let mut frontier_changes = Vec::with_capacity(plan.checkpoint_frontier.len());
    let mut boundary_parent_auth = Vec::new();
    for hash in &plan.checkpoint_frontier {
        let encoded = crate::dag_store::get_encoded(conn, hash)?.ok_or_else(|| {
            SyncSqliteError::CorruptState(format!(
                "checkpoint frontier change {} is missing while building snapshot",
                hash.to_hex()
            ))
        })?;
        let change = decode_stored_change(&encoded)?;
        if change.group_id.as_str() != group_id {
            return Err(SyncSqliteError::CorruptState(
                "checkpoint frontier contains a foreign-group change".into(),
            ));
        }
        for op in &change.ops {
            if let Some(version_hash) = op_version_hash(op) {
                let version = crate::dag_store::get_file_version(conn, group_id, &version_hash)?
                    .ok_or_else(|| {
                        SyncSqliteError::CorruptState(format!(
                            "checkpoint frontier references missing file version {}",
                            hex::encode(version_hash.0)
                        ))
                    })?;
                versions.entry(version_hash).or_insert_with(|| version.canonical_encoding());
            }
        }
        for parent_hash in &change.parents {
            if !pruned.contains(parent_hash) {
                continue;
            }
            let parent_encoded =
                crate::dag_store::get_encoded(conn, parent_hash)?.ok_or_else(|| {
                    SyncSqliteError::CorruptState(format!(
                        "pruned checkpoint-boundary parent {} disappeared before \
                         snapshot construction",
                        parent_hash.to_hex()
                    ))
                })?;
            let parent = decode_stored_change(&parent_encoded)?;
            boundary_parent_auth.push(BoundaryParentAuth {
                child_hash: *hash,
                parent_hash: *parent_hash,
                parent_lamport: parent.lamport,
            });
        }
        frontier_changes.push(encoded);
    }

    // Every retained file's authoring change needs its own evidence
    // carried forward as a witness, or `RebootstrapSnapshot::new` refuses
    // to construct this snapshot at all (a compacted snapshot must never be constructible with
    // content that
    // has lost its evidence). A frontier change's rows are no exception:
    // the change travels as a body, but a receiver that retires the history
    // a base absorbs -- as a seal does, and as a merge does -- keeps no body
    // to vouch for them, and only the witness lets it serve their content.
    // This device already independently verified that evidence when the
    // change was first admitted/published -- carrying it forward here is
    // not re-trusting anything new, only preserving proof this device
    // already checked.
    let mut witnessed: HashSet<ChangeHash> = HashSet::new();
    let mut published_change_witnesses = Vec::new();
    for file in &files {
        let Some(authoring_change_hash) = file.authoring_change_hash else { continue };
        if !witnessed.insert(authoring_change_hash) {
            continue;
        }
        published_change_witnesses.push(build_witness_for_change(conn, &authoring_change_hash)?);
    }

    // The causal summary of the history this checkpoint replaces. Without
    // it an installed base describes a set of files and a frontier, and a
    // receiver has no attested position for any author whose writes the
    // frontier no longer shows -- see `SnapshotAuthorState`'s own doc
    // comment for what that costs.
    let summary = build_group_history_summary(conn, group_id)?;

    // Every head's evidence travels with the base too, not only the
    // evidence of a row's author. A head no row holds -- a directory that
    // lost its path by rank, which is owed no copy -- is still content the
    // base carries, and a later merge that leaves it the only head of its
    // path has to write its row: without its witness on either side that
    // merge is refused, and nothing that arrives later can supply it.
    for head in &summary.path_heads {
        if witnessed.insert(head.change_hash) {
            published_change_witnesses.push(build_witness_for_change(conn, &head.change_hash)?);
        }
    }

    // At most one live head per author per path. The snapshot refuses more
    // outright; saying which author and path is the useful half of that.
    let mut author_heads: HashSet<(&str, &str)> = HashSet::new();
    for head in &summary.path_heads {
        if !author_heads.insert((head.path.as_str(), head.device_id.as_str())) {
            return Err(seal::refuse(
                group_id,
                SealRefusal::TwoHeadsFromOneAuthor {
                    path: head.path.clone(),
                    device_id: head.device_id.clone(),
                },
            ));
        }
    }

    // Every head's content travels with the base, not only the content
    // some current row holds. A losing head of a conflict is content the
    // history still has, and the change that wrote it is one this seal
    // prunes -- along with every version only it referenced.
    for head in &summary.path_heads {
        if versions.contains_key(&head.version_hash) {
            continue;
        }
        let version = crate::dag_store::get_file_version(conn, group_id, &head.version_hash)?
            .ok_or_else(|| {
                seal::refuse(
                    group_id,
                    SealRefusal::ContentNotCarried {
                        path: head.path.clone(),
                        version: head.version_hash,
                    },
                )
            })?;
        versions.insert(head.version_hash, version.canonical_encoding());
    }

    Ok(RebootstrapSnapshot::new(
        plan.group_id.clone(),
        files,
        frontier_changes,
        versions.into_values().collect(),
        published_change_witnesses,
        boundary_parent_auth,
        summary.author_state,
        summary.path_heads,
        summary.lamport_ceiling,
    )?)
}

/// Carries a single already-published Change's own checkpoint evidence
/// into a self-contained [`yadorilink_replica_engine::rebootstrap_snapshot::PublishedChangeWitness`]
/// -- both `change_evidence`/`checkpoint_envelope` must already be
/// present (this device only ever calls this for a Change it has already
/// independently verified and published; see [`build_compaction_snapshot`]'s
/// own doc comment).
fn build_witness_for_change(
    conn: &Connection,
    change_hash: &ChangeHash,
) -> Result<yadorilink_replica_engine::rebootstrap_snapshot::PublishedChangeWitness, SyncSqliteError>
{
    use yadorilink_replica_engine::rebootstrap_snapshot::PublishedChangeWitness;

    let (checkpoint_hash, merkle_proof_encoded) =
        crate::dag_store::published_view::change_evidence(conn, change_hash)?.ok_or_else(|| {
            SyncSqliteError::CorruptState(format!(
                "cannot build a compaction-surviving witness for {}: no retained authorization \
                 evidence",
                change_hash.to_hex()
            ))
        })?;
    let (checkpoint_encoded, checkpoint_signature, author_signing_public_key) =
        crate::dag_store::published_view::checkpoint_envelope(conn, &checkpoint_hash)?.ok_or_else(
            || {
                SyncSqliteError::CorruptState(format!(
                    "cannot build a compaction-surviving witness for {}: its checkpoint \
                     envelope is missing",
                    change_hash.to_hex()
                ))
            },
        )?;
    Ok(PublishedChangeWitness {
        change_hash: *change_hash,
        checkpoint_hash,
        checkpoint_encoded,
        checkpoint_signature,
        author_signing_public_key,
        merkle_proof_encoded,
    })
}

/// Moves `checkpoint`'s group onto the base the checkpoint derives from, in
/// the caller's transaction: the atomic epoch reset that commits a seal.
///
/// `absorbed` is every change the base replaces, and it has to be every
/// change the group retains -- a base describes the whole history below it,
/// so a change it does not absorb has no history left to stand on. The
/// reset:
///
/// 1. records the checkpoint and the snapshot, which carries the files and
///    the summary `Q = (W, L, Gamma)`;
/// 2. switches the group onto the base: the base and its summary are
///    written, and every author whose position the base carries is
///    anchored on it, so its next change continues from the base by its
///    signed history epoch rather than by naming a change;
/// 3. retires the absorbed history: every absorbed change, frontier
///    included, and everything derived from one. `W` and `L` are not
///    cleared -- they live in the author state and the base's summary --
///    and the files the base carries keep their versions and the evidence
///    that authorized them.
///
/// Afterwards the group retains no change at all. The next one written
/// here is a root on the new base, clocked from its ceiling.
///
/// All three steps commit together or not at all: a crash before the
/// caller commits leaves the old base and its whole history, and one after
/// leaves the new base and nothing of the old history.
///
/// Test fixtures only. This commits `snapshot` without checking it against
/// the history it replaces, so it can install any base at all; a seal goes
/// through [`seal_group`], which checks the seal's preconditions and
/// commits it with the same reset in the same transaction.
#[cfg(any(test, feature = "test-support"))]
pub fn commit_compaction_snapshot(
    tx: &rusqlite::Transaction<'_>,
    checkpoint: &Checkpoint,
    snapshot: &RebootstrapSnapshot,
    absorbed: &[ChangeHash],
) -> Result<(), SyncSqliteError> {
    reset_group_epoch(tx, checkpoint, snapshot, absorbed, None)
}

/// The atomic epoch reset [`seal_group`] commits, as the doc of
/// `commit_compaction_snapshot` describes it, optionally stopped with an
/// error right after `interrupt_after`.
fn reset_group_epoch(
    tx: &rusqlite::Transaction<'_>,
    checkpoint: &Checkpoint,
    snapshot: &RebootstrapSnapshot,
    absorbed: &[ChangeHash],
    interrupt_after: Option<EpochResetStep>,
) -> Result<(), SyncSqliteError> {
    let group_id = checkpoint.group_id.as_str();
    let reached = |step: EpochResetStep| -> Result<(), SyncSqliteError> {
        if interrupt_after == Some(step) {
            return Err(SyncSqliteError::Io(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                format!("the seal of group {group_id} was interrupted after {step:?}"),
            )));
        }
        Ok(())
    };
    snapshot.validate_against_checkpoint(checkpoint)?;
    init_rebootstrap_schema(tx)?;

    // 1. The checkpoint and the snapshot carrying the summary.
    tx.execute(
        "INSERT OR REPLACE INTO change_checkpoint_snapshots \
         (checkpoint_hash, group_id, snapshot) VALUES (?1, ?2, ?3)",
        params![&checkpoint.checkpoint_hash().0[..], group_id, snapshot.canonical_encoding()],
    )?;
    record_checkpoint(tx, checkpoint)?;
    reached(EpochResetStep::SummaryRecorded)?;

    // 2. The switch. A genuine local advance: the new checkpoint's
    // predecessor is whatever checkpoint this device has installed now --
    // `None` only if it has never crossed a base before.
    let previous_checkpoint_hash: Option<[u8; 32]> = tx
        .query_row(
            "SELECT checkpoint_hash FROM group_history_bases WHERE group_id = ?1",
            [group_id],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?
        .map(|bytes| {
            <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
                SyncSqliteError::CorruptState(
                    "stored HistoryBase checkpoint_hash is not 32 bytes".into(),
                )
            })
        })
        .transpose()?;
    persist_history_base(tx, checkpoint, snapshot, previous_checkpoint_hash)?;
    reached(EpochResetStep::BaseSwitched)?;

    // 3. The absorbed history goes.
    retire_absorbed_history(
        tx,
        group_id,
        &HistoryBase::from_checkpoint(checkpoint),
        absorbed,
        snapshot,
    )?;
    reached(EpochResetStep::HistoryRetired)?;
    Ok(())
}

/// Records `checkpoint` as the group's newest, and closes the prune context
/// its insertion opens: nothing deleted after it is a prune that leaves a
/// stub behind.
fn record_checkpoint(conn: &Connection, checkpoint: &Checkpoint) -> Result<(), SyncSqliteError> {
    let group_id = checkpoint.group_id.as_str();
    let next_seq: i64 = conn.query_row(
        "SELECT COALESCE(MAX(seq), 0) + 1 FROM change_checkpoints WHERE group_id = ?1",
        [group_id],
        |row| row.get(0),
    )?;
    conn.execute(
        "INSERT OR REPLACE INTO change_checkpoints \
         (checkpoint_hash, group_id, snapshot_hash, encoded, seq) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            &checkpoint.checkpoint_hash().0[..],
            group_id,
            &checkpoint.snapshot_hash[..],
            checkpoint.canonical_encoding(),
            next_seq,
        ],
    )?;
    conn.execute("DELETE FROM active_prune_context WHERE group_id = ?1", [group_id])?;
    Ok(())
}

/// Removes every change of `group_id` -- exactly `absorbed` -- and every row
/// derived from one, leaving what `base` carries.
///
/// Nothing that names an absorbed change is kept as history: not a parent
/// edge, a head, a path effect, a prune stub, an orphan waiting on the
/// replaced history, a peer's acknowledged frontier, a conflict copy's
/// provenance, an interned causal basis or the materialized generation
/// that used it. A change arriving later that names an absorbed one is
/// either written on the replaced history, and refused as another history,
/// or names what it cannot have seen here.
///
/// A refusal decided against the replaced history (a change refused for
/// being written on another one) is dropped with it: it already stopped
/// standing when the group left that history.
///
/// Kept: the content of every row the base carries. Each version its rows
/// hold stays stored, and stays linked to a change that authored it, whose
/// authorization evidence is kept while a file row or a version link names
/// that change (`authorization_witness_gc` collects only what nothing
/// retained names) -- so the content stays servable with the change gone.
fn retire_absorbed_history(
    tx: &rusqlite::Transaction<'_>,
    group_id: &str,
    base: &HistoryBase,
    absorbed: &[ChangeHash],
    snapshot: &RebootstrapSnapshot,
) -> Result<(), SyncSqliteError> {
    let mut retained = seal::retained_change_hashes(tx, group_id)?;
    retained.sort();
    let mut expected = absorbed.to_vec();
    expected.sort();
    expected.dedup();
    if retained != expected {
        return Err(SyncSqliteError::CorruptState(format!(
            "base {} of group {group_id} absorbs {} changes but the group retains {}; a base \
             replaces the whole history below it",
            base.to_hex(),
            expected.len(),
            retained.len()
        )));
    }
    let absorbed: HashSet<ChangeHash> = expected.into_iter().collect();

    // Links first, while the rows that say who authored what are at hand.
    // One link per version: any change whose evidence authorized the
    // version justifies serving it, and a version already linked -- by an
    // earlier seal, say -- keeps the link it has.
    for file in &snapshot.files {
        let Some(author) = file.authoring_change_hash else { continue };
        if !absorbed.contains(&author) {
            continue;
        }
        let version = FileVersion::from_index_row(
            file.record.blocks.clone(),
            file.record.size,
            file.record.mtime_unix_nanos,
            file.record_kind,
            file.unix_mode,
            file.symlink_target.clone(),
            file.xattrs.clone(),
        );
        let linked: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM pruned_published_change_versions \
             WHERE group_id = ?1 AND version_hash = ?2)",
            params![group_id, &version.version_hash.0[..]],
            |row| row.get(0),
        )?;
        if !linked {
            crate::dag_store::record_pruned_published_change_version(
                tx,
                group_id,
                &version.version_hash,
                &author,
            )?;
        }
    }

    tx.execute(
        "DELETE FROM change_parents WHERE child_hash IN \
           (SELECT change_hash FROM changes WHERE group_id = ?1 \
            UNION ALL SELECT change_hash FROM orphan_changes WHERE group_id = ?1)",
        [group_id],
    )?;
    for table in [
        "change_file_versions",
        "changes",
        "group_heads",
        "orphan_changes",
        "device_frontier",
        "pruned_change_parents",
        "pruned_changes",
        "change_time_index",
    ] {
        tx.execute(&format!("DELETE FROM {table} WHERE group_id = ?1"), [group_id])?;
    }
    crate::dag_store::rebuild_group_path_frontier(tx, group_id)?;
    crate::dag_store::init_conflict_copy_provenance_schema(tx)?;
    tx.execute("DELETE FROM conflict_copy_provenance WHERE group_id = ?1", [group_id])?;
    crate::materialized_generation::forget_group_materialized_generations(
        tx,
        group_id,
        "history-sealed",
        crate::dag_store::now_unix_nanos(),
    )?;
    tx.execute(
        "DELETE FROM causal_basis_members WHERE basis_id IN \
           (SELECT basis_id FROM causal_basis_sets WHERE group_id = ?1)",
        [group_id],
    )?;
    tx.execute("DELETE FROM causal_basis_sets WHERE group_id = ?1", [group_id])?;
    tx.execute(
        "DELETE FROM rejected_changes WHERE group_id = ?1 \
           AND refused_on_epoch IS NOT NULL AND refused_on_epoch != ?2",
        params![group_id, &base.0[..]],
    )?;

    // Versions nothing retained references any more go; then every version
    // the snapshot carries is put back, the content of every head the base
    // carries included.
    crate::dag_store::sweep_unreferenced_file_versions(tx, group_id)?;
    for encoded in &snapshot.file_versions {
        crate::dag_store::put_file_version(tx, group_id, &decode_stored_file_version(encoded)?)?;
    }
    Ok(())
}

/// A Lamport value from a snapshot as the integer it is stored as. The
/// snapshot refuses values beyond this range when it is built or decoded;
/// this keeps a value that got past that from being stored wrapped negative.
fn storable_lamport(lamport: u64) -> Result<i64, SyncSqliteError> {
    i64::try_from(lamport).map_err(|_| {
        SyncSqliteError::CorruptState(format!(
            "history base Lamport value {lamport} is beyond the storable range"
        ))
    })
}

/// Refuses a base that does not carry every author in `local` at least as
/// far as `local` holds it: at a later position, or at the same position
/// attested by the same change.
fn require_base_carries_local_authors(
    group_id: &str,
    carried: &[SnapshotAuthorState],
    local: &[SnapshotAuthorState],
) -> Result<(), SyncSqliteError> {
    for held in local {
        let dominated = carried.iter().any(|author| {
            author.device_id == held.device_id
                && (author.watermark > held.watermark
                    || (author.watermark == held.watermark
                        && author.tip_change_hash == held.tip_change_hash))
        });
        if !dominated {
            return Err(SyncSqliteError::HistoryBaseInstallDoesNotCarryAuthor {
                group_id: group_id.to_owned(),
                device_id: held.device_id.clone(),
            });
        }
    }
    Ok(())
}

/// The rows a base carries, in place of the group's, and every version
/// they and its summary name. The rows are held where the disk under them still belongs to
/// the rows they replaced (see [`replace_group_files_from_snapshot`]).
fn install_base_rows(
    tx: &rusqlite::Transaction<'_>,
    group_id: &str,
    snapshot: &RebootstrapSnapshot,
) -> Result<(), SyncSqliteError> {
    replace_group_files_from_snapshot(tx, group_id, &snapshot.files)?;
    for encoded in &snapshot.file_versions {
        let version = decode_stored_file_version(encoded)?;
        crate::dag_store::put_file_version(tx, group_id, &version)?;
    }
    Ok(())
}

/// Writes the base's causal summary beside the base itself, replacing
/// whatever the previous base for this group left behind.
///
/// Scoped to the group and then keyed by the base, so the rows can never
/// be read as belonging to a base this device no longer has: a summary
/// left over from a replaced base would describe positions and heads from
/// a history this device has already thrown away.
fn persist_history_base_summary(
    conn: &Connection,
    group_id: &str,
    history_base: &HistoryBase,
    snapshot: &RebootstrapSnapshot,
) -> Result<(), SyncSqliteError> {
    for table in [
        "history_base_author_state",
        "history_base_path_heads",
        "history_base_named_heads",
        "history_base_carried_authors",
        "history_base_meta",
    ] {
        conn.execute(&format!("DELETE FROM {table} WHERE group_id = ?1"), [group_id])?;
    }
    for author in &snapshot.author_state {
        conn.execute(
            "INSERT INTO history_base_author_state \
             (group_id, base_hash, device_id, watermark, tip_change_hash) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                group_id,
                &history_base.0[..],
                &author.device_id,
                author.watermark.get() as i64,
                &author.tip_change_hash.0[..],
            ],
        )?;
    }
    for head in &snapshot.path_heads {
        conn.execute(
            "INSERT INTO history_base_path_heads \
             (group_id, base_hash, path, change_hash, device_id, author_seq, lamport, \
              version_hash, naming_device_id) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                group_id,
                &history_base.0[..],
                &head.path,
                &head.change_hash.0[..],
                &head.device_id,
                head.author_seq.get() as i64,
                storable_lamport(head.lamport)?,
                &head.version_hash.0[..],
                &head.naming_device_id,
            ],
        )?;
    }
    for author in snapshot.files.iter().filter_map(|file| file.authoring_change_hash) {
        conn.execute(
            "INSERT OR IGNORE INTO history_base_carried_authors \
             (group_id, base_hash, change_hash) VALUES (?1, ?2, ?3)",
            params![group_id, &history_base.0[..], &author.0[..]],
        )?;
    }
    conn.execute(
        "INSERT INTO history_base_meta (group_id, base_hash, lamport_ceiling) \
         VALUES (?1, ?2, ?3)",
        params![group_id, &history_base.0[..], storable_lamport(snapshot.lamport_ceiling)?],
    )?;
    Ok(())
}

fn persist_history_base(
    conn: &Connection,
    checkpoint: &Checkpoint,
    snapshot: &RebootstrapSnapshot,
    previous_checkpoint_hash: Option<[u8; 32]>,
) -> Result<(), SyncSqliteError> {
    let checkpoint_hash = checkpoint.checkpoint_hash();
    let history_base = HistoryBase::from_checkpoint(checkpoint);
    conn.execute(
        "INSERT OR REPLACE INTO group_history_bases \
         (group_id, history_base, checkpoint_hash, previous_checkpoint_hash) \
         VALUES (?1, ?2, ?3, ?4)",
        params![
            checkpoint.group_id.as_str(),
            &history_base.0[..],
            &checkpoint_hash.0[..],
            previous_checkpoint_hash.as_ref().map(|h| &h[..]),
        ],
    )?;
    persist_history_base_summary(conn, checkpoint.group_id.as_str(), &history_base, snapshot)?;
    // The snapshot of the base the group leaves goes with it. Only the
    // installed base is ever served, verified or merged again, and each
    // snapshot is a copy of every row the group held, so keeping them
    // would grow the store by the whole file set per base.
    conn.execute(
        "DELETE FROM change_checkpoint_snapshots WHERE group_id = ?1 AND checkpoint_hash != ?2",
        params![checkpoint.group_id.as_str(), &checkpoint_hash.0[..]],
    )?;
    // So does the header of the base the group leaves, unless a prune
    // proof still names it. The installed header is the one advertised and
    // the newest by sequence; nothing walks back to an older one (a merged
    // base is trusted by its signer, not by its provenance), and every
    // open re-verifies every header kept, so keeping one per base would
    // make startup grow with the number of seals.
    conn.execute(
        "DELETE FROM change_checkpoints \
         WHERE group_id = ?1 AND checkpoint_hash != ?2 \
           AND NOT EXISTS (SELECT 1 FROM pruned_changes pc \
                           WHERE pc.group_id = ?1 \
                             AND pc.checkpoint_hash = change_checkpoints.checkpoint_hash) \
           AND NOT EXISTS (SELECT 1 FROM pruned_change_parents pcp \
                           WHERE pcp.group_id = ?1 \
                             AND pcp.checkpoint_hash = change_checkpoints.checkpoint_hash)",
        params![checkpoint.group_id.as_str(), &checkpoint_hash.0[..]],
    )?;
    // Every author whose position here is the one this base carries now
    // resumes from the base: the change that attained that position is
    // absorbed into it, and the next change links to the base through its
    // signed history epoch. Last, after every position the install or seal
    // restores has been written, so only positions the base really carries
    // are matched.
    crate::dag_store::author_chain::anchor_carried_positions_on_base(
        conn,
        checkpoint.group_id.as_str(),
        &history_base,
        &snapshot.author_state,
    )
}

/// A rebootstrap-from-peer-snapshot install (currently unreachable in
/// production -- gated behind `yadorilink_replica_engine::rebootstrap::
/// COMPACTION_SCHEDULING_READY == false`, see that constant's own doc
/// comment) that nonetheless deletes and re-inserts every `files` row for
/// the group. `SnapshotFile` (peer-shared, wire-derived) has no
/// `held_reason`/`held_since_unix_nanos`/`pinned` fields at all -- these
/// are purely local, device-specific state, never sent over the wire (see
/// `MaterializationStateRepository::set_held`'s own doc comment) -- so a
/// plain DELETE+re-INSERT would silently wipe them for every path,
/// regardless of whether this device still has a live, unresolved reason
/// to protect that exact path.
///
/// For a hazard-held path this is the SAME "Hydrated-with-nothing-on-disk
/// looks like an offline deletion" bug class via a ninth mechanism:
/// `hold_record` opens no materialization intent (by design), and
/// `HazardHeld` settlement deliberately deletes that path's projection
/// obligation, on the theory that `held_reason` alone is what protects it
/// from then on. Losing `held_reason` here removes that last protection
/// with nothing compensating -- and the row becomes invisible to the
/// hazard-recheck sweep too (`list_held_paths` reads `held_reason IS NOT
/// NULL`). `pinned` is simpler but the same shape of bug: silently
/// unpinning a file makes it evictable without any user action.
///
/// Captured here, before the DELETE, and reapplied below for any path
/// this snapshot still carries as a live (`state == Current`, not
/// deleted) row -- the same condition that already decides
/// `materialization_state` just below, since a path this snapshot itself
/// says is now deleted, or superseded, has no live row to protect. See
/// this function's own post-insert `debug_assert!` for the enforced
/// half of this invariant.
///
/// `pinned` and `held_reason`/`held_since_unix_nanos` are captured
/// together but carried forward under DIFFERENT conditions below --
/// deliberately, not an oversight. A pin is path-keyed user intent ("I
/// always want this path's content locally"), not content-keyed, so it
/// must survive a delete-then-resurrect at this path exactly the way
/// `upsert_file_in_tx`'s own ordinary carry-forward already does
/// unconditionally (it reads whatever the current row was, deleted or
/// not, when superseding it -- see that function's own doc comment): the
/// captured `deleted` flag is NOT consulted for `pinned` below. A hold is
/// the opposite: it exists to protect a specific NAME from being
/// misclassified as offline-deleted while nothing is on disk under it,
/// which is meaningless for a row this device itself already believes is
/// deleted -- so `held_reason`/`held_since_unix_nanos` are only carried
/// forward when the captured row was NOT deleted, same as before.
fn replace_group_files_from_snapshot(
    conn: &Connection,
    group_id: &str,
    files: &[SnapshotFile],
) -> Result<(), SyncSqliteError> {
    let local_only_state: HashMap<String, (Option<String>, Option<i64>, bool, bool)> = {
        let mut stmt = conn.prepare(
            "SELECT path, held_reason, held_since_unix_nanos, pinned, deleted FROM files \
             WHERE group_id = ?1 AND state = 'current'",
        )?;
        let rows = stmt.query_map([group_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, Option<i64>>(2)?,
                row.get::<_, i64>(3)? != 0,
                row.get::<_, i64>(4)? != 0,
            ))
        })?;
        let mut map = HashMap::new();
        for row in rows {
            let (path, held_reason, held_since_unix_nanos, pinned, deleted) = row?;
            map.insert(path, (held_reason, held_since_unix_nanos, pinned, deleted));
        }
        map
    };

    // What this device had placed, read before the rows describing it go:
    // the disk still holds it after this function returns, and
    // `settle_replaced_rows` below decides from it which paths the disk now
    // disagrees with.
    let replaced = crate::snapshot_install_hold::live_rows(conn, group_id)?;
    conn.execute("DELETE FROM files WHERE group_id = ?1", [group_id])?;
    // One clock read for the whole replace: every row this install writes
    // was admitted by this device at the same instant, because that is
    // literally what happened -- the snapshot arrived and was applied as a
    // unit. See `file_index::upsert_file_in_tx`'s "stamping invariant"
    // section for why this write site has to stamp at all, and why several
    // rows of one path sharing a stamp is safe (the reader's `version_seq
    // DESC` tie-break resolves them to the path's current row).
    let admitted_at_unix_nanos = crate::file_index::now_unix_nanos_checked();
    // The same instant, recorded once more as this group's local history
    // floor -- the boundary below which this device's own `files` history
    // for the group no longer exists, because the DELETE above just removed
    // it. Written from the very same clock read as the row stamps, in the
    // same transaction, so the floor and the rows it bounds can never
    // describe two different instants.
    //
    // Not derivable from the reinstalled rows themselves, which is the whole
    // reason it is stored: they carry the SOURCE device's `version_seq`
    // numbering, so a file created long ago and never edited arrives with
    // `version_seq = 1` and looks, to any reader of `files` alone, exactly
    // like a path this device first indexed at the install. See
    // `crate::rewind_plan::classify_without_history` for the inference this
    // exists to keep honest.
    //
    // A clock that cannot be read at all (before the Unix epoch) writes no
    // floor and leaves any earlier one in place: every row this install
    // writes is then unstamped, which the reader already reports as
    // unanswerable on its own, and an older floor can only make an answer
    // more conservative, never more confident.
    //
    // The other writer of this table is a join's own link commit
    // (`enrollment::EnrollmentRepository::add_link_with_pending_enrollment_
    // and_begin_setup`); both go through the one statement in
    // `rewind_plan::record_local_history_floor` so their conflict handling
    // cannot drift apart.
    if let Some(admitted_at_unix_nanos) = admitted_at_unix_nanos {
        crate::rewind_plan::record_local_history_floor(conn, group_id, admitted_at_unix_nanos)?;
    }
    for file in files {
        let blocks_json = serde_json::to_string(&file.record.blocks)?;
        let is_live_current = file.state == SnapshotVersionState::Current && !file.record.deleted;
        let materialization_state = if is_live_current { "placeholder" } else { "hydrated" };
        let captured = is_live_current.then(|| local_only_state.get(&file.record.path)).flatten();
        // Unconditional on the captured row's own `deleted` flag -- see
        // this function's own doc comment for why a pin must survive a
        // delete-then-resurrect at this path.
        let pinned = captured.map(|(_, _, pinned, _)| *pinned).unwrap_or(false);
        // Gated on the captured row's `deleted` flag too, unlike `pinned`
        // just above -- see this function's own doc comment for why.
        let (held_reason, held_since_unix_nanos) = captured
            .filter(|(_, _, _, deleted)| !deleted)
            .map(|(held_reason, held_since_unix_nanos, _, _)| {
                (held_reason.clone(), *held_since_unix_nanos)
            })
            .unwrap_or((None, None));
        conn.execute(
            "INSERT INTO files \
             (group_id, path, size, mtime_unix_nanos, blocks_json, deleted, \
              version_seq, state, origin_device_id, materialization_state, pinned, \
              record_kind, symlink_target, unix_mode, symlink_out_of_root, \
              held_reason, held_since_unix_nanos, admitted_at_unix_nanos, xattrs_json, \
              authoring_change_hash) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, \
                     ?18, ?19, ?20)",
            params![
                group_id,
                &file.record.path,
                file.record.size as i64,
                file.record.mtime_unix_nanos,
                blocks_json,
                file.record.deleted as i64,
                file.version_seq,
                file.state.as_db_str(),
                file.origin_device_id.as_deref(),
                materialization_state,
                pinned as i64,
                file.record_kind.as_db_str(),
                file.symlink_target.as_deref(),
                crate::file_index::encode_unix_mode_column(file.unix_mode),
                file.symlink_out_of_root as i64,
                held_reason,
                held_since_unix_nanos,
                admitted_at_unix_nanos,
                crate::file_index::encode_xattrs_column(&file.xattrs),
                file.authoring_change_hash.as_ref().map(|hash| &hash.0[..]),
            ],
        )?;
    }
    // A base's rows are per path, so they can name a file `a` and a live
    // `a/x` at once, which no filesystem can hold. The index takes the
    // namespace projection's shape instead, as the reconcile pass would
    // leave it: `a` is a directory and its file sits at its copy name.
    let relocated: HashMap<String, String> =
        crate::snapshot_install_hold::relocate_rows_displaced_by_descendants(conn, group_id)?
            .into_iter()
            .collect();

    // The rows are replaced; the disk is not, and cannot be in this
    // transaction. Every path whose installed row places something other
    // than what this device had placed is held here, atomically with the
    // replacement, until a reconciliation pass has looked at its disk. See
    // `crate::snapshot_install_hold` for what that hold stops and why.
    crate::snapshot_install_hold::settle_replaced_rows(
        conn,
        group_id,
        &replaced,
        admitted_at_unix_nanos.unwrap_or_else(crate::dag_store::now_unix_nanos),
    )?;

    // Hard, code-enforced half of this fix, not just the apply logic
    // above: re-reads the ACTUAL persisted state (a fresh SELECT, not the
    // in-memory bookkeeping the loop above already trusted) and checks it
    // against what was captured before the DELETE. `COMPACTION_SCHEDULING_
    // READY` must not flip true while this invariant can silently break --
    // a future edit to this function that drops the held/pinned carry-
    // forward trips this in any debug build that exercises a rebootstrap
    // install, not just in the one production scenario that would
    // otherwise be the only thing to ever notice.
    #[cfg(debug_assertions)]
    {
        let mut stmt = conn.prepare(
            "SELECT path, held_reason, held_since_unix_nanos, pinned FROM files \
             WHERE group_id = ?1 AND state = 'current'",
        )?;
        let persisted: HashMap<String, (Option<String>, Option<i64>, bool)> = stmt
            .query_map([group_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    (
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, Option<i64>>(2)?,
                        row.get::<_, i64>(3)? != 0,
                    ),
                ))
            })?
            .collect::<Result<_, _>>()?;
        // A set, not a scan of `files` per captured row: this runs over
        // every current row of the group, and a scan per row made debug
        // installs and merges quadratic in the group's size.
        let live_current: std::collections::HashSet<&str> = files
            .iter()
            .filter(|f| f.state == SnapshotVersionState::Current && !f.record.deleted)
            .map(|f| f.record.path.as_str())
            .collect();
        for (path, (held_reason, held_since_unix_nanos, pinned, captured_deleted)) in
            &local_only_state
        {
            if !live_current.contains(path.as_str()) {
                continue;
            }
            // A relocated row carries its local-only state to its copy name.
            let persisted_path = relocated.get(path).unwrap_or(path);
            let (persisted_held, persisted_since, persisted_pinned) =
                persisted.get(persisted_path).cloned().unwrap_or((None, None, false));
            // `pinned` is checked unconditionally here -- NOT gated on
            // `captured_deleted` -- matching the apply logic above: a pin
            // must survive even when the captured row was itself already
            // deleted (see this function's own doc comment).
            debug_assert_eq!(
                persisted_pinned, *pinned,
                "rebootstrap-snapshot install dropped pinned for a path that survives as a live \
                 current row: {path}"
            );
            if *captured_deleted {
                // The captured row was itself already deleted -- held_reason/
                // held_since_unix_nanos are deliberately NOT carried forward
                // in that case (see this function's own doc comment), so
                // nothing further to check for this path.
                continue;
            }
            debug_assert_eq!(
                persisted_held.is_some(),
                held_reason.is_some(),
                "rebootstrap-snapshot install dropped held_reason for a path that survives as a \
                 live current row: {path}"
            );
            // Checked separately from `held_reason` above, not folded into
            // one tuple comparison: `get_held_state`'s own doc comment
            // notes the two columns are only ever written/cleared
            // together, but a regression that kept `held_reason` while
            // dropping `held_since_unix_nanos` would produce the exact
            // same "row still looks held" outcome the check above alone
            // cannot see -- `HeldState`'s `since_unix_nanos` field is
            // still read by callers (e.g. hazard-recheck age-based
            // policy), so a silently zeroed timestamp is its own bug even
            // though it doesn't change whether the tombstone loop's
            // `is_held` veto fires.
            debug_assert_eq!(
                persisted_since, *held_since_unix_nanos,
                "rebootstrap-snapshot install dropped held_since_unix_nanos for a path that \
                 survives as a live current row: {path}"
            );
        }
    }
    // Read only by the debug check above.
    let _ = relocated;

    Ok(())
}

fn op_version_hash(op: &Op) -> Option<VersionHash> {
    match op {
        Op::Put { version, .. } | Op::Move { version, .. } => Some(*version),
        Op::Delete { .. } => None,
    }
}

/// Installs the witness of every row the snapshot carries: for each
/// `SnapshotFile` that names an authoring change, installs that change's
/// witness evidence into `authorization_checkpoints`/`change_authorization`
/// (idempotent, via the SAME `attach_authorization_evidence_on_conn` a live
/// Change's receive path uses) and links the file's version to it via
/// [`crate::dag_store::record_pruned_published_change_version`].
///
/// Every row has to be witnessed: a base install keeps no change body
/// behind, so a witness is the only thing that can vouch for a row.
///
/// **Trust boundary**: this function performs NO cryptographic
/// verification of any witness -- it trusts the caller already did
/// (`authorization_checkpoint::verify_change_admission`, resolving the
/// authority key against this device's OWN policy chain, exactly the way
/// an ordinary received Change is verified). A witness for a change no
/// file actually needs is simply not installed (this loop only walks what
/// `files` references, never treats "the witness list" as itself the set to
/// install).
fn install_row_witnesses(
    tx: &rusqlite::Transaction<'_>,
    group_id: &str,
    snapshot: &RebootstrapSnapshot,
) -> Result<(), SyncSqliteError> {
    let witnesses_by_hash: HashMap<
        ChangeHash,
        &yadorilink_replica_engine::rebootstrap_snapshot::PublishedChangeWitness,
    > = snapshot.published_change_witnesses.iter().map(|w| (w.change_hash, w)).collect();

    // The evidence of every head the base carries, whether or not a row
    // holds it: the head is content still to be projected here, and the
    // next base this replica seals or mints has to carry its witness on.
    let mut heads: Vec<ChangeHash> =
        snapshot.path_heads.iter().map(|head| head.change_hash).collect();
    heads.sort();
    heads.dedup();
    for change in heads {
        let Some(witness) = witnesses_by_hash.get(&change) else {
            return Err(SyncSqliteError::CorruptState(format!(
                "history base snapshot carries head {} with no witness",
                change.to_hex(),
            )));
        };
        attach_witness(tx, group_id, &change, witness)?;
    }

    for file in &snapshot.files {
        let Some(authoring_change_hash) = file.authoring_change_hash else { continue };
        let Some(witness) = witnesses_by_hash.get(&authoring_change_hash) else {
            return Err(SyncSqliteError::CorruptState(format!(
                "history base snapshot retains {} authored by {} with no witness",
                file.record.path,
                authoring_change_hash.to_hex(),
            )));
        };

        attach_witness(tx, group_id, &authoring_change_hash, witness)?;

        // One link per version, as a seal records them: any change whose
        // evidence authorized the version justifies serving it, and two
        // rows can hold one version under two authors (a removal's
        // tombstone and the write it removed, say).
        let version = FileVersion::from_index_row(
            file.record.blocks.clone(),
            file.record.size,
            file.record.mtime_unix_nanos,
            file.record_kind,
            file.unix_mode,
            file.symlink_target.clone(),
            file.xattrs.clone(),
        );
        let linked: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM pruned_published_change_versions \
             WHERE group_id = ?1 AND version_hash = ?2)",
            params![group_id, &version.version_hash.0[..]],
            |row| row.get(0),
        )?;
        if !linked {
            crate::dag_store::record_pruned_published_change_version(
                tx,
                group_id,
                &version.version_hash,
                &authoring_change_hash,
            )?;
        }
    }
    Ok(())
}

/// Records `witness` as this replica's evidence for `change`.
fn attach_witness(
    tx: &rusqlite::Transaction<'_>,
    group_id: &str,
    change: &ChangeHash,
    witness: &yadorilink_replica_engine::rebootstrap_snapshot::PublishedChangeWitness,
) -> Result<(), SyncSqliteError> {
    let checkpoint = yadorilink_replica_domain::authorization_checkpoint::decode_checkpoint(
        &witness.checkpoint_encoded,
    )
    .map_err(|error| {
        SyncSqliteError::CorruptState(format!(
            "cannot install witness for {}: its checkpoint envelope is undecodable: {error:?}",
            change.to_hex()
        ))
    })?;
    let checkpoint_signature: [u8; 64] =
        witness.checkpoint_signature.as_slice().try_into().map_err(|_| {
            SyncSqliteError::CorruptState(format!(
                "cannot install witness for {}: its checkpoint signature is not 64 bytes",
                change.to_hex()
            ))
        })?;
    crate::dag_store::published_view::attach_authorization_evidence_on_conn(
        tx,
        &witness.checkpoint_hash,
        group_id,
        checkpoint.device_id.as_str(),
        checkpoint.checkpoint_seq,
        &witness.checkpoint_encoded,
        &checkpoint_signature,
        &witness.author_signing_public_key,
        &[(*change, witness.merkle_proof_encoded.clone())],
    )
}

#[cfg(test)]
mod summary_join_tests;

#[cfg(test)]
mod replace_group_files_from_snapshot_tests;

#[cfg(test)]
mod group_history_summary_tests;

/// The named-base-heads record is derived: checked at startup, recomputed
/// by a rebuild.
#[cfg(test)]
mod named_heads_rebuild_tests;

/// Installing a base with the atomic epoch reset, and the fixtures the
/// other install tests build on.
#[cfg(test)]
mod base_install_tests;

/// Where an author resumes on an installed base: the base's own carried
/// position, continued by the change's signed history epoch rather than by
/// naming the absorbed tip.
#[cfg(test)]
mod base_anchored_author_tests;

/// Where the Lamport clock resumes on an installed base: above the
/// greatest value the history the base absorbed reached.
#[cfg(test)]
mod base_anchored_lamport_tests;

/// What an install leaves between the rows it replaced and the disk those
/// rows described.
#[cfg(test)]
mod install_disk_hold_tests;

/// Sealing a group's history into a new base: the exact summary it
/// carries, its preconditions, and where authors resume after it.
#[cfg(test)]
mod seal_tests;

/// Sealing a group whose paths form a tree: the rows a seal carries are
/// the namespace projection of the summary it carries.
#[cfg(test)]
mod seal_namespace_tests;

/// What a committed seal leaves: the group on the new base, nothing of the
/// history it absorbed still retained, and authors, clock and files
/// continuing from the base.
#[cfg(test)]
mod epoch_reset_tests;

#[cfg(test)]
mod foreign_merge_tests;

#[cfg(test)]
mod merge_install_tests;

/// What stays bounded across repeated seals and merges: every table's
/// size depends on the files and the authors, never on how many changes,
/// seals or merges the group has been through.
#[cfg(test)]
mod bounded_metadata_tests;

/// What admission, a seal, an install and a merge cost as the group grows,
/// counted in SQLite's own steps rather than timed.
#[cfg(test)]
mod scale_cost_tests;
