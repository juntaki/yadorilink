//! Persistence for the change-history DAG, stored in the same SQLite
//! database as the file index.
//!
//! Every function here takes a plain `&Connection`. A `rusqlite::Transaction`
//! dereferences to `Connection`, so passing `&tx` runs the operation inside
//! that transaction — this is what lets a local mutation append its change
//! and mutate the file index atomically, in one commit. Reads take the same
//! `&Connection` so callers can query heads/ancestry either standalone or
//! inside a write transaction.
//!
//! This module is a thin orchestration layer over five submodules, each
//! owning one derived structure and re-verifying it against the signed
//! canonical `Change`/`Checkpoint` bytes rather than trusting it at face
//! value -- the split exists so a gap in any one of them (as several were,
//! found by the `dag_*_integrity_red.rs` integration tests) is caught by
//! that structure's own `repair`/read path, not lost in one large function
//! that touches every table at once:
//! - [`retained_history_integrity`] — `changes` (durable, fail-closed) and
//!   the `change_parents` ancestry index derived from it.
//! - [`orphan_integrity`] — `orphan_changes`, a bounded, best-effort holding
//!   buffer (drop-on-inconsistency, never fail-closed).
//! - [`frontier_index`] — `group_heads` and `device_frontier`.
//! - [`serving_authorization_index`] — `file_versions`, the
//!   `change_file_versions` block-serving authorization boundary, and
//!   `group_block_provenance`.
//! - [`checkpoint_store`] — `change_checkpoints`, condensed pruned prefixes.
//! - [`causal_basis`] — `causal_basis_sets`/`causal_basis_members`, the
//!   content-addressed, deduplicated encoding of a causal frontier (an
//!   arbitrary set of change hashes) shared across every path that frontier
//!   backs.
//! - [`retention_roots`] — `dag_retention_roots`, the one table any
//!   subsystem registers an exact retained change hash into (and states why),
//!   so compaction never has to decode a subsystem-specific payload to learn
//!   what it must not evict.
//!
//! What stays here: schema creation/repair orchestration
//! ([`init_dag_schema`]), and the operations that inherently cross more than
//! one of those structures in a single atomic step
//! ([`admit_change`]/[`emit_local_change`]/[`commit_prune`]).

pub(crate) mod author_chain;
mod causal_basis;
mod checkpoint_store;
mod conflict_authoring;
mod frontier_index;
pub(crate) mod observed_base_heads;
mod orphan_integrity;
pub(crate) mod path_frontier;
pub mod published_view;
mod recursive_operations;
mod rejected_changes;
mod retained_history_integrity;
mod retention_roots;
mod serving_authorization_index;

pub use causal_basis::{intern_causal_basis, lookup_causal_basis_members};
pub use checkpoint_store::latest_checkpoint;
pub(crate) use conflict_authoring::directory_head_changes;
pub use conflict_authoring::record_conflict_copy_ops_provenance;
pub use conflict_authoring::{
    derive_required_conflict_copy_ops, derive_required_conflict_copy_ops_including_buried_roots,
    init_conflict_copy_provenance_schema, path_heads_at_frontier,
    path_heads_at_frontier_including_buried_roots, validate_carrier_conflict_copy_ops,
};
pub use frontier_index::{
    get_device_frontier, group_heads, max_parent_lamport, remove_device_frontier,
    set_device_frontier,
};
pub use observed_base_heads::SeenVersions;
pub use orphan_integrity::{promote_orphans, ORPHAN_BOUND};
pub(crate) use path_frontier::record_admission as record_path_frontier_admission;
/// `live_path_heads`/`rebuild_group_path_frontier` are public so the
/// differential suite can hold the derived index against an independent
/// re-derivation of the same question -- see
/// `tests/path_frontier_differential.rs`. `record_path_frontier_admission`
/// stays crate-visible: it is only correct called from inside an
/// admission transaction, after that transaction has updated
/// `group_heads`.
pub use path_frontier::{
    gamma_has_live_descendant, gamma_heads_at_level, gamma_heads_by_path, has_live_descendant,
    live_descendant_paths, live_heads_at_level, live_heads_by_path, live_path_heads,
    path_gamma_heads, rebuild_group as rebuild_group_path_frontier,
};
pub use recursive_operations::{
    check_recursive_operation_part, init_recursive_operations_schema,
    record_recursive_operation_part, recursive_operation, recursive_operation_of_change,
    RecordedRecursiveOperation, RecordedRecursivePart, RecursiveOperationCompleteness,
};
pub use rejected_changes::list_rejected_changes;
#[cfg(test)]
pub(crate) use rejected_changes::record_rejected_change;
pub(crate) use rejected_changes::{
    current_rejection_domain, current_rules_stamps, is_change_rejected,
    record_rejected_change_resting_on, RejectionDomain,
};
pub use retained_history_integrity::{
    frontier_heads_at_or_before, get_encoded, group_history_paths, has_all_parents, has_change,
    has_change_or_pruned, is_ancestor, is_verified_authoring_change, lamport_of, parents_of,
};
pub use retention_roots::{
    full_payload_retained_block_hashes, full_payload_retained_block_hashes_all_groups,
    register_retention_root, release_retention_root, RetentionClass,
};
pub use serving_authorization_index::sweep_unreferenced_file_versions;
pub use serving_authorization_index::{
    get_file_version, group_file_version_references_block, group_has_block_provenance,
    has_file_version, put_file_version, record_group_block_provenance,
    record_pruned_published_change_version,
};

use rusqlite::{Connection, OptionalExtension};

#[cfg(test)]
use orphan_integrity::insert_orphan;
#[cfg(test)]
use retained_history_integrity::append_change;
#[cfg(test)]
use yadorilink_replica_domain::file::FileVersion;

use crate::error::SyncSqliteError;
use yadorilink_replica_domain::change::{
    encoded_op_len, Change, ChangePurpose, Op, RepairObligation, MAX_CHANGE_OP_BYTES,
};
use yadorilink_replica_domain::ids::{AuthorSeq, ChangeHash, DeviceId, FolderGroupId};
use yadorilink_replica_domain::recursive_operation::RecursiveOperation;

pub use yadorilink_replica_domain::admission::{
    AdmissionRefusal, AdmitOutcome, AdmitResult, AuthorChainRefusal, ChangeEmitter, ChangeOrdering,
    PathRefusal,
};
pub use yadorilink_replica_domain::rebootstrap::HistoryEpoch;

/// The `change_checkpoints` table schema. If that schema ever changes,
/// this copy must change with it.
pub(crate) const CHECKPOINT_TABLE_MIGRATION: &str = "\
CREATE TABLE IF NOT EXISTS change_checkpoints (
    checkpoint_hash BLOB PRIMARY KEY,
    group_id        TEXT NOT NULL,
    snapshot_hash   BLOB NOT NULL,
    encoded         BLOB NOT NULL,
    seq             INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_change_checkpoints_group
    ON change_checkpoints(group_id, seq);
";

fn dst_trace(path: &str, msg: impl FnOnce() -> String) {
    if dst_trace_enabled(path) {
        eprintln!("[DSTTRACE {path}] {}", msg());
    }
}

fn dst_trace_enabled(path: &str) -> bool {
    static TRACED: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();
    let traced = TRACED.get_or_init(|| std::env::var("DST_TRACE_PATH").ok());
    match traced.as_deref() {
        None => false,
        Some("*") => true,
        Some(spec) => spec.split(',').any(|candidate| candidate.trim() == path),
    }
}

/// Creates the DAG tables. There are no migrations here: a database stamped
/// with an older `SCHEMA_VERSION` is refused at open, so every table this
/// creates is created in its current shape, once.
#[allow(clippy::too_many_lines, reason = "one DAG schema-creation sequence, kept in one place")]
pub fn init_dag_schema(conn: &Connection) -> Result<(), SyncSqliteError> {
    // Admission runs more distinct statements than rusqlite caches by
    // default; see `STATEMENT_CACHE_CAPACITY`. Pooled connections get this
    // from the pool, and this covers a connection the store is opened on
    // directly.
    conn.set_prepared_statement_cache_capacity(yadorilink_sqlite_runtime::STATEMENT_CACHE_CAPACITY);
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS changes (
            change_hash          BLOB PRIMARY KEY,
            group_id             TEXT NOT NULL,
            device_id            TEXT NOT NULL,
            -- This change's position in its own author's chain within
            -- `group_id`: the third component of its causal dot,
            -- `(group_id, device_id, author_seq)`. A plain column copy of
            -- the signed field, exactly like `device_id` and `lamport`,
            -- so an author's next position can be read without decoding
            -- `encoded`. It counts only this author's own writes, is
            -- consecutive from 1, and never restarts.
            author_seq           INTEGER NOT NULL,
            lamport              INTEGER NOT NULL,
            encoded              BLOB NOT NULL,
            -- `Change::authenticated_header_encoding()` for this row,
            -- computed once at append time. Retained so a future prune can
            -- hand it straight to `pruned_changes.authenticated_header`
            -- (via the `BEFORE DELETE` trigger in
            -- `retained_history_integrity`) without decoding `encoded` --
            -- pure column copy, same as `lamport`/`device_id` already are.
            authenticated_header BLOB NOT NULL DEFAULT X''
        );
        CREATE INDEX IF NOT EXISTS changes_by_group ON changes(group_id);
        -- Unique, not merely an index. Two different changes at one dot is
        -- equivocation: the same author claiming two histories at the same
        -- position, which no merge rule can reconcile and which makes a
        -- per-author watermark stop deciding what a replica holds.
        -- Admission refuses it on its own, and this constraint is the last
        -- place it can be refused -- it holds for every writer of this
        -- table, including one that has not yet been written. It also
        -- serves the lookup the emission funnel does before every single
        -- local edit, which must not cost a scan of the whole group.
        CREATE UNIQUE INDEX IF NOT EXISTS changes_by_author
            ON changes(group_id, device_id, author_seq);

        CREATE TABLE IF NOT EXISTS change_parents (
            child_hash  BLOB NOT NULL,
            parent_hash BLOB NOT NULL,
            PRIMARY KEY (child_hash, parent_hash)
        );
        CREATE INDEX IF NOT EXISTS change_parents_by_parent
            ON change_parents(parent_hash);

        CREATE TABLE IF NOT EXISTS authorization_checkpoints (
            checkpoint_hash BLOB PRIMARY KEY,
            group_id        TEXT NOT NULL,
            device_id       TEXT NOT NULL,
            checkpoint_seq  INTEGER NOT NULL,
            encoded         BLOB NOT NULL,
            signature       BLOB NOT NULL,
            -- The device's raw 32-byte Ed25519 verifying key, carried
            -- alongside the checkpoint so a fresh device (or one that
            -- never pinned this author's key locally) can verify history
            -- from a since-revoked/forgotten author. The daemon
            -- verifies `SHA256(author_signing_public_key) ==
            -- signing_key_fingerprint` (implied by `encoded`'s own signed
            -- content) before ever storing this, so a stored row's key is
            -- always the one the authority actually vouched for.
            author_signing_public_key BLOB NOT NULL
        );
        CREATE INDEX IF NOT EXISTS authorization_checkpoints_by_device
            ON authorization_checkpoints(group_id, device_id);

        CREATE TABLE IF NOT EXISTS change_authorization (
            change_hash     BLOB PRIMARY KEY,
            checkpoint_hash BLOB NOT NULL,
            merkle_proof    BLOB NOT NULL
        );
        CREATE INDEX IF NOT EXISTS change_authorization_by_checkpoint
            ON change_authorization(checkpoint_hash);

        -- Enforced by triggers, not a `REFERENCES` + `PRAGMA foreign_keys`
        -- pair: `foreign_keys` is a per-CONNECTION setting that, once
        -- turned on, stays on for that connection's entire remaining
        -- lifetime (including after the transaction that set it commits)
        -- -- it is not scoped to one transaction the way an earlier
        -- revision of this schema assumed. That also means it backstops
        -- nothing against a DIFFERENT connection (e.g. a pooled one)
        -- whose own `foreign_keys` setting is still off. A trigger fires
        -- unconditionally, on every connection, regardless of any pragma
        -- -- the correct mechanism for an invariant these two tables must
        -- hold no matter which connection or future writer touches them.
        CREATE TRIGGER IF NOT EXISTS change_authorization_requires_checkpoint
        BEFORE INSERT ON change_authorization
        WHEN NOT EXISTS (
            SELECT 1 FROM authorization_checkpoints
            WHERE checkpoint_hash = NEW.checkpoint_hash
        )
        BEGIN
            SELECT RAISE(ABORT, 'change_authorization.checkpoint_hash references a checkpoint that does not exist');
        END;

        -- The reverse direction: a checkpoint must not be deleted while
        -- any change_authorization row still cites it.
        -- `authorization_witness_gc` deletes a checkpoint only after the
        -- last evidence citing it is gone; this trigger holds that order
        -- for any other deletion path too.
        CREATE TRIGGER IF NOT EXISTS authorization_checkpoints_protect_referenced
        BEFORE DELETE ON authorization_checkpoints
        WHEN EXISTS (
            SELECT 1 FROM change_authorization
            WHERE checkpoint_hash = OLD.checkpoint_hash
        )
        BEGIN
            SELECT RAISE(ABORT, 'authorization_checkpoints row is still referenced by change_authorization');
        END;

        -- One row per admission EVENT on this device (not per change --
        -- `admission_seq` is this device's own local per-group counter,
        -- unrelated to `lamport`), storing the group's actual head-set
        -- immediately after that admission completed, alongside this
        -- device's own local clock at that moment (never a peer-reported
        -- or change-embedded timestamp -- untrusted input, same reasoning
        -- as `lamport` itself).
        --
        -- Ground truth captured at write time, not derived later: `lamport`
        -- alone cannot represent "the frontier at time T", because it does
        -- not form a meaningful total order across concurrent branches --
        -- two causally-unrelated changes (neither an ancestor of the
        -- other) can both be genuine live heads simultaneously with no
        -- single "highest" one, and lamport values are not even guaranteed
        -- distinct across devices that concurrently emit off the same
        -- parent. `heads_snapshot` sidesteps this entirely by recording the
        -- REAL head-set (as `group_heads` itself already computes it, right
        -- after this same admission's own head-set mutations), not a
        -- scalar approximation of it.
        --
        -- Answers "what was this group's frontier at wall-clock time T, as
        -- observed on this device" with a single index seek (`ORDER BY
        -- observed_at_unix_nanos DESC LIMIT 1` against the index below),
        -- never a DAG walk and never a scan of the whole retained history.
        --
        -- Deliberately NOT the mechanism behind Folder Rewind's per-path
        -- planning layer (`crate::rewind_plan`): a head-set says what the
        -- group's DAG frontier was, and turning that into "what should
        -- path X contain at T" would need a per-path ancestor walk against
        -- a historical frontier -- exactly the call shape `is_ancestor`'s
        -- own doc comment documents as expensive at 100k-file scale. This table
        -- answers a group-level question and stays on that side.
        CREATE TABLE IF NOT EXISTS change_time_index (
            group_id               TEXT NOT NULL,
            admission_seq          INTEGER NOT NULL,
            observed_at_unix_nanos INTEGER NOT NULL,
            -- Sorted concatenation of 32-byte `ChangeHash`es -- the group's
            -- `group_heads` rows immediately after this admission. Sorted
            -- so two snapshots covering the same actual head-set always
            -- compare byte-equal, and so decoding never depends on
            -- insertion order.
            heads_snapshot         BLOB NOT NULL,
            PRIMARY KEY (group_id, admission_seq)
        );
        -- `admission_seq` is the third column so `frontier_heads_at_or_
        -- before`'s `ORDER BY observed_at_unix_nanos DESC, admission_seq
        -- DESC LIMIT 1` is satisfied entirely by a reverse index scan that
        -- stops at the first row. Without it the tie-break (needed because
        -- two admissions can share a coarse-granularity timestamp -- see
        -- that function's own doc comment) would force a temporary sort
        -- over the whole `observed_at_unix_nanos <= ?` range, turning a
        -- bounded seek into a cost proportional to the group's entire
        -- admission history.
        CREATE INDEX IF NOT EXISTS change_time_index_by_time
            ON change_time_index(group_id, observed_at_unix_nanos, admission_seq);

        CREATE TABLE IF NOT EXISTS group_heads (
            group_id    TEXT NOT NULL,
            change_hash BLOB NOT NULL,
            PRIMARY KEY (group_id, change_hash)
        );

        CREATE TABLE IF NOT EXISTS device_frontier (
            group_id    TEXT NOT NULL,
            device_id   TEXT NOT NULL,
            change_hash BLOB NOT NULL,
            PRIMARY KEY (group_id, device_id, change_hash)
        );

        CREATE TABLE IF NOT EXISTS orphan_changes (
            change_hash  BLOB PRIMARY KEY,
            group_id     TEXT NOT NULL,
            device_id    TEXT NOT NULL,
            lamport      INTEGER NOT NULL,
            encoded      BLOB NOT NULL,
            received_seq INTEGER NOT NULL,
            -- Whether live admission accepted this Change on the DELIVERING
            -- PEER's authority (a current writer relaying somebody else's
            -- already-signed work) rather than on its own author's. A row
            -- with this set was never subject to an author-freshness
            -- requirement at receipt, so `orphan_integrity::promote_orphans`
            -- must not impose one on it at promotion time. Added to an
            -- `DEFAULT 0` so a row reads as the conservative
            -- (non-exempt) value it was actually admitted under, and so a
            -- downgrade to a build that never writes the column still
            -- inserts a valid row.
            relay_admitted INTEGER NOT NULL DEFAULT 0,
            -- WHICH peer's authority that was: the authenticated transport
            -- identity of the session the Change arrived on. Empty string
            -- for a row that was not relay-admitted.
            --
            -- This column buys nothing at admission time -- the decision is
            -- already made and recorded in `relay_admitted` -- and exists
            -- purely so the decision stays auditable afterwards. Promotion
            -- deliberately does NOT re-check the relay's current role (see
            -- `promote_orphans`), `ORPHAN_BOUND` bounds this table by ROW
            -- COUNT globally with no TTL, and eviction only runs on insert
            -- -- so on a quiet device a vouched row can sit indefinitely and
            -- promote long after both its author and its voucher were
            -- revoked. That is a defensible decision (the relay's
            -- authorization AT RECEIPT is what vouched for the row, and
            -- re-checking would reintroduce the convergence failure the
            -- exemption closes) but it is only defensible while an operator
            -- can still answer "who vouched for this?". Without this column
            -- that question has no answer at all, which is the part that
            -- is not defensible.
            relay_vouched_by TEXT NOT NULL DEFAULT '',
            -- The previous change of this change's own author, when that is
            -- what the row is waiting for. NULL when the row is waiting
            -- only on DAG ancestry (or when the change names no
            -- predecessor at all, which only a first change may do).
            --
            -- Deliberately NOT a `change_parents` edge. That table is DAG
            -- ancestry and `frontier_index::repair` reads it to decide
            -- which changes still have children; an author link recorded
            -- there would drop the author's own tip out of the group heads.
            -- Author ordering and causality are two relations, and each
            -- gets its own column.
            author_prev_hash BLOB
        );
        -- `promote_orphans` wakes a row whose named author predecessor has
        -- just been admitted, and `missing_ancestor_frontier` asks the same
        -- question in reverse; both look a row up by this name, once per
        -- admitted change.
        CREATE INDEX IF NOT EXISTS orphan_changes_by_author_prev
            ON orphan_changes(author_prev_hash);
        -- `insert_orphan`'s own eviction check (`ORDER BY received_seq DESC
        -- LIMIT -1 OFFSET ORPHAN_BOUND`, run on every single insert) has no
        -- other way to avoid a full-table sort every time without this --
        -- with it, skipping past the first `ORPHAN_BOUND` rows is a bounded
        -- index walk instead of re-sorting the whole (potentially still-
        -- growing) table from scratch on each of what can be hundreds of
        -- buffered orphans in one anti-entropy round.
        CREATE INDEX IF NOT EXISTS orphan_changes_by_received_seq
            ON orphan_changes(received_seq);

        CREATE TABLE IF NOT EXISTS file_versions (
            version_hash BLOB NOT NULL,
            group_id     TEXT NOT NULL,
            encoded      BLOB NOT NULL,
            PRIMARY KEY (group_id, version_hash)
        );
        CREATE INDEX IF NOT EXISTS file_versions_by_group ON file_versions(group_id);

        CREATE TABLE IF NOT EXISTS change_file_versions (
            group_id     TEXT NOT NULL,
            change_hash  BLOB NOT NULL,
            version_hash BLOB NOT NULL,
            PRIMARY KEY (group_id, change_hash, version_hash)
        );
        CREATE INDEX IF NOT EXISTS change_file_versions_by_version
            ON change_file_versions(group_id, version_hash);

        -- Physical blocks remain globally content-addressed and deduplicated,
        -- while this table records the groups through which this device has
        -- actually obtained the verified bytes.  FileVersion metadata alone
        -- must never create one of these rows.
        CREATE TABLE IF NOT EXISTS group_block_provenance (
            group_id   TEXT NOT NULL,
            block_hash BLOB NOT NULL,
            PRIMARY KEY (group_id, block_hash)
        );

        -- A version's `change_file_versions` justification is lost the
        -- moment its only referencing (authoring) change is compacted away
        -- (`commit_prune` deletes that change's `change_file_versions`
        -- rows), even when the version itself is still a live (current or
        -- retained superseded) row in the group's materialized file index,
        -- AND even though that change's own `change_authorization` row
        -- (its checkpoint evidence) is deliberately left untouched by
        -- `commit_prune` (until `authorization_witness_gc` collects it once
        -- nothing retained names the change) -- the witness model: this table is exactly that lost
        -- link, version_hash to its
        -- authoring change_hash, so `published_group_file_version_
        -- references_block` can still reach the SAME, already-verified
        -- `change_authorization`/`authorization_checkpoints` rows a live
        -- change's version would -- replacing the former evidence-FREE
        -- `compacted_file_version_authorization` (removed), which granted
        -- block-serving with no evidence at all. A cross-device rebootstrap
        -- install populates this only after the daemon layer independently
        -- re-verifies the wire-carried witness evidence
        -- (`authorization_checkpoint::verify_change_admission`) and
        -- installs it into `change_authorization`/`authorization_
        -- checkpoints` via the ordinary `attach_authorization_evidence`
        -- path first -- this table's mere existence is not itself proof of
        -- anything, exactly like `change_authorization`'s own trust
        -- boundary; it is a link, not an evidence store.
        CREATE TABLE IF NOT EXISTS pruned_published_change_versions (
            group_id              TEXT NOT NULL,
            version_hash          BLOB NOT NULL,
            authoring_change_hash BLOB NOT NULL,
            PRIMARY KEY (group_id, version_hash)
        );

        -- A change hash `admit_change` refused for a reason that cannot
        -- resolve on retry (see `rejected_changes`'s module doc comment).
        -- `change_hash` alone is the key, matching `changes`'s own PK
        -- shape: a change is content-addressed, so the same hash always
        -- means the same bytes and the same rejection everywhere.
        -- `rejection_domain` names which body of rules produced the
        -- verdict, and `rules_version` is THAT domain's version at the time
        -- the row was recorded — see `rejected_changes`'s module doc
        -- comment on why a row is only trusted as a settled verdict while
        -- its stamp still matches its own domain's rules, and why one
        -- version number for every domain would both strand and needlessly
        -- re-open verdicts.
        CREATE TABLE IF NOT EXISTS rejected_changes (
            change_hash      BLOB PRIMARY KEY,
            group_id         TEXT NOT NULL,
            reason           TEXT NOT NULL,
            rejected_at      INTEGER NOT NULL,
            rejection_domain TEXT NOT NULL,
            rules_version    INTEGER NOT NULL,
            -- The refused change this verdict follows from, when it is not
            -- a verdict on this change's own content: a DAG parent or
            -- author predecessor that can never be held here. NULL for a
            -- verdict of its own. The row stands only while that change's
            -- refusal does -- see `rejected_changes`'s module doc comment.
            rests_on         BLOB,
            -- The history this replica was on when it refused the change,
            -- for a verdict measured against that history (a change written
            -- on another one): empty for genesis, the base's bytes above
            -- one. The row stands only while the group is still on it. NULL
            -- for a verdict that does not depend on the local history.
            refused_on_epoch BLOB
        );
        CREATE INDEX IF NOT EXISTS rejected_changes_by_group ON rejected_changes(group_id);
        "#,
    )?;
    author_chain::init_author_chain_schema(conn)?;
    causal_basis::init_causal_basis_schema(conn)?;
    path_frontier::init_path_frontier_schema(conn)?;
    retention_roots::init_retention_roots_schema(conn)?;
    recursive_operations::init_recursive_operations_schema(conn)?;
    crate::projection_obligations::init_projection_obligations_schema(conn)?;
    // A path's materialized generation names a causal basis interned in
    // this schema, and the writers that change what that basis may mean --
    // local emission, prune, a base install -- live here too and must be
    // able to retire it in their own transaction. So the table has to
    // exist wherever the DAG does. Pure `CREATE ... IF NOT EXISTS`.
    crate::materialized_generation::init_materialized_generation_schema(conn)?;
    // Written by local capture in the transaction that emits its change, so
    // it has to exist wherever the DAG does, like the table above.
    crate::local_capture_provenance::init_local_capture_provenance_schema(conn)?;
    // Bumps the same per-path mutation fence the table above keeps, in the
    // same transaction, so it has to exist wherever that one does.
    crate::structural_origin::init_structural_origin_schema(conn)?;
    // The history-base tables belong to the same call. Admission measures
    // every incoming change against the base this group holds, so the row
    // that says which base that is has to exist wherever the DAG exists --
    // and reading it must not have to create it first, which on the
    // admission path would turn a read into a write. Created before the
    // repair passes below, which check the record of named base heads as
    // part of the derived path state. Pure `CREATE ... IF NOT EXISTS`,
    // idempotent with the re-bootstrap module's own calls.
    crate::rebootstrap_store::init_rebootstrap_schema(conn)?;
    // Also reports any group whose stored path effects no longer match
    // the changes they were derived from -- checked inside that pass
    // because it is already decoding every retained change, so the extra
    // cost is one indexed lookup and one op scan per change rather than a
    // second decode of the whole history.
    let effect_mismatches = retained_history_integrity::repair(conn)?;
    orphan_integrity::repair(conn)?;
    // Before the orphan promotion sweep below, and not after it. Promotion
    // applies the author-chain rules, and a refusal there is destructive:
    // the orphan is recorded as permanently rejected and its subtree is
    // dropped. This rebuild exists precisely for the case where
    // `author_chain_state` is missing or behind, which is exactly the case
    // in which a sweep run first would measure every buffered orphan against
    // a position its author has in fact already passed, refuse each one as a
    // sequence gap, and destroy it moments before the rebuild that would
    // have made it admissible.
    //
    // One transaction for the whole pass: it only ever raises watermarks, so
    // a crash part-way through costs nothing but a repeat at the next start,
    // but there is no reason to leave the window open. Running it first
    // changes nothing when the state is already current, because
    // `advance_author_state` never lowers anything and `append_change`
    // advances the state on every promotion anyway.
    {
        let tx = conn.unchecked_transaction()?;
        author_chain::rebuild_author_chain_state(&tx)?;
        tx.commit()?;
    }
    // Self-heal: an orphan whose parent is already durably admitted but that
    // was never promoted (a crash between `append_change` and
    // `promote_orphans`, or an orphan buffered directly out of band) has no
    // future admission left to seed a promotion pass for it, since ordinary
    // operation only seeds from the change that was just admitted. This is
    // the one place a full-buffer sweep is appropriate: it runs once at
    // startup, not once per admission.
    //
    // Under `AuthorizationCheckpoint` admission, a change's authorization is a static,
    // content-addressed fact that never goes stale between original
    // admission and this sweep -- there is no live-trust dependency left
    // to defer on, so this can promote directly, immediately, at startup.
    let self_heal_seeds = orphan_integrity::already_satisfied_parents(conn)?;
    if !self_heal_seeds.is_empty() {
        // Unlike ordinary admission (whose caller always wraps `admit_change`
        // in `write_immediate`), nothing wraps this startup sweep: `init_dag_
        // schema` runs directly on a freshly-opened, plain autocommit
        // connection (see `SyncDatabase::open`/`open_in_memory`'s
        // `schema_init(&conn)` call, with no enclosing transaction). Without
        // this transaction, a crash between `promote_orphans` committing and
        // `bump_execution_fence_for_promoted` running would leave a change
        // durably promoted with no corresponding fence bump -- the exact
        // "DAG holds a change, no fence exists for its paths" crash window
        // `admit_change`'s own promotion path never has, since it never runs
        // outside `write_immediate`.
        let tx = conn.unchecked_transaction()?;
        let self_healed = orphan_integrity::promote_orphans(&tx, &self_heal_seeds)?;
        // Each of these just moved from buffered to durably admitted, on
        // this very connection -- exactly what `admit_change`'s own
        // promotion step does, and it must be fenced the same way: a
        // reservation recorded before a crash is still in the table across
        // restart, and a plan built against it must not resume as if this
        // newly-promoted change had never happened.
        bump_execution_fence_for_promoted(&tx, &self_healed)?;
        tx.commit()?;
    }
    frontier_index::repair(conn)?;
    // The normalized path effects and the live path frontier are derived
    // from retained history, so any group whose derived rows do not hold
    // up against it is rebuilt from canonical changes -- see
    // `path_frontier::groups_needing_rebuild` for what "hold up" means
    // and why a rebuild is the answer to both an absent index and a
    // damaged one. That rebuild is also the entire migration for a
    // database that predates these tables: there is no version ladder to
    // walk, because a replacement never has to reconcile with what it
    // replaces.
    //
    // This runs after `frontier_index::repair` above deliberately: the
    // rebuild replays admission, and a replay whose starting frontier
    // disagreed with the repaired one would produce a frontier that
    // disagrees with `group_heads`. When nothing is wrong -- every
    // startup after the first -- it costs two indexed queries and no
    // writes.
    //
    // Fails closed. A group whose history cannot be replayed has no safe
    // reduced service to fall back to: resolving its paths against an
    // index known to be incomplete would silently report content as
    // absent, which materialization would then act on.
    let mut needs_rebuild = path_frontier::groups_needing_rebuild(conn)?;
    for group_id in effect_mismatches {
        if !needs_rebuild.contains(&group_id) {
            needs_rebuild.push(group_id);
        }
    }
    for group_id in needs_rebuild {
        let tx = conn.unchecked_transaction()?;
        path_frontier::rebuild_group(&tx, &group_id)?;
        tx.commit()?;
    }
    // The checkpoint table is created in the same step as the other DAG
    // tables so the whole change-history schema is provisioned by one call and
    // in one order; the DDL itself is owned by the compaction module, which
    // reads and writes it. Pure `CREATE TABLE/INDEX IF NOT EXISTS`, so this is
    // idempotent on both a fresh and an already-upgraded database.
    conn.execute_batch(crate::dag_store::CHECKPOINT_TABLE_MIGRATION)?;
    Ok(())
}

/// Installs a checkpoint and deletes the pruned prefix, all on the
/// supplied connection — pass an open transaction so the checkpoint insert
/// and every delete commit together and a crash can never leave history
/// half-pruned with no checkpoint to answer ancestry against. Each pruned
/// hash is removed from `changes`, from `change_parents` as both a child
/// and a parent (so the retained cut changes become clean roots and an
/// ancestry walk terminates at the boundary with no dangling edge into
/// deleted history), and from `group_heads`. The checkpoint frontier
/// changes are *not* in `pruned`, so they and the live history above them
/// are retained intact. This is a per-hash skip, not a whole-checkpoint
/// refusal: the checkpoint still commits and every other planned hash
/// still prunes, so one held root can delay compaction of *its own* change
/// indefinitely without blocking the rest of the group's history from
/// compacting on schedule. The skipped hash simply remains an ordinary
/// live row in `changes` — not part of `checkpoint.frontier`, but no
/// different in shape from any other retained change; its own already-live
/// parents/children need no adjustment, and
/// `sweep_unreferenced_file_versions` below still observes (and keeps) the
/// file versions it references, since it re-scans `changes` after this
/// loop runs, not the `pruned` list this function was given. Releasing an
/// orphaned root (one whose registering owner never follows up to release
/// it — see [`register_retention_root`]'s own idempotency note) is out of
/// scope here: this function enforces the contract a live root states, it
/// does not judge whether that root is still wanted. A root that is never
/// released holds its one change indefinitely; that owner's own lifecycle
/// (e.g.
pub fn commit_prune(
    conn: &Connection,
    checkpoint: &yadorilink_replica_domain::rebootstrap::Checkpoint,
    pruned: &[ChangeHash],
) -> Result<(), SyncSqliteError> {
    let group_id = checkpoint.group_id.as_str();
    // Per-group monotonic sequence so `latest_checkpoint` can pick the newest.
    let next_seq: i64 = conn.query_row(
        "SELECT COALESCE(MAX(seq), 0) + 1 FROM change_checkpoints WHERE group_id = ?1",
        [group_id],
        |r| r.get(0),
    )?;
    let checkpoint_hash = checkpoint.checkpoint_hash();
    conn.execute(
        "INSERT OR REPLACE INTO change_checkpoints \
         (checkpoint_hash, group_id, snapshot_hash, encoded, seq) VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![
            &checkpoint_hash.as_bytes()[..],
            group_id,
            &checkpoint.snapshot_hash[..],
            checkpoint.canonical_encoding(),
            next_seq,
        ],
    )?;
    let rooted = retention_roots::full_payload_rooted(conn, group_id, pruned)?;
    let mut removed: std::collections::HashSet<ChangeHash> = std::collections::HashSet::new();
    for hash in pruned {
        if rooted.contains(hash) {
            continue;
        }
        conn.execute(
            "DELETE FROM change_file_versions WHERE group_id = ?1 AND change_hash = ?2",
            rusqlite::params![group_id, &hash.0[..]],
        )?;
        conn.execute("DELETE FROM changes WHERE change_hash = ?1", [&hash.0[..]])?;
        conn.execute(
            "DELETE FROM change_parents WHERE child_hash = ?1 OR parent_hash = ?1",
            [&hash.0[..]],
        )?;
        conn.execute(
            "DELETE FROM group_heads WHERE group_id = ?1 AND change_hash = ?2",
            rusqlite::params![group_id, &hash.0[..]],
        )?;
        // Everything derived for this change goes with it. A path whose
        // last live head is pruned resolves as untouched -- the same
        // answer the ancestry walk this index replaced already gave for a
        // pruned change, which was unreachable from the group's heads and
        // so never became a candidate. Keeping compaction from pruning
        // content that is still wanted is `build_compaction_snapshot`'s
        // job, unchanged by this.
        path_frontier::forget_change(conn, hash)?;
        removed.insert(*hash);
    }
    // The time index is derived from `group_heads`, so it has to be cut back
    // alongside it: a recorded frontier snapshot naming a change this loop
    // just deleted describes a point that can no longer be reconstructed.
    // Skipped hashes (`rooted`) are deliberately not in `removed` -- their
    // bodies are still live, so snapshots naming them stay answerable.
    retained_history_integrity::drop_time_index_snapshots_naming(conn, group_id, &removed)?;
    // Materialized bases are derived from `group_heads` too, at the moment
    // each was published, so they can name what this loop just removed. A
    // local edit is parented on its path's basis, and one parented below
    // the checkpoint would name history peers starting from it do not hold.
    if !removed.is_empty() {
        crate::materialized_generation::forget_group_materialized_generations(
            conn,
            group_id,
            "history-pruned",
            now_unix_nanos(),
        )?;
    }
    // Pruning history can orphan file-version rows: a version referenced only
    // by a now-deleted change can never be materialized again, so it is dead
    // weight. Sweep the group's versions against what its retained changes
    // still reference, in the same transaction as the prune so a crash can
    // never leave a version deleted while a change that needs it survives.
    serving_authorization_index::sweep_unreferenced_file_versions(conn, group_id)?;
    Ok(())
}

/// Every path one `Op` touches — for a `Put`/`Delete` just its own path; for
/// a `Move`, both `from` and `to`, since either side moving the desired
/// state can invalidate a plan built against the old one. A `Put`'s
/// `PutOrigin::ConflictCopy::source_path` is deliberately excluded: it names
/// where the losing content used to live, not a path this op writes, and
/// that path's own admission already ran this same accounting when the
/// losing change itself was admitted.
pub(crate) fn op_touched_paths(op: &Op) -> Vec<&str> {
    match op {
        Op::Put { path, .. } | Op::Delete { path } => vec![path.as_str()],
        Op::Move { from, to, .. } => vec![from.as_str(), to.as_str()],
    }
}

/// Bumps the projection-obligation fence for every hash in `promoted` --
/// shared by [`admit_change`]'s own promotion step and [`init_dag_schema`]'s
/// startup self-heal sweep, the two places a buffered orphan turns into a
/// durably admitted change without an already-in-hand [`Change`] to read
/// its touched paths from directly. Each hash is re-read via
/// [`describe_hash`] (already admitted on this same connection by the time
/// this runs) rather than trusting the caller to have kept the decoded
/// `Change` around.
///
/// Bumps `crate::projection_obligations::bump_projection_
/// obligations_for_touched_paths` for the touched paths of each promoted
/// hash's decoded `Change`.
fn bump_execution_fence_for_promoted(
    conn: &Connection,
    promoted: &[ChangeHash],
) -> Result<(), SyncSqliteError> {
    for hash in promoted {
        match describe_hash(conn, hash)? {
            DagHashDisposition::Admitted { change, .. } => {
                // The promoted-orphan seam of the projection-obligation bump.
                let touched: Vec<&str> = change.ops.iter().flat_map(op_touched_paths).collect();
                if !touched.is_empty() {
                    crate::projection_obligations::bump_projection_obligations_for_touched_paths(
                        conn,
                        change.group_id.as_str(),
                        &touched,
                        now_unix_nanos(),
                    )?;
                }
            }
            other => {
                return Err(SyncSqliteError::CorruptState(format!(
                    "promote_orphans reported {} as newly admitted, but it is {other:?}",
                    hash.to_hex()
                )));
            }
        }
    }
    Ok(())
}

/// Admits a verified peer change: if its ancestry is complete it is applied
/// (and any orphans it unblocks are promoted); otherwise it is buffered. The
/// caller MUST have already run `change::verify_change` — this function
/// assumes the change is authentic and authorized.
///
/// Under `AuthorizationCheckpoint` admission, authorization is a static, content-addressed
/// fact checked once before this function is ever called, never re-checked
/// here or at promotion time -- so there is no orphan-promotion writer
/// check and no causal-auth-monotonicity check left in this path; whether a
/// change applies directly or buffers as an orphan depends purely on
/// whether its ancestry is structurally complete.
/// Installs exactly one Change into the canonical DAG and does nothing else.
///
/// This is [`admit_change`] without its orphan promotion. It appends the
/// Change, updates the indexes and raises the projection obligation for the
/// paths it touches — and stops. Whatever this Change may have unblocked is
/// left for its own promotion to handle.
///
/// # Why remote admission needs this
///
/// `admit_change` finishes by recursively promoting every buffered
/// `orphan_changes` row the new Change completes. For the old receive path
/// that is correct: an orphan there was already fully verified on arrival and
/// only ever lacked ancestry.
///
/// It is not correct for promotion out of the verified-change store. A Change
/// promoted through [`crate::remote_admission`] passes a plan/revalidate
/// sequence — the local capture fences of every path it touches are read
/// during planning and required to be unchanged at commit — and a child
/// swept in by recursive orphan promotion would bypass all of it, being
/// installed inside someone else's transaction against fences nobody checked.
/// Every Change must earn its own promotion, so remote admission installs one
/// Change and wakes the coordinator for the rest.
///
/// What [`install_canonical_change_only`] did.
///
/// Missing parents are a distinct outcome rather than an error. They mean the
/// caller's plan went stale — a parent it saw as canonical no longer is — which
/// is an ordinary re-drive. Returning it as an error would force the caller to
/// tell "your plan is stale" apart from "the database is inconsistent" by
/// inspecting an error variant that the append path can also legitimately
/// produce, and a genuine corruption would then be retried forever as though
/// it were a race.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum InstallCanonicalOutcome {
    /// The Change is now canonical, and was not before.
    Installed,
    /// The Change was already canonical. Idempotent: a redelivery costs a
    /// lookup.
    AlreadyPresent,
    /// Something the Change names is not canonical yet — one of its DAG
    /// parents, or the previous change of its own author — so it cannot be
    /// installed. Nothing was written, and the caller should re-plan rather
    /// than stop asking.
    ParentsNotPresent,
    /// Every parent is canonical and the Change's own author chain refuses
    /// it. Unlike `ParentsNotPresent` this is not a stale plan: no later
    /// arrival makes it installable, so the caller must stop asking rather
    /// than re-plan. Nothing was written.
    RefusedAuthorChain(AuthorChainRefusal),
    /// Every parent is canonical and the Change was written on a different
    /// history than this replica's. Final for the same reason as
    /// `RefusedAuthorChain`, and separate from it because the remedy is a
    /// re-bootstrap onto this replica's base rather than anything the
    /// author's chain could supply.
    RefusedForeignHistoryBase { local: HistoryEpoch, incoming: HistoryEpoch },
    /// The Change names a path no replica may store. Final, like the two
    /// refusals above, and decided before any of them. Nothing was written
    /// for the Change itself; its durable refusal was.
    RefusedPath(PathRefusal),
    /// One of the Change's DAG parents is permanently refused here, so it
    /// can never be installed. Final, and recorded durably under the rules
    /// that refused the parent. Distinct from `ParentsNotPresent`, which
    /// is a stale plan to re-drive.
    RefusedBehindRejectedParent { parent: ChangeHash },
    /// The Change names an observed base head this replica's base does not
    /// carry at any path it touches. Final while the replica stays on its
    /// base, like `RefusedForeignHistoryBase`. Nothing was written.
    RefusedInvalidObservedBaseHead { local: HistoryEpoch, head: ChangeHash },
}

impl From<AdmissionRefusal> for InstallCanonicalOutcome {
    fn from(refusal: AdmissionRefusal) -> Self {
        match refusal {
            AdmissionRefusal::AuthorChain(refusal) => Self::RefusedAuthorChain(refusal),
            AdmissionRefusal::ForeignHistoryBase { local, incoming } => {
                Self::RefusedForeignHistoryBase { local, incoming }
            }
            AdmissionRefusal::BehindRejectedParent { parent } => {
                Self::RefusedBehindRejectedParent { parent }
            }
            AdmissionRefusal::InvalidObservedBaseHead { local, head } => {
                Self::RefusedInvalidObservedBaseHead { local, head }
            }
        }
    }
}

pub fn install_canonical_change_only(
    conn: &Connection,
    change: &Change,
) -> Result<InstallCanonicalOutcome, SyncSqliteError> {
    if let Some(refusal) = reject_permanently_inadmissible_paths(conn, change)? {
        return Ok(InstallCanonicalOutcome::RefusedPath(refusal));
    }
    // Before the parent shape, as in `admit_change`: a change from another
    // history is not a change with missing parents, and reporting it as a
    // stale plan would have it re-planned for as long as it stays staged.
    if let Some(refusal) = refuse_foreign_history_base(conn, change)? {
        return Ok(refusal.into());
    }
    serving_authorization_index::validate_referenced_versions(conn, change)?;

    if !retained_history_integrity::validate_present_parent_shape(conn, change)? {
        if let Some(refusal) = refuse_behind_rejected_parent(conn, change)? {
            return Ok(refusal.into());
        }
        return Ok(InstallCanonicalOutcome::ParentsNotPresent);
    }
    match admission_verdict(conn, change)? {
        AdmissionVerdict::Admit => {}
        // Not installable yet for the same reason as a missing parent, and
        // reported the same way: the change names a previous change of its
        // own author that is not here. Author ordering is not DAG
        // causality, so a complete parent set does not imply a complete
        // author chain, and this is a stale plan rather than a verdict —
        // re-plan once that change is canonical.
        AdmissionVerdict::AwaitAuthorPredecessor { .. } => {
            return Ok(InstallCanonicalOutcome::ParentsNotPresent)
        }
        AdmissionVerdict::Refuse(refusal) => return Ok(refusal.into()),
    }

    match append_structurally_complete_change(conn, change)? {
        true => Ok(InstallCanonicalOutcome::Installed),
        false => Ok(InstallCanonicalOutcome::AlreadyPresent),
    }
}

/// Records a final admission refusal durably and hands it back unchanged.
///
/// Every refusal that reaches here is final by construction: it is a
/// property of the Change's own signed bytes measured against history this
/// replica already holds, and no later delivery of anything changes the
/// answer. Recording it is what makes "final" true in practice rather than
/// only in the comment. `has_change_or_buffered_orphan` and
/// `missing_ancestor_frontier` treat a hash as still-missing unless it is
/// in `changes`, `orphan_changes` or `rejected_changes`, so a refusal that
/// wrote nothing would be re-requested from a peer at the next heads
/// exchange, forever, while being refused again each time.
///
/// It lives at the verdict itself rather than in each caller because the
/// callers are the thing that drifted: the staged-bundle path and orphan
/// promotion each recorded their own refusals while the main remote path
/// returned one as an ordinary `Ok` and wrote nothing. One place decides
/// and one place records.
fn record_final_refusal(
    conn: &Connection,
    change: &Change,
    refusal: AdmissionRefusal,
    decided_by: RejectionDomain,
    rests_on: Option<&ChangeHash>,
) -> Result<AdmissionRefusal, SyncSqliteError> {
    // A change from another history is foreign only relative to the history
    // this replica is on now, so that verdict is scoped to it.
    // So is a name measured against its base.
    let refused_on = match &refusal {
        AdmissionRefusal::ForeignHistoryBase { local, .. }
        | AdmissionRefusal::InvalidObservedBaseHead { local, .. } => Some(*local),
        _ => None,
    };
    record_permanent_rejection(
        conn,
        change,
        decided_by,
        rests_on,
        refused_on,
        &format!("admission: {refusal}"),
    )?;
    Ok(refusal)
}

/// The one place a permanent rejection of `change` is persisted, whichever
/// rule domain decided it: records the verdict under `domain`'s current
/// rules and releases everything buffered against the rejected hash.
///
/// A rejection is also a release. The rejected hash will never enter
/// retained history, so anything still buffered against it -- a change
/// that named it as a DAG parent, or one that named it as its own author's
/// previous change -- is waiting on something that cannot arrive. Left in
/// the buffer such a row is not merely stale: a buffered hash counts as
/// known, so no peer is ever asked for it again, and the one name it waits
/// on is now recorded as rejected and so counted as resolved by
/// `missing_ancestor_frontier` -- it would sit there with an empty missing
/// frontier, never promoted, never re-requested and never dropped. That
/// holds for a change rejected for its paths exactly as for one the author
/// chain refuses, so the two are not recorded separately.
///
/// `rests_on` names the refused change this verdict follows from, when it
/// is not a verdict on the change's own content: a DAG parent or author
/// predecessor that can never be held here. The record then stands only
/// while that change's own refusal does (see `rejected_changes`).
/// `refused_on` names the local history a verdict was measured against, when
/// it was; the record then stands only while the group stays on it.
fn record_permanent_rejection(
    conn: &Connection,
    change: &Change,
    domain: RejectionDomain,
    rests_on: Option<&ChangeHash>,
    refused_on: Option<HistoryEpoch>,
    reason: &str,
) -> Result<(), SyncSqliteError> {
    let hash = change.compute_hash();
    record_rejected_change_resting_on(
        conn,
        &hash,
        change.group_id.as_str(),
        domain,
        rests_on,
        refused_on,
        reason,
        now_unix_nanos(),
    )?;
    orphan_integrity::drop_orphan_subtree(conn, &hash.0[..])
}

/// The admission verdict for a Change whose DAG parents are all present:
/// `None` to admit, `Some` to refuse finally.
///
/// A refusal is recorded durably here, by [`record_final_refusal`], before
/// it is returned. Callers report it; they do not also have to remember to
/// persist it.
///
/// The one place the fixed admission order is expressed, so that every entry
/// point applying it applies the same one -- ordinary admission, the staged
/// canonical install, and the promotion of a buffered orphan alike. A Change this replica already
/// knows short-circuits to `None` before the author chain is consulted at
/// all: a re-delivery necessarily sits at or below its author's watermark,
/// so validating it as though it were new would turn ordinary repetition
/// into a forked-history verdict.
///
/// "Already knows" includes a Change this replica admitted and has since
/// compacted away. It is not new history either, and its own tombstone —
/// not the author chain — is what has the right answer for it: a replayed
/// pruned Change must be refused as pruned, which says that this replica
/// decided about it and moved on, rather than as a forked author history,
/// which would accuse the author of something it did not do.
pub(crate) fn admission_verdict(
    conn: &Connection,
    change: &Change,
) -> Result<AdmissionVerdict, SyncSqliteError> {
    if retained_history_integrity::has_change_or_pruned(
        conn,
        change.group_id.as_str(),
        &change.compute_hash(),
    )? {
        return Ok(AdmissionVerdict::Admit);
    }
    // The history the change was written on, before anything about its
    // author is consulted. A change from another history has no position
    // in THIS history's author chains, so measuring it against them would
    // answer a question that was never asked -- and would answer it with
    // an accusation, since a self-consistent old history looks exactly
    // like an author that forked.
    //
    // The change is already known not to be held here, which is the only
    // thing `foreign_history_base_verdict` asks before comparing epochs, so
    // only the comparison is repeated.
    if let Some(refusal) = history_epoch_mismatch(conn, change)? {
        return Ok(AdmissionVerdict::Refuse(record_foreign_history_base_refusal(
            conn, change, refusal,
        )?));
    }
    Ok(match author_chain::check_admission(conn, change)? {
        // The author's chain takes the change; a part of a recursive
        // operation must also agree with the parts of it this author
        // already wrote. Asked only now, so the parts it is measured
        // against are exactly the author's earlier changes.
        author_chain::AuthorChainVerdict::Admit => {
            match recursive_operations::recursive_operation_part_refusal(conn, change)? {
                None => AdmissionVerdict::Admit,
                Some(refusal) => AdmissionVerdict::Refuse(record_final_refusal(
                    conn,
                    change,
                    AdmissionRefusal::AuthorChain(refusal),
                    RejectionDomain::AuthorChain,
                    None,
                )?),
            }
        }
        author_chain::AuthorChainVerdict::AwaitAuthorPredecessor { named } => {
            AdmissionVerdict::AwaitAuthorPredecessor { named }
        }
        author_chain::AuthorChainVerdict::Refuse(refusal) => {
            AdmissionVerdict::Refuse(record_final_refusal(
                conn,
                change,
                AdmissionRefusal::AuthorChain(refusal),
                RejectionDomain::AuthorChain,
                None,
            )?)
        }
        author_chain::AuthorChainVerdict::RefuseBehindRejectedPredecessor {
            refusal,
            decided_by,
            rests_on,
        } => AdmissionVerdict::Refuse(record_final_refusal(
            conn,
            change,
            AdmissionRefusal::AuthorChain(refusal),
            decided_by,
            Some(&rests_on),
        )?),
    })
}

/// What the full admission rules say about a change whose DAG parents are
/// all present: store it, hold it, or refuse it finally.
///
/// The middle answer exists because author ordering is not DAG causality.
/// A change names the previous change of its own author, and that change is
/// routinely not one of its DAG parents — an ordinary local edit is
/// parented on the basis of the bytes it edited, while its author's latest
/// write went to some unrelated path. So "every parent is present" does not
/// imply "this author's previous change is present", and a change that is
/// merely early must be held rather than refused. See
/// [`author_chain::check_admission`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AdmissionVerdict {
    /// Admissible now.
    Admit,
    /// The change names a previous change of its own author that this
    /// replica does not hold. Nothing is decided and nothing is recorded:
    /// it is buffered against that name, exactly as a change with a missing
    /// DAG parent is, and the verdict is taken again in full once the named
    /// change is admitted.
    AwaitAuthorPredecessor { named: ChangeHash },
    /// Refused, finally and durably: the refusal is already recorded.
    Refuse(AdmissionRefusal),
}

/// Whether this Change was written on a history other than the one this
/// replica is on.
///
/// Decidable from the Change's own signed bytes and this group's installed
/// base alone — like a reserved-namespace path, and unlike a missing
/// parent, no later delivery can change the answer. That is why
/// [`admit_change`] asks it before the ancestry question rather than after:
/// a whole self-consistent foreign history would otherwise arrive
/// child-first, fill the bounded orphan buffer on its way to this same
/// verdict, and evict orphans that were merely early.
///
/// A Change this replica already holds is not measured at all. Retained
/// history spans the base switch that produced it — the frontier bodies an
/// install writes were authored on the history the base replaced — so
/// asking this of a re-delivery would report history this device itself
/// installed as foreign.
fn foreign_history_base_verdict(
    conn: &Connection,
    change: &Change,
) -> Result<Option<AdmissionRefusal>, SyncSqliteError> {
    if retained_history_integrity::has_change_or_pruned(
        conn,
        change.group_id.as_str(),
        &change.compute_hash(),
    )? {
        return Ok(None);
    }
    history_epoch_mismatch(conn, change)
}

/// The comparison half of [`foreign_history_base_verdict`], for a caller
/// that has just established the change is not held here.
///
/// A change on this history is also measured against the base it names:
/// every observed base head it names has to be one of that base's heads at
/// a path it touches (see [`Change::observed_base_heads`]). Like the epoch
/// itself this is decided from the change's signed bytes and the installed
/// base alone -- not from which heads are still live here, so no delivery
/// order changes it -- and it is asked at the same point, before anything
/// about the change's ancestry.
fn history_epoch_mismatch(
    conn: &Connection,
    change: &Change,
) -> Result<Option<AdmissionRefusal>, SyncSqliteError> {
    let local = crate::rebootstrap_store::current_history_epoch(conn, change.group_id.as_str())?;
    if change.history_epoch != local {
        return Ok(Some(AdmissionRefusal::ForeignHistoryBase {
            local,
            incoming: change.history_epoch,
        }));
    }
    if let Some(head) = observed_base_heads::invalid_observed_base_head(conn, change)? {
        return Ok(Some(AdmissionRefusal::InvalidObservedBaseHead { local, head }));
    }
    Ok(None)
}

/// Refuses `change`, finally and durably, when it was written on a history
/// other than the one this replica is on. See
/// [`foreign_history_base_verdict`] for why every entry point asks this
/// before it asks anything about the change's ancestry: [`admit_change`],
/// [`install_canonical_change_only`] and the staged promotion alike.
pub(crate) fn refuse_foreign_history_base(
    conn: &Connection,
    change: &Change,
) -> Result<Option<AdmissionRefusal>, SyncSqliteError> {
    let Some(refusal) = foreign_history_base_verdict(conn, change)? else {
        return Ok(None);
    };
    record_foreign_history_base_refusal(conn, change, refusal).map(Some)
}

fn record_foreign_history_base_refusal(
    conn: &Connection,
    change: &Change,
    refusal: AdmissionRefusal,
) -> Result<AdmissionRefusal, SyncSqliteError> {
    // A change from another history is refused for what its author chains
    // are, not for what paths it names.
    record_final_refusal(conn, change, refusal, RejectionDomain::AuthorChain, None)
}

/// The shared body of [`admit_change`]'s structurally-complete arm and
/// [`install_canonical_change_only`]: everything that installs exactly this
/// one Change, and nothing that touches any other.
fn append_structurally_complete_change(
    conn: &Connection,
    change: &Change,
) -> Result<bool, SyncSqliteError> {
    // A change's `ConflictCopy` puts claim things about its OWN parent
    // frontier (see `conflict_authoring::validate_carrier_conflict_copy_ops`'s
    // doc comment) -- only checkable once its parents are confirmed
    // present, which the caller has just done.
    conflict_authoring::validate_carrier_conflict_copy_ops(conn, change.group_id.as_str(), change)?;
    let newly_appended = retained_history_integrity::append_change(conn, change, now_unix_nanos())?;
    conflict_authoring::record_conflict_copy_ops_provenance(
        conn,
        change.group_id.as_str(),
        change,
    )?;
    // Every caller has had `admission_verdict` admit the change, which
    // refuses a part that contradicts its operation, so this only records.
    recursive_operations::record_recursive_operation_part(conn, change)?;

    // `append_change` is idempotent -- `false` means this exact hash
    // was already durably admitted, so this call is a redelivery.
    // "A Change receipt is not a projection event" must hold
    // here too, so the bump below is gated on genuine, first-time
    // appendment.
    if newly_appended {
        let touched: Vec<&str> = change.ops.iter().flat_map(op_touched_paths).collect();
        if !touched.is_empty() {
            crate::projection_obligations::bump_projection_obligations_for_touched_paths(
                conn,
                change.group_id.as_str(),
                &touched,
                now_unix_nanos(),
            )?;
        }
    }

    Ok(newly_appended)
}

/// Refuses a change for a path it names, when it names one no replica may
/// store: records the refusal durably, so a peer stops being asked for a
/// Change that can never be admitted, and releases what was buffered
/// against it (see [`record_permanent_rejection`]). Shared by
/// [`admit_change`] and [`install_canonical_change_only`].
///
/// The refusal comes back as a value, never as an error. Every production
/// caller runs admission inside a transaction it commits only on `Ok`, so
/// an error here would roll back the very record and release this function
/// exists to write, and the refused hash would be re-requested at every
/// heads exchange while the changes waiting on it stayed held.
fn reject_permanently_inadmissible_paths(
    conn: &Connection,
    change: &Change,
) -> Result<Option<PathRefusal>, SyncSqliteError> {
    // Unlike every other admission failure (a missing referenced version,
    // an incomplete parent shape — all properties of what this device has
    // received SO FAR, which change as more of the DAG arrives), a
    // reserved-namespace collision or a non-portable path is a fixed
    // property of the change's own signed bytes: re-admitting the identical
    // change can never produce a different verdict. Record it durably so
    // `missing_ancestor_frontier`/`has_change_or_buffered_orphan` stop
    // treating this hash as merely not-yet-received — see
    // `rejected_changes`'s module doc comment for the retry loop this
    // closes.
    let refusal = match serving_authorization_index::validate_no_reserved_paths(change) {
        Ok(()) => return Ok(None),
        Err(SyncSqliteError::ReservedNamespaceCollision(path)) => {
            PathRefusal::ReservedNamespaceCollision { path }
        }
        Err(SyncSqliteError::NonPortablePath(path)) => PathRefusal::NonPortablePath { path },
        Err(other) => return Err(other),
    };
    record_permanent_rejection(
        conn,
        change,
        RejectionDomain::Path,
        None,
        None,
        &refusal.to_string(),
    )?;
    Ok(Some(refusal))
}

pub fn admit_change(conn: &Connection, change: &Change) -> Result<AdmitResult, SyncSqliteError> {
    if let Some(refusal) = reject_permanently_inadmissible_paths(conn, change)? {
        return Ok(AdmitResult {
            outcome: AdmitOutcome::RefusedPath(refusal),
            newly_admitted: Vec::new(),
        });
    }
    // Before the ancestry question, for the reason given on
    // `foreign_history_base_verdict`. `admission_verdict` asks it again
    // below, so the rule stays expressed in one place for the entry points
    // that reach it only there.
    if let Some(refusal) = refuse_foreign_history_base(conn, change)? {
        return Ok(AdmitResult { outcome: refusal.into(), newly_admitted: Vec::new() });
    }
    serving_authorization_index::validate_referenced_versions(conn, change)?;
    let structurally_complete =
        retained_history_integrity::validate_present_parent_shape(conn, change)?;
    match structurally_complete {
        true => {
            match admission_verdict(conn, change)? {
                AdmissionVerdict::Admit => {}
                // Complete ancestry, but the author's own previous change
                // is not here. Held, not refused: author ordering is not
                // DAG causality, so an author's previous change need not be
                // an ancestor of this one and can still be in flight. See
                // `buffer_as_orphan`.
                AdmissionVerdict::AwaitAuthorPredecessor { .. } => {
                    buffer_as_orphan(conn, change)?;
                    return Ok(AdmitResult {
                        outcome: AdmitOutcome::Orphaned,
                        newly_admitted: Vec::new(),
                    });
                }
                AdmissionVerdict::Refuse(refusal) => {
                    return Ok(AdmitResult { outcome: refusal.into(), newly_admitted: Vec::new() })
                }
            }
            append_structurally_complete_change(conn, change)?;
            let hash = change.compute_hash();
            let promoted = orphan_integrity::promote_orphans(conn, &[hash])?;
            // Every orphan `promote_orphans` just promoted also just moved the
            // desired state, exactly like the primary change above -- fence out
            // any plan built on the paths its own ops touch too.
            // (bump_execution_fence_for_promoted now also bumps the
            // projection-obligation fence for each promoted hash's touched
            // paths -- see that function's own doc comment.)
            bump_execution_fence_for_promoted(conn, &promoted)?;
            let mut newly_admitted = vec![hash];
            newly_admitted.extend(promoted);
            Ok(AdmitResult { outcome: AdmitOutcome::Applied, newly_admitted })
        }
        false => {
            if let Some(refusal) = refuse_behind_rejected_parent(conn, change)? {
                return Ok(AdmitResult { outcome: refusal.into(), newly_admitted: Vec::new() });
            }
            // The parent is structurally missing -- buffer and retry once
            // more of the DAG arrives.
            buffer_as_orphan(conn, change)?;
            Ok(AdmitResult { outcome: AdmitOutcome::Orphaned, newly_admitted: Vec::new() })
        }
    }
}

/// Refuses a change one of whose DAG parents is permanently refused here,
/// recording the refusal under the rule domain that refused that parent.
///
/// Asked before the change would be buffered for a missing parent, and by
/// staged promotion before it would report a stale plan. Buffering would
/// wait on a name that can never arrive, and one nothing would ask for
/// either: a refused hash counts as resolved in `missing_ancestor_frontier`
/// and a buffered one as known in `has_change_or_buffered_orphan`. The row
/// would sit in the bounded buffer until evicted. A staged copy is worse
/// off still: it stays possessed, and so is never asked for again, while
/// never becoming canonical. Refusing the parent released such a change
/// once, but a peer still holding it sends it again, and a child can also
/// arrive for the first time after its parent was refused.
///
/// The DAG-parent counterpart of refusing a sequence gap behind a refused
/// author predecessor, and recorded the same way: it stands exactly as long
/// as the parent's refusal does. It is stamped with that refusal's domain,
/// so it is re-opened when those rules move, and it names the parent, so it
/// also lapses if the parent's own verdict stops standing for any other
/// reason. A parent this replica holds is never a reason to refuse, whatever
/// a stale row says about it.
pub(crate) fn refuse_behind_rejected_parent(
    conn: &Connection,
    change: &Change,
) -> Result<Option<AdmissionRefusal>, SyncSqliteError> {
    for parent in &change.parents {
        if retained_history_integrity::has_change_or_pruned(conn, change.group_id.as_str(), parent)?
        {
            continue;
        }
        if let Some(decided_by) = current_rejection_domain(conn, parent)? {
            let refusal = AdmissionRefusal::BehindRejectedParent { parent: *parent };
            return record_final_refusal(conn, change, refusal, decided_by, Some(parent)).map(Some);
        }
    }
    Ok(None)
}

/// Holds a change that names something this replica does not have yet — a
/// DAG parent, or its own author's previous change — and records the names
/// it is waiting on so a later admission can wake it.
///
/// The author link is recorded on the orphan row itself (`author_prev_hash`)
/// rather than as a `change_parents` edge, and that placement is the point:
/// `change_parents` is DAG ancestry, and `frontier_index::repair` reads it
/// to decide which changes still have children. An author link written
/// there would make the author's own tip look like it had a child and drop
/// it out of the group heads, which is exactly the conflation this
/// separation exists to prevent.
fn buffer_as_orphan(conn: &Connection, change: &Change) -> Result<(), SyncSqliteError> {
    let hash = change.compute_hash();
    for parent in &change.parents {
        conn.execute(
            "INSERT OR IGNORE INTO change_parents (child_hash, parent_hash) VALUES (?1, ?2)",
            rusqlite::params![&hash.0[..], &parent.0[..]],
        )?;
    }
    orphan_integrity::insert_orphan(conn, change)?;
    Ok(())
}

/// Whether a change is already known locally — either durably admitted,
/// already buffered in the orphan holding area awaiting its own ancestry,
/// or durably recorded as a permanent rejection (see `rejected_changes`'s
/// module doc comment — a change naming a reserved-namespace path, whose
/// verdict can never change no matter how many times it is re-sent).
/// Deliberately distinct from `has_change`, which existing callers rely on to
/// mean "durably admitted" specifically (e.g. deciding whether a change still
/// needs promoting). This one is for a different question: whether a peer
/// needs to (re-)send a hash at all. A hash already sitting in the orphan
/// buffer need not be re-requested on every repeated frontier announce while
/// its own ancestors are still in flight — only the genuinely-unknown hashes
/// do, so re-requesting an already-buffered one is pure waste that scales
/// with how often the peer re-announces during a long catch-up; a
/// permanently-rejected hash is the same waste, forever, since nothing about
/// re-requesting it can ever produce a different outcome.
pub fn has_change_or_buffered_orphan(
    conn: &Connection,
    hash: &ChangeHash,
) -> Result<bool, SyncSqliteError> {
    if retained_history_integrity::has_change(conn, hash)? {
        return Ok(true);
    }
    let present: Option<i64> = conn
        .query_row("SELECT 1 FROM orphan_changes WHERE change_hash = ?1", [&hash.0[..]], |r| {
            r.get(0)
        })
        .optional()?;
    if present.is_some() {
        return Ok(true);
    }
    is_change_rejected(conn, hash)
}

/// The true missing frontier reachable from `roots`: every hash that is
/// neither durably admitted nor buffered as an orphan, found by walking
/// *through* buffered orphans via their recorded `change_parents` edges
/// rather than stopping at the first one (as `has_change_or_buffered_orphan`
/// deliberately does for its own, different purpose — see that fn's doc
/// comment). Takes every root of one logical request together (rather than
/// one call per root) so shared ancestry between them — common when several
/// announced heads descend from the same still-orphaned change — is walked
/// once, not once per root.
///
/// This exists because `has_change_or_buffered_orphan`'s one-level check has
/// a real gap for a multi-generation orphan chain: a root -> a buffered
/// parent -> a grandparent that was never received at all. A caller that
/// only checks the root's *immediate* parents against
/// `has_change_or_buffered_orphan` sees the buffered parent and stops
/// there, so the truly-missing grandparent is never discovered or
/// re-requested — and since nothing else ever independently re-examines a
/// buffered orphan's own ancestry (see `promote_orphans`'s doc comment: it
/// only ever walks *outward* from a hash that just became durably admitted,
/// never proactively re-checks a stuck one), that grandparent, the root, and
/// everything descending from it stays stuck for the rest of the session —
/// confirmed as a real, reproduced convergence failure, not a hypothetical.
///
/// A DB error while walking (e.g. transient contention on a query) is
/// propagated via `?`, never folded into "missing" — treating contention as
/// "the peer doesn't have this either" would turn a local hiccup into an
/// unnecessary re-fetch storm.
///
/// Bounded explicitly at `ORPHAN_BOUND` visited hashes (in addition to the
/// natural bound of how many orphans can exist at all) as a latency
/// safeguard against a pathological/adversarial chain shape rather than
/// trusting the DB-row cap alone — a single call is not the place to
/// discover that assumption was wrong. If the cap is hit, the walk gives up
/// and falls back to returning `roots` unchanged: strictly no worse than
/// the one-level check's own behavior (the roots still get re-requested),
/// just without the deeper-frontier discovery this fn otherwise adds.
pub fn missing_ancestor_frontier(
    conn: &Connection,
    roots: impl IntoIterator<Item = ChangeHash>,
) -> Result<Vec<ChangeHash>, SyncSqliteError> {
    let roots: Vec<ChangeHash> = roots.into_iter().collect();
    let mut missing = Vec::new();
    let mut visited: std::collections::HashSet<ChangeHash> = std::collections::HashSet::new();
    let mut queue: std::collections::VecDeque<ChangeHash> = std::collections::VecDeque::new();
    for root in &roots {
        if visited.insert(*root) {
            queue.push_back(*root);
        }
    }
    while let Some(hash) = queue.pop_front() {
        if visited.len() > orphan_integrity::ORPHAN_BOUND {
            tracing::warn!(
                "missing-ancestor-frontier walk exceeded ORPHAN_BOUND visited hashes; \
                 falling back to re-requesting the original roots directly"
            );
            return Ok(roots);
        }
        if retained_history_integrity::has_change(conn, &hash)? {
            continue;
        }
        // A permanently-rejected hash (see `rejected_changes`'s module doc
        // comment) is resolved, not missing: nothing a peer could send
        // would change the verdict, so treating it as still-missing would
        // just re-request it forever. Distinct from `has_change` above —
        // this branch is content this device has SEEN and definitively
        // refused, not content it never received.
        if is_change_rejected(conn, &hash)? {
            continue;
        }
        let buffered: Option<Option<Vec<u8>>> = conn
            .query_row(
                "SELECT author_prev_hash FROM orphan_changes WHERE change_hash = ?1",
                [&hash.0[..]],
                |r| r.get(0),
            )
            .optional()?;
        let Some(author_prev) = buffered else {
            missing.push(hash);
            continue;
        };
        // A buffered row may be waiting on its author's previous change
        // rather than on any DAG parent, and that change is a hash no
        // parent walk would ever reach: author ordering is not ancestry.
        // Without this the row would sit in the buffer forever — counted as
        // "already known" by `has_change_or_buffered_orphan`, so never
        // re-sent — while the one change that could release it was never
        // asked for.
        if let Some(author_prev) = author_prev {
            let author_prev = retained_history_integrity::hash_from_blob(author_prev)?;
            if visited.insert(author_prev) {
                queue.push_back(author_prev);
            }
        }
        let parents: Vec<Vec<u8>> = {
            let mut stmt =
                conn.prepare("SELECT parent_hash FROM change_parents WHERE child_hash = ?1")?;
            let rows = stmt.query_map([&hash.0[..]], |r| r.get::<_, Vec<u8>>(0))?;
            rows.collect::<Result<_, _>>()?
        };
        for parent_blob in parents {
            let parent_hash = retained_history_integrity::hash_from_blob(parent_blob)?;
            if visited.insert(parent_hash) {
                queue.push_back(parent_hash);
            }
        }
    }
    Ok(missing)
}

/// Read-only diagnostic snapshot of one group's DAG-level progress, for
/// convergence tests/tools that need to distinguish "delivery/admission is
/// stalled" from "everything is admitted but projection lags" without
/// dumping raw tables. Never consulted by any production sync path.
#[derive(Debug, Clone, Default)]
pub struct GroupDagDiagnostics {
    /// Rows in `changes` for this group.
    pub admitted_total: u64,
    /// Admitted-change count per authoring device — lets a caller see
    /// whether one device keeps emitting *new local* changes after its
    /// nominal input stopped (a projection → filesystem-watcher echo
    /// signature), which head hashes alone cannot show.
    pub admitted_by_author: std::collections::BTreeMap<String, u64>,
    /// Changes buffered in `orphan_changes` for this group.
    pub orphan_total: u64,
    /// The genuinely missing ancestor frontier reachable from every buffered
    /// orphan (see [`missing_ancestor_frontier`]). Non-empty means this
    /// device is provably waiting on specific hashes it has never received.
    pub orphan_missing_frontier: Vec<ChangeHash>,
}

/// Collects [`GroupDagDiagnostics`] for `group_id`. Purely read-only.
pub fn group_dag_diagnostics(
    conn: &Connection,
    group_id: &str,
) -> Result<GroupDagDiagnostics, SyncSqliteError> {
    let admitted_total: i64 =
        conn.query_row("SELECT COUNT(*) FROM changes WHERE group_id = ?1", [group_id], |r| {
            r.get(0)
        })?;
    let mut admitted_by_author = std::collections::BTreeMap::new();
    {
        let mut stmt = conn.prepare(
            "SELECT device_id, COUNT(*) FROM changes WHERE group_id = ?1 GROUP BY device_id",
        )?;
        let rows =
            stmt.query_map([group_id], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?;
        for row in rows {
            let (device_id, count) = row?;
            admitted_by_author.insert(device_id, count as u64);
        }
    }
    let orphan_roots: Vec<ChangeHash> = {
        let mut stmt =
            conn.prepare("SELECT change_hash FROM orphan_changes WHERE group_id = ?1")?;
        let rows = stmt.query_map([group_id], |r| r.get::<_, Vec<u8>>(0))?;
        rows.collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(retained_history_integrity::hash_from_blob)
            .collect::<Result<_, _>>()?
    };
    let orphan_total = orphan_roots.len() as u64;
    let orphan_missing_frontier = missing_ancestor_frontier(conn, orphan_roots)?;
    Ok(GroupDagDiagnostics {
        admitted_total: admitted_total as u64,
        admitted_by_author,
        orphan_total,
        orphan_missing_frontier,
    })
}

/// Every admitted change for `group_id`, decoded, oldest-lamport-first.
/// Diagnostic only (convergence tests dump per-path op history from it);
/// unbounded in group size, so never called on a production sync path.
pub fn list_group_changes(
    conn: &Connection,
    group_id: &str,
) -> Result<Vec<Change>, SyncSqliteError> {
    let mut stmt = conn
        .prepare("SELECT encoded FROM changes WHERE group_id = ?1 ORDER BY lamport, change_hash")?;
    let rows = stmt.query_map([group_id], |r| r.get::<_, Vec<u8>>(0))?;
    let mut out = Vec::new();
    for row in rows {
        let change = Change::from_wire_bytes(&row?).map_err(|error| {
            SyncSqliteError::CorruptState(format!(
                "cannot list changes for group {group_id}: retained change is corrupt: {error}"
            ))
        })?;
        out.push(change);
    }
    Ok(out)
}

/// Where one specific hash currently stands on this device: durably admitted
/// (applied or still pending projection), buffered as an orphan, or not
/// present at all. Diagnostic counterpart to
/// [`has_change_or_buffered_orphan`], which deliberately collapses the first
/// two states and cannot express the third.
#[derive(Debug, Clone)]
pub enum DagHashDisposition {
    Admitted { change: Change },
    Orphaned { received_seq: i64, change: Change },
    Missing,
}

/// Classifies `hash` per [`DagHashDisposition`]. Purely read-only; a stored
/// row whose bytes no longer decode is a [`SyncSqliteError::CorruptState`], never
/// silently reported as `Missing`.
pub fn describe_hash(
    conn: &Connection,
    hash: &ChangeHash,
) -> Result<DagHashDisposition, SyncSqliteError> {
    let admitted: Option<Vec<u8>> = conn
        .query_row("SELECT encoded FROM changes WHERE change_hash = ?1", [&hash.0[..]], |r| {
            r.get(0)
        })
        .optional()?;
    if let Some(encoded) = admitted {
        let change = Change::from_wire_bytes(&encoded).map_err(|error| {
            SyncSqliteError::CorruptState(format!(
                "admitted change {} no longer decodes: {error}",
                hash.to_hex()
            ))
        })?;
        return Ok(DagHashDisposition::Admitted { change });
    }
    let orphaned: Option<(Vec<u8>, i64)> = conn
        .query_row(
            "SELECT encoded, received_seq FROM orphan_changes WHERE change_hash = ?1",
            [&hash.0[..]],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    if let Some((encoded, received_seq)) = orphaned {
        let change = Change::from_wire_bytes(&encoded).map_err(|error| {
            SyncSqliteError::CorruptState(format!(
                "buffered orphan {} no longer decodes: {error}",
                hash.to_hex()
            ))
        })?;
        return Ok(DagHashDisposition::Orphaned { received_seq, change });
    }
    Ok(DagHashDisposition::Missing)
}

/// Builds, signs, and appends a change for a local mutation. Its parents are
/// the group's current heads, so it narrows the head set to itself. Runs
/// entirely on the supplied connection, so passing an open transaction makes
/// the change append atomic with whatever index mutation shares it.
///
/// `auth` is the emitting device's authorization stamp (membership sequence,
/// epoch, and pinned policy-log head); it is baked into the signed change so
/// admission on any replica is judged against the membership/policy state the
/// author held, not against whatever the log says now.
pub fn emit_local_change(
    conn: &Connection,
    group_id: &str,
    ops: Vec<Op>,
    emitter: &ChangeEmitter,
) -> Result<Change, SyncSqliteError> {
    let parents = plain_frontier_parents(conn, group_id)?;
    emit_change_with_derived_conflict_copies(
        conn,
        group_id,
        parents,
        ops,
        emitter,
        ChangePurpose::Ordinary,
        None,
        None,
    )
}

/// The group's current heads as the parents of a write onto the plain
/// frontier, refusing an empty frontier over retained history.
fn plain_frontier_parents(
    conn: &Connection,
    group_id: &str,
) -> Result<Vec<ChangeHash>, SyncSqliteError> {
    let parents = frontier_index::group_heads(conn, group_id)?;
    if parents.is_empty() {
        // An empty frontier is only legitimate for a group with no retained
        // history at all. `group_heads` is a derived index of `changes`; if
        // it lost its rows for a group that still has retained history (a
        // corrupted/missing index, not a fresh group), signing a change with
        // no parents here would silently start a second, disconnected root
        // under the same group_id.
        let has_history: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM changes WHERE group_id = ?1)",
            [group_id],
            |r| r.get(0),
        )?;
        if has_history {
            return Err(SyncSqliteError::CorruptState(format!(
                "cannot emit local change for group {group_id}: retained history exists but no \
                 head is recorded; refusing to start a competing root"
            )));
        }
    }
    Ok(parents)
}

/// One emission with everything the database can settle already settled --
/// conflict-copy derivation, the parent Lamport lookup, the present-parent
/// shape check and the carrier check -- and nothing left to do but stamp an
/// authorization coordinate on it, sign, and append.
///
/// This exists so an authorization coordinate can be acquired at the emission's
/// true commit point rather than minutes of database and filesystem work
/// earlier. Every check this type's construction performs reads only fields
/// that a signature cannot change (parents, Lamport, ops, purpose), so running
/// them before signing is the identical check run earlier, not a weaker one.
///
/// Deliberately move-only (no [`Clone`]) and opaque outside this module: a
/// second [`prepare_emission`] for the same logical write would re-derive
/// conflict copies against a frontier that may have moved, which is exactly
/// the class of double-derivation this split exists to prevent.
pub struct PreparedEmission {
    group_id: String,
    parents: Vec<ChangeHash>,
    all_ops: Vec<Op>,
    purpose: ChangePurpose,
    /// The Lamport value this change is clocked one above: the greatest of
    /// its parents' values and the floor of the history it is written on.
    clocked_from: u64,
    author_seq: AuthorSeq,
    /// The change this author wrote at the position before `author_seq`,
    /// read in the same breath as the sequence and signed with it. `None`
    /// for this author's first change in the group, and for its first
    /// change above the history base that carried its position.
    ///
    /// Author ordering, not causality: `parents` above is the causal basis
    /// this emission is authored onto, and it is untouched by this field.
    /// An ordinary local edit is parented on the basis its bytes came from,
    /// which this author may have written past — that is exactly why the
    /// author link is named rather than derived from ancestry.
    author_prev: Option<ChangeHash>,
    /// The history this emission will be written on, read from the group's
    /// installed base at preparation time and signed unchanged. A local
    /// change is only ever authored onto the history this device is
    /// actually on: signing one onto any other would produce a change its
    /// own store refuses on the next open.
    history_epoch: HistoryEpoch,
    /// Set when this emission is one part of a recursive delete or
    /// directory rename, signed into the change unchanged.
    recursive_operation: Option<RecursiveOperation>,
    /// The installed base's heads this emission supersedes, computed from
    /// what its writer was shown (see [`Change::observed_base_heads`]) and
    /// signed unchanged.
    observed_base_heads: Vec<ChangeHash>,
    /// The author the sequence above was minted for. Kept so signing can
    /// refuse to stamp one author's position onto another author's
    /// signature: the two halves of an emission are separate calls, and a
    /// mismatched pair would put the same dot on two different changes.
    device_id: String,
}

/// Derives, validates and freezes everything about an emission that depends on
/// the database, leaving only signing and appending for
/// [`admit_prepared_emission`]. See [`PreparedEmission`].
///
/// `seen` is what the writer was shown at each path it writes: the
/// installed base's heads among those, and only those, are superseded. With
/// `None` it is read from the rows at the paths `ops` names -- the version
/// each current row holds is the version shown there -- which is what an
/// ordinary edit of a path means. A write that acts on a row at another
/// path than the op's own (a write-through of a conflict copy to its
/// source) passes what that row showed instead.
#[allow(clippy::too_many_arguments)]
pub fn prepare_emission(
    conn: &Connection,
    group_id: &str,
    device_id: &str,
    parents: Vec<ChangeHash>,
    ops: Vec<Op>,
    purpose: ChangePurpose,
    recursive_operation: Option<RecursiveOperation>,
    seen: Option<&SeenVersions>,
) -> Result<PreparedEmission, SyncSqliteError> {
    if recursive_operation.is_some() && !matches!(purpose, ChangePurpose::Ordinary) {
        return Err(SyncSqliteError::InvalidInput(format!(
            "cannot emit local change for group {group_id}: a retroactive-repair change cannot \
             be part of a recursive operation"
        )));
    }
    // A `RetroactiveRepair` carrier's own conflict-copy ops are derived with
    // the buried-root-aware walk (see `derive_required_conflict_copy_ops_
    // including_buried_roots`'s own doc comment), so this re-derivation
    // agrees with `plan_retroactive_merge`'s own obligation computation --
    // `validate_retroactive_repair_claims` requires the two to match
    // exactly, or this carrier would fail its own local emission-time
    // validation below. `ChangePurpose::Ordinary` (every other caller: the
    // live watcher, rebootstrap's squash, restore) keeps the cheap
    // early-stopping walk unconditionally -- see that function's own doc
    // comment for why widening it here would regress the measured
    // writer-gate-hold cost of every ordinary local edit.
    //
    // Asked the way this change's own validation below will ask it, too: the
    // group-wide existence check answers a different question (see
    // `derive_required_conflict_copy_ops_as_admission_will`), and where the
    // two differ this function would sign a change that its own
    // `validate_carrier_conflict_copy_ops_parts` call then rejects.
    let derived_ops = conflict_authoring::derive_required_conflict_copy_ops_as_admission_will(
        conn,
        group_id,
        &parents,
        &ops,
        matches!(purpose, ChangePurpose::RetroactiveRepair { .. }),
    )?;
    // Read before `ops` joins the derived copies: a derived copy's path is
    // not one the writer acted on.
    let shown_by_rows = match seen {
        Some(_) => None,
        None => Some(versions_shown_at_op_paths(conn, group_id, &ops)?),
    };
    let mut all_ops = ops;
    all_ops.extend(derived_ops.iter().cloned());

    // `Change::create_signed` sorts and dedups parents itself; do it here too
    // so the parent set validated below is byte-for-byte the one that will be
    // signed, rather than a merely equivalent one.
    let mut parents = parents;
    parents.sort();
    parents.dedup();

    let max_parent_lamport = frontier_index::max_parent_lamport(conn, group_id, &parents)?;
    // Clocked from the history this change is written on as well as from
    // its parents: above an installed base, a change descends everything
    // the base absorbed, and restarting the clock there would rank it below
    // that history. The installed base always carries its ceiling.
    let history_epoch = crate::rebootstrap_store::current_history_epoch(conn, group_id)?;
    let lamport_floor = crate::rebootstrap_store::lamport_floor(conn, group_id, history_epoch)?
        .ok_or_else(|| {
            SyncSqliteError::CorruptState(format!(
                "cannot emit local change for group {group_id}: no Lamport floor is known for \
                 {history_epoch}, the history it is on"
            ))
        })?;
    let clocked_from = max_parent_lamport.max(lamport_floor);

    // `group_heads`/caller-specified `parents` are trusted as this group's
    // frontier, but that trust is itself just a derived index; re-validate
    // against `changes` before signing so a foreign-group head injected (or
    // corrupted) into it cannot make this device sign a change that claims
    // ancestry from a different group's history, or one whose "parent" isn't
    // actually retained at all.
    if !retained_history_integrity::validate_present_parent_shape_parts(
        conn,
        group_id,
        &parents,
        clocked_from.saturating_add(1),
        Some(lamport_floor),
    )? {
        return Err(SyncSqliteError::CorruptState(format!(
            "cannot emit local change for group {group_id}: a recorded parent is not actually \
             present in retained history"
        )));
    }
    conflict_authoring::validate_carrier_conflict_copy_ops_parts(
        conn, group_id, &parents, &all_ops, &purpose,
    )?;

    // The author's own position in its chain is settled here, with every
    // other database-derived field, and consumed unchanged by
    // `admit_prepared_emission`'s signature. Deciding it anywhere else
    // would mean two callers could mint the same position for two
    // different changes, which is precisely the state an author chain
    // exists to make impossible.
    //
    // The sequence and the predecessor link come from one read, because
    // admission checks them as one fact. There is no policy knob here and
    // no caller exempt from the rule: a local edit authored onto an older
    // basis still names its author's previous change, so it satisfies the
    // author chain on every replica while its parents stay the causal
    // basis its bytes actually came from. Those were two conflicting
    // demands only while author ordering was expressed as DAG ancestry.
    let (author_seq, author_prev) = author_chain::next_author_position(conn, group_id, device_id)?;

    let observed_base_heads = observed_base_heads::observed_base_heads_for(
        conn,
        group_id,
        &all_ops,
        seen.or(shown_by_rows.as_ref()).unwrap_or(&SeenVersions::new()),
    )?;

    Ok(PreparedEmission {
        group_id: group_id.to_string(),
        parents,
        all_ops,
        purpose,
        clocked_from,
        author_seq,
        author_prev,
        history_epoch,
        recursive_operation,
        observed_base_heads,
        device_id: device_id.to_string(),
    })
}

/// What an ordinary write of `ops` was shown: at each path an op names,
/// the change the path's current row holds the version of. A path with no
/// live row with content -- never indexed, holding only the
/// `version_seq = 0` scaffold a placement writes first, or a tombstone --
/// showed no version there.
///
/// Nothing is read on the group's original history: it has no base, so
/// there is no base head to name whatever a row shows.
fn versions_shown_at_op_paths(
    conn: &Connection,
    group_id: &str,
    ops: &[Op],
) -> Result<SeenVersions, SyncSqliteError> {
    let mut shown = SeenVersions::new();
    if crate::rebootstrap_store::current_history_epoch(conn, group_id)? == HistoryEpoch::Genesis {
        return Ok(shown);
    }
    for path in ops.iter().flat_map(op_touched_paths) {
        if let Some(author) = content_shown_at(conn, group_id, path)? {
            shown.entry(path.to_owned()).or_default().insert(author);
        }
    }
    Ok(shown)
}

/// The change the current row at `path` names as its author, tombstone or
/// not: the version -- or the removal -- this device has shown there.
/// What an unseen cut measures a path's live heads against.
pub(crate) fn version_shown_at(
    conn: &Connection,
    group_id: &str,
    path: &str,
) -> Result<Option<ChangeHash>, SyncSqliteError> {
    row_author_at(conn, group_id, path, false)
}

/// The change whose content the current row at `path` holds, when the row
/// holds live content. A tombstone shows no version, so it is never a
/// reason to name a base head as seen (see [`Change::observed_base_heads`]).
pub(crate) fn content_shown_at(
    conn: &Connection,
    group_id: &str,
    path: &str,
) -> Result<Option<ChangeHash>, SyncSqliteError> {
    row_author_at(conn, group_id, path, true)
}

fn row_author_at(
    conn: &Connection,
    group_id: &str,
    path: &str,
    live_only: bool,
) -> Result<Option<ChangeHash>, SyncSqliteError> {
    let shown: Option<Option<Vec<u8>>> = conn
        .prepare_cached(
            "SELECT authoring_change_hash FROM files \
              WHERE group_id = ?1 AND path = ?2 AND state = 'current' AND version_seq > 0 \
                AND (?3 = 0 OR deleted = 0)",
        )?
        .query_row(rusqlite::params![group_id, path, live_only], |row| row.get(0))
        .optional()?;
    Ok(shown
        .flatten()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).ok())
        .map(ChangeHash))
}

/// Signs `prepared` and appends it with its companion rows.
///
/// Consumes the preparation by value. Between the caller preparing the fields
/// and this function's append there is no filesystem read, no block-store
/// I/O, no parent lookup, no conflict derivation and no unrelated SQL: only
/// the in-memory assembly of already-validated fields, the signature, the
/// hash, the purely in-memory structural/size checks over those same fields,
/// and the admission writes themselves.
pub fn admit_prepared_emission(
    conn: &Connection,
    prepared: PreparedEmission,
    emitter: &ChangeEmitter,
) -> Result<Change, SyncSqliteError> {
    let PreparedEmission {
        group_id,
        parents,
        all_ops,
        purpose,
        clocked_from,
        author_seq,
        author_prev,
        history_epoch,
        recursive_operation,
        observed_base_heads,
        device_id,
    } = prepared;
    let group_id = group_id.as_str();
    if device_id != emitter.device_id() {
        return Err(SyncSqliteError::InvalidInput(format!(
            "cannot emit local change for group {group_id}: author sequence {author_seq} was \
             read for device {device_id} but the change would be signed by {}",
            emitter.device_id()
        )));
    }

    let change = Change::create_signed_observing(
        parents,
        clocked_from,
        DeviceId(emitter.device_id().to_string()),
        author_seq,
        author_prev,
        FolderGroupId(group_id.to_string()),
        history_epoch,
        purpose,
        recursive_operation,
        observed_base_heads,
        all_ops,
        emitter.signing_key(),
    );
    // The combined `all_ops` (direct + derived `ConflictCopy`) is never
    // validated by `Change::create_signed` itself -- an ordinary direct op
    // and a derived `ConflictCopy` op can legitimately target the SAME path
    // (an easy real-world trigger: a user's ordinary filename happens to
    // collide with the deterministic conflict-copy name for some unrelated
    // loser), producing two ops on one path in a single change. Without
    // this check, that change signs and appends successfully on THIS
    // device, only to be rejected by every peer's own structural
    // validation on receipt, AND to fail-closed this device's own
    // retained-history repair on its next restart (the exact same
    // `validate_structure` call, run unconditionally against every
    // retained change) -- a self-inflicted DB-open failure. Checking here,
    // before the change is observed anywhere, turns that into an ordinary
    // emit-time error instead. Purely in-memory over fields the preparation
    // already fixed; it cannot be run before signing only because the hash
    // it checks against is itself a function of the authorization stamp.
    let change_hash = change.compute_hash();
    change.validate_structure(&change_hash).map_err(|error| {
        SyncSqliteError::InvalidInput(format!(
            "cannot emit local change for group {group_id}: combined direct + derived \
             conflict-copy ops are structurally invalid: {error}"
        ))
    })?;
    // `admit_change` (the RECEIVING side, for a peer's incoming change)
    // calls this same `validate_no_reserved_paths` before ever admitting a
    // change into this device's own history, and this LOCAL-authoring
    // emission path must match it for every one of its callers (`emit_local_change`, the
    // live watcher's own path; `emit_local_change_onto`, rebootstrap's
    // squash; `emit_retroactive_repair`, conflict-copy/retroactive
    // repair; and `SyncState::append_history_backfill`, which itself
    // calls `emit_local_change`). A path this device's own filesystem
    // happens to produce (e.g. a POSIX peer's user creating `"report."`,
    // legal on Linux/macOS, silently normalized away on Windows) could
    // otherwise sign and append successfully HERE, become this device's own head,
    // and only then be discovered unacceptable -- by every OTHER peer's
    // `admit_change`, which permanently records the hash as rejected and
    // never re-requests it, orphaning every descendant change forever.
    // Checking before `append_change` below keeps the two sides
    // symmetric: the identical predicate runs on both sides, so a
    // non-portable path is refused before it can ever become local
    // history to propagate in the first place, not just refused by
    // peers after the fact.
    serving_authorization_index::validate_no_reserved_paths(&change)?;
    // The same measure of the names against the installed base that
    // admission applies to a peer's change, so this device never signs a
    // change every other replica refuses.
    if let Some(head) = observed_base_heads::invalid_observed_base_head(conn, &change)? {
        return Err(SyncSqliteError::InvalidInput(format!(
            "cannot emit local change for group {group_id}: it names {} as an observed base \
             head, which the installed base carries at no path it touches",
            head.to_hex()
        )));
    }
    // `validate_structure` bounds op count and shape, but not encoded byte
    // size -- derived `ConflictCopy` ops are added *after* the direct ops
    // this device was asked to emit, so a small direct edit on a path with
    // many concurrent losers can still push the combined change past
    // `MAX_CHANGE_OP_BYTES`. That cap exists because a change cannot be
    // wire-split: one signed on this device that exceeds it would append
    // locally, become this device's head, and then be undeliverable to
    // every peer. Reject before signing is observed anywhere rather than
    // silently stranding this device's history.
    let op_bytes: usize = change.ops.iter().map(encoded_op_len).sum();
    if op_bytes > MAX_CHANGE_OP_BYTES {
        return Err(SyncSqliteError::InvalidInput(format!(
            "cannot emit local change for group {group_id}: combined direct + derived \
             conflict-copy ops encode to {op_bytes} bytes, exceeding MAX_CHANGE_OP_BYTES \
             ({MAX_CHANGE_OP_BYTES}); this change could never be delivered to a peer as a \
             single wire message"
        )));
    }
    for op in &change.ops {
        let (kind, path) = match op {
            Op::Put { path, .. } => ("put", path.as_str()),
            Op::Delete { path } => ("delete", path.as_str()),
            Op::Move { from, .. } => ("move-from", from.as_str()),
        };
        dst_trace(path, || {
            format!(
                "emit_local_change by {}: {kind} hash={} lamport={} parents={:?}",
                change.device_id.0,
                hex::encode(&change_hash.0[..4]),
                change.lamport,
                change.parents.iter().map(|p| hex::encode(&p.0[..4])).collect::<Vec<_>>(),
            )
        });
    }
    recursive_operations::check_recursive_operation_part(conn, &change)?;
    retained_history_integrity::append_change(conn, &change, now_unix_nanos())?;
    conflict_authoring::record_conflict_copy_ops_provenance(conn, group_id, &change)?;
    recursive_operations::record_recursive_operation_part(conn, &change)?;
    // The local-emission seam of the projection-obligation bump. Covers every
    // path in `change.ops`, direct and derived alike -- this is what makes it
    // safe for this function to no longer also enqueue a separate
    // `materialization_jobs` row for each derived conflict-copy path: the
    // obligation-driven scheduler claims off this bump's target directly, so
    // that redundant enqueue (which used to race the admission-side re-arm
    // over which `version_hash` won the same `(group, path)` row) has
    // nothing left to feed. Covers every caller of this shared body
    // (`emit_local_change`, `emit_local_change_onto`, `emit_retroactive_
    // repair`).
    {
        let touched: Vec<&str> = change.ops.iter().flat_map(op_touched_paths).collect();
        if !touched.is_empty() {
            crate::projection_obligations::bump_projection_obligations_for_touched_paths(
                conn,
                group_id,
                &touched,
                now_unix_nanos(),
            )?;
            // This is the sole local-authoring emission seam: the bytes this
            // change describes were already observed on this device's own
            // disk (that observation is what produced the change), so the
            // obligation this bump just created/advanced can never
            // represent content not yet placed locally. Tag it `Local`
            // (overwriting the bump's own conservative `Remote` default)
            // so the offline-delete-vs-not-yet-placed tombstone veto never
            // treats this device's own already-authored write as a reason
            // to withhold a later, genuine offline deletion. See
            // `ObligationOrigin`'s own doc comment for the full reasoning.
            crate::projection_obligations::mark_projection_obligations_local_origin(
                conn, group_id, &touched,
            )?;
            // Every path this change writes has just moved past whatever
            // materialized basis it held. That covers the paths no caller
            // named (derived conflict copies), a restore whose write comes
            // later and may never come, and a repair carrier -- so the
            // bases are retired here, in the emission's own transaction,
            // rather than by each caller.
            crate::materialized_generation::retire_bases_after_local_emission(
                conn,
                group_id,
                &touched,
                now_unix_nanos(),
            )?;
        }
    }
    Ok(change)
}

/// Builds, signs, and appends a new local change onto caller-specified
/// `parents` rather than the group's current heads. Used for a local edit
/// whose bytes came from a basis this device has since written past: the
/// change is authored onto that basis, so the edit means what the user's
/// bytes meant. The signed content is otherwise identical: same
/// signature/authorization shape, same structural re-validation before
/// appending. Always leaves the appended change unapplied
/// (`applied = false`), matching this call site's own convention,
/// independent of whether any conflict-copy op was derived.
pub fn emit_local_change_onto(
    conn: &Connection,
    group_id: &str,
    parents: Vec<ChangeHash>,
    ops: Vec<Op>,
    emitter: &ChangeEmitter,
) -> Result<Change, SyncSqliteError> {
    emit_change_with_derived_conflict_copies(
        conn,
        group_id,
        parents,
        ops,
        emitter,
        ChangePurpose::Ordinary,
        None,
        None,
    )
}

/// [`emit_local_change_onto`] with what the writer was shown at each path
/// stated rather than read from the rows at the paths `ops` names: the
/// installed base's heads it supersedes are those among `seen` (see
/// [`prepare_emission`]). For a write that acts on a row at another path
/// than its op's own, and for a caller with no rows to read.
pub fn emit_local_change_onto_seeing(
    conn: &Connection,
    group_id: &str,
    parents: Vec<ChangeHash>,
    ops: Vec<Op>,
    seen: &SeenVersions,
    emitter: &ChangeEmitter,
) -> Result<Change, SyncSqliteError> {
    emit_change_with_derived_conflict_copies(
        conn,
        group_id,
        parents,
        ops,
        emitter,
        ChangePurpose::Ordinary,
        None,
        Some(seen),
    )
}

/// [`emit_local_change`] with what the writer was shown stated, as
/// [`emit_local_change_onto_seeing`] states it.
pub fn emit_local_change_seeing(
    conn: &Connection,
    group_id: &str,
    ops: Vec<Op>,
    seen: &SeenVersions,
    emitter: &ChangeEmitter,
) -> Result<Change, SyncSqliteError> {
    let parents = plain_frontier_parents(conn, group_id)?;
    emit_local_change_onto_seeing(conn, group_id, parents, ops, seen, emitter)
}

/// [`emit_local_change_onto`] for one part of a recursive delete or
/// directory rename: the same emission, with `part` signed into it. The
/// part's effect ops are `ops`; a conflict copy the emission derives rides
/// along outside the operation's effect set (see
/// [`yadorilink_replica_domain::recursive_operation::is_recursive_effect`]).
pub fn emit_recursive_part_onto(
    conn: &Connection,
    group_id: &str,
    parents: Vec<ChangeHash>,
    ops: Vec<Op>,
    part: RecursiveOperation,
    emitter: &ChangeEmitter,
) -> Result<Change, SyncSqliteError> {
    emit_change_with_derived_conflict_copies(
        conn,
        group_id,
        parents,
        ops,
        emitter,
        ChangePurpose::Ordinary,
        Some(part),
        None,
    )
}

/// [`emit_recursive_part_onto`] with what the writer was shown stated, as
/// [`emit_local_change_onto_seeing`] states it.
pub fn emit_recursive_part_onto_seeing(
    conn: &Connection,
    group_id: &str,
    parents: Vec<ChangeHash>,
    ops: Vec<Op>,
    part: RecursiveOperation,
    seen: &SeenVersions,
    emitter: &ChangeEmitter,
) -> Result<Change, SyncSqliteError> {
    emit_change_with_derived_conflict_copies(
        conn,
        group_id,
        parents,
        ops,
        emitter,
        ChangePurpose::Ordinary,
        Some(part),
        Some(seen),
    )
}

/// Emits a signed, first-class retroactive-repair carrier on the current
/// group frontier. The caller supplies the exact obligations its planning
/// pass observed; the common emission body derives the copy ops and refuses
/// any mismatch before append.
pub fn emit_retroactive_repair(
    conn: &Connection,
    group_id: &str,
    direct_ops: Vec<Op>,
    obligations: Vec<RepairObligation>,
    emitter: &ChangeEmitter,
) -> Result<Change, SyncSqliteError> {
    let parents = group_heads(conn, group_id)?;
    emit_change_with_derived_conflict_copies(
        conn,
        group_id,
        parents,
        direct_ops,
        emitter,
        ChangePurpose::RetroactiveRepair { obligations },
        None,
        None,
    )
}

/// Shared body of `emit_local_change`/`emit_local_change_onto`: derives any
/// `ConflictCopy` puts this change's exact `(parents, ops)` requires (see
/// `conflict_authoring::derive_required_conflict_copy_ops`'s own doc comment
/// for why authoring happens exactly here, at the moment a new local edit's
/// parents causally close over a prior fork), folds them into the same
/// signed change as `ops`, appends, and records their provenance.
///
/// `default_applied` is the caller's own convention when no conflict-copy op
/// was derived (`true` for `emit_local_change`'s ordinary local edits, whose
/// own direct effect is already on disk; `false` for `emit_local_change_onto`'s
/// rebootstrap-squash caller, which always leaves its result for the
/// reprojection backstop). When a conflict-copy op IS derived, the change is
/// always left unapplied regardless of `default_applied`: the derived op's
/// content is something this device must still fetch/materialize at a new
/// path, exactly like a peer-received change would need, so `applied = true`
/// would be a lie about content that plainly isn't on disk yet. A
/// materialization job for each derived conflict-copy path is enqueued in the
/// SAME transaction, so the Convergence Engine picks it up without waiting
/// for the periodic reprojection sweep.
#[allow(clippy::too_many_arguments)]
fn emit_change_with_derived_conflict_copies(
    conn: &Connection,
    group_id: &str,
    parents: Vec<ChangeHash>,
    ops: Vec<Op>,
    emitter: &ChangeEmitter,
    purpose: ChangePurpose,
    recursive_operation: Option<RecursiveOperation>,
    seen: Option<&SeenVersions>,
) -> Result<Change, SyncSqliteError> {
    let prepared = prepare_emission(
        conn,
        group_id,
        emitter.device_id(),
        parents,
        ops,
        purpose,
        recursive_operation,
        seen,
    )?;
    admit_prepared_emission(conn, prepared, emitter)
}

pub(crate) fn now_unix_nanos() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests;
