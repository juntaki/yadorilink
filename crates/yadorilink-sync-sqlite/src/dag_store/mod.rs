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

mod causal_basis;
mod checkpoint_store;
mod conflict_authoring;
mod frontier_index;
mod orphan_integrity;
mod rejected_changes;
mod retained_history_integrity;
mod retention_roots;
mod serving_authorization_index;

pub use causal_basis::{intern_causal_basis, lookup_causal_basis_members};
pub use checkpoint_store::latest_checkpoint;
pub use conflict_authoring::record_conflict_copy_ops_provenance;
pub use conflict_authoring::{
    derive_required_conflict_copy_ops, init_conflict_copy_provenance_schema,
    path_heads_at_frontier, validate_carrier_conflict_copy_ops,
};
pub use frontier_index::{
    get_device_frontier, group_heads, max_parent_lamport, remove_device_frontier,
    set_device_frontier,
};
pub use orphan_integrity::{promote_orphans, ORPHAN_BOUND};
pub use rejected_changes::list_rejected_changes;
pub(crate) use rejected_changes::{is_change_rejected, record_rejected_change};
pub use retained_history_integrity::{
    get_encoded, group_history_paths, has_all_parents, has_change, has_change_or_pruned,
    is_ancestor, lamport_of, list_unapplied, mark_applied, parents_of,
};
pub use retention_roots::{
    full_payload_retained_block_hashes, full_payload_retained_block_hashes_all_groups,
    register_retention_root, release_retention_root, RetentionClass,
};
pub use serving_authorization_index::sweep_unreferenced_file_versions;
pub use serving_authorization_index::{
    get_file_version, group_file_version_references_block, group_has_block_provenance,
    has_file_version, put_file_version, record_compacted_file_version_authorization,
    record_group_block_provenance,
};

use rusqlite::{Connection, OptionalExtension};

#[cfg(test)]
use orphan_integrity::insert_orphan;
#[cfg(test)]
use retained_history_integrity::append_change;
#[cfg(test)]
use yadorilink_replica_domain::file::FileVersion;

use crate::error::SyncSqliteError;
use crate::filesystem_transaction;
use yadorilink_replica_domain::change::{
    encoded_op_len, Change, ChangeAuth, ChangePurpose, Op, RepairObligation, MAX_CHANGE_OP_BYTES,
};
use yadorilink_replica_domain::ids::{ChangeHash, DeviceId, FolderGroupId};

pub use yadorilink_replica_domain::admission::{
    AdmitOutcome, AdmitResult, ChangeEmitter, ChangeOrdering,
};

/// The `change_checkpoints` table schema. Duplicated from
/// `yadorilink-sync-core::compaction::CHECKPOINT_TABLE_MIGRATION` rather than
/// reached back up for -- this crate sits below sync-core in the dependency
/// graph (see this crate's own lib.rs doc comment), so it cannot depend on
/// it. If that schema ever changes, this copy must change with it.
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

/// DST-only targeted trace, duplicated from `yadorilink-sync-core::dst_trace`
/// for the same "this crate sits below sync-core" reason as
/// [`CHECKPOINT_TABLE_MIGRATION`] above -- see that function's own doc
/// comment for the full rationale (set `DST_TRACE_PATH=<exact sync path>`).
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

/// Creates the DAG tables if they do not exist. New tables only, so — like
/// the index's own `group_policy_watermark` — a
/// bare `CREATE TABLE IF NOT EXISTS` is the whole migration.
pub fn init_dag_schema(conn: &Connection) -> Result<(), SyncSqliteError> {
    // v2 keyed versions by hash alone and attached one first-writer group.
    // Rebuild it with group ownership in the primary key before the regular
    // idempotent DDL runs. This preserves every existing row while allowing
    // identical content to be referenced independently by multiple groups.
    let legacy_file_versions =
        conn.prepare("PRAGMA table_info(file_versions)").and_then(|mut stmt| {
            let rows =
                stmt.query_map([], |row| Ok((row.get::<_, String>(1)?, row.get::<_, i64>(5)?)))?;
            rows.collect::<Result<Vec<_>, _>>()
        })?;
    if legacy_file_versions.iter().any(|(name, pk)| name == "version_hash" && *pk == 1)
        && !legacy_file_versions.iter().any(|(name, pk)| name == "group_id" && *pk > 0)
    {
        let tx = conn.unchecked_transaction()?;
        tx.execute_batch(
            r#"
            ALTER TABLE file_versions RENAME TO file_versions_v2;
            CREATE TABLE file_versions (
                version_hash BLOB NOT NULL,
                group_id     TEXT NOT NULL,
                encoded      BLOB NOT NULL,
                PRIMARY KEY (group_id, version_hash)
            );
            INSERT INTO file_versions (version_hash, group_id, encoded)
                SELECT version_hash, group_id, encoded FROM file_versions_v2;
            DROP TABLE file_versions_v2;
            CREATE TABLE IF NOT EXISTS change_file_versions (
                group_id     TEXT NOT NULL,
                change_hash  BLOB NOT NULL,
                version_hash BLOB NOT NULL,
                PRIMARY KEY (group_id, change_hash, version_hash)
            );
            "#,
        )?;

        // A v2 row recorded only the first group that stored a global
        // version, even though retained Changes in other groups could
        // legally reference the same hash. Reconstruct cross-group ownership
        // from the authoritative retained history in the same transaction as
        // the shape change itself: missing or corrupt history rolls back the
        // whole conversion rather than committing a partially-converted,
        // unusable table shape. (A database that already carries this shape
        // from an earlier, incomplete conversion — or that lost ownership
        // some other way, e.g. a promote-then-crash race — never enters this
        // `if`; it is instead repaired by the unconditional
        // `retained_history_integrity::repair`/`orphan_integrity::repair` pass
        // below, which also covers `orphan_changes`.)
        let admitted_changes: Vec<Vec<u8>> = {
            let mut stmt = tx.prepare("SELECT encoded FROM changes")?;
            let rows = stmt.query_map([], |row| row.get(0))?;
            rows.collect::<Result<_, _>>()?
        };
        for encoded in admitted_changes {
            let change = Change::from_wire_bytes(&encoded).map_err(|error| {
                SyncSqliteError::CorruptState(format!(
                    "cannot migrate v2 file versions: retained change is corrupt: {error}"
                ))
            })?;
            serving_authorization_index::repair_change_file_versions(&tx, &change, true)?;
        }
        tx.commit()?;
    }
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS changes (
            change_hash          BLOB PRIMARY KEY,
            group_id             TEXT NOT NULL,
            device_id            TEXT NOT NULL,
            lamport              INTEGER NOT NULL,
            encoded              BLOB NOT NULL,
            applied              INTEGER NOT NULL DEFAULT 0,
            -- `Change::authenticated_header_encoding()` for this row,
            -- computed once at append time. Retained so a future prune can
            -- hand it straight to `pruned_changes.authenticated_header`
            -- (via the `BEFORE DELETE` trigger in
            -- `retained_history_integrity`) without decoding `encoded` --
            -- pure column copy, same as `lamport`/`device_id` already are.
            authenticated_header BLOB NOT NULL DEFAULT X''
        );
        CREATE INDEX IF NOT EXISTS changes_by_group ON changes(group_id);

        CREATE TABLE IF NOT EXISTS change_parents (
            child_hash  BLOB NOT NULL,
            parent_hash BLOB NOT NULL,
            PRIMARY KEY (child_hash, parent_hash)
        );
        CREATE INDEX IF NOT EXISTS change_parents_by_parent
            ON change_parents(parent_hash);

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
            applied      INTEGER NOT NULL,
            received_seq INTEGER NOT NULL
        );

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

        -- A version's `change_file_versions` justification is lost the moment
        -- its only referencing change is compacted away, even when the
        -- version itself is still a live (current or retained superseded)
        -- row in the group's materialized file index. This table is that
        -- justification's compaction-surviving analog: the re-bootstrap
        -- snapshot layer records one row per version it re-persisted from
        -- live index state, so `group_file_version_references_block` never
        -- has to treat "the admitting change was pruned" as "this device is
        -- no longer authorized to serve it".
        CREATE TABLE IF NOT EXISTS compacted_file_version_authorization (
            group_id     TEXT NOT NULL,
            version_hash BLOB NOT NULL,
            PRIMARY KEY (group_id, version_hash)
        );

        -- A change hash `admit_change` refused for a reason that cannot
        -- resolve on retry (see `rejected_changes`'s module doc comment).
        -- `change_hash` alone is the key, matching `changes`'s own PK
        -- shape: a change is content-addressed, so the same hash always
        -- means the same bytes and the same rejection everywhere.
        -- `rules_version` is `reserved_namespace::RULES_VERSION` at the time
        -- this row was recorded — see `rejected_changes`'s module doc
        -- comment on why a row is only trusted as a settled verdict while
        -- its stamped version still matches the rules running right now.
        CREATE TABLE IF NOT EXISTS rejected_changes (
            change_hash   BLOB PRIMARY KEY,
            group_id      TEXT NOT NULL,
            reason        TEXT NOT NULL,
            rejected_at   INTEGER NOT NULL,
            rules_version INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS rejected_changes_by_group ON rejected_changes(group_id);
        "#,
    )?;
    causal_basis::init_causal_basis_schema(conn)?;
    retention_roots::init_retention_roots_schema(conn)?;
    // `admit_change`/`emit_change_with_derived_conflict_copies` (and this
    // function's own self-heal promotion below) look up
    // `filesystem_transaction_reservations` on every admission to decide
    // whether to bump a live transaction's execution-generation fence (see
    // `bump_execution_fence_for_change`) -- that table must exist before any
    // of them run. `init_filesystem_transaction_schema` is pure `CREATE
    // TABLE/INDEX IF NOT EXISTS`, so calling it again here is a harmless
    // no-op for a caller that also separately initializes it (every
    // production DB-open path already does, per `index.rs`).
    filesystem_transaction::init_filesystem_transaction_schema(conn)?;
    retained_history_integrity::repair(conn)?;
    orphan_integrity::repair(conn)?;
    // Self-heal: an orphan whose parent is already durably admitted but that
    // was never promoted (a crash between `append_change` and
    // `promote_orphans`, or an orphan buffered directly out of band) has no
    // future admission left to seed a promotion pass for it, since ordinary
    // operation only seeds from the change that was just admitted. This is
    // the one place a full-buffer sweep is appropriate: it runs once at
    // startup, not once per admission.
    let self_heal_seeds = orphan_integrity::already_satisfied_parents(conn)?;
    if !self_heal_seeds.is_empty() {
        let self_healed = orphan_integrity::promote_orphans(conn, &self_heal_seeds)?;
        // Each of these just moved from buffered to durably admitted, on
        // this very connection -- exactly what `admit_change`'s own
        // promotion step does, and it must be fenced the same way: a
        // reservation recorded before a crash is still in the table across
        // restart, and a plan built against it must not resume as if this
        // newly-promoted change had never happened.
        bump_execution_fence_for_promoted(conn, &self_healed)?;
    }
    frontier_index::repair(conn)?;
    // The checkpoint table is created in the same step as the other DAG
    // tables so the whole change-history schema is provisioned by one call and
    // in one order; the DDL itself is owned by the compaction module, which
    // reads and writes it. Pure `CREATE TABLE/INDEX IF NOT EXISTS`, so this is
    // idempotent on both a fresh and an already-upgraded database.
    conn.execute_batch(crate::dag_store::CHECKPOINT_TABLE_MIGRATION)?;
    Ok(())
}

/// Installs a checkpoint and deletes the pruned prefix, all on the supplied
/// connection — pass an open transaction so the checkpoint insert and every
/// delete commit together and a crash can never leave history half-pruned with
/// no checkpoint to answer ancestry against.
///
/// Each pruned hash is removed from `changes`, from `change_parents` as both a
/// child and a parent (so the retained cut changes become clean roots and an
/// ancestry walk terminates at the boundary with no dangling edge into deleted
/// history), and from `group_heads`. The checkpoint frontier changes are *not*
/// in `pruned`, so they and the live history above them are retained intact.
///
/// A hash in `pruned` that currently carries a `full_payload`
/// [`RetentionClass`] root ([`register_retention_root`]) is skipped entirely
/// — not deleted, not reduced to a `pruned_changes` stub — per that class's
/// own contract ("compaction must not even reduce this change to a causal
/// stub"; see `retention_roots`'s module doc and
/// `yadorilink-sync-core::captured_authoring`, its first registering owner). This is a
/// per-hash skip, not a whole-checkpoint refusal: the checkpoint still
/// commits and every other planned hash still prunes, so one held root can
/// delay compaction of *its own* change indefinitely without blocking the
/// rest of the group's history from compacting on schedule. The skipped hash
/// simply remains an ordinary live row in `changes` — not part of
/// `checkpoint.frontier`, but no different in shape from any other retained
/// change; its own already-live parents/children need no adjustment, and
/// `sweep_unreferenced_file_versions` below still observes (and keeps) the
/// file versions it references, since it re-scans `changes` after this loop
/// runs, not the `pruned` list this function was given.
///
/// This root check is a caller-independent safety net at the one place that
/// actually deletes change bodies, not merely a planner-side filter: the
/// planner (`compaction::plan_prune`) has no visibility into
/// `dag_retention_roots`, so any future or direct caller of this function
/// gets the same protection `plan_prune` (`yadorilink-sync-core::compaction::plan_prune`)'s
/// own callers do.
///
/// Releasing an orphaned root (one whose registering owner never follows up
/// to release it — see [`register_retention_root`]'s own idempotency note)
/// is out of scope here: this function enforces the contract a live root
/// states, it does not judge whether that root is still wanted. A root that
/// is never released holds its one change indefinitely; that owner's own
/// lifecycle (e.g. `yadorilink-sync-core::retained_obligation::delete_if_eligible` for
/// `captured_authoring`'s roots) is what is expected to call
/// [`release_retention_root`] once the content it protects is durable
/// through some other path.
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
fn op_touched_paths(op: &Op) -> Vec<&str> {
    match op {
        Op::Put { path, .. } | Op::Delete { path } => vec![path.as_str()],
        Op::Move { from, to, .. } => vec![from.as_str(), to.as_str()],
    }
}

/// Bumps the `execution_generation` fence (`filesystem_transaction::
/// bump_transactions_for_touched_paths`) of every live filesystem
/// transaction whose reservation covers a path `change`'s ops touch. Called
/// at every point a change durably lands in `changes` -- see this
/// function's call sites: [`admit_change`] (the change just applied, and
/// any orphan it promoted) and `emit_change_with_derived_conflict_copies`
/// (every local emission path, `captured_authoring::
/// author_captured_change` included, since it emits through
/// [`emit_local_change_onto`]).
///
/// A no-op, cheaply, for the overwhelmingly common case where nothing is
/// held on any touched path -- see `bump_transactions_for_touched_paths`'s
/// own doc for why that is also the ONLY reachable case while
/// [`filesystem_transaction::EXECUTION_ENABLED`] is `false`.
fn bump_execution_fence_for_change(
    conn: &Connection,
    change: &Change,
) -> Result<(), SyncSqliteError> {
    let touched: Vec<&str> = change.ops.iter().flat_map(op_touched_paths).collect();
    if touched.is_empty() {
        return Ok(());
    }
    filesystem_transaction::bump_transactions_for_touched_paths(
        conn,
        change.group_id.as_str(),
        &touched,
    )?;
    Ok(())
}

/// [`bump_execution_fence_for_change`] for every hash in `promoted` --
/// shared by [`admit_change`]'s own promotion step and [`init_dag_schema`]'s
/// startup self-heal sweep, the two places a buffered orphan turns into a
/// durably admitted change without an already-in-hand [`Change`] to pass
/// straight to [`bump_execution_fence_for_change`]. Each hash is re-read via
/// [`describe_hash`] (already admitted on this same connection by the time
/// this runs) rather than trusting the caller to have kept the decoded
/// `Change` around.
fn bump_execution_fence_for_promoted(
    conn: &Connection,
    promoted: &[ChangeHash],
) -> Result<(), SyncSqliteError> {
    for hash in promoted {
        match describe_hash(conn, hash)? {
            DagHashDisposition::Admitted { change, .. } => {
                bump_execution_fence_for_change(conn, &change)?;
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
pub fn admit_change(
    conn: &Connection,
    change: &Change,
    applied: bool,
) -> Result<AdmitResult, SyncSqliteError> {
    if let Err(e) = serving_authorization_index::validate_no_reserved_paths(change) {
        // Unlike every other admission failure below (a missing referenced
        // version, an incomplete parent shape — all properties of what this
        // device has received SO FAR, which change as more of the DAG
        // arrives), a reserved-namespace collision or a non-portable path
        // is a fixed property of the change's own signed bytes:
        // re-admitting the identical change can never produce a different
        // verdict. Record it durably so
        // `missing_ancestor_frontier`/`has_change_or_buffered_orphan` stop
        // treating this hash as merely not-yet-received and a peer stops
        // being asked for it forever — see `rejected_changes`'s module doc
        // comment for the retry loop this closes.
        match &e {
            SyncSqliteError::ReservedNamespaceCollision(path) => {
                record_rejected_change(
                    conn,
                    &change.compute_hash(),
                    change.group_id.as_str(),
                    &format!("reserved namespace collision: {path:?}"),
                    now_unix_nanos(),
                )?;
            }
            SyncSqliteError::NonPortablePath(path) => {
                record_rejected_change(
                    conn,
                    &change.compute_hash(),
                    change.group_id.as_str(),
                    &format!("non-portable path: {path:?}"),
                    now_unix_nanos(),
                )?;
            }
            _ => {}
        }
        return Err(e);
    }
    serving_authorization_index::validate_referenced_versions(conn, change)?;
    if retained_history_integrity::validate_present_parent_shape(conn, change)? {
        // A change's `ConflictCopy` puts claim things about its OWN parent
        // frontier (see `conflict_authoring::validate_carrier_conflict_copy_ops`'s
        // doc comment) -- only checkable once its parents are confirmed
        // present, which `validate_present_parent_shape` above just did.
        conflict_authoring::validate_carrier_conflict_copy_ops(
            conn,
            change.group_id.as_str(),
            change,
        )?;
        retained_history_integrity::append_change(conn, change, applied)?;
        conflict_authoring::record_conflict_copy_ops_provenance(
            conn,
            change.group_id.as_str(),
            change,
        )?;
        // This change just moved the desired state under every path its ops
        // touch -- fence out any plan a live filesystem transaction already
        // built against the pre-admission state on one of those paths.
        bump_execution_fence_for_change(conn, change)?;
        // The current change lands first, then any orphans its arrival
        // unblocked. All of them became durable in this call, so the caller
        // must project and gate every one — return the full set in append
        // order (current change first).
        let hash = change.compute_hash();
        let promoted = orphan_integrity::promote_orphans(conn, &[hash])?;
        // Every orphan `promote_orphans` just promoted also just moved the
        // desired state, exactly like the primary change above -- fence out
        // any plan built on the paths its own ops touch too.
        bump_execution_fence_for_promoted(conn, &promoted)?;
        let mut newly_admitted = vec![hash];
        newly_admitted.extend(promoted);
        Ok(AdmitResult { outcome: AdmitOutcome::Applied, newly_admitted })
    } else {
        // Record the edges now so `promote_orphans` can test completeness
        // cheaply once the parents land.
        let hash = change.compute_hash();
        for parent in &change.parents {
            conn.execute(
                "INSERT OR IGNORE INTO change_parents (child_hash, parent_hash) VALUES (?1, ?2)",
                rusqlite::params![&hash.0[..], &parent.0[..]],
            )?;
        }
        orphan_integrity::insert_orphan(conn, change, applied)?;
        Ok(AdmitResult { outcome: AdmitOutcome::Orphaned, newly_admitted: Vec::new() })
    }
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
        let is_buffered: Option<i64> = conn
            .query_row("SELECT 1 FROM orphan_changes WHERE change_hash = ?1", [&hash.0[..]], |r| {
                r.get(0)
            })
            .optional()?;
        if is_buffered.is_none() {
            missing.push(hash);
            continue;
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
    /// Rows in `changes` for this group (durably admitted, applied or not).
    pub admitted_total: u64,
    /// Admitted changes whose path projection has not succeeded yet.
    pub admitted_unapplied: u64,
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
    let admitted_unapplied: i64 = conn.query_row(
        "SELECT COUNT(*) FROM changes WHERE group_id = ?1 AND applied = 0",
        [group_id],
        |r| r.get(0),
    )?;
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
        admitted_unapplied: admitted_unapplied as u64,
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
    Admitted { applied: bool, change: Change },
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
    let admitted: Option<(Vec<u8>, i64)> = conn
        .query_row(
            "SELECT encoded, applied FROM changes WHERE change_hash = ?1",
            [&hash.0[..]],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    if let Some((encoded, applied)) = admitted {
        let change = Change::from_wire_bytes(&encoded).map_err(|error| {
            SyncSqliteError::CorruptState(format!(
                "admitted change {} no longer decodes: {error}",
                hash.to_hex()
            ))
        })?;
        return Ok(DagHashDisposition::Admitted { applied: applied != 0, change });
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
    auth: ChangeAuth,
    emitter: &ChangeEmitter,
) -> Result<Change, SyncSqliteError> {
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
    emit_change_with_derived_conflict_copies(
        conn,
        group_id,
        parents,
        ops,
        auth,
        emitter,
        ChangePurpose::Ordinary,
        true,
    )
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
    derived_ops: Vec<Op>,
    purpose: ChangePurpose,
    max_parent_lamport: u64,
    applied: bool,
}

/// Derives, validates and freezes everything about an emission that depends on
/// the database, leaving only signing and appending for
/// [`admit_prepared_emission`]. See [`PreparedEmission`].
pub fn prepare_emission(
    conn: &Connection,
    group_id: &str,
    parents: Vec<ChangeHash>,
    ops: Vec<Op>,
    purpose: ChangePurpose,
    default_applied: bool,
) -> Result<PreparedEmission, SyncSqliteError> {
    let derived_ops =
        conflict_authoring::derive_required_conflict_copy_ops(conn, group_id, &parents, &ops)?;
    let applied = default_applied && derived_ops.is_empty();
    let mut all_ops = ops;
    all_ops.extend(derived_ops.iter().cloned());

    // `Change::create_signed` sorts and dedups parents itself; do it here too
    // so the parent set validated below is byte-for-byte the one that will be
    // signed, rather than a merely equivalent one.
    let mut parents = parents;
    parents.sort();
    parents.dedup();

    let max_parent_lamport = frontier_index::max_parent_lamport(conn, group_id, &parents)?;

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
        max_parent_lamport.saturating_add(1),
    )? {
        return Err(SyncSqliteError::CorruptState(format!(
            "cannot emit local change for group {group_id}: a recorded parent is not actually \
             present in retained history"
        )));
    }
    conflict_authoring::validate_carrier_conflict_copy_ops_parts(
        conn, group_id, &parents, &all_ops, &purpose,
    )?;

    Ok(PreparedEmission {
        group_id: group_id.to_string(),
        parents,
        all_ops,
        derived_ops,
        purpose,
        max_parent_lamport,
        applied,
    })
}

/// Signs `prepared` under `auth` and appends it with its companion rows.
///
/// Consumes the preparation by value. Between the caller acquiring `auth` and
/// this function's append there is no filesystem read, no block-store I/O, no
/// parent lookup, no conflict derivation and no unrelated SQL: only the
/// in-memory assembly of already-validated fields, the signature, the hash,
/// the purely in-memory structural/size checks over those same fields, and the
/// admission writes themselves.
pub fn admit_prepared_emission(
    conn: &Connection,
    prepared: PreparedEmission,
    auth: ChangeAuth,
    emitter: &ChangeEmitter,
) -> Result<Change, SyncSqliteError> {
    let PreparedEmission {
        group_id,
        parents,
        all_ops,
        derived_ops,
        purpose,
        max_parent_lamport,
        applied,
    } = prepared;
    let group_id = group_id.as_str();

    let change = match purpose {
        ChangePurpose::Ordinary => Change::create_signed(
            parents,
            max_parent_lamport,
            auth,
            DeviceId(emitter.device_id().to_string()),
            FolderGroupId(group_id.to_string()),
            all_ops,
            emitter.signing_key(),
        ),
        ChangePurpose::RetroactiveRepair { obligations } => Change::create_repair_signed(
            parents,
            max_parent_lamport,
            auth,
            DeviceId(emitter.device_id().to_string()),
            FolderGroupId(group_id.to_string()),
            obligations,
            all_ops,
            emitter.signing_key(),
        ),
    };
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
    // An independent review's finding: `admit_change` (the RECEIVING
    // side, for a peer's incoming change) already calls this same
    // `validate_no_reserved_paths` before ever admitting a change into
    // this device's own history -- but this LOCAL-authoring emission
    // path never did, for any of its callers (`emit_local_change`, the
    // live watcher's own path; `emit_local_change_onto`, rebootstrap's
    // squash; `emit_retroactive_repair`, conflict-copy/retroactive
    // repair; and `SyncState::append_history_backfill`, which itself
    // calls `emit_local_change`). A path this device's own filesystem
    // happens to produce (e.g. a POSIX peer's user creating `"report."`,
    // legal on Linux/macOS, silently normalized away on Windows) would
    // sign and append successfully HERE, become this device's own head,
    // and only then be discovered unacceptable -- by every OTHER peer's
    // `admit_change`, which permanently records the hash as rejected and
    // never re-requests it, orphaning every descendant change forever.
    // Checking before `append_change` below closes the asymmetry at its
    // root: the identical predicate now runs on both sides, so a
    // non-portable path is refused before it can ever become local
    // history to propagate in the first place, not just refused by
    // peers after the fact.
    serving_authorization_index::validate_no_reserved_paths(&change)?;
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
    retained_history_integrity::append_change(conn, &change, applied)?;
    conflict_authoring::record_conflict_copy_ops_provenance(conn, group_id, &change)?;
    // This locally authored change just moved the desired state under every
    // path its ops (direct and derived conflict-copy) touch -- fence out any
    // plan a live filesystem transaction already built against the
    // pre-admission state on one of those paths. Covers every caller of this
    // shared body (`emit_local_change`, `emit_local_change_onto`,
    // `emit_retroactive_repair`) and, transitively, `captured_authoring`,
    // which emits through this same split.
    bump_execution_fence_for_change(conn, &change)?;
    if !derived_ops.is_empty() {
        let now = now_unix_nanos();
        // Keyed by the CARRIER's change hash, exactly like the admission-side
        // enqueue in `handle_change_batch` (its `path_versions` stores the
        // touching change's hash). A job row keyed by the copy's content
        // VersionHash here used to race the admission-side re-arm: the two
        // sites disagreed on `version_hash` for the same `(group, path)`
        // row, so the engine's Completed transition (guarded by the version
        // it claimed) could no-op against a row the other site had re-keyed,
        // leaving a finished job permanently non-terminal.
        for op in &derived_ops {
            let Op::Put { path, .. } = op else {
                unreachable!("derive_required_conflict_copy_ops only ever returns Put ops");
            };
            crate::enqueue_pending(
                conn,
                group_id,
                path.as_str(),
                &change_hash.0,
                change.lamport,
                now,
            )?;
        }
    }
    Ok(change)
}

/// Builds, signs, and appends a new local change onto caller-specified
/// `parents` rather than the group's current heads. Used by re-bootstrap to
/// squash an offline-diverged local branch (one whose head does not descend
/// from an incoming checkpoint frontier) into a single new change re-parented
/// onto the just-installed frontier -- at that point in the atomic installer
/// `group_heads` does not yet reflect the new frontier, so `emit_local_change`'s
/// own current-heads resolution cannot be reused as-is. The signed content is
/// otherwise identical: same signature/authorization shape, same structural
/// re-validation before appending. Always leaves the appended change
/// unapplied (`applied = false`), matching this call site's own convention
/// (a squashed offline branch is deliberately left for the ordinary
/// reprojection backstop), independent of whether any conflict-copy op was
/// derived.
pub fn emit_local_change_onto(
    conn: &Connection,
    group_id: &str,
    parents: Vec<ChangeHash>,
    ops: Vec<Op>,
    auth: ChangeAuth,
    emitter: &ChangeEmitter,
) -> Result<Change, SyncSqliteError> {
    emit_change_with_derived_conflict_copies(
        conn,
        group_id,
        parents,
        ops,
        auth,
        emitter,
        ChangePurpose::Ordinary,
        false,
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
    auth: ChangeAuth,
    emitter: &ChangeEmitter,
) -> Result<Change, SyncSqliteError> {
    let parents = group_heads(conn, group_id)?;
    emit_change_with_derived_conflict_copies(
        conn,
        group_id,
        parents,
        direct_ops,
        auth,
        emitter,
        ChangePurpose::RetroactiveRepair { obligations },
        false,
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
    auth: ChangeAuth,
    emitter: &ChangeEmitter,
    purpose: ChangePurpose,
    default_applied: bool,
) -> Result<Change, SyncSqliteError> {
    let prepared = prepare_emission(conn, group_id, parents, ops, purpose, default_applied)?;
    admit_prepared_emission(conn, prepared, auth, emitter)
}

fn now_unix_nanos() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use yadorilink_replica_domain::change::PutOrigin;
    use yadorilink_replica_domain::file::RecordKind;
    use yadorilink_replica_domain::file::{FileMeta, VersionBlock};
    use yadorilink_replica_domain::ids::{BlockHash, SyncPath};
    use yadorilink_replica_domain::session_state::ChangeContent;

    fn conn() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        init_dag_schema(&c).unwrap();
        c
    }

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[42u8; 32])
    }

    fn test_version() -> FileVersion {
        FileVersion::new(
            vec![],
            0,
            FileMeta {
                mtime_unix_nanos: 0,
                exec_bit: false,
                symlink_target: None,
                record_kind: RecordKind::File,
            },
        )
    }

    fn seed_test_version(conn: &Connection, group_id: &str) {
        put_file_version(conn, group_id, &test_version()).unwrap();
    }

    fn collapse_file_versions_to_v2(conn: &Connection, retained_group: &str) {
        conn.execute_batch(
            "ALTER TABLE file_versions RENAME TO file_versions_v3; \
             CREATE TABLE file_versions ( \
                 version_hash BLOB PRIMARY KEY, \
                 group_id TEXT NOT NULL, \
                 encoded BLOB NOT NULL);",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO file_versions (version_hash, group_id, encoded) \
             SELECT version_hash, group_id, encoded FROM file_versions_v3 WHERE group_id = ?1",
            [retained_group],
        )
        .unwrap();
        conn.execute_batch("DROP TABLE file_versions_v3; DELETE FROM change_file_versions;")
            .unwrap();
    }

    #[test]
    fn v2_migration_reconstructs_cross_group_version_ownership_from_changes() {
        let c = conn();
        let version = test_version();
        put_file_version(&c, "group-a", &version).unwrap();
        emit_local_change(
            &c,
            "group-a",
            vec![Op::Put {
                path: SyncPath("a".into()),
                version: version.version_hash,
                origin: PutOrigin::Direct,
            }],
            ChangeAuth::PLACEHOLDER,
            &emitter(),
        )
        .unwrap();
        put_file_version(&c, "group-b", &version).unwrap();
        emit_local_change(
            &c,
            "group-b",
            vec![Op::Put {
                path: SyncPath("b".into()),
                version: version.version_hash,
                origin: PutOrigin::Direct,
            }],
            ChangeAuth::PLACEHOLDER,
            &emitter(),
        )
        .unwrap();
        collapse_file_versions_to_v2(&c, "group-a");

        init_dag_schema(&c).unwrap();

        assert!(get_file_version(&c, "group-a", &version.version_hash).unwrap().is_some());
        assert!(get_file_version(&c, "group-b", &version.version_hash).unwrap().is_some());
        let relations: i64 =
            c.query_row("SELECT COUNT(*) FROM change_file_versions", [], |row| row.get(0)).unwrap();
        assert_eq!(relations, 2);
    }

    #[test]
    fn v2_migration_rolls_back_when_a_retained_change_has_no_global_version() {
        let c = conn();
        let version = test_version();
        put_file_version(&c, "group-a", &version).unwrap();
        emit_local_change(
            &c,
            "group-a",
            vec![Op::Put {
                path: SyncPath("a".into()),
                version: version.version_hash,
                origin: PutOrigin::Direct,
            }],
            ChangeAuth::PLACEHOLDER,
            &emitter(),
        )
        .unwrap();
        collapse_file_versions_to_v2(&c, "missing-group");

        let error = init_dag_schema(&c).expect_err("missing v2 metadata must fail closed");
        assert!(matches!(error, SyncSqliteError::CorruptState(_)));
        let columns: Vec<String> = c
            .prepare("PRAGMA table_info(file_versions)")
            .unwrap()
            .query_map([], |row| row.get(1))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(columns, vec!["version_hash", "group_id", "encoded"]);
        assert!(!c
            .prepare("PRAGMA table_info(file_versions)")
            .unwrap()
            .query_map([], |row| row.get::<_, i64>(5))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
            .contains(&2));
    }

    #[test]
    fn already_group_scoped_database_missing_cross_group_ownership_is_repaired() {
        // Reproduces a database that already carries the group-scoped
        // `file_versions` shape from an earlier, incomplete conversion (the
        // historical bug in `3edca8f0`, which copied each v2 row under only
        // its first-writer group): the `if legacy_file_versions...` branch
        // above never fires for it, since the shape is already current, so
        // only the unconditional `repair_missing_file_version_ownership`
        // pass can close this gap.
        let c = conn();
        let version = test_version();
        put_file_version(&c, "group-a", &version).unwrap();
        emit_local_change(
            &c,
            "group-a",
            vec![Op::Put {
                path: SyncPath("a".into()),
                version: version.version_hash,
                origin: PutOrigin::Direct,
            }],
            ChangeAuth::PLACEHOLDER,
            &emitter(),
        )
        .unwrap();
        put_file_version(&c, "group-b", &version).unwrap();
        emit_local_change(
            &c,
            "group-b",
            vec![Op::Put {
                path: SyncPath("b".into()),
                version: version.version_hash,
                origin: PutOrigin::Direct,
            }],
            ChangeAuth::PLACEHOLDER,
            &emitter(),
        )
        .unwrap();
        // Simulate the prior migration's bug directly: drop group-b's row
        // while leaving the table itself in the (already current)
        // group-scoped shape.
        c.execute(
            "DELETE FROM file_versions WHERE group_id = 'group-b' AND version_hash = ?1",
            [&version.version_hash.0[..]],
        )
        .unwrap();
        assert!(get_file_version(&c, "group-b", &version.version_hash).unwrap().is_none());

        init_dag_schema(&c).unwrap();

        assert!(get_file_version(&c, "group-a", &version.version_hash).unwrap().is_some());
        assert!(
            get_file_version(&c, "group-b", &version.version_hash).unwrap().is_some(),
            "a database already in the group-scoped shape must still have \
             cross-group ownership repaired from retained Changes"
        );
    }

    #[test]
    fn schema_init_repairs_file_version_ownership_referenced_only_by_a_buffered_orphan() {
        // The plain `changes`-table backfill cannot see a version referenced
        // only by a change still buffered in `orphan_changes` (arrived
        // before its parent). Left unrepaired, that group's later
        // `promote_orphans` would fail `validate_referenced_versions`
        // forever once the parent does arrive.
        let sender = conn();
        let version = test_version();
        put_file_version(&sender, "group-b", &version).unwrap();
        let orphan = emit_local_change(
            &sender,
            "group-b",
            vec![Op::Put {
                path: SyncPath("b".into()),
                version: version.version_hash,
                origin: PutOrigin::Direct,
            }],
            ChangeAuth::PLACEHOLDER,
            &emitter(),
        )
        .unwrap();

        let c = conn();
        put_file_version(&c, "group-a", &version).unwrap();
        insert_orphan(&c, &orphan, false).unwrap();
        assert!(get_file_version(&c, "group-b", &version.version_hash).unwrap().is_none());

        init_dag_schema(&c).unwrap();

        assert!(
            get_file_version(&c, "group-b", &version.version_hash).unwrap().is_some(),
            "a version referenced only by a buffered orphan must still be \
             repaired into that orphan's group"
        );
        // An orphan is not yet admitted, so repairing its group's version
        // ownership must not also grant it block-serving authorization.
        let relations: i64 = c
            .query_row(
                "SELECT COUNT(*) FROM change_file_versions WHERE group_id = 'group-b'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(relations, 0);
    }

    #[test]
    fn list_unapplied_fails_closed_on_corrupt_retained_change() {
        let c = conn();
        c.execute(
            "INSERT INTO changes \
             (change_hash, group_id, device_id, lamport, encoded, applied) \
             VALUES (?1, 'g', 'device-a', 1, ?2, 0)",
            rusqlite::params![vec![0x72u8; 32], b"not-a-change".as_slice()],
        )
        .unwrap();

        let error = list_unapplied(&c, "g").expect_err("corrupt retry state must be visible");
        assert!(matches!(error, SyncSqliteError::CorruptState(_)));
    }

    #[test]
    fn block_reference_authorization_is_group_scoped() {
        let c = conn();
        let block_hash = vec![0xabu8; 32];
        let version = FileVersion::new(
            vec![VersionBlock { hash: BlockHash(block_hash.clone()), size: 7 }],
            7,
            FileMeta {
                mtime_unix_nanos: 0,
                exec_bit: false,
                symlink_target: None,
                record_kind: RecordKind::File,
            },
        );
        put_file_version(&c, "group-a", &version).unwrap();

        assert!(
            !group_file_version_references_block(&c, "group-a", &block_hash).unwrap(),
            "an unreferenced version must not authorize block service"
        );
        emit_local_change(
            &c,
            "group-a",
            vec![Op::Put {
                path: SyncPath("a.bin".into()),
                version: version.version_hash,
                origin: PutOrigin::Direct,
            }],
            ChangeAuth::PLACEHOLDER,
            &emitter(),
        )
        .unwrap();
        assert!(group_file_version_references_block(&c, "group-a", &block_hash).unwrap());
        assert!(!group_file_version_references_block(&c, "group-b", &block_hash).unwrap());
        assert!(!group_file_version_references_block(&c, "group-a", &[0xcdu8; 32]).unwrap());
    }

    #[test]
    fn admitted_metadata_does_not_forge_block_provenance() {
        let c = conn();
        let block_hash = vec![0xabu8; 32];
        let version = FileVersion::new(
            vec![VersionBlock { hash: BlockHash(block_hash.clone()), size: 7 }],
            7,
            FileMeta {
                mtime_unix_nanos: 0,
                exec_bit: false,
                symlink_target: None,
                record_kind: RecordKind::File,
            },
        );
        put_file_version(&c, "group-a", &version).unwrap();
        emit_local_change(
            &c,
            "group-a",
            vec![Op::Put {
                path: SyncPath("attacker-controlled.bin".into()),
                version: version.version_hash,
                origin: PutOrigin::Direct,
            }],
            ChangeAuth::PLACEHOLDER,
            &emitter(),
        )
        .unwrap();

        assert!(group_file_version_references_block(&c, "group-a", &block_hash).unwrap());
        assert!(
            !group_has_block_provenance(&c, "group-a", &block_hash).unwrap(),
            "even admitted, correctly signed metadata must not prove byte ownership"
        );

        record_group_block_provenance(&c, "group-b", std::slice::from_ref(&block_hash)).unwrap();
        assert!(group_has_block_provenance(&c, "group-b", &block_hash).unwrap());
        assert!(
            !group_has_block_provenance(&c, "group-a", &block_hash).unwrap(),
            "physical dedup must not leak provenance across groups"
        );

        record_group_block_provenance(&c, "group-a", std::slice::from_ref(&block_hash)).unwrap();
        assert!(group_has_block_provenance(&c, "group-a", &block_hash).unwrap());
    }

    #[test]
    fn rejected_change_rolls_back_its_versions_and_grants_no_block_capability() {
        let state =
            yadorilink_daemon::replica_coordinator::ReplicaCoordinator::open_in_memory().unwrap();
        let block_hash = vec![0x42; 32];
        let version = FileVersion::new(
            vec![VersionBlock { hash: BlockHash(block_hash.clone()), size: 7 }],
            7,
            FileMeta {
                mtime_unix_nanos: 0,
                exec_bit: false,
                symlink_target: None,
                record_kind: RecordKind::File,
            },
        );
        let signing = key();
        let mut change = Change::create_signed(
            vec![],
            0,
            ChangeAuth::PLACEHOLDER,
            DeviceId("device-A".into()),
            FolderGroupId("group-a".into()),
            vec![Op::Put {
                path: SyncPath("poison.bin".into()),
                version: version.version_hash,
                origin: PutOrigin::Direct,
            }],
            &signing,
        );
        change.lamport = 99;
        change.sign(&signing);

        assert!(state
            .change_history_repository()
            .dag_admit_change_with_versions(&change, std::slice::from_ref(&version), false)
            .is_err());
        assert!(!state.sqlite().dag_has_file_version("group-a", &version.version_hash).unwrap());
        assert!(!state
            .change_history_repository()
            .dag_group_file_version_references_block("group-a", &block_hash)
            .unwrap());
    }

    #[test]
    fn orphan_version_grants_no_block_capability_until_promotion() {
        let c = conn();
        let block_hash = vec![0x24; 32];
        let version = FileVersion::new(
            vec![VersionBlock { hash: BlockHash(block_hash.clone()), size: 7 }],
            7,
            FileMeta {
                mtime_unix_nanos: 0,
                exec_bit: false,
                symlink_target: None,
                record_kind: RecordKind::File,
            },
        );
        put_file_version(&c, "g", &version).unwrap();
        let signing = key();
        let parent = Change::create_signed(
            vec![],
            0,
            ChangeAuth::PLACEHOLDER,
            DeviceId("device-A".into()),
            FolderGroupId("g".into()),
            vec![Op::Delete { path: SyncPath("old.bin".into()) }],
            &signing,
        );
        let child = Change::create_signed(
            vec![parent.compute_hash()],
            parent.lamport,
            ChangeAuth::PLACEHOLDER,
            DeviceId("device-A".into()),
            FolderGroupId("g".into()),
            vec![Op::Put {
                path: SyncPath("new.bin".into()),
                version: version.version_hash,
                origin: PutOrigin::Direct,
            }],
            &signing,
        );

        assert_eq!(admit_change(&c, &child, false).unwrap().outcome, AdmitOutcome::Orphaned);
        assert!(!group_file_version_references_block(&c, "g", &block_hash).unwrap());
        assert_eq!(admit_change(&c, &parent, false).unwrap().outcome, AdmitOutcome::Applied);
        assert!(group_file_version_references_block(&c, "g", &block_hash).unwrap());
    }

    #[test]
    fn schema_init_backfills_admitted_change_version_relations() {
        let c = conn();
        let block_hash = vec![0x66; 32];
        let version = FileVersion::new(
            vec![VersionBlock { hash: BlockHash(block_hash.clone()), size: 7 }],
            7,
            FileMeta {
                mtime_unix_nanos: 0,
                exec_bit: false,
                symlink_target: None,
                record_kind: RecordKind::File,
            },
        );
        put_file_version(&c, "g", &version).unwrap();
        emit_local_change(
            &c,
            "g",
            vec![Op::Put {
                path: SyncPath("a".into()),
                version: version.version_hash,
                origin: PutOrigin::Direct,
            }],
            ChangeAuth::PLACEHOLDER,
            &emitter(),
        )
        .unwrap();
        c.execute("DELETE FROM change_file_versions", []).unwrap();
        assert!(!group_file_version_references_block(&c, "g", &block_hash).unwrap());

        init_dag_schema(&c).unwrap();
        assert!(group_file_version_references_block(&c, "g", &block_hash).unwrap());
    }

    #[test]
    fn version_sweep_fails_closed_on_a_corrupt_retained_change() {
        let c = conn();
        let version = test_version();
        put_file_version(&c, "g", &version).unwrap();
        c.execute(
            "INSERT INTO changes \
             (change_hash, group_id, device_id, lamport, encoded, applied) \
             VALUES (?1, 'g', 'device-A', 1, ?2, 1)",
            rusqlite::params![vec![0x91u8; 32], b"not-a-change".as_slice()],
        )
        .unwrap();

        let error = sweep_unreferenced_file_versions(&c, "g")
            .expect_err("corrupt retained history must abort version GC");
        assert!(matches!(error, SyncSqliteError::CorruptState(_)));
        assert!(get_file_version(&c, "g", &version.version_hash).unwrap().is_some());
    }

    fn create_op(path: &str) -> Op {
        Op::Put {
            path: SyncPath(path.into()),
            version: test_version().version_hash,
            origin: PutOrigin::Direct,
        }
    }

    /// Builds a validly-signed root change directly via `Change::
    /// create_signed`, bypassing `emit_local_change` entirely -- used by
    /// the `admit_change_rejects_*` tests below, which construct a
    /// deliberately reserved/non-portable-path change specifically to
    /// drive the RECEIVING side's own rejection (`admit_change`), not the
    /// local-emission-side check `emit_local_change` now also applies
    /// (added for an independent review's CRITICAL-3 finding -- see that
    /// change's own doc comment). Using `emit_local_change` to build these
    /// fixtures would now refuse the change before it could ever reach
    /// the `admit_change` call these tests actually exercise.
    fn hand_signed_change(group_id: &str, ops: Vec<Op>) -> Change {
        Change::create_signed(
            vec![],
            0,
            ChangeAuth::PLACEHOLDER,
            DeviceId("device-A".into()),
            FolderGroupId(group_id.into()),
            ops,
            &key(),
        )
    }

    fn emitter() -> ChangeEmitter {
        ChangeEmitter::new("device-A", key())
    }

    #[test]
    fn local_emission_chains_heads() {
        let c = conn();
        let em = emitter();

        let c1 =
            emit_local_change(&c, "g", vec![create_op("a")], ChangeAuth::PLACEHOLDER, &em).unwrap();
        assert_eq!(c1.parents, vec![]);
        assert_eq!(c1.lamport, 1);
        assert_eq!(group_heads(&c, "g").unwrap(), vec![c1.compute_hash()]);

        let c2 =
            emit_local_change(&c, "g", vec![create_op("b")], ChangeAuth::PLACEHOLDER, &em).unwrap();
        // c2 descends from c1, so c1 is no longer a head.
        assert_eq!(c2.parents, vec![c1.compute_hash()]);
        assert_eq!(c2.lamport, 2);
        assert_eq!(group_heads(&c, "g").unwrap(), vec![c2.compute_hash()]);

        assert!(is_ancestor(&c, &c1.compute_hash(), &c2.compute_hash()).unwrap());
        assert!(!is_ancestor(&c, &c2.compute_hash(), &c1.compute_hash()).unwrap());
    }

    /// An independent review's finding: `admit_change` (the RECEIVING side)
    /// already refuses a change containing a non-portable path component
    /// (a trailing `.`/` `, which a POSIX filesystem accepts but Windows
    /// silently normalizes away) via `validate_no_reserved_paths` -- but
    /// LOCAL authoring (`emit_local_change`, reachable directly here, and
    /// by extension every one of its own callers: the live watcher,
    /// `append_history_backfill`, `emit_local_change_onto`'s rebootstrap
    /// squash, `emit_retroactive_repair`) never applied the identical
    /// check before signing. A POSIX device could therefore sign and
    /// append a change no other peer could ever admit, becoming this
    /// device's own head with nothing left to build on for every peer
    /// that permanently rejects it.
    #[test]
    fn emit_local_change_refuses_a_non_portable_path() {
        let c = conn();
        let em = emitter();

        let err = emit_local_change(
            &c,
            "g",
            vec![create_op("report.")], // trailing dot: invalid on Windows
            ChangeAuth::PLACEHOLDER,
            &em,
        )
        .expect_err("a non-portable path must be refused before it is ever signed and appended");
        assert!(
            matches!(err, SyncSqliteError::NonPortablePath(_)),
            "unexpected error variant: {err:?}"
        );
        assert!(
            group_heads(&c, "g").unwrap().is_empty(),
            "the refused change must never become this group's head"
        );
    }

    /// Same local-authoring-side coverage as
    /// `emit_local_change_refuses_a_non_portable_path`, for the reserved
    /// Windows device-basename branch of `path_has_non_portable_wire_
    /// component` instead of the trailing-dot/space branch. Mirrors
    /// `admit_change_rejects_a_reserved_windows_device_name_path` (the
    /// RECEIVING-side test for this same predicate, above), so both call
    /// sites of `validate_no_reserved_paths` are directly, independently
    /// covered for this hazard shape rather than only the receiving side.
    #[test]
    fn emit_local_change_refuses_a_reserved_windows_device_name() {
        for name in ["CON", "com1", "LPT9.log"] {
            let c = conn();
            let em = emitter();
            let err =
                emit_local_change(&c, "g", vec![create_op(name)], ChangeAuth::PLACEHOLDER, &em)
                    .expect_err(
                        "a reserved Windows device name must be refused before it is ever signed \
                     and appended",
                    );
            assert!(
                matches!(err, SyncSqliteError::NonPortablePath(ref p) if p == name),
                "{name:?}: expected NonPortablePath, got {err:?}"
            );
            assert!(
                group_heads(&c, "g").unwrap().is_empty(),
                "{name:?}: the refused change must never become this group's head"
            );
        }
    }

    /// Same local-authoring-side coverage as
    /// `emit_local_change_refuses_a_non_portable_path`, for the Win32
    /// reserved-filename-character branch instead of the trailing-dot/space
    /// branch. Mirrors `admit_change_rejects_a_path_with_a_win32_reserved_
    /// filename_character` (the RECEIVING-side test for this same
    /// predicate, above).
    #[test]
    fn emit_local_change_refuses_a_win32_reserved_filename_character() {
        for ch in ['<', '>', '"', '|', '?', '*'] {
            let path = format!("notes{ch}draft.txt");
            let c = conn();
            let em = emitter();
            let err =
                emit_local_change(&c, "g", vec![create_op(&path)], ChangeAuth::PLACEHOLDER, &em)
                    .expect_err(
                        "a Win32-reserved filename character must be refused before it is ever \
                         signed and appended",
                    );
            assert!(
                matches!(err, SyncSqliteError::NonPortablePath(ref p) if p == &path),
                "{ch:?}: expected NonPortablePath, got {err:?}"
            );
            assert!(
                group_heads(&c, "g").unwrap().is_empty(),
                "{ch:?}: the refused change must never become this group's head"
            );
        }
    }

    #[test]
    fn append_is_idempotent_under_duplicate_delivery() {
        let c = conn();
        let change =
            emit_local_change(&c, "g", vec![create_op("a")], ChangeAuth::PLACEHOLDER, &emitter())
                .unwrap();
        // Re-appending the identical change changes nothing.
        assert!(!append_change(&c, &change, true).unwrap());
        let count: i64 = c.query_row("SELECT COUNT(*) FROM changes", [], |r| r.get(0)).unwrap();
        assert_eq!(count, 1);
        assert_eq!(group_heads(&c, "g").unwrap().len(), 1);
    }

    #[test]
    fn concurrent_changes_are_both_heads() {
        // Two devices edit from the same (empty) frontier without seeing
        // each other: both become heads.
        let c = conn();
        let a = ChangeEmitter::new("device-A", SigningKey::from_bytes(&[1u8; 32]));
        let b = ChangeEmitter::new("device-B", SigningKey::from_bytes(&[2u8; 32]));
        let ca =
            emit_local_change(&c, "g", vec![create_op("a")], ChangeAuth::PLACEHOLDER, &a).unwrap();
        seed_test_version(&c, "g");
        // Force B's change to also root at the empty frontier by admitting it
        // as if it arrived from a peer (its parents = []).
        let cb = Change::create_signed(
            vec![],
            0,
            ChangeAuth::PLACEHOLDER,
            DeviceId("device-B".into()),
            FolderGroupId("g".into()),
            vec![create_op("b")],
            &SigningKey::from_bytes(&[2u8; 32]),
        );
        let _ = b;
        assert_eq!(admit_change(&c, &cb, true).unwrap().outcome, AdmitOutcome::Applied);
        let mut heads = group_heads(&c, "g").unwrap();
        heads.sort();
        let mut expected = vec![ca.compute_hash(), cb.compute_hash()];
        expected.sort();
        assert_eq!(heads, expected);
    }

    #[test]
    fn out_of_order_arrival_is_orphaned_then_promoted() {
        // Build a chain root -> child on a "sender", then deliver child
        // first to a fresh receiver.
        let sender = conn();
        let em = emitter();
        let root =
            emit_local_change(&sender, "g", vec![create_op("a")], ChangeAuth::PLACEHOLDER, &em)
                .unwrap();
        let child =
            emit_local_change(&sender, "g", vec![create_op("b")], ChangeAuth::PLACEHOLDER, &em)
                .unwrap();

        let recv = conn();
        seed_test_version(&recv, "g");
        // Child arrives before its parent: held, not applied.
        assert_eq!(admit_change(&recv, &child, true).unwrap().outcome, AdmitOutcome::Orphaned);
        assert!(!has_change(&recv, &child.compute_hash()).unwrap());
        assert!(group_heads(&recv, "g").unwrap().is_empty());

        // Parent arrives: it applies and promotes the buffered child.
        assert_eq!(admit_change(&recv, &root, true).unwrap().outcome, AdmitOutcome::Applied);
        assert!(has_change(&recv, &root.compute_hash()).unwrap());
        assert!(has_change(&recv, &child.compute_hash()).unwrap());
        // The frontier converged to the single child head, just like the sender.
        assert_eq!(group_heads(&recv, "g").unwrap(), vec![child.compute_hash()]);
        assert_eq!(group_heads(&recv, "g").unwrap(), group_heads(&sender, "g").unwrap());
    }

    #[test]
    fn missing_ancestor_frontier_walks_through_a_stuck_buffered_orphan() {
        // A 3-generation chain root -> mid -> leaf built on a sender.
        // Deliver `leaf` and `mid` to a fresh receiver, but never `root` --
        // both `leaf` and `mid` buffer as orphans, `root` never arrives.
        let sender = conn();
        let em = emitter();
        let root =
            emit_local_change(&sender, "g", vec![create_op("a")], ChangeAuth::PLACEHOLDER, &em)
                .unwrap();
        let mid =
            emit_local_change(&sender, "g", vec![create_op("b")], ChangeAuth::PLACEHOLDER, &em)
                .unwrap();
        let leaf =
            emit_local_change(&sender, "g", vec![create_op("c")], ChangeAuth::PLACEHOLDER, &em)
                .unwrap();

        let recv = conn();
        seed_test_version(&recv, "g");
        assert_eq!(admit_change(&recv, &leaf, true).unwrap().outcome, AdmitOutcome::Orphaned);
        assert_eq!(admit_change(&recv, &mid, true).unwrap().outcome, AdmitOutcome::Orphaned);

        // The one-level check treats `leaf` as fully known (it's buffered),
        // exactly the gap this fn exists to close: a caller relying on it
        // alone would never discover that `root` is genuinely missing.
        assert!(has_change_or_buffered_orphan(&recv, &leaf.compute_hash()).unwrap());

        let missing = missing_ancestor_frontier(&recv, [leaf.compute_hash()]).unwrap();
        assert_eq!(missing, vec![root.compute_hash()]);

        // Once `root` lands, the whole buffered chain promotes.
        assert_eq!(admit_change(&recv, &root, true).unwrap().outcome, AdmitOutcome::Applied);
        assert!(has_change(&recv, &leaf.compute_hash()).unwrap());
        assert_eq!(group_heads(&recv, "g").unwrap(), vec![leaf.compute_hash()]);
        assert!(missing_ancestor_frontier(&recv, [leaf.compute_hash()]).unwrap().is_empty());
    }

    #[test]
    fn missing_ancestor_frontier_is_empty_for_a_change_only_waiting_on_an_in_flight_parent() {
        // A single-generation chain: `leaf`'s direct parent `root` simply
        // hasn't arrived yet (not itself stuck behind anything). The old
        // one-level check already handled this correctly -- confirms the
        // new fn doesn't regress the ordinary in-flight case into treating
        // an about-to-be-satisfied orphan as if its own immediate parent
        // were missing when it's genuinely just still in transit.
        let sender = conn();
        let em = emitter();
        let root =
            emit_local_change(&sender, "g", vec![create_op("a")], ChangeAuth::PLACEHOLDER, &em)
                .unwrap();
        let leaf =
            emit_local_change(&sender, "g", vec![create_op("b")], ChangeAuth::PLACEHOLDER, &em)
                .unwrap();

        let recv = conn();
        seed_test_version(&recv, "g");
        assert_eq!(admit_change(&recv, &leaf, true).unwrap().outcome, AdmitOutcome::Orphaned);

        let missing = missing_ancestor_frontier(&recv, [leaf.compute_hash()]).unwrap();
        assert_eq!(missing, vec![root.compute_hash()]);
    }

    #[test]
    fn missing_ancestor_frontier_dedups_a_missing_ancestor_shared_by_two_roots() {
        // Two independent chains, `root -> a` and `root -> b`, sharing the
        // same never-delivered `root`. Both `a` and `b` buffer as orphans;
        // querying both as roots together must report the shared missing
        // ancestor exactly once, not twice -- this is the whole point of
        // taking every root of one logical request in a single call instead
        // of one call per root. Built via two sibling connections both
        // seeded with the already-admitted `root` (so each independently
        // emits a local change parented on it), rather than hand-building
        // `Change` values directly.
        let origin = conn();
        let em_root = emitter();
        let root = emit_local_change(
            &origin,
            "g",
            vec![create_op("root")],
            ChangeAuth::PLACEHOLDER,
            &em_root,
        )
        .unwrap();

        let sender_a = conn();
        seed_test_version(&sender_a, "g");
        assert_eq!(admit_change(&sender_a, &root, true).unwrap().outcome, AdmitOutcome::Applied);
        let em_a = ChangeEmitter::new("device-a", key());
        let a =
            emit_local_change(&sender_a, "g", vec![create_op("a")], ChangeAuth::PLACEHOLDER, &em_a)
                .unwrap();
        assert_eq!(a.parents, vec![root.compute_hash()]);

        let sender_b = conn();
        seed_test_version(&sender_b, "g");
        assert_eq!(admit_change(&sender_b, &root, true).unwrap().outcome, AdmitOutcome::Applied);
        let em_b = ChangeEmitter::new("device-b", key());
        let b =
            emit_local_change(&sender_b, "g", vec![create_op("b")], ChangeAuth::PLACEHOLDER, &em_b)
                .unwrap();
        assert_eq!(b.parents, vec![root.compute_hash()]);

        let recv = conn();
        seed_test_version(&recv, "g");
        assert_eq!(admit_change(&recv, &a, true).unwrap().outcome, AdmitOutcome::Orphaned);
        assert_eq!(admit_change(&recv, &b, true).unwrap().outcome, AdmitOutcome::Orphaned);

        let missing =
            missing_ancestor_frontier(&recv, [a.compute_hash(), b.compute_hash()]).unwrap();
        assert_eq!(missing, vec![root.compute_hash()]);
    }

    #[test]
    fn missing_ancestor_frontier_reports_only_the_genuinely_missing_branch() {
        // Two independent single-parent chains: one whose parent is already
        // durably admitted (fully resolved, contributes nothing), one whose
        // parent never arrived (genuinely missing). Confirms the walk
        // doesn't conflate an admitted branch with a missing one when both
        // are queried together.
        let admitted_origin = conn();
        let em_p1 = emitter();
        let admitted_parent = emit_local_change(
            &admitted_origin,
            "g",
            vec![create_op("p1")],
            ChangeAuth::PLACEHOLDER,
            &em_p1,
        )
        .unwrap();

        let missing_origin = conn();
        let em_p2 = ChangeEmitter::new("device-missing", key());
        let missing_parent = emit_local_change(
            &missing_origin,
            "g",
            vec![create_op("p2")],
            ChangeAuth::PLACEHOLDER,
            &em_p2,
        )
        .unwrap();

        let recv = conn();
        seed_test_version(&recv, "g");
        // `admitted_parent` lands normally (its own parent set is empty --
        // the first change in this group's history on `recv` -- so it
        // applies immediately).
        assert_eq!(
            admit_change(&recv, &admitted_parent, true).unwrap().outcome,
            AdmitOutcome::Applied
        );

        let resolved_sender = conn();
        seed_test_version(&resolved_sender, "g");
        assert_eq!(
            admit_change(&resolved_sender, &admitted_parent, true).unwrap().outcome,
            AdmitOutcome::Applied
        );
        let em_resolved = ChangeEmitter::new("device-a", key());
        let resolved_child = emit_local_change(
            &resolved_sender,
            "g",
            vec![create_op("resolved-child")],
            ChangeAuth::PLACEHOLDER,
            &em_resolved,
        )
        .unwrap();
        assert_eq!(
            admit_change(&recv, &resolved_child, true).unwrap().outcome,
            AdmitOutcome::Applied
        );

        let orphaned_sender = conn();
        seed_test_version(&orphaned_sender, "g");
        assert_eq!(
            admit_change(&orphaned_sender, &missing_parent, true).unwrap().outcome,
            AdmitOutcome::Applied
        );
        let em_orphaned = ChangeEmitter::new("device-b", key());
        let orphaned_child = emit_local_change(
            &orphaned_sender,
            "g",
            vec![create_op("orphaned-child")],
            ChangeAuth::PLACEHOLDER,
            &em_orphaned,
        )
        .unwrap();
        assert_eq!(
            admit_change(&recv, &orphaned_child, true).unwrap().outcome,
            AdmitOutcome::Orphaned
        );

        let missing = missing_ancestor_frontier(
            &recv,
            [resolved_child.compute_hash(), orphaned_child.compute_hash()],
        )
        .unwrap();
        assert_eq!(missing, vec![missing_parent.compute_hash()]);
    }

    #[test]
    fn missing_ancestor_frontier_propagates_a_corrupt_parent_hash_rather_than_calling_it_missing() {
        // A malformed (non-32-byte) `change_parents.parent_hash` column must
        // surface as an error from the walk, not be silently treated as
        // "the peer doesn't have this either" -- folding a local data/DB
        // problem into "missing" would trigger needless re-fetch storms
        // instead of surfacing the real defect.
        let sender = conn();
        let em = emitter();
        // `leaf` needs a genuinely missing parent to orphan at all -- a
        // change with no parents (the group's very first) applies
        // immediately instead.
        let _root =
            emit_local_change(&sender, "g", vec![create_op("root")], ChangeAuth::PLACEHOLDER, &em)
                .unwrap();
        let leaf =
            emit_local_change(&sender, "g", vec![create_op("a")], ChangeAuth::PLACEHOLDER, &em)
                .unwrap();

        let recv = conn();
        seed_test_version(&recv, "g");
        assert_eq!(admit_change(&recv, &leaf, true).unwrap().outcome, AdmitOutcome::Orphaned);
        recv.execute(
            "DELETE FROM change_parents WHERE child_hash = ?1",
            [&leaf.compute_hash().0[..]],
        )
        .unwrap();
        recv.execute(
            "INSERT INTO change_parents (child_hash, parent_hash) VALUES (?1, ?2)",
            rusqlite::params![&leaf.compute_hash().0[..], vec![0xffu8; 4]],
        )
        .unwrap();

        let error = missing_ancestor_frontier(&recv, [leaf.compute_hash()])
            .expect_err("a malformed parent-hash column must be a hard error");
        assert!(matches!(error, SyncSqliteError::NotFound(_)));
    }

    #[test]
    fn promote_orphans_returns_promoted_hashes_in_append_order() {
        // A chain root -> c1 -> c2 built on a sender, with the two descendants
        // delivered to a fresh receiver before their common ancestor. When the
        // ancestor lands, promotion must return the promoted changes' hashes in
        // the order they were appended (oldest-first): the admission caller
        // projects each promoted orphan's paths, so it needs their identities,
        // not just a count.
        let sender = conn();
        let em = emitter();
        let root =
            emit_local_change(&sender, "g", vec![create_op("a")], ChangeAuth::PLACEHOLDER, &em)
                .unwrap();
        let c1 =
            emit_local_change(&sender, "g", vec![create_op("b")], ChangeAuth::PLACEHOLDER, &em)
                .unwrap();
        let c2 =
            emit_local_change(&sender, "g", vec![create_op("c")], ChangeAuth::PLACEHOLDER, &em)
                .unwrap();

        let recv = conn();
        seed_test_version(&recv, "g");
        // Both descendants arrive before the root: buffered, nothing promoted.
        assert_eq!(admit_change(&recv, &c1, true).unwrap().outcome, AdmitOutcome::Orphaned);
        assert_eq!(admit_change(&recv, &c2, true).unwrap().outcome, AdmitOutcome::Orphaned);

        // Land the root directly and promote: c1 unblocks first (its parent is
        // the root), then c2 (its parent is c1).
        assert!(append_change(&recv, &root, true).unwrap());
        let promoted = promote_orphans(&recv, &[root.compute_hash()]).unwrap();
        assert_eq!(promoted, vec![c1.compute_hash(), c2.compute_hash()]);
    }

    #[test]
    fn admit_change_reports_the_current_change_and_promoted_orphans() {
        // The other half of the same guarantee, but through `admit_change`:
        // admitting the root that unblocks a buffered child must report BOTH
        // the root and the promoted child in `newly_admitted`, root first.
        let sender = conn();
        let em = emitter();
        let root =
            emit_local_change(&sender, "g", vec![create_op("a")], ChangeAuth::PLACEHOLDER, &em)
                .unwrap();
        let child =
            emit_local_change(&sender, "g", vec![create_op("b")], ChangeAuth::PLACEHOLDER, &em)
                .unwrap();

        let recv = conn();
        seed_test_version(&recv, "g");
        let orphaned = admit_change(&recv, &child, true).unwrap();
        assert_eq!(orphaned.outcome, AdmitOutcome::Orphaned);
        assert!(orphaned.newly_admitted.is_empty(), "an orphaned change admits nothing yet");

        let applied = admit_change(&recv, &root, true).unwrap();
        assert_eq!(applied.outcome, AdmitOutcome::Applied);
        assert_eq!(applied.newly_admitted, vec![root.compute_hash(), child.compute_hash()]);
    }

    /// A change naming a versioned reserved-namespace artefact must be
    /// rejected before admission, so a peer can never route an artefact
    /// path into another device's index.
    #[test]
    fn admit_change_rejects_a_versioned_artefact_path() {
        let artefact_path = yadorilink_root_authority::reserved_namespace::artefact_component_name(
            yadorilink_root_authority::reserved_namespace::ArtefactKind::Preimage,
            "deadbeef",
        )
        .unwrap();
        let change = hand_signed_change("g", vec![create_op(&artefact_path)]);

        let recv = conn();
        seed_test_version(&recv, "g");
        let err = admit_change(&recv, &change, true).unwrap_err();
        assert!(
            matches!(err, SyncSqliteError::ReservedNamespaceCollision(ref p) if p == &artefact_path),
            "expected ReservedNamespaceCollision naming the artefact path, got {err:?}"
        );
    }

    /// THE remote-admission hole this pins closed: a peer's signed change
    /// naming this device's own sync-root lock file
    /// (`yadorilink_root_authority::sync_root_lock::SYNC_ROOT_LOCK_FILE_NAME`) must be refused
    /// at admission -- driven through the real `admit_change` entry point a
    /// peer's change actually arrives through, not a bare predicate call.
    /// Without this, the change would later materialize and replace the
    /// on-disk lock file out from under this device's own live OS lock,
    /// letting a second daemon acquire a fresh lock at the same path and
    /// believe it owns the root exclusively too.
    #[test]
    fn admit_change_rejects_a_sync_root_lock_path() {
        let lock_path =
            yadorilink_root_authority::sync_root_lock::SYNC_ROOT_LOCK_FILE_NAME.to_string();
        let change = hand_signed_change("g", vec![create_op(&lock_path)]);

        let recv = conn();
        seed_test_version(&recv, "g");
        let err = admit_change(&recv, &change, true).unwrap_err();
        assert!(
            matches!(err, SyncSqliteError::ReservedNamespaceCollision(ref p) if p == &lock_path),
            "expected ReservedNamespaceCollision naming the sync-root lock path, got {err:?}"
        );
    }

    /// The fix for a real defect: rejecting a change at admission used to
    /// write nothing durable, so the hash was indistinguishable from one
    /// this device simply never received — `has_change_or_buffered_orphan`
    /// and `missing_ancestor_frontier` would treat it as still-missing
    /// forever, and a peer would be asked for the identical, permanently
    /// unadmittable change on every future heads announce. A
    /// reserved-namespace rejection is a fixed property of the change's own
    /// bytes (re-admitting the identical change can never produce a
    /// different verdict), so it must be durably recorded and both
    /// "is this hash known" functions must recognize it — proven directly
    /// here rather than only through `admit_change`'s own return value.
    #[test]
    fn a_rejected_change_stops_being_reported_missing_and_is_not_re_requested() {
        let artefact_path = yadorilink_root_authority::reserved_namespace::artefact_component_name(
            yadorilink_root_authority::reserved_namespace::ArtefactKind::Backup,
            "cafef00d",
        )
        .unwrap();
        let change = hand_signed_change("g", vec![create_op(&artefact_path)]);
        let hash = change.compute_hash();

        let recv = conn();
        seed_test_version(&recv, "g");
        assert!(!has_change_or_buffered_orphan(&recv, &hash).unwrap(), "not seen yet");
        let missing_before = missing_ancestor_frontier(&recv, [hash]).unwrap();
        assert_eq!(missing_before, vec![hash], "genuinely unseen, so genuinely missing");

        admit_change(&recv, &change, true).unwrap_err();

        assert!(
            has_change_or_buffered_orphan(&recv, &hash).unwrap(),
            "a permanently-rejected hash must count as known — nothing about \
             re-requesting it can ever change the outcome"
        );
        let missing_after = missing_ancestor_frontier(&recv, [hash]).unwrap();
        assert!(
            missing_after.is_empty(),
            "a permanently-rejected hash must never be reported as missing again, or a peer \
             re-request loop never terminates: {missing_after:?}"
        );

        let rejected = list_rejected_changes(&recv, "g").unwrap();
        assert_eq!(rejected.len(), 1);
        assert_eq!(rejected[0].0, hash);
        assert!(rejected[0].1.contains(&artefact_path), "reason must name the exact path");
    }

    /// The converse guardrail, and the fix for a real defect: a change
    /// naming a path that merely *contains* the LEGACY `.yadorilink-tmp.`
    /// substring must still be admitted normally. Rejecting it here would
    /// (a) permanently block a genuine user file that happens to look like
    /// the marker (the marker is a substring match precisely because
    /// arbitrary user content can precede it — see
    /// `materialization::cleanup_stale_temp_files`'s own refusal to delete
    /// such a look-alike), and (b) make any already-signed history
    /// containing a legacy-marked path (admitted before this namespace
    /// excluded it from indexing) permanently unadmittable by an upgraded
    /// peer, stalling the whole group. `admit_change` must key its
    /// rejection on the artefact-only predicate, not the broader exclusion
    /// predicate; this test fails if it is pointed at the latter.
    #[test]
    fn admit_change_admits_a_legacy_marker_look_alike_path() {
        let sender = conn();
        let em = emitter();
        let legacy_path = "report.yadorilink-tmp.old";
        let change = emit_local_change(
            &sender,
            "g",
            vec![create_op(legacy_path)],
            ChangeAuth::PLACEHOLDER,
            &em,
        )
        .unwrap();

        let recv = conn();
        seed_test_version(&recv, "g");
        let result = admit_change(&recv, &change, true).unwrap();
        assert_eq!(result.outcome, AdmitOutcome::Applied);
    }

    /// Windows drops trailing `.`/` ` in most Win32 path APIs, so a peer
    /// that spells a reserved name with a trailing dot or space types a
    /// path that is not literally the reserved name, but would land on
    /// disk — on a Windows device — as exactly the reserved name. This
    /// check is a wire-facing boundary between arbitrary peers, so it must
    /// catch both forms regardless of which platform is running admission.
    #[test]
    fn admit_change_rejects_a_versioned_artefact_path_with_windows_trailing_normalization() {
        for suffix in [" ", "."] {
            let artefact_path = format!(
                "{}{suffix}",
                yadorilink_root_authority::reserved_namespace::artefact_component_name(
                    yadorilink_root_authority::reserved_namespace::ArtefactKind::Preimage,
                    "deadbeef",
                )
                .unwrap()
            );
            let change = hand_signed_change("g", vec![create_op(&artefact_path)]);

            let recv = conn();
            seed_test_version(&recv, "g");
            let err = admit_change(&recv, &change, true).unwrap_err();
            assert!(
                matches!(err, SyncSqliteError::ReservedNamespaceCollision(ref p) if p == &artefact_path),
                "suffix {suffix:?}: expected ReservedNamespaceCollision, got {err:?}"
            );
        }
    }

    /// A trailing space makes this path non-portable (Windows silently
    /// drops it), independently of whether the path also happens to look
    /// like a legacy marker: two distinct wire paths differing only in a
    /// trailing '.'/' ' must never both be admitted as independent index
    /// rows, since they'd silently collide onto one on-disk name the
    /// moment either materializes on a Windows device. See
    /// `admit_change_admits_a_legacy_marker_look_alike_path` for the
    /// sibling case (same look-alike name, no trailing space) that
    /// confirms the legacy-marker substring match alone must not block an
    /// ordinary user file, and
    /// `reserved_namespace::tests::wire_predicate_still_excludes_the_legacy_marker_with_a_trailing_space`
    /// for where the narrower "trailing-space stripping must not widen the
    /// artefact predicate" property this test used to pin now lives — it
    /// can no longer be exercised through this full admission pipeline,
    /// since the non-portability check below refuses the path before the
    /// artefact-vs-legacy classification is ever reached.
    #[test]
    fn admit_change_rejects_a_non_portable_path_even_when_it_also_looks_like_a_legacy_marker() {
        let legacy_path = "report.yadorilink-tmp.old ";
        let change = hand_signed_change("g", vec![create_op(legacy_path)]);

        let recv = conn();
        seed_test_version(&recv, "g");
        let err = admit_change(&recv, &change, true).unwrap_err();
        assert!(
            matches!(err, SyncSqliteError::NonPortablePath(ref p) if p == legacy_path),
            "expected NonPortablePath naming the trailing-space path, got {err:?}"
        );
    }

    /// NTFS `filename::$DATA` addresses `filename`'s own default stream,
    /// so a change naming an ADS-suffixed alias for a versioned artefact
    /// must be rejected at admission exactly like the un-suffixed name —
    /// otherwise a remote peer can get history admitted that later
    /// materializes as a write through the artefact's own default stream.
    #[test]
    fn admit_change_rejects_an_alternate_data_stream_alias_for_a_versioned_artefact() {
        let artefact_path = format!(
            "{}::$DATA",
            yadorilink_root_authority::reserved_namespace::artefact_component_name(
                yadorilink_root_authority::reserved_namespace::ArtefactKind::Stage,
                "deadbeef",
            )
            .unwrap()
        );
        let change = hand_signed_change("g", vec![create_op(&artefact_path)]);

        let recv = conn();
        seed_test_version(&recv, "g");
        let err = admit_change(&recv, &change, true).unwrap_err();
        assert!(
            matches!(err, SyncSqliteError::ReservedNamespaceCollision(ref p) if p == &artefact_path),
            "expected ReservedNamespaceCollision naming the ADS-aliased path, got {err:?}"
        );
    }

    /// `change::validate_path` accepts both `/` and `\` as separators, so
    /// a change naming a backslash-delimited artefact component must be
    /// rejected the same on every host running admission — resolving the
    /// path through the local `std::path::Path` type instead would make a
    /// Unix receiver admit exactly the history a Windows receiver refuses
    /// forever, permanently splitting the group along platform lines.
    #[test]
    fn admit_change_rejects_a_backslash_delimited_artefact_path_on_every_host() {
        let artefact_path = format!(
            "safe\\{}",
            yadorilink_root_authority::reserved_namespace::artefact_component_name(
                yadorilink_root_authority::reserved_namespace::ArtefactKind::Preimage,
                "cafef00d",
            )
            .unwrap()
        );
        let change = hand_signed_change("g", vec![create_op(&artefact_path)]);

        let recv = conn();
        seed_test_version(&recv, "g");
        let err = admit_change(&recv, &change, true).unwrap_err();
        assert!(
            matches!(err, SyncSqliteError::ReservedNamespaceCollision(ref p) if p == &artefact_path),
            "expected ReservedNamespaceCollision naming the backslash-delimited path, got {err:?}"
        );
    }

    /// A literal backslash anywhere in a wire path is refused outright, on
    /// every platform — not just converted or reinterpreted on Windows. A
    /// Unix-authored path containing a literal backslash byte would
    /// otherwise be ambiguous the moment it reaches a Windows receiver,
    /// where `\` is the path separator: the same wire string would name two
    /// different filesystem shapes depending on which OS materializes it.
    /// Refusing it at the source is the only choice that is unambiguous
    /// everywhere.
    #[test]
    fn admit_change_refuses_an_ordinary_backslash_containing_path() {
        let sender = conn();
        let em = emitter();
        let err = emit_local_change(
            &sender,
            "g",
            vec![create_op("safe\\ordinary-file.txt")],
            ChangeAuth::PLACEHOLDER,
            &em,
        )
        .unwrap_err();
        assert!(
            matches!(err, SyncSqliteError::InvalidInput(ref msg) if msg.contains("backslash")),
            "expected a backslash-rejection InvalidInput, got {err:?}"
        );
    }

    /// A literal `:` anywhere in an ordinary (non-artefact) path component
    /// is refused the same way as trailing-dot/space: on a POSIX host it's
    /// just a character, but on Windows it's the alternate-data-stream
    /// separator, so `"notes"` and `"notes:draft"` would alias the same
    /// on-disk object there — see
    /// `reserved_namespace::path_has_non_portable_wire_component`'s doc
    /// comment.
    #[test]
    fn admit_change_rejects_a_path_with_a_literal_colon() {
        let path = "notes:draft.txt";
        let change = hand_signed_change("g", vec![create_op(path)]);

        let recv = conn();
        seed_test_version(&recv, "g");
        let err = admit_change(&recv, &change, true).unwrap_err();
        assert!(
            matches!(err, SyncSqliteError::NonPortablePath(ref p) if p == path),
            "expected NonPortablePath naming the colon-containing path, got {err:?}"
        );
    }

    /// Windows reserves `CON`, `PRN`, `AUX`, `NUL`, `COM1`-`COM9` and
    /// `LPT1`-`LPT9` (matched against a component's stem, case-
    /// insensitively) as device names: a Windows peer can never create a
    /// file under one of these names, while the identical path is a
    /// perfectly ordinary file on Linux/macOS. Refused at admission for
    /// the same host-independence reason as every other check in this
    /// module — a change every non-Windows member accepts must not be one
    /// a Windows member can never materialize.
    #[test]
    fn admit_change_rejects_a_reserved_windows_device_name_path() {
        for name in ["CON", "com1", "LPT9.log"] {
            let change = hand_signed_change("g", vec![create_op(name)]);

            let recv = conn();
            seed_test_version(&recv, "g");
            let err = admit_change(&recv, &change, true).unwrap_err();
            assert!(
                matches!(err, SyncSqliteError::NonPortablePath(ref p) if p == name),
                "{name:?}: expected NonPortablePath, got {err:?}"
            );
        }
    }

    /// Win32's `CreateFile` family refuses `<`, `>`, `"`, `|`, `?` and `*`
    /// in a filename outright, on every Windows version, every time — each
    /// is a perfectly ordinary character in a Linux/macOS filename. Same
    /// host-independence reasoning as every other check in this module: a
    /// change every non-Windows member accepts must not be one a Windows
    /// member can never materialize.
    #[test]
    fn admit_change_rejects_a_path_with_a_win32_reserved_filename_character() {
        for ch in ['<', '>', '"', '|', '?', '*'] {
            let path = format!("notes{ch}draft.txt");
            let change = hand_signed_change("g", vec![create_op(&path)]);

            let recv = conn();
            seed_test_version(&recv, "g");
            let err = admit_change(&recv, &change, true).unwrap_err();
            assert!(
                matches!(err, SyncSqliteError::NonPortablePath(ref p) if p == &path),
                "{ch:?}: expected NonPortablePath, got {err:?}"
            );
        }
    }

    #[test]
    fn delivery_order_does_not_change_final_heads() {
        // Same three-change set delivered in two different orders converges
        // to the same head set (commutativity at the store level).
        let sender = conn();
        let em = emitter();
        let r = emit_local_change(&sender, "g", vec![create_op("a")], ChangeAuth::PLACEHOLDER, &em)
            .unwrap();
        let m = emit_local_change(&sender, "g", vec![create_op("b")], ChangeAuth::PLACEHOLDER, &em)
            .unwrap();
        let t = emit_local_change(&sender, "g", vec![create_op("c")], ChangeAuth::PLACEHOLDER, &em)
            .unwrap();

        let forward = conn();
        seed_test_version(&forward, "g");
        for ch in [&r, &m, &t] {
            admit_change(&forward, ch, true).unwrap();
        }
        let reverse = conn();
        seed_test_version(&reverse, "g");
        for ch in [&t, &r, &m] {
            admit_change(&reverse, ch, true).unwrap();
        }
        assert_eq!(group_heads(&forward, "g").unwrap(), group_heads(&reverse, "g").unwrap());
        assert_eq!(group_heads(&forward, "g").unwrap(), vec![t.compute_hash()]);
    }

    #[test]
    fn admission_rejects_malformed_lamport() {
        let c = conn();
        let em = emitter();
        let root =
            emit_local_change(&c, "g", vec![create_op("a")], ChangeAuth::PLACEHOLDER, &em).unwrap();
        seed_test_version(&c, "g");
        let bad = Change::create_signed(
            vec![root.compute_hash()],
            99,
            ChangeAuth::PLACEHOLDER,
            DeviceId("device-B".into()),
            FolderGroupId("g".into()),
            vec![create_op("b")],
            &SigningKey::from_bytes(&[2u8; 32]),
        );
        assert!(admit_change(&c, &bad, true).is_err());
    }

    #[test]
    fn admission_rejects_file_version_from_another_group() {
        let c = conn();
        put_file_version(&c, "other-group", &test_version()).unwrap();
        let bad = Change::create_signed(
            vec![],
            0,
            ChangeAuth::PLACEHOLDER,
            DeviceId("device-B".into()),
            FolderGroupId("g".into()),
            vec![create_op("b")],
            &SigningKey::from_bytes(&[2u8; 32]),
        );
        assert!(admit_change(&c, &bad, true).is_err());
    }

    #[test]
    fn identical_file_version_is_independently_owned_by_each_group() {
        let c = conn();
        let version = test_version();
        assert!(put_file_version(&c, "group-a", &version).unwrap());
        assert!(put_file_version(&c, "group-b", &version).unwrap());
        assert!(has_file_version(&c, "group-a", &version.version_hash).unwrap());
        assert!(has_file_version(&c, "group-b", &version.version_hash).unwrap());
        assert_eq!(
            get_file_version(&c, "group-b", &version.version_hash).unwrap().unwrap(),
            version
        );
    }

    #[test]
    fn device_frontier_replaces_and_removes() {
        let c = conn();
        let h1 = ChangeHash([1u8; 32]);
        let h2 = ChangeHash([2u8; 32]);
        let h3 = ChangeHash([3u8; 32]);

        // A frontier can carry several concurrent heads.
        set_device_frontier(&c, "g", "dev", &[h2, h1]).unwrap();
        assert_eq!(get_device_frontier(&c, "g", "dev").unwrap(), vec![h1, h2]);

        // Setting replaces the whole frontier rather than accumulating.
        set_device_frontier(&c, "g", "dev", &[h3]).unwrap();
        assert_eq!(get_device_frontier(&c, "g", "dev").unwrap(), vec![h3]);

        // Removal clears it entirely.
        remove_device_frontier(&c, "g", "dev").unwrap();
        assert!(get_device_frontier(&c, "g", "dev").unwrap().is_empty());
    }

    #[test]
    fn encoded_bytes_are_served_verbatim() {
        let c = conn();
        let change =
            emit_local_change(&c, "g", vec![create_op("a")], ChangeAuth::PLACEHOLDER, &emitter())
                .unwrap();
        let served = get_encoded(&c, &change.compute_hash()).unwrap().unwrap();
        assert_eq!(served, change.to_wire_bytes());
        // A relayed change round-trips to the identical change.
        assert_eq!(Change::from_wire_bytes(&served).unwrap(), change);
    }

    /// The dual-write path: `upsert_file_emitting_change` must land the index
    /// row and the signed change in one commit, with the change becoming the
    /// group's sole head.
    #[test]
    fn dual_write_commits_index_row_and_change_together() {
        use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
        use yadorilink_replica_domain::file::FileRecord;

        let state = ReplicaCoordinator::open_in_memory().unwrap();
        state.set_local_change_auth_provider(std::sync::Arc::new(|_| {
            Ok(ChangeAuth { auth_seq: 7, auth_epoch: 3, policy_head_hash: [9u8; 32] })
        }));
        let em = ChangeEmitter::new("device-A", SigningKey::from_bytes(&[7u8; 32]));
        let record = FileRecord {
            path: "a.txt".into(),
            size: 3,
            mtime_unix_nanos: 1,
            blocks: vec![],
            deleted: false,
        };
        let hash = state
            .upsert_file_emitting_change(
                "g",
                &record,
                "device-A",
                ChangeContent { ops: vec![create_op("a.txt")], versions: &[] },
                None,
                yadorilink_daemon::replica_coordinator::ReplicaChangeEmission {
                    emitter: &em,
                    permit: &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
                },
            )
            .unwrap();

        assert!(state.file_index_repository().get_file("g", "a.txt").unwrap().is_some());
        assert!(state.change_history_repository().dag_has_change(&hash).unwrap());
        assert_eq!(state.sqlite().dag_group_heads("g").unwrap(), vec![hash]);
        let decoded = state.sqlite().dag_get_change(&hash).unwrap().unwrap();
        assert_eq!(decoded.compute_hash(), hash);
        assert_eq!(decoded.auth_seq, 7);
        assert_eq!(decoded.auth_epoch, 3);
        assert_eq!(decoded.policy_head_hash, [9u8; 32]);

        // A subsequent tombstone chains from the first change and becomes the
        // new sole head.
        let del = state
            .mark_deleted_emitting_change(
                "g",
                "a.txt",
                "device-A",
                2,
                &em,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .unwrap();
        assert_eq!(state.sqlite().dag_group_heads("g").unwrap(), vec![del]);
        assert!(state.change_history_repository().dag_is_ancestor(&hash, &del).unwrap());
        assert!(state.file_index_repository().get_file("g", "a.txt").unwrap().unwrap().deleted);
    }

    /// Regression test for the defect described on `frontier_index::
    /// max_parent_lamport`'s own doc comment: signing must agree with
    /// `validate_present_parent_shape`'s pruned-aware Lamport computation
    /// even when a resolved basis is composed *entirely* of pruned parents
    /// (the shape a delayed capture can resolve against after a checkpoint
    /// prunes the frontier it was materialized on). Before the fix,
    /// `max_parent_lamport` read only live `changes` rows, signed this
    /// change with Lamport 1, and the very next validation step inside this
    /// same call then rejected it against `prior`'s real (pruned) Lamport --
    /// permanently, since every retry resolves the identical all-pruned
    /// basis.
    #[test]
    fn emission_onto_a_wholly_pruned_basis_agrees_with_the_pruned_aware_validator() {
        let c = conn();
        let em = emitter();

        let prior =
            emit_local_change(&c, "g", vec![create_op("prior.txt")], ChangeAuth::PLACEHOLDER, &em)
                .unwrap();
        let prior_hash = prior.compute_hash();
        assert_eq!(prior.lamport, 1);

        let child =
            emit_local_change(&c, "g", vec![create_op("child.txt")], ChangeAuth::PLACEHOLDER, &em)
                .unwrap();
        let child_hash = child.compute_hash();
        assert_eq!(child.lamport, 2);

        // Checkpoint at `child` prunes `prior`: the frontier moves past the
        // point a delayed capture's basis was resolved against.
        let checkpoint = yadorilink_replica_domain::rebootstrap::Checkpoint::new(
            FolderGroupId("g".into()),
            vec![child_hash],
            [0u8; 32],
        );
        {
            let tx = c.unchecked_transaction().unwrap();
            commit_prune(&tx, &checkpoint, &[prior_hash]).unwrap();
            tx.commit().unwrap();
        }
        assert!(!has_change(&c, &prior_hash).unwrap());

        // A delayed capture resolves its displaced basis to `[prior]` alone
        // -- wholly pruned -- and signs onto it directly, the same shape
        // `captured_authoring`'s `an_all_pruned_basis_is_currently_refused`
        // exercises through the higher-level capture path.
        let delayed = emit_local_change_onto(
            &c,
            "g",
            vec![prior_hash],
            vec![create_op("delayed.txt")],
            ChangeAuth::PLACEHOLDER,
            &em,
        )
        .unwrap();
        // `prior`'s recorded (pruned) Lamport is 1, so the correct, agreed
        // clock is 1 + 1 = 2 -- not the pruned-blind 0 + 1 = 1 that used to
        // be signed and then rejected one line later.
        assert_eq!(delayed.lamport, 2);
        assert_eq!(delayed.parents, vec![prior_hash]);
    }

    /// The common, already-working shape: a basis with at least one live
    /// member alongside a pruned one. Guards against a fix that only checks
    /// `pruned_lamport` and stops consulting live `changes` rows.
    #[test]
    fn emission_onto_a_mixed_live_and_pruned_basis_still_agrees() {
        let c = conn();
        let em = emitter();

        let prior =
            emit_local_change(&c, "g", vec![create_op("prior.txt")], ChangeAuth::PLACEHOLDER, &em)
                .unwrap();
        let prior_hash = prior.compute_hash();
        assert_eq!(prior.lamport, 1);

        let child =
            emit_local_change(&c, "g", vec![create_op("child.txt")], ChangeAuth::PLACEHOLDER, &em)
                .unwrap();
        let child_hash = child.compute_hash();
        assert_eq!(child.lamport, 2);

        let checkpoint = yadorilink_replica_domain::rebootstrap::Checkpoint::new(
            FolderGroupId("g".into()),
            vec![child_hash],
            [0u8; 32],
        );
        {
            let tx = c.unchecked_transaction().unwrap();
            commit_prune(&tx, &checkpoint, &[prior_hash]).unwrap();
            tx.commit().unwrap();
        }
        assert!(!has_change(&c, &prior_hash).unwrap());
        assert!(has_change(&c, &child_hash).unwrap());

        // Basis names both the now-pruned `prior` and the still-live `child`;
        // the live parent's Lamport (2) dominates, so the expected clock is
        // 2 + 1 = 3.
        let mixed = emit_local_change_onto(
            &c,
            "g",
            vec![prior_hash, child_hash],
            vec![create_op("mixed.txt")],
            ChangeAuth::PLACEHOLDER,
            &em,
        )
        .unwrap();
        assert_eq!(mixed.lamport, 3);
    }
}
