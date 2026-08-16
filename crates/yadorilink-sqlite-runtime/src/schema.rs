//! Schema creation, migration, and version-check machinery for the sync
//! index database. Pure, stateless functions -- no `SyncState` fields live
//! here; `SyncState::open`/`open_in_memory` call [`init_schema`] once per
//! freshly opened connection.

use rusqlite::Connection;

use crate::error::DatabaseError;

/// An explicit, monotonically
/// increasing marker for this crate's on-disk schema, stored via SQLite's
/// built-in `PRAGMA user_version` (a plain integer SQLite reserves in the
/// database header specifically for application use — no extra table
/// needed, so this doesn't disturb the crate's existing "no separate
/// schema-version table" convention for detecting *which* migrations have
/// run; every individual migration above still self-detects from the
/// actual table shape exactly as before). This purely adds a fast,
/// explicit version check (`check_schema_version_supported`)
/// layered on top: bump this constant whenever a migration changes the
/// on-disk shape in a way an older binary must not silently reopen.
/// Version 1 is the schema as of the first public beta baseline (every
/// migration present in this file up to this point). Version 2 adds the
/// change-history DAG tables (`crate::dag_store::init_dag_schema`), which are
/// created — like `group_policy_watermark` — by a bare `CREATE TABLE IF NOT
/// EXISTS`, so an older database upgrades in place with no data conversion.
/// Version 3 scopes `file_versions` ownership by `(group_id, version_hash)`;
/// opening a v2 database rebuilds that table before advancing the watermark.
/// Version 4 adds the admitted-change/file-version relation used for block
/// authorization and backfills it from retained admitted changes.
/// Version 5 adds `group_block_provenance`, the non-backfilled record of blocks
/// this device actually obtained through each group. Older binaries must not
/// reopen this shape because their serving and custody logic ignores it.
/// Version 6 adds durable per-path duplicate-root recovery progress.
/// Version 7 adds the retained DAG change identity that authored each file
/// projection; peer causality no longer derives from version vectors.
/// Version 8 marks the signed change-purpose encoding (`CHANGE_DOMAIN_TAG`
/// v4, first-class retroactive-repair carriers): a database stamped 7 holds
/// retained change bytes in the v3 encoding, which this build can no longer
/// decode, so it must be refused up front at open (the pre-current-version
/// gate below) instead of surfacing as per-change decode corruption later.
/// Version 9 drops the `version_json` column from `files` and
/// `restore_operations` together with the per-file version-vector model, and
/// advances the re-bootstrap snapshot domain tag for the same reason. A
/// database stamped 8 still carries that column and rows written against it, so
/// it is refused at open by the same pre-current-version gate rather than being
/// read with a column this build no longer selects.
/// Version 10 adds `changes.authenticated_header` (the signed change header
/// with `ops` left out, computed once at append time) and extends
/// `pruned_changes` with `author_identity`/`authenticated_header`/
/// `encoding_version`, plus the new `causal_basis_sets`/`causal_basis_members`
/// and `dag_retention_roots` tables. A database stamped 9 has neither the new
/// `changes` column nor the wider `pruned_changes` shape, so it is refused at
/// open by the same pre-current-version gate rather than being read with
/// columns this build now requires.
/// Version 11 adds `path_materialized_generations` (the materialized-disk-
/// generation record, `crate::materialized_generation`) — new, additive, and
/// unread by any production caller yet, so a bare `CREATE TABLE IF NOT
/// EXISTS` is the whole migration and there is nothing for an older binary to
/// misread. The version is still bumped, not left implicit, because this
/// table's presence is a precondition later phases will depend on.
/// Version 12 adds `filesystem_transactions`, `filesystem_transaction_epochs`
/// and `filesystem_transaction_reservations` (`crate::filesystem_transaction`)
/// — the transaction engine's journal tables. Additive only, same reasoning
/// as version 11: no production caller reaches them yet (they sit behind
/// `filesystem_transaction::EXECUTION_ENABLED = false`), so a bare
/// `CREATE TABLE IF NOT EXISTS` is the whole migration.
/// Version 13 changes the shape `filesystem_transaction_epochs.
/// parent_directory_identity` encodes: `DirectoryIdentity` gained
/// `birth_or_creation_time` (`crate::fs_identity`), needed for `compare` to
/// have an honest `Ambiguous` case on a volume with no directory generation
/// counter, instead of an earlier version's unconditional `SameObject`. The
/// blob's own `EPOCH_ENCODING_VERSION` tag already refuses to decode a v2
/// blob written before this change — bumped 2 -> 3 alongside this constant —
/// but that refusal only fires when a specific row is later read, which
/// could be mid-recovery, exactly when a surprise decode failure is least
/// welcome. Bumping this constant too makes a stale database refuse at open
/// instead, before anything tries to read that row. No production caller
/// reaches these rows yet (same `EXECUTION_ENABLED = false` gate as version
/// 12), so there is no data to migrate and none is written.
/// Version 15 changes what `files.symlink_target` (and `change::FileMeta::
/// symlink_target`/the change encoding's canonical field) hold: raw target
/// bytes instead of a lossy UTF-8 conversion of them — see `change.rs`'s
/// `FileMeta::symlink_target` doc for why. A v14 (or older) database's
/// `symlink_target` values were written through the old lossy conversion
/// and cannot be reinterpreted as the new byte-exact encoding, so, matching
/// this pre-release codebase's existing no-compat-path policy, a v14
/// database is refused at open rather than silently reread — see this
/// binary's rejection of any `on_disk_version < SCHEMA_VERSION` above.
/// Version 16 adds `captured_authoring_receipts.content_fingerprint`, a
/// `NOT NULL` column recording what a capture receipt actually captured, so
/// a later write that leaves the displaced basis unchanged can no longer be
/// mistaken for a retry of the same capture. A v15 database's receipts have
/// no such column and nothing honest to backfill it with — the content they
/// described is gone. Same no-compat-path policy: refused at open.
/// The bump matters even though that table is created with
/// `IF NOT EXISTS`: without it a v15 database keeps its stamp, passes the
/// exact-version check, and fails later on the missing column instead.
/// Version 17 adds `filesystem_transaction_epochs.unresolved_block_reason`,
/// recording *why* an epoch reached `EpochState::Blocked` for the one writer
/// that blocks without being able to determine anything physical (early
/// physical recovery). Startup recovery keys its reservation withholding on
/// that column instead of on the bare `Blocked` phase, which two other
/// writers also produce with nothing unresolved. A v16 database's blocked
/// epochs have no such column and nothing honest to backfill it with — a
/// blanket `NULL` would silently release reservations a genuinely
/// undetermined epoch still needs withheld, and a blanket non-`NULL` would
/// withhold forever for the two writers this change exists to separate out.
/// Same no-compat-path policy as versions 15 and 16: refused at open.
/// Version 18 adds `restore_operations.record_kind`/`symlink_target`/
/// `symlink_out_of_root`/`exec_bit`, so a restored symlink or executable
/// version's classification can be journaled and committed to the
/// `current` row's own metadata columns, not just its `FileRecord`
/// content. A v17 database's in-flight restore journal rows (if any)
/// have no such columns and default to `File`/no-target/not-executable
/// on read — an independent review's finding that restoring a symlink
/// or executable version without this recreated the correct bytes on
/// disk but left the index still classified as whatever it was before
/// the restore. Same no-compat-path policy: refused at open.
/// Version 19 adds `membership_operations.durability_scope`/
/// `latch_group_ids`, and two new `state` values (`local-settlement-pending`,
/// `recovery-blocked`). A v18 database's rows default to
/// `durability_scope = 'known'`, which is wrong for an in-flight
/// `--force` removal whose blast radius was never verified (previously
/// tracked via a `state = 'unknown-scope'` this build no longer
/// recognizes) — and, more importantly, an older binary reopening this
/// schema does not understand that `recovery-blocked` rows are explicitly
/// forbidden from automatic replay, which is the whole safety property
/// that state exists to provide. Same no-compat-path policy: refused at
/// open.
/// Version 20 expands `enrollment_operations` from a late `CancelPending`
/// backstop into the complete pre-prepare enrollment journal: `group_id`
/// becomes nullable, `group_name`/`storage_mode` are added, and the full
/// `PreparePending`/`Prepared`/`Transferred`/`CancelPending`/`RecoveryBlocked`
/// state machine replaces the single state a v19 row's `state` column could
/// ever hold. A v19 database's rows (if any) are missing the new columns
/// entirely and describe a fundamentally different point in the enrollment
/// lifecycle than any v20 state does. Same no-compat-path policy: refused at
/// open.
/// Version 21 splits the single `Transferred` state into `LocalSetupPending`
/// (link row + `pending_enrollments` marker committed, but the fallible
/// post-commit setup -- watcher registration, on-demand materialization
/// config -- not yet confirmed) and `ActivationPending` (local setup
/// confirmed; remote activation may now be attempted). A v20 `Transferred`
/// row conflates these two: the pending-enrollment activation reconciler
/// used to activate off nothing but a matching local link, with no check
/// that local setup had actually finished, so a crash between the atomic
/// commit and `finish_link_setup` returning could let the reconciler
/// activate a remote authorization for a link this device never finished
/// registering a watcher for -- and a `finish_link_setup` failure followed
/// by a successful local rollback raced a concurrent remote activation that
/// was never told to stop, producing a remote-Active/local-absent phantom
/// full replica. A v20 database's `transferred` rows do not distinguish
/// these two cases and cannot be safely reread as one or the other -- same
/// no-compat-path policy: refused at open.
/// Version 22 adds `files.placeholder_dev`/`placeholder_ino`/
/// `placeholder_provider_kind` (M1-2): a persisted identity for the exact
/// on-disk object `write_placeholder` created, replacing the pure
/// size/mtime/sparse-file heuristic `local_change.rs` previously used
/// alone to infer "this is still my own untouched placeholder." A v21
/// database's rows are missing these columns entirely; same no-compat-path
/// policy as every version above: refused at open, not silently reread
/// with columns absent.
pub const SCHEMA_VERSION: i32 = 22;

/// Reads `PRAGMA user_version` and
/// errors if it's newer than this binary's [`SCHEMA_VERSION`] — an older
/// binary opening state a newer one already migrated. Deliberately checked
/// *before* any migration statement runs (see `init_schema`'s call site), so an
/// unsupported downgrade is refused outright rather than partially applying
/// migrations against a shape this binary doesn't fully understand.
///
/// A version *older* than [`SCHEMA_VERSION`] (but explicitly stamped, i.e.
/// non-zero) is refused the same way: this pre-release codebase does not
/// carry cross-version data migrations, and pretending to (an additive
/// `ALTER` ladder followed by an invariant audit the un-backfilled rows can
/// never pass — v7's mandatory authoring identity) would fail the open
/// anyway, later and with a worse message. Version `0` stays accepted
/// because a first run that crashed between table creation and the final
/// version stamp reports `0` — `interrupted_migration_recovers_on_restart`
/// pins that recovery path — and the idempotent schema statements complete
/// it safely.
fn check_schema_version_supported(conn: &Connection) -> Result<(), DatabaseError> {
    let on_disk_version: i32 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if on_disk_version > SCHEMA_VERSION {
        return Err(DatabaseError::UnsupportedSchemaDowngrade {
            on_disk_version,
            supported_version: SCHEMA_VERSION,
        });
    }
    if on_disk_version != 0 && on_disk_version < SCHEMA_VERSION {
        return Err(DatabaseError::CorruptSchema(format!(
            "index database schema v{on_disk_version} predates this build's v{SCHEMA_VERSION}, \
             and pre-release builds do not migrate old databases -- delete the index database \
             and re-import the folder"
        )));
    }
    Ok(())
}

/// This crate's own core schema DDL/version-check machinery. Takes only a
/// raw SQLite [`Connection`] and knows nothing about any caller's domain
/// concepts (DAG, filesystem transactions, materialization jobs, ...) --
/// callers with their own schema pieces that must interleave with this
/// one (an ordering dependency, not a naming one -- the triggers below
/// reference `changes`/`pruned_changes`, tables this function does not
/// create) sequence their own calls around this one in the single
/// `schema_init` closure they hand to [`crate::SyncDatabase::open`]/
/// `open_in_memory`; this function does not accept or invoke any hook.
pub fn init_schema(conn: &Connection) -> Result<(), DatabaseError> {
    // Refuse to touch a database
    // an older binary migrated *this* binary doesn't understand,
    // before any migration below runs a single statement against it —
    // an unsupported downgrade must error cleanly, not silently drop
    // into the migration loop and potentially reinterpret/clobber
    // columns this binary has never heard of. A brand-new database
    // reads `user_version = 0` (SQLite's own default), which is always
    // `<= SCHEMA_VERSION`, so this never blocks first-run.
    check_schema_version_supported(conn)?;

    // Widening `files`' primary key
    // from `(group_id, path)` to `(group_id, path, version_seq)` is not
    // expressible as an `ALTER TABLE... ADD COLUMN` — SQLite has no
    // syntax to change a declared primary key in place. Must run
    // *before* the `CREATE TABLE IF NOT EXISTS`/`ALTER TABLE` migration
    // below, which only ever adds columns to whatever `files` table
    // already exists; see the function's own doc comment for the
    // rebuild it performs (a no-op on a brand-new database, and
    // idempotent on one already migrated).
    migrate_files_table_widen_primary_key(conn)?;

    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS files (
            group_id          TEXT NOT NULL,
            path              TEXT NOT NULL,
            size              INTEGER NOT NULL,
            mtime_unix_nanos  INTEGER NOT NULL,
            blocks_json       TEXT NOT NULL,
            deleted           INTEGER NOT NULL DEFAULT 0,
            -- A per-`(group_id,
            -- path)` monotonically increasing counter. Exactly one row
            -- per `(group_id, path)` has `state = 'current'` at a time;
            -- `state` and `origin_device_id` below are additionally
            -- covered by the `ALTER TABLE` loop further down for a
            -- database whose `files` table pre-dates this change but
            -- was somehow left with the old primary key by the rebuild
            -- above (defensive; the rebuild always adds them itself).
            version_seq       INTEGER NOT NULL DEFAULT 1,
            state             TEXT NOT NULL DEFAULT 'current',
            origin_device_id  TEXT,
            authoring_change_hash BLOB,
            PRIMARY KEY (group_id, path, version_seq)
        );

        CREATE TABLE IF NOT EXISTS links (
            local_path TEXT PRIMARY KEY,
            group_id   TEXT NOT NULL,
            paused     INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS duplicate_recovery_paths (
            group_id TEXT NOT NULL,
            path     TEXT NOT NULL,
            PRIMARY KEY (group_id, path)
        );

        -- One outstanding local link with an unconfirmed coordination-plane
        -- activation -- the crash-safety net for a create/join whose local
        -- link is already committed but whose matching server-side
        -- activation was never confirmed (the caller was killed in that
        -- exact window). Keyed by `operation_id` (idempotent: re-recording after a retry
        -- that reaches the same point again is a plain overwrite, not a
        -- duplicate entry). Lives in the same database as `links` so
        -- `add_link_with_pending_enrollment` can write both in one
        -- transaction -- a local link is never committed without a durable
        -- trace of the coordination-side enrollment it depends on.
        CREATE TABLE IF NOT EXISTS pending_enrollments (
            operation_id TEXT PRIMARY KEY,
            kind         TEXT NOT NULL,
            group_id     TEXT NOT NULL,
            device_id    TEXT NOT NULL,
            local_path   TEXT NOT NULL
        );

        -- Anti-rollback watermark for each group's signed policy log (see
        -- `PolicyWatermark`). One row per group; the daemon advances it
        -- only forward and rejects any snapshot that would move it back,
        -- so a replayed older-but-valid chain cannot survive a restart. A
        -- new additive table, so a bare `CREATE TABLE IF NOT EXISTS` is the
        -- whole migration, like `files`/`links` themselves.
        CREATE TABLE IF NOT EXISTS group_policy_watermark (
            group_id                  TEXT PRIMARY KEY,
            highest_verified_seq      INTEGER NOT NULL,
            highest_verified_head     BLOB NOT NULL,
            authority_key_generation  INTEGER NOT NULL,
            -- SHA-256 of the authority public key at that head. NULLable
            -- because a database created before this column existed keeps
            -- its rows with no fingerprint (see the lightweight migration
            -- below); the read path maps NULL to `None` and the verifier
            -- treats that as "unknown", never as a fork.
            authority_key_fingerprint BLOB
        );
        -- Durable journal of local paths detected as changed but not yet
        -- fully processed into the index + change DAG. A path is recorded
        -- here *before* the read/blockify/put/index+DAG step runs and only
        -- deleted once that step commits, so a crash, restart, or a
        -- multi-second block-store fault (disk-full / EIO) mid-processing
        -- can never silently drop an already-detected local edit: the row
        -- survives and the daemon re-drives it (startup rescan + retry).
        -- One row per `(group_id, path)`; a fresher watcher event for the
        -- same path supersedes `change_kind`/`observed_at_unix_nanos` (via
        -- `INSERT ... ON CONFLICT`) rather than accumulating history, while
        -- `first_seen_unix_nanos` records when the divergence was first
        -- noticed and `attempts`/`last_error` accrue across retries for
        -- diagnosis. A new additive table, so a bare `CREATE TABLE IF NOT
        -- EXISTS` is the whole migration, like `files`/`links` themselves.
        CREATE TABLE IF NOT EXISTS local_dirty_paths (
            group_id               TEXT NOT NULL,
            path                   TEXT NOT NULL,
            change_kind            TEXT NOT NULL,
            first_seen_unix_nanos  INTEGER NOT NULL,
            observed_at_unix_nanos INTEGER NOT NULL,
            attempts               INTEGER NOT NULL DEFAULT 0,
            last_error             TEXT,
            PRIMARY KEY (group_id, path)
        );

        -- Restore spans an atomic filesystem rename and a SQLite index
        -- transaction. Persist the intended new current row before the
        -- rename; completing the index upsert deletes this row in the
        -- same transaction, making startup reconciliation idempotent.
        CREATE TABLE IF NOT EXISTS restore_operations (
            operation_id      TEXT PRIMARY KEY,
            group_id          TEXT NOT NULL,
            path              TEXT NOT NULL,
            target_version_seq INTEGER NOT NULL,
            expected_current_version_seq INTEGER,
            state             TEXT NOT NULL,
            size              INTEGER NOT NULL,
            mtime_unix_nanos  INTEGER NOT NULL,
            blocks_json       TEXT NOT NULL,
            origin_device_id  TEXT NOT NULL,
            authoring_change_hash BLOB,
            created_at_unix_nanos INTEGER NOT NULL,
            record_kind       TEXT NOT NULL DEFAULT 'file',
            symlink_target    BLOB,
            symlink_out_of_root INTEGER NOT NULL DEFAULT 0,
            exec_bit          INTEGER NOT NULL DEFAULT 0
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_restore_operations_path
            ON restore_operations(group_id, path);

        -- A coordination-worker-issued full-replica-handoff lease this
        -- device (as the handoff TARGET) is currently holding, pinning the
        -- exact `(path, version_seq)` rows its own local readiness check
        -- verified at request time against this device's retention sweep
        -- (`expire_superseded_and_trashed_versions`) until the source's
        -- role-loss commit confirms the lease or it is released/expires.
        -- See `HandoffLease`'s doc comment for the full lifecycle. One row
        -- per outstanding lease; a device normally holds at most one
        -- lease per `group_id` at a time, but this is not enforced here
        -- (a stale, not-yet-swept row for an old lease is simply ignored
        -- once its `state`/`expires_at_unix` no longer qualify it as
        -- pinning). A new additive table, so a bare `CREATE TABLE IF NOT
        -- EXISTS` is the whole migration, like `local_dirty_paths` above.
        CREATE TABLE IF NOT EXISTS handoff_leases (
            lease_id             TEXT PRIMARY KEY,
            group_id             TEXT NOT NULL,
            root_digest          BLOB NOT NULL,
            state                TEXT NOT NULL DEFAULT 'provisional',
            pinned_versions_json TEXT NOT NULL,
            created_at_unix      INTEGER NOT NULL,
            expires_at_unix      INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_handoff_leases_group_id ON handoff_leases(group_id);

        -- A durable journal of an in-flight full-replica role-loss
        -- operation (demote/unlink) this device is driving as the
        -- SOURCE device: the coordination-worker role-loss commit
        -- (`commit_handoff_role_loss`) and this device's own matching
        -- local policy/link change are two separate commits, and a
        -- crash -- or a local failure landing AFTER the Worker commit
        -- already succeeded -- must not be left as a silent split
        -- state (Worker thinks this device demoted; local storage
        -- still thinks it's eager). This row is written BEFORE the
        -- Worker commit and only removed once the operation's outcome
        -- is fully settled, one way or the other -- see
        -- `RoleLossOperation`'s doc comment for the full state
        -- machine. A new additive table, so a bare `CREATE TABLE IF
        -- NOT EXISTS` is the whole migration, like `handoff_leases`
        -- above.
        CREATE TABLE IF NOT EXISTS role_loss_operations (
            operation_id     TEXT PRIMARY KEY,
            group_id         TEXT NOT NULL,
            source_device_id TEXT NOT NULL,
            target_device_id TEXT NOT NULL,
            lease_id         TEXT,
            worker_membership_generation INTEGER,
            action           TEXT NOT NULL,
            state            TEXT NOT NULL,
            local_path       TEXT,
            attempts         INTEGER NOT NULL DEFAULT 0,
            created_at_unix  INTEGER NOT NULL,
            updated_at_unix  INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_role_loss_operations_state
            ON role_loss_operations(state);
        -- A durable journal for an account-membership operation this
        -- device drives against another device (revoke from one group,
        -- or remove from the whole account): unlike
        -- `role_loss_operations` above (this device's OWN demotion,
        -- always one group/lease), a single removal here can span
        -- several groups at once (account-wide `handoff-remove`), so
        -- `group_ids`/`target_device_ids`/`lease_ids` are JSON arrays,
        -- index-parallel to each other. A row is written whenever the
        -- coordination-plane commit's outcome is ambiguous (so the
        -- caller must not release tickets or fall through to a plain
        -- revoke/remove — the Worker may already have committed) or
        -- when `--force` proceeds without a verified list of groups at
        -- risk (`state = 'unknown-scope'`, `group_ids = []`) so
        -- `status` can keep reporting degraded until the scope is
        -- known. A new additive table, so a bare `CREATE TABLE IF NOT
        -- EXISTS` is the whole migration, like `role_loss_operations`
        -- above.
        CREATE TABLE IF NOT EXISTS membership_operations (
            operation_id      TEXT PRIMARY KEY,
            action            TEXT NOT NULL,
            commit_mode       TEXT NOT NULL DEFAULT 'plain-revoke',
            removed_device_id TEXT NOT NULL,
            group_ids         TEXT NOT NULL,
            target_device_ids TEXT NOT NULL,
            lease_ids         TEXT NOT NULL,
            state             TEXT NOT NULL,
            durability_scope  TEXT NOT NULL DEFAULT 'known',
            latch_group_ids   TEXT NOT NULL DEFAULT '[]',
            last_error        TEXT,
            created_at_unix   INTEGER NOT NULL,
            updated_at_unix   INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_membership_operations_state
            ON membership_operations(state);
        -- Force overrides must remain visible after daemon restart until
        -- a later positive whole-group durability check clears them.
        CREATE TABLE IF NOT EXISTS durability_unknown_latches (
            group_id TEXT PRIMARY KEY
        );
        -- Durable journal of an in-flight materialization write: one row
        -- per `(group_id, path)` whose on-disk content a
        -- temp-write-then-rename is CURRENTLY producing but has not yet
        -- finished and fsynced into place. The row is written BEFORE that
        -- write begins and deleted only AFTER it completes, so startup
        -- repair can tell a genuine crash-mid-materialization (intent
        -- still present => the indexed blocks must be re-assembled onto
        -- disk) apart from a file the user deleted or renamed while the
        -- daemon was stopped (no intent => a real offline deletion that
        -- must propagate as a tombstone, never be silently reconstructed
        -- from the index). `PRAGMA synchronous = FULL` (set at open) makes
        -- the intent durable before the disk write starts, which is what
        -- makes the disambiguation crash-safe. One row per
        -- `(group_id, path)`; a fresh write for the same path overwrites
        -- the previous intent via `INSERT ... ON CONFLICT`. A new additive
        -- table, so a bare `CREATE TABLE IF NOT EXISTS` is the whole
        -- migration, like `local_dirty_paths`/`restore_operations` above.
        CREATE TABLE IF NOT EXISTS materialization_intents (
            group_id              TEXT NOT NULL,
            path                  TEXT NOT NULL,
            target_version_hash   BLOB NOT NULL,
            created_at_unix_nanos INTEGER NOT NULL,
            PRIMARY KEY (group_id, path)
        );
        -- A durable backstop for the one enrollment-rollback path that
        -- had none: if `link()` fails during create/join AND the
        -- immediate cancel-with-retries also fails, NOTHING is written
        -- anywhere else -- the journal is opened BEFORE remote prepare is
        -- ever called, not just as a late backstop for a `link()`
        -- failure: `PreparePending` covers the window before the
        -- coordination plane has even heard of this operation,
        -- `Prepared` the window after prepare confirms a `group_id` but
        -- before the local link/pending_enrollment handoff commits,
        -- `Transferred` the brief window between that handoff commit and
        -- this row's own cleanup delete, and `CancelPending` a `link()`
        -- failure needing remote cancellation -- durable and retried
        -- until CONFIRMED, never a late best-effort insert. `group_id`
        -- is nullable (a `Create` row has none until prepare confirms
        -- one); `group_name` is only meaningful for a `Create` row still
        -- in `PreparePending` (needed to resend the exact same prepare
        -- request). `RecoveryBlocked` (see `membership_operations`'
        -- sibling state of the same name) marks a row automatic recovery
        -- must never touch again: an operation_id conflict, a malformed
        -- row, or an identity mismatch. Same shape (and same
        -- no-migration, refuse-at-open policy) as `membership_operations`.
        CREATE TABLE IF NOT EXISTS enrollment_operations (
            operation_id    TEXT PRIMARY KEY,
            kind            TEXT NOT NULL,
            group_id        TEXT,
            group_name      TEXT,
            device_id       TEXT NOT NULL,
            local_path      TEXT NOT NULL,
            storage_mode    TEXT NOT NULL,
            state           TEXT NOT NULL,
            last_error      TEXT,
            attempts        INTEGER NOT NULL DEFAULT 0,
            created_at_unix INTEGER NOT NULL,
            updated_at_unix INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_enrollment_operations_state
            ON enrollment_operations(state);
        -- M5-A soak-closure durability investigation: durable record of a
        -- peer EXPLICITLY, definitively refusing a fetch for lack of
        -- verified provenance on the EXACT current version
        -- (`FetchOutcome::Rejected { reason: NoVerifiedProvenance }`) --
        -- deliberately distinct both from a transient miss
        -- (`NotFound`/`TimedOut`/`Busy`) and from any OTHER rejection
        -- reason (unauthorized, malformed request, etc.), neither of
        -- which writes a row here: only a rejection that specifically
        -- proves "this peer does not hold this exact version's bytes" is
        -- evidence of unobtainability. This is keyed by `version_hash`,
        -- not just `path`: a refusal recorded against an OLDER version
        -- must never be read as evidence about a NEWER version that
        -- superseded it (a stale-refusal false positive an M5-A review
        -- caught -- `path` alone conflates every version a file has ever
        -- had). This is the evidence `known_unobtainable_required_
        -- content` (`DurabilityFacts`) needs to positively confirm no
        -- CURRENTLY authorized peer can serve the CURRENT version's
        -- content, rather than merely inferring it from
        -- connectivity/timing. One row per `(group_id, path, version_
        -- hash, peer_device_id)`; a fresh rejection overwrites the
        -- previous one via `INSERT ... ON CONFLICT`, and a later
        -- successful fetch of the SAME version from the SAME peer
        -- deletes any prior refusal row for it (see `ensure_blocks_
        -- present`'s success arm) -- old evidence never outlives being
        -- proven wrong. A new additive table, so a bare `CREATE TABLE IF
        -- NOT EXISTS` is the whole migration, like `materialization_
        -- intents`/`enrollment_operations` above.
        CREATE TABLE IF NOT EXISTS block_fetch_refusals (
            group_id              TEXT NOT NULL,
            path                  TEXT NOT NULL,
            version_hash          TEXT NOT NULL,
            peer_device_id        TEXT NOT NULL,
            reason                TEXT NOT NULL,
            refused_at_unix_nanos INTEGER NOT NULL,
            PRIMARY KEY (group_id, path, version_hash, peer_device_id)
        );
        "#,
    )?;
    // Lightweight migrations (on-demand-sync): `CREATE TABLE IF NOT
    // EXISTS` above is a no-op against a database from before these
    // columns existed, so add them explicitly, ignoring the
    // "duplicate column" error on a database that already has them.
    // Existing rows default to `hydrated`/`eager` — every file and
    // link already on disk before this change keeps behaving exactly
    // as it did — no rollback concerns for this migration.
    for stmt in [
        "ALTER TABLE files ADD COLUMN materialization_state TEXT NOT NULL DEFAULT 'hydrated'",
        "ALTER TABLE files ADD COLUMN pinned INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE files ADD COLUMN last_accessed_unix INTEGER",
        "ALTER TABLE role_loss_operations ADD COLUMN lease_id TEXT",
        "ALTER TABLE role_loss_operations ADD COLUMN worker_membership_generation INTEGER",
        "ALTER TABLE membership_operations ADD COLUMN commit_mode TEXT NOT NULL DEFAULT 'plain-revoke'",
        "ALTER TABLE membership_operations ADD COLUMN durability_scope TEXT NOT NULL DEFAULT 'known'",
        "ALTER TABLE membership_operations ADD COLUMN latch_group_ids TEXT NOT NULL DEFAULT '[]'",
        "ALTER TABLE links ADD COLUMN materialization_policy TEXT NOT NULL DEFAULT 'eager'",
        "ALTER TABLE links ADD COLUMN max_local_size_bytes INTEGER",
        // Every pre-existing row
        // defaults to `record_kind = 'file'` (the only kind scan/watch
        // ever produced before this change) with no symlink target,
        // `exec_bit = 0` (no workflow depended on the bit being set,
        // since it was never captured or propagated at all), and no
        // held state (nothing was ever held before hazard detection
        // existed) — every existing installation keeps behaving
        // exactly as it did, matching the "no behavior change without
        // opt-in" guarantee already established above.
        "ALTER TABLE files ADD COLUMN record_kind TEXT NOT NULL DEFAULT 'file'",
        "ALTER TABLE files ADD COLUMN symlink_target BLOB",
        "ALTER TABLE files ADD COLUMN exec_bit INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE files ADD COLUMN held_reason TEXT",
        "ALTER TABLE files ADD COLUMN held_since_unix_nanos INTEGER",
        // Whether a symlink's raw target is
        // an absolute path, or resolves (syntactically, never via
        // dereferencing) outside the linked folder's root. Deliberately
        // a *separate* column from `held_reason`/`held_since_unix_nanos`
        // above rather than reusing them: `held_*` (section 4) gates
        // materialization — a held file is never written to disk. An
        // out-of-root/absolute symlink is not held by this flag alone —
        // says it's "synced as a record like any other
        // symlink but flagged", so it must keep materializing normally
        // (as a real symlink on POSIX) while carrying a distinct
        // out-of-scope-risk signal a later policy change can consult.
        // Defaults to 0 (not flagged) for every pre-existing row, same
        // "no behavior change without opt-in" guarantee as every other
        // column in this list.
        "ALTER TABLE files ADD COLUMN symlink_out_of_root INTEGER NOT NULL DEFAULT 0",
        // Per-link opt-in for attempting
        // real Win32 symlink creation on Windows (default 0 — the safe
        // skip-with-visible-status policy describes, since a
        // default assuming `SeCreateSymbolicLinkPrivilege`/Developer
        // Mode would fail unpredictably per-machine). Mirrors
        // `materialization_policy` above: a per-link
        // column on `links`, not a per-file one, since this is a
        // device-local link-wide policy decision, not something that
        // varies symlink-by-symlink.
        "ALTER TABLE links ADD COLUMN windows_symlink_opt_in INTEGER NOT NULL DEFAULT 0",
        // Set once a pending enrollment's `reconcile` pass confirms the
        // coordination-side group/ACL row this link depends on is
        // permanently gone (never just a transient failure) --
        // distinct from `paused`, which is a reversible, user-chosen
        // sync gate. An orphaned link's on-disk files are never
        // touched; only its own further participation in sync is
        // affected. Defaults to 0 (not orphaned) for every
        // pre-existing row, the same "no behavior change without
        // opt-in" guarantee as every other column in this list.
        "ALTER TABLE links ADD COLUMN orphaned INTEGER NOT NULL DEFAULT 0",
        // Opaque per-link identity nonce for this link's sync root, mirrored
        // into a marker file inside the root itself
        // (`crate::root_identity`). The pair is what lets a scan tell "this
        // folder is empty" from "this folder's filesystem is not mounted" --
        // an unmounted volume leaves the bare mountpoint directory behind,
        // which every existence check happily accepts and every scan then
        // reads as "the user deleted everything".
        //
        // NULLable with no default, and that NULL is load-bearing rather
        // than incidental: it is precisely the "this link predates root
        // identity, adopt it on first boot" signal. Defaulting it to a
        // constant would be actively wrong -- a token shared by every link
        // identifies nothing -- and minting one here is impossible, since a
        // migration cannot know whether the root it would be vouching for is
        // currently mounted. Backfill therefore happens in
        // `VerifiedRoot::open`, which can look at the folder.
        "ALTER TABLE links ADD COLUMN root_token TEXT",
        // Set on the SURVIVING link when a group is recovered out of the
        // two-live-roots state by unlinking one of its folders. `DELETE FROM
        // files` is only ever keyed by path, so unlinking a folder leaves
        // that folder's rows in the group's index -- and the survivor's next
        // authoritative full scan would read every one of them as "indexed
        // but not on my disk" and tombstone it to every device. That would
        // make the remedy this fix instructs the user to perform ("unlink
        // the other folder") destroy the very files it was meant to save.
        //
        // While set, the survivor's full scan is ADDITIVE: it indexes what
        // it finds and emits no deletions, so the departed root's paths
        // survive and can hydrate in from a peer that still holds them. The
        // flag clears after one clean full scan. Worst case (a single-device
        // group where no peer holds the content) is a stall, which is
        // recoverable -- the user still has the folder on disk -- rather
        // than a delete, which is not.
        //
        // Defaults to 0 for every pre-existing row: no behavior change
        // without the recovery that sets it, the same guarantee as every
        // other column in this list.
        "ALTER TABLE links ADD COLUMN suppress_tombstones_until_scan INTEGER NOT NULL DEFAULT 0",
        // Defensive: `files.version_seq`/
        // `state`/`origin_device_id` are normally already present by the
        // time this loop runs, via either a fresh `CREATE TABLE IF NOT
        // EXISTS` above or `migrate_files_table_widen_primary_key`'s own
        // rebuild — these three are listed here too only so a database
        // that somehow reaches this point without them (there is no
        // known path to that today) still ends up correct rather than
        // erroring on every later query that references these columns.
        "ALTER TABLE files ADD COLUMN version_seq INTEGER NOT NULL DEFAULT 1",
        "ALTER TABLE files ADD COLUMN state TEXT NOT NULL DEFAULT 'current'",
        "ALTER TABLE files ADD COLUMN origin_device_id TEXT",
        // Durable causal identity for the DAG change that authored this
        // projection. Only the temporary pre-import scan may be NULL;
        // once a group has DAG history the triggers below require a
        // verified retained/pruned identity for every current row.
        "ALTER TABLE files ADD COLUMN authoring_change_hash BLOB",
        // Authority-key fingerprint on the policy watermark. Added
        // NULLable with no default, so every pre-existing watermark row
        // keeps a NULL fingerprint until the next verified snapshot
        // backfills it. A NULL must NOT read as a fork — the verifier
        // treats "no stored fingerprint" as unknown and accepts, matching
        // the "no behavior change without opt-in" guarantee of every
        // column above: an already-trusted chain stays trusted across the
        // upgrade.
        "ALTER TABLE group_policy_watermark ADD COLUMN authority_key_fingerprint BLOB",
        // M1-2: persisted placeholder identity, replacing the pure
        // size/mtime/sparse-file heuristic `local_change.rs` used to infer
        // "this on-disk object is still the untouched placeholder this
        // process wrote." `write_placeholder` (yadorilink-local-storage)
        // captures the (device, inode) of the file it just created,
        // immediately after its own rename-into-place, from the still-open
        // handle -- so this identifies the exact filesystem object this
        // process wrote, not a re-derived guess. `placeholder_provider_kind`
        // records which identity scheme produced it ("internal-inode" is
        // the only kind today; a future real OS provider -- File Provider
        // on macOS, CfAPI on Windows -- would record its own kind here
        // instead once wired, per `PlaceholderBackend`'s own doc comment in
        // yadorilink-filesystem-sync::placeholder_backend). All three
        // NULLable with no default: NULL means "no identity recorded for
        // this row" -- which callers MUST treat the same as a later
        // mismatch (fail closed), never as "still untouched." Every
        // pre-existing row gets NULL, so no pre-existing placeholder is
        // wrongly trusted as untouched after this upgrade -- the opposite
        // failure mode (silently discarding a real edit) is the one this
        // change exists to close, so erring toward "not proven untouched"
        // here is the safe default.
        "ALTER TABLE files ADD COLUMN placeholder_dev INTEGER",
        "ALTER TABLE files ADD COLUMN placeholder_ino INTEGER",
        "ALTER TABLE files ADD COLUMN placeholder_provider_kind TEXT",
        // M5-A review follow-up (blocker #56): the already-`Hydrated`
        // fast path in `hydrate_inner` used to infer "still the real
        // materialization, safe to skip" from a bare `metadata.len() > 0`
        // check -- indistinguishable from a genuine local edit that
        // truncates the file to zero bytes before the watcher journals
        // it, silently destroying that edit. A size-only OR even a
        // size+mtime check cannot fix this either: BOTH a real edit and a
        // genuinely-missing/corrupted leftover artifact look the same
        // from a stateless filesystem observation alone -- the only sound
        // discriminator is remembering, from this process's OWN last
        // successful write, what the disk object looked like right after
        // that write completed, then comparing NOW against THAT specific
        // snapshot rather than re-deriving an expectation from the index
        // alone. Reuses `peer_session::disk_race_fingerprint`'s own
        // `(len, mtime, ctime, ctime_nsec)` shape -- the exact tuple
        // already used elsewhere in this codebase to detect "did this
        // path change since I last looked" -- captured immediately after
        // a successful `reconstruct_file` call and persisted alongside
        // the `Hydrated` transition. All four NULLable with no default,
        // same "NULL means not proven, fail closed" discipline as
        // `placeholder_dev`/`placeholder_ino` above: every pre-existing
        // `Hydrated` row gets NULL, so hydrate_inner's shortcut falls
        // through to a real re-verification for it rather than trusting
        // an identity that was never actually captured.
        "ALTER TABLE files ADD COLUMN materialized_fingerprint_len INTEGER",
        "ALTER TABLE files ADD COLUMN materialized_fingerprint_mtime_nanos INTEGER",
        "ALTER TABLE files ADD COLUMN materialized_fingerprint_ctime INTEGER",
        "ALTER TABLE files ADD COLUMN materialized_fingerprint_ctime_nsec INTEGER",
    ] {
        match conn.execute(stmt, []) {
            Ok(_) => {}
            Err(rusqlite::Error::SqliteFailure(_, Some(ref msg)))
                if msg.starts_with("duplicate column name") =>
            {
                // Already migrated.
            }
            Err(e) => return Err(e.into()),
        }
    }

    // A group has at most ONE live link. Enforced in the schema itself, not
    // only in Rust: the index is group-scoped and path-relative while every
    // scan is root-scoped and authoritative, so two live roots on one group
    // make each root's scan read the other's files as deleted and tombstone
    // them — signed changes that ride the change-DAG to every device. This
    // layer survives a writer that never reads the Rust chokepoint, a raw
    // `sqlite3` session, and a second process.
    //
    // A partial UNIQUE index on `group_id` would be the obvious spelling and
    // is WRONG twice over: `INSERT OR REPLACE` against a UNIQUE index does
    // not error, it DELETES the conflicting row (silent link loss), and the
    // index cannot even be CREATEd on a database that already holds a
    // duplicate — i.e. it fails exactly on the installs that need it. A
    // BEFORE trigger raising ABORT installs cleanly on such a database,
    // leaves both rows intact and visible for recovery, and overrides
    // `INSERT OR REPLACE` rather than being subverted by it.
    //
    // Placed after the `orphaned` ALTER above, and kept there. SQLite
    // resolves a trigger's column references when the trigger FIRES, not
    // when it is created (measured), so this would in fact tolerate being
    // created before that ALTER — every statement in `init_schema` runs before any
    // caller can insert. That tolerance is a coincidence of ordering rather
    // than a guarantee, and it fails loudly and totally if the column is
    // never added at all ("no such column: NEW.orphaned", on every insert),
    // so this stays downstream of the column it depends on, where the
    // dependency is visible.
    //
    // The UPDATE trigger's `WHEN` is scoped to the 0 ← 1 un-orphan
    // transition rather than to `NEW.orphaned = 0` alone. Unscoped, it
    // aborts ordinary pause/policy/token writes on an
    // already-duplicated database — turning a rare data-loss bug into a
    // common "cannot use the app" bug. Transition-scoped, every legitimate
    // update passes and the un-orphan hole still closes. That hole is real
    // and not theoretical: `INSERT OR REPLACE` silently flipped `orphaned`
    // 1 → 0, which is why this trigger exists alongside the INSERT one.
    conn.execute_batch(
        "CREATE TRIGGER IF NOT EXISTS links_one_live_root_per_group_insert \
         BEFORE INSERT ON links \
         WHEN NEW.orphaned = 0 AND EXISTS ( \
             SELECT 1 FROM links \
             WHERE group_id = NEW.group_id AND orphaned = 0 \
               AND local_path <> NEW.local_path) \
         BEGIN \
             SELECT RAISE(ABORT, \
                 'links: group already has a live link at a different local_path'); \
         END; \
         CREATE TRIGGER IF NOT EXISTS links_one_live_root_per_group_unorphan \
         BEFORE UPDATE ON links \
         WHEN NEW.orphaned = 0 AND OLD.orphaned = 1 AND EXISTS ( \
             SELECT 1 FROM links \
             WHERE group_id = NEW.group_id AND orphaned = 0 \
               AND local_path <> NEW.local_path) \
         BEGIN \
             SELECT RAISE(ABORT, \
                 'links: un-orphaning would give this group a second live link'); \
         END;",
    )?;

    // The triggers immediately below reference `changes`/`pruned_changes` --
    // tables this function does not create. The caller's `schema_init`
    // closure (see `crate::SyncDatabase::open`'s own doc comment) is
    // responsible for creating them, and anything else this database's
    // schema needs, before calling this function at all.
    conn.execute_batch(
        r#"
        CREATE TRIGGER IF NOT EXISTS files_require_authoring_identity_on_insert
        AFTER INSERT ON files
        WHEN NEW.state = 'current' AND NEW.version_seq > 0
          AND (EXISTS(SELECT 1 FROM changes WHERE group_id = NEW.group_id)
               OR EXISTS(SELECT 1 FROM pruned_changes WHERE group_id = NEW.group_id))
          AND (NEW.authoring_change_hash IS NULL
               OR length(NEW.authoring_change_hash) != 32
               OR NOT EXISTS(
                   SELECT 1 FROM changes
                    WHERE group_id = NEW.group_id
                      AND change_hash = NEW.authoring_change_hash
                   UNION ALL
                   SELECT 1 FROM pruned_changes
                    WHERE group_id = NEW.group_id
                      AND change_hash = NEW.authoring_change_hash
               ))
        BEGIN
            SELECT RAISE(ABORT, 'current DAG-backed file row requires verified authoring identity');
        END;

        CREATE TRIGGER IF NOT EXISTS files_require_authoring_identity_on_update
        AFTER UPDATE OF state, version_seq, authoring_change_hash ON files
        WHEN NEW.state = 'current' AND NEW.version_seq > 0
          AND (EXISTS(SELECT 1 FROM changes WHERE group_id = NEW.group_id)
               OR EXISTS(SELECT 1 FROM pruned_changes WHERE group_id = NEW.group_id))
          AND (NEW.authoring_change_hash IS NULL
               OR length(NEW.authoring_change_hash) != 32
               OR NOT EXISTS(
                   SELECT 1 FROM changes
                    WHERE group_id = NEW.group_id
                      AND change_hash = NEW.authoring_change_hash
                   UNION ALL
                   SELECT 1 FROM pruned_changes
                    WHERE group_id = NEW.group_id
                      AND change_hash = NEW.authoring_change_hash
               ))
        BEGIN
            SELECT RAISE(ABORT, 'current DAG-backed file row requires verified authoring identity');
        END;
        "#,
    )?;
    let invalid_authoring_rows: i64 = conn.query_row(
        "SELECT COUNT(*) FROM files f
         WHERE f.state = 'current' AND f.version_seq > 0
           AND (EXISTS(SELECT 1 FROM changes c WHERE c.group_id = f.group_id)
                OR EXISTS(SELECT 1 FROM pruned_changes pc WHERE pc.group_id = f.group_id))
           AND (f.authoring_change_hash IS NULL
                OR length(f.authoring_change_hash) != 32
                OR NOT EXISTS(
                    SELECT 1 FROM changes c
                     WHERE c.group_id = f.group_id
                       AND c.change_hash = f.authoring_change_hash
                    UNION ALL
                    SELECT 1 FROM pruned_changes pc
                     WHERE pc.group_id = f.group_id
                       AND pc.change_hash = f.authoring_change_hash
                ))",
        [],
        |row| row.get(0),
    )?;
    if invalid_authoring_rows != 0 {
        return Err(DatabaseError::CorruptSchema(format!(
            "{invalid_authoring_rows} current DAG-backed file row(s) lack verified authoring identity"
        )));
    }
    // Stamp the now-current
    // schema version *after* every migration above has run —
    // unconditionally, not just when it changed, so this is exactly as
    // idempotent as the migrations themselves (setting `user_version`
    // to the value it's already at is a harmless no-op restart-safety
    // net if a crash happened between the last migration statement
    // above and this pragma on a previous attempt).
    conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    Ok(())
}

/// Rebuilds `files` from its pre-this-
/// change shape (primary key `(group_id, path)`) into the version-history
/// shape (primary key `(group_id, path, version_seq)`, plus `state`/
/// `origin_device_id`) — see the schema init step's call site for why this
/// can't be an `ALTER TABLE ADD COLUMN` like every other migration here.
///
/// A no-op in two cases, both detected purely from `files`' own current
/// shape (no separate schema-version table, matching this crate's existing
/// no-schema-version-table convention): a brand-new database (`files`
/// doesn't exist yet — the schema init step's own `CREATE TABLE IF NOT
/// EXISTS` creates the final shape directly), and a database that has
/// already been through this migration (`files.version_seq` already
/// exists). Otherwise, creates `files_new` with the full new schema,
/// copies every existing row across — preserving whatever subset of the
/// later `ALTER TABLE ADD COLUMN` columns (`materialization_state`,
/// `pinned`, `record_kind`, etc.) this particular database happens to
/// already have, defaulting any it doesn't — as `version_seq = 1, state =
/// 'current', origin_device_id = NULL` (every pre-existing row was, by
/// definition, the only row that existed for its path; there is no
/// history to backfill, which is honest — this change's retention only
/// starts accruing from the first edit/delete after upgrade), then drops
/// the old table and renames the new one into place.
pub(crate) fn migrate_files_table_widen_primary_key(
    conn: &Connection,
) -> Result<(), DatabaseError> {
    if !table_exists(conn, "files")? {
        return Ok(());
    }
    if files_table_has_column(conn, "version_seq")? {
        return Ok(());
    }

    // Every column a prior change has ever added to `files` via `ALTER
    // TABLE... ADD COLUMN... DEFAULT...`, paired with that same
    // default expression (as a literal SQL fragment) — used below only for
    // whichever of these a *given* pre-existing database doesn't already
    // have, so its rows still get the exact same default value they'd get
    // from the ordinary `ALTER TABLE` loop having run instead.
    const OPTIONAL_COLUMNS: &[(&str, &str)] = &[
        ("materialization_state", "'hydrated'"),
        ("pinned", "0"),
        ("last_accessed_unix", "NULL"),
        ("record_kind", "'file'"),
        ("symlink_target", "NULL"),
        ("exec_bit", "0"),
        ("held_reason", "NULL"),
        ("held_since_unix_nanos", "NULL"),
        ("symlink_out_of_root", "0"),
    ];
    let mut select_list =
        String::from("group_id, path, size, mtime_unix_nanos, blocks_json, deleted");
    let mut insert_list = select_list.clone();
    for (col, default_expr) in OPTIONAL_COLUMNS {
        insert_list.push_str(", ");
        insert_list.push_str(col);
        select_list.push_str(", ");
        if files_table_has_column(conn, col)? {
            select_list.push_str(col);
        } else {
            select_list.push_str(default_expr);
        }
    }

    conn.execute_batch(&format!(
        r#"
        CREATE TABLE files_new (
            group_id               TEXT NOT NULL,
            path                    TEXT NOT NULL,
            size                    INTEGER NOT NULL,
            mtime_unix_nanos        INTEGER NOT NULL,
            blocks_json             TEXT NOT NULL,
            deleted                 INTEGER NOT NULL DEFAULT 0,
            -- Column order from here down matches the schema init step's own
            -- `CREATE TABLE IF NOT EXISTS files` exactly (`version_seq`/
            -- `state`/`origin_device_id` immediately after `deleted`, then
            -- every optional column in the order its own `ALTER TABLE`
            -- migration originally introduced it) — `PRAGMA table_info`
            -- reports column order, and `fresh_and_upgraded_schema_are_
            -- identical` asserts a fresh database and one rebuilt by this
            -- migration produce byte-for-byte identical output, not just
            -- the same *set* of columns.
            version_seq             INTEGER NOT NULL DEFAULT 1,
            state                   TEXT NOT NULL DEFAULT 'current',
            origin_device_id        TEXT,
            authoring_change_hash   BLOB,
            materialization_state   TEXT NOT NULL DEFAULT 'hydrated',
            pinned                  INTEGER NOT NULL DEFAULT 0,
            last_accessed_unix      INTEGER,
            record_kind             TEXT NOT NULL DEFAULT 'file',
            symlink_target          BLOB,
            exec_bit                INTEGER NOT NULL DEFAULT 0,
            held_reason             TEXT,
            held_since_unix_nanos   INTEGER,
            symlink_out_of_root     INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (group_id, path, version_seq)
        );
        INSERT INTO files_new ({insert_list}, version_seq, state, origin_device_id, authoring_change_hash)
            SELECT {select_list}, 1, 'current', NULL, NULL FROM files;
        DROP TABLE files;
        ALTER TABLE files_new RENAME TO files;
        "#
    ))?;
    Ok(())
}

pub fn table_exists(conn: &Connection, table: &str) -> Result<bool, DatabaseError> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
        [table],
        |r| r.get(0),
    )?;
    Ok(count > 0)
}

fn files_table_has_column(conn: &Connection, column: &str) -> Result<bool, DatabaseError> {
    let mut stmt = conn.prepare("PRAGMA table_info(files)")?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let name: String = row.get(1)?;
        if name == column {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use rusqlite::Connection;

    use super::*;

    fn stub_dag_tables(conn: &Connection) -> Result<(), DatabaseError> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS changes (group_id TEXT NOT NULL, change_hash BLOB NOT NULL);
             CREATE TABLE IF NOT EXISTS pruned_changes (group_id TEXT NOT NULL, change_hash BLOB NOT NULL);",
        )?;
        Ok(())
    }

    /// The authoring-identity triggers reference `changes`/`pruned_changes`
    /// -- this crate's own `init_schema` no longer creates them (that is
    /// now exclusively the caller's responsibility, sequenced before this
    /// call), so it must fail cleanly, not panic or silently skip the
    /// triggers, when they don't already exist.
    #[test]
    fn init_schema_fails_without_caller_supplied_dag_tables() {
        let conn = Connection::open_in_memory().expect("open");
        let result = init_schema(&conn);
        assert!(
            result.is_err(),
            "init_schema must fail when changes/pruned_changes don't already exist"
        );
    }

    /// When the caller has already created `changes`/`pruned_changes`
    /// before calling `init_schema` (as `SyncDatabase::open`'s composed
    /// `schema_init` closure does), the core schema -- including the
    /// triggers that reference them -- succeeds.
    #[test]
    fn init_schema_succeeds_when_caller_supplied_dag_tables_already_exist() {
        let conn = Connection::open_in_memory().expect("open");
        stub_dag_tables(&conn).expect("stub dag tables");
        init_schema(&conn).expect("init_schema");
        assert!(table_exists(&conn, "changes").unwrap());
    }

    /// Running `init_schema` twice in a row (schema already present) must
    /// not fail -- the `CREATE TABLE IF NOT EXISTS` migrations are
    /// idempotent, not just safe to run once.
    #[test]
    fn init_schema_is_idempotent() {
        let conn = Connection::open_in_memory().expect("open");
        stub_dag_tables(&conn).expect("stub dag tables");
        init_schema(&conn).expect("first init_schema");
        init_schema(&conn).expect("second init_schema");
    }
}
