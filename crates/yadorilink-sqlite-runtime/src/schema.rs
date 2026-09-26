//! Schema creation and version checking for the sync index database. Pure,
//! stateless functions -- no `SyncState` fields live here;
//! `SyncState::open`/`open_in_memory` call [`init_schema`] once per freshly
//! opened connection.

use rusqlite::Connection;

use crate::error::DatabaseError;

/// The on-disk schema's version, stored in SQLite's `PRAGMA user_version`.
///
/// There is one schema, not a ladder: [`init_schema`] creates the current
/// shape outright, and [`check_schema_version_supported`] refuses any
/// database stamped with a different version rather than upgrading it. A
/// pre-release build does not carry data migrations -- the user deletes the
/// index database and re-imports the folder.
///
/// Bump this whenever the created shape changes at all, since the previous
/// shape becomes unopenable by this binary and unopenable is the intended
/// outcome.
pub const SCHEMA_VERSION: i32 = 63;

/// Reads `PRAGMA user_version` and refuses anything that is not exactly
/// this binary's [`SCHEMA_VERSION`], in either direction: a newer stamp is
/// an older binary opening state it does not understand, and an older
/// stamp is a database this pre-release codebase has no migration for.
///
/// `0` is accepted here because it is also what a brand-new file reports,
/// and this function alone cannot tell that from a database an
/// un-stamping build left behind. [`check_replica_schema_generation`] is
/// the entry point that can, and is what the replica index opens through.
pub fn check_schema_version_supported(conn: &Connection) -> Result<(), DatabaseError> {
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

/// The replica index database's own generation policy, for its owner to
/// call as the FIRST thing in its `schema_init` -- before any table is
/// created, which is what makes the distinction below possible.
///
/// On top of [`check_schema_version_supported`], this refuses the one case
/// that function cannot see: `user_version == 0` on a database that
/// already holds tables. A brand-new file reports `0` and has none, so the
/// two are distinguishable exactly here and nowhere later. Accepting `0`
/// unconditionally is how a database written before this build stamped
/// versions at all would have been adopted in place, silently, with no
/// migration and no check on its actual shape.
pub fn check_replica_schema_generation(conn: &Connection) -> Result<(), DatabaseError> {
    check_schema_version_supported(conn)?;
    let on_disk_version: i32 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if on_disk_version != 0 {
        return Ok(());
    }
    let tables: i64 = conn.query_row(
        "SELECT count(*) FROM sqlite_master WHERE type = 'table' \
         AND name NOT LIKE 'sqlite_%'",
        [],
        |r| r.get(0),
    )?;
    if tables > 0 {
        return Err(DatabaseError::CorruptSchema(
            "index database carries tables but no schema version stamp, so this build cannot \
             establish what shape it is in -- delete the index database and re-import the folder"
                .to_string(),
        ));
    }
    Ok(())
}

/// This crate's own core schema DDL/version-check machinery. Takes only a
/// raw SQLite [`Connection`] and knows nothing about any caller's domain
/// concepts (DAG, filesystem transactions, materialization jobs, ...) --
/// callers with their own schema pieces that must interleave with this
/// one (an ordering dependency, not a naming one -- the triggers below
/// reference `changes`/`pruned_changes`/`group_history_bases`/
/// `history_base_path_heads`/`history_base_carried_authors`, tables this
/// function does not create) sequence their own calls around this one in the single
/// `schema_init` closure they hand to [`crate::SyncDatabase::open`]/
/// `open_in_memory`; this function does not accept or invoke any hook.
#[allow(
    clippy::too_many_lines,
    reason = "one ordered schema-init sequence: the downgrade guard, the `files` primary-key \
              rebuild, the idempotent CREATE TABLE/ALTER TABLE DDL and the trigger definitions \
              must run in exactly this order against the same connection, and each step's \
              comment explains the migration dependency on the step before it; splitting it \
              into helpers would let a caller invoke them out of order and silently \
              reinterpret an old database"
)]
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
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS files (
            group_id          TEXT NOT NULL,
            path              TEXT NOT NULL,
            size              INTEGER NOT NULL,
            mtime_unix_nanos  INTEGER NOT NULL,
            blocks_json       TEXT NOT NULL,
            deleted           INTEGER NOT NULL DEFAULT 0,
            -- `version_seq` is a per-`(group_id, path)` monotonically
            -- increasing counter; exactly one row per `(group_id, path)`
            -- has `state = 'current'` at a time.
            version_seq       INTEGER NOT NULL DEFAULT 1,
            state             TEXT NOT NULL DEFAULT 'current',
            origin_device_id  TEXT,
            -- Causal identity of the DAG change that authored this
            -- projection. Only the pre-import scan may leave it NULL; once
            -- a group has history the triggers below require one.
            authoring_change_hash BLOB,
            materialization_state TEXT NOT NULL DEFAULT 'placeholder',
            pinned            INTEGER NOT NULL DEFAULT 0,
            last_accessed_unix INTEGER,
            record_kind       TEXT NOT NULL DEFAULT 'file',
            symlink_target    BLOB,
            -- -1 means "no Unix permission info".
            unix_mode         INTEGER NOT NULL DEFAULT -1,
            held_reason       TEXT,
            held_since_unix_nanos INTEGER,
            -- What a hold that waits on the file itself was decided
            -- against (its observed identity, the path's mutation fence and
            -- the desired version), so an unchanged path is not re-examined.
            -- NULL for every other hold; cleared with `held_reason`.
            held_key          TEXT,
            symlink_out_of_root INTEGER NOT NULL DEFAULT 0,
            placeholder_dev   INTEGER,
            placeholder_ino   INTEGER,
            placeholder_provider_kind TEXT,
            xattrs_json       TEXT NOT NULL DEFAULT '[]',
            admitted_at_unix_nanos INTEGER,
            -- On a `trashed` row whose deletion was one part of a recursive
            -- delete or directory rename: that operation's author and id.
            -- Kept on the row itself so restoring the whole operation does
            -- not depend on the deleting change still being retained.
            -- NULL for every other row.
            trashed_by_operation_author TEXT,
            trashed_by_operation_id     BLOB,
            PRIMARY KEY (group_id, path, version_seq)
        );

        CREATE TABLE IF NOT EXISTS links (
            local_path TEXT PRIMARY KEY,
            group_id   TEXT NOT NULL,
            paused     INTEGER NOT NULL DEFAULT 0,
            materialization_policy TEXT NOT NULL DEFAULT 'eager',
            max_local_size_bytes INTEGER,
            windows_symlink_opt_in INTEGER NOT NULL DEFAULT 0,
            orphaned   INTEGER NOT NULL DEFAULT 0,
            root_token TEXT,
            -- Set by departed-root recovery: while 1, a full scan is
            -- additive (indexes what it finds, emits no deletions) so the
            -- departed root's paths survive and can hydrate from a peer.
            -- Cleared after one clean full scan.
            suppress_tombstones_until_scan INTEGER NOT NULL DEFAULT 0
        );

        -- A folder kept on this device as a whole: every entry at or below
        -- `prefix`, those there now and those that arrive later, counts as
        -- pinned. Local policy, never replicated; the link root is the
        -- empty prefix. A file's own `files.pinned` flag is separate.
        CREATE TABLE IF NOT EXISTS pinned_directories (
            group_id TEXT NOT NULL,
            prefix   TEXT NOT NULL,
            PRIMARY KEY (group_id, prefix)
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
            -- SHA-256 of the authority public key at that head. Required:
            -- the only writer is a completed verification, which always has
            -- it, so there is no "unknown fingerprint" state for the
            -- verifier to treat leniently.
            authority_key_fingerprint BLOB NOT NULL
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
            -- `-1` = no Unix permission info (see `SCHEMA_VERSION` v23's
            -- own doc comment); `0..=0o777` = actual replicated mode bits.
            unix_mode          INTEGER NOT NULL DEFAULT -1,
            -- See `files.xattrs_json`'s own comment (`SCHEMA_VERSION` v24).
            xattrs_json        TEXT NOT NULL DEFAULT '[]'
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
            -- Required: `open_role_loss_operation` is the only writer and
            -- always supplies it. A row without one cannot be compensated.
            lease_id         TEXT NOT NULL,
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
            updated_at_unix INTEGER NOT NULL,
            -- What this operation's link commit did to the `links` row,
            -- written in that commit's transaction so crash recovery can
            -- undo exactly that and nothing more: NULL before the commit,
            -- 'inserted' for a new row, 'updated' for a row that already
            -- existed at the path for the same group (a re-join), with the
            -- prior values of the columns a re-link and its setup change.
            -- The row's `root_token` is never among them: a re-link never
            -- touches it, so an undo leaves it where it was.
            link_row_write                 TEXT,
            prior_link_paused              INTEGER,
            prior_link_orphaned            INTEGER,
            prior_link_policy              TEXT,
            prior_link_max_local_size_bytes INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_enrollment_operations_state
            ON enrollment_operations(state);
        -- Durable record of a
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
        -- superseded it (a stale-refusal false positive: `path` alone
        -- conflates every version a file has ever had). This is the evidence
        -- `known_unobtainable_required_
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

        -- The instant this device's own *continuous* local file history for
        -- a group begins, when that history started somewhere other than at
        -- this device's own first sight of each path. Two events write it,
        -- each at the moment it happens:
        --
        --   * LINKING a group this device did not originate and holds no
        --     files for yet -- both link commits that can name such a group
        --     (`add_link_with_pending_enrollment_and_begin_setup` with a
        --     `Join` marker, and the marker-less `add_link` behind
        --     `share accept`/`yadorilink link`). Every path the group
        --     already holds arrives afterwards, and `upsert_file_in_tx`
        --     numbers a path it is seeing for the first time from
        --     `version_seq = 1` however much history that path already has
        --     elsewhere.
        --   * a re-bootstrap snapshot install
        --     (`replace_group_files_from_snapshot`), which deletes every
        --     `files` row for the group and reinstalls the snapshot's rows
        --     carrying the SOURCE device's `version_seq` numbering.
        --
        -- After either, a row's `version_seq` says nothing about when THIS
        -- device first saw the path.
        --
        -- Read only by the rewind planning layer, which needs it to tell the
        -- two cases apart: below this instant its own `version_seq` evidence
        -- describes someone else's history and cannot be reasoned from, so
        -- the honest answer for a target that early is "no answer here"
        -- rather than an inference. At or above it, the group's local
        -- history is this device's own unbroken record and the inference is
        -- sound. No row means this device originated the group locally and
        -- has never re-bootstrapped it, so its history really does run back
        -- to each path's own first version.
        --
        -- One row per group, overwritten (never accumulated) by each such
        -- event, because only the most recent one bounds the history that
        -- actually survives. Deliberately stores the instant alone and not
        -- which event set it: the reader states both possible causes rather
        -- than committing to one, and a stored cause would be one more thing
        -- to keep true. A new additive table, so a bare `CREATE TABLE IF NOT
        -- EXISTS` is the whole migration, like `group_policy_watermark`
        -- above.
        CREATE TABLE IF NOT EXISTS group_local_history_floor (
            group_id         TEXT PRIMARY KEY,
            floor_unix_nanos INTEGER NOT NULL
        );

        -- The last authorization a live netmap gave this device about its
        -- peers, kept so a restart taken while the coordination plane is
        -- unreachable can go on talking to peers that plane already
        -- authorized. A last-known-good snapshot, NOT an authority: every
        -- row here was written by a live netmap application and is replaced
        -- or deleted by the next one, so this can only ever repeat a
        -- decision the plane made, never make one.
        --
        -- One row per peer device. `signing_key` is that device's pinned
        -- Ed25519 key, which is also its endpoint id: it is the identity a
        -- local-network announcement must prove, and a different key
        -- announcing the same device id matches nothing here.
        -- `membership_generation` and `captured_at_unix` record which
        -- authorization version this row mirrors and when, so a reader can
        -- say how old the offline authorization it is running on is.
        CREATE TABLE IF NOT EXISTS offline_peer_authorization (
            device_id             TEXT PRIMARY KEY,
            signing_key           BLOB NOT NULL,
            membership_generation INTEGER NOT NULL,
            captured_at_unix      INTEGER NOT NULL
        );

        -- The two version counters the peer rows above cannot carry between
        -- them, in one single-row table (`id` is pinned to 1).
        --
        -- `membership_generation` is this device's own authorization
        -- version, and it must never go BACKWARDS across a restart: a
        -- version-present confirmation compares one captured before a peer
        -- round-trip against one captured after it, so a generation the
        -- previous run had already passed must not be handed out again.
        -- Taking the maximum over the surviving peer rows is not enough,
        -- because the row carrying the highest generation is exactly the
        -- one a withdrawal DELETES, and unchanged rows are not rewritten
        -- just to restate a number. This row advances (never retreats) in
        -- the same transaction as every row write and every withdrawal, so
        -- it costs no extra transaction and cannot be lost with the row
        -- that moved it.
        --
        -- `snapshot_generation` is the coordination plane's own snapshot
        -- version that the peer rows were last written from -- the
        -- provenance of the cache, not an authority. A run that starts on
        -- this cache uses it to refuse the destructive half of a FIRST
        -- netmap frame older than the cache itself: an authenticated but
        -- replayed frame may still be applied additively, but it may not
        -- prune peers the plane never withdrew. 0 means "no netmap has
        -- ever written these rows", which gates nothing.
        CREATE TABLE IF NOT EXISTS offline_authorization_snapshot (
            id                    INTEGER PRIMARY KEY CHECK (id = 1),
            membership_generation INTEGER NOT NULL,
            snapshot_generation   INTEGER NOT NULL
        );

        -- What each peer in `offline_peer_authorization` was authorized for:
        -- one row per (device, group) writer edge, with the netmap's
        -- full-replica attribute for that edge. A peer with no row here is
        -- pinned but authorized for nothing, which is not enough to act on
        -- a local-network announcement for it.
        --
        -- Rewritten wholesale with its parent row, never patched, for the
        -- same reason `replace_peer_netmap_metadata` replaces rather than
        -- patches: a demotion must not be able to leave a stale writer edge
        -- behind.
        CREATE TABLE IF NOT EXISTS offline_peer_authorization_group (
            device_id       TEXT NOT NULL,
            group_id        TEXT NOT NULL,
            is_full_replica INTEGER NOT NULL,
            PRIMARY KEY (device_id, group_id)
        );

        -- The raw signed policy log the coordination plane last sent for
        -- each group, kept so a restart taken while that plane is
        -- unreachable can re-verify it and go on admitting changes instead
        -- of withholding every group until a netmap arrives.
        --
        -- Signed bytes, not a decision: every record in `log` carries the
        -- group authority's signature over its own canonical preimage, and
        -- the reader verifies the whole chain against this device's pinned
        -- coordination service key and against `group_policy_watermark`
        -- before believing any of it. A tampered row fails verification and
        -- an older chain fails the watermark, so this table cannot widen
        -- what the plane granted.
        CREATE TABLE IF NOT EXISTS offline_group_policy_log (
            group_id         TEXT PRIMARY KEY,
            log              TEXT NOT NULL,
            captured_at_unix INTEGER NOT NULL
        );
        "#,
    )?;

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

    // The triggers immediately below reference `changes`/`pruned_changes`
    // and the installed history base's `group_history_bases`/
    // `history_base_path_heads`/`history_base_carried_authors` -- tables
    // this function does not create.
    // The caller's `schema_init` closure (see `crate::SyncDatabase::open`'s
    // own doc comment) is responsible for creating them, and anything else
    // this database's schema needs, before calling this function at all.
    let violation = unverified_authoring_identity("NEW");
    conn.execute_batch(&format!(
        r#"
        CREATE TRIGGER IF NOT EXISTS files_require_authoring_identity_on_insert
        AFTER INSERT ON files
        WHEN {violation}
        BEGIN
            SELECT RAISE(ABORT, 'current DAG-backed file row requires verified authoring identity');
        END;

        CREATE TRIGGER IF NOT EXISTS files_require_authoring_identity_on_update
        AFTER UPDATE OF state, version_seq, authoring_change_hash ON files
        WHEN {violation}
        BEGIN
            SELECT RAISE(ABORT, 'current DAG-backed file row requires verified authoring identity');
        END;
        "#
    ))?;

    // A change-detector for each group's durability-root set, so a caller
    // can tell "this group's root set has not moved since I last read it"
    // in one indexed row read instead of re-enumerating and re-hashing
    // every root.
    //
    // It is a trigger rather than a counter bumped from Rust deliberately.
    // The consumer is a memoised digest, and a memo that misses an
    // invalidation hands back a digest the table no longer supports --
    // which, for the durability comparison this backs, is a false positive
    // in the one direction that must never happen. A Rust-side bump would
    // be correct against today's write paths and silently wrong the first
    // time a new one is added; a trigger cannot be bypassed by any SQL
    // path, including one written later, and it commits in the same
    // transaction as the write it observes, so a rolled-back write takes
    // its own bump back with it.
    //
    // Deliberately never deleted, not even when a group is unlinked. The
    // row is one integer, and restarting a group's generation at 1 after a
    // relink is exactly how a memo keyed on it could match an entry
    // belonging to the previous life of the same group id.
    //
    // Must come after the primary-key rebuild above, which drops and
    // recreates `files` and would take any trigger attached to it along.
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS file_root_set_generation (
            group_id   TEXT PRIMARY KEY,
            generation INTEGER NOT NULL
        );

        CREATE TRIGGER IF NOT EXISTS files_root_set_generation_on_insert
        AFTER INSERT ON files
        BEGIN
            INSERT INTO file_root_set_generation (group_id, generation)
            VALUES (NEW.group_id, 1)
            ON CONFLICT(group_id) DO UPDATE SET generation = generation + 1;
        END;

        -- Bumps BOTH sides, because an UPDATE can move a row between
        -- groups. Bumping only `NEW.group_id` would leave the group the row
        -- LEFT with an unchanged generation and one fewer root -- a memo
        -- keyed on that generation would go on serving a digest that
        -- includes the departed row, for as long as nothing else writes to
        -- that group. No production statement moves a row across groups
        -- today; the trigger does not depend on that staying true, which is
        -- the only reason to prefer a trigger here at all.
        CREATE TRIGGER IF NOT EXISTS files_root_set_generation_on_update
        AFTER UPDATE ON files
        BEGIN
            INSERT INTO file_root_set_generation (group_id, generation)
            VALUES (NEW.group_id, 1)
            ON CONFLICT(group_id) DO UPDATE SET generation = generation + 1;
            INSERT INTO file_root_set_generation (group_id, generation)
            SELECT OLD.group_id, 1 WHERE OLD.group_id <> NEW.group_id
            ON CONFLICT(group_id) DO UPDATE SET generation = generation + 1;
        END;

        CREATE TRIGGER IF NOT EXISTS files_root_set_generation_on_delete
        AFTER DELETE ON files
        BEGIN
            INSERT INTO file_root_set_generation (group_id, generation)
            VALUES (OLD.group_id, 1)
            ON CONFLICT(group_id) DO UPDATE SET generation = generation + 1;
        END;
        "#,
    )?;

    let invalid_authoring_rows: i64 = conn.query_row(
        &format!("SELECT COUNT(*) FROM files f WHERE {}", unverified_authoring_identity("f")),
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

/// The condition under which the `files` row `row` is a current,
/// DAG-backed row without a verified authoring identity.
///
/// A group is DAG-backed once it has any history: a retained change, a
/// pruned change's stub, or an installed history base -- a sealed group
/// retains no change at all, and its base is its whole history. A row's
/// authoring change is verified when this device retains it, keeps its
/// stub, or the group's installed base carries it: as a content head, or
/// as the author of a row the base carries. A row outlives the head that
/// wrote it -- a removal's row, a conflict copy after its path is
/// rewritten -- so the heads alone would refuse rows the base carries.
fn unverified_authoring_identity(row: &str) -> String {
    format!(
        "{row}.state = 'current' AND {row}.version_seq > 0
          AND (EXISTS(SELECT 1 FROM changes WHERE group_id = {row}.group_id)
               OR EXISTS(SELECT 1 FROM pruned_changes WHERE group_id = {row}.group_id)
               OR EXISTS(SELECT 1 FROM group_history_bases WHERE group_id = {row}.group_id))
          AND ({row}.authoring_change_hash IS NULL
               OR length({row}.authoring_change_hash) != 32
               OR NOT EXISTS(
                   SELECT 1 FROM changes
                    WHERE group_id = {row}.group_id
                      AND change_hash = {row}.authoring_change_hash
                   UNION ALL
                   SELECT 1 FROM pruned_changes
                    WHERE group_id = {row}.group_id
                      AND change_hash = {row}.authoring_change_hash
                   UNION ALL
                   SELECT 1 FROM history_base_path_heads h
                     JOIN group_history_bases b
                       ON b.group_id = h.group_id AND b.history_base = h.base_hash
                    WHERE h.group_id = {row}.group_id
                      AND h.change_hash = {row}.authoring_change_hash
                   UNION ALL
                   SELECT 1 FROM history_base_carried_authors a
                     JOIN group_history_bases b
                       ON b.group_id = a.group_id AND b.history_base = a.base_hash
                    WHERE a.group_id = {row}.group_id
                      AND a.change_hash = {row}.authoring_change_hash
               ))"
    )
}

pub fn table_exists(conn: &Connection, table: &str) -> Result<bool, DatabaseError> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
        [table],
        |r| r.get(0),
    )?;
    Ok(count > 0)
}

#[cfg(test)]
mod tests;
