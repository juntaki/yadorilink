//! `path_materialized_generations`: the durable record of what the engine
//! believes the disk currently reflects for a path, kept separate from what
//! the change DAG resolves that path to (`DiskGenerationBasis`).
//!
//! This module is deliberately narrow: it records and reads one row per
//! `(group_id, path)`. Nothing here decides *when* a generation should
//! change -- that is a caller's job, restated here because it is easy to get
//! backwards: a new admission (desired state) must never touch this table; a
//! row here changes only after a filesystem placement has been observed
//! committed and durably recorded. `yadorilink_sync_core::optimistic_placement::
//! execute_short_commit_window_unchecked` is that caller: it writes a
//! generation in the same SQLite transaction that marks the epoch
//! `Committed`, after the platform placement and its required durability
//! flush have both succeeded; every other outcome of that window (a
//! `NotStarted`, `RequiresRecovery`, or failed-flush result) writes no
//! generation at all. `yadorilink_sync_core::index`'s
//! `backfill_materialized_generations` provides a best-effort seed for a
//! database that predates the writer, and `resolution_planning` still reads
//! the epoch journal instead of this table (see that module's own doc for
//! why).
//!
//! # Immutability
//!
//! A generation's causal basis is fixed for its lifetime: if the
//! frontier a path reflects moves, that is a *new* generation, never an
//! edit to the old one's basis. This module has exactly one write entry
//! point, [`record_materialized_generation`], and it always replaces every
//! column together under a freshly minted [`GenerationId`] -- there is no
//! "update just the basis" function to reach for by mistake. Basis
//! membership itself is even more strongly protected: interned causal
//! bases (`crate::dag_store::causal_basis`) are never mutated once written,
//! only ever referenced by a new row.
//!
//! # Absence is a generation too
//!
//! A path with nothing on disk is not "no row" -- it is a row whose
//! `object_kind` is [`MaterializedObjectKind::Absent`], `version` is
//! `None`, and `filesystem_identity` is `None`. The basis is still the
//! frontier whose resolution produced that absence (a tombstone or a
//! move-away). [`record_materialized_generation`] does not special-case
//! this: an absent generation is written through the exact same call as a
//! present one, with `object_kind: Absent`, so there is no separate path to
//! forget to handle it on.
//!
//! # History
//!
//! Split out of `yadorilink-sync-core::materialized_generation` in two
//! steps. Phase 7D-7.2 hoisted the `FileIdentity` binary codec and
//! `GenerationId` (dag_store-independent) into this crate's
//! [`crate::file_identity_codec`], since `filesystem_transaction`'s epoch
//! rows reuse that exact encoding; `record_materialized_generation`/
//! `lookup_materialized_generation` (this module) stayed behind because
//! they call `dag_store::intern_causal_basis`, and `dag_store` had not
//! moved into this crate yet. Phase 7D-7.5 finished the hoist: `dag_store`
//! landed in this crate in Phase 7D-7.3, removing that blocker, so the rest
//! of the module (this file) followed. `yadorilink-sync-core`'s
//! `materialized_generation` module now re-exports everything here (and
//! everything in `file_identity_codec`) under its old names, so its ~10
//! existing in-crate consumers did not need their `use` paths touched.

use rusqlite::{Connection, OptionalExtension};
use sha2::{Digest, Sha256};

use crate::dag_store::intern_causal_basis;
use crate::error::SyncSqliteError;
use crate::file_identity_codec::{
    decode_file_identity, encode_file_identity, GenerationId,
    MATERIALIZED_GENERATION_ENCODING_VERSION,
};
use yadorilink_replica_domain::ids::{ChangeHash, VersionHash};
use yadorilink_root_authority::fs_identity::FileIdentity;

/// `pub`, not `pub(crate)`: exposed to `yadorilink-sync-core` (this crate's
/// re-export shim, and that crate's own tests that build a full-schema
/// in-memory database) the same way `dag_store::init_dag_schema` already is.
pub fn init_materialized_generation_schema(conn: &Connection) -> Result<(), SyncSqliteError> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS path_materialized_generations (
            group_id                   TEXT NOT NULL,
            path                       TEXT NOT NULL,
            generation_id              TEXT NOT NULL,
            causal_basis_id            TEXT NOT NULL,
            resolved_path_state_hash   BLOB NOT NULL,
            object_kind                TEXT NOT NULL,
            version_hash               BLOB,
            filesystem_identity        BLOB,
            metadata_fingerprint       BLOB,
            hardlink_group_id          TEXT,
            encoding_version           INTEGER NOT NULL,
            updated_at_unix_nanos      INTEGER NOT NULL,
            PRIMARY KEY (group_id, path)
        );

        -- C4-12 decision 3d/PROJ-8: the filesystem-side fence, independent
        -- of and complementary to the DAG-side `invalidation_generation`
        -- (`projection_obligations`). Bumped by every physical mutator
        -- before its first mutating syscall, inside the same path-lock
        -- critical section as the mutation; snapshotted (never bumped) by
        -- a content-identical verification. A row's existence has no
        -- relationship to whether `path_materialized_generations` holds a
        -- row for the same path -- the fence must exist even for a path
        -- with no proof yet (see `snapshot_mutation_fence`'s own doc
        -- comment).
        CREATE TABLE IF NOT EXISTS path_actual_mutation_fences (
            group_id            TEXT NOT NULL,
            path                TEXT NOT NULL,
            mutation_generation INTEGER NOT NULL,
            last_mutation_kind  TEXT NOT NULL,
            last_mutation_at    INTEGER NOT NULL,
            PRIMARY KEY (group_id, path)
        );
        "#,
    )?;
    // Lightweight migration, same idempotent shape as `materialization_
    // jobs.rs`'s own `trigger_lamport` column. `published_under_mutation_
    // generation` records the filesystem-side fence value a row's publisher
    // observed (via `snapshot_mutation_fence` or a caller-supplied claimed
    // epoch) at the moment it wrote -- `lookup_materialized_generation`
    // trusts a row only while this still equals the path's CURRENT fence,
    // so a `NULL` here (every pre-migration row) is correctly untrusted
    // until something republishes it, exactly like a path with no row at
    // all. There is no default that would make an old row retroactively
    // "current" -- the whole point is that nothing can vouch for a
    // pre-migration row's freshness after the fact.
    match conn.execute(
        "ALTER TABLE path_materialized_generations \
         ADD COLUMN published_under_mutation_generation INTEGER",
        [],
    ) {
        Ok(_) => {}
        Err(rusqlite::Error::SqliteFailure(_, Some(ref msg)))
            if msg.starts_with("duplicate column name") =>
        {
            // Already migrated.
        }
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

/// Bumps (or creates, at generation 1) the filesystem-side mutation fence
/// for `(group_id, path)`, and returns the new value. The bump is a single
/// atomic `INSERT ... ON CONFLICT DO UPDATE ... RETURNING` -- never a read
/// followed by a write -- so two concurrent callers always receive two
/// *distinct* values, even absent any lock: the fence is a staleness
/// detector, not a mutual-exclusion primitive (decision 3d's own
/// "adversarial check on the fence itself"). Callers MUST still hold
/// `path_lock` (or equivalent) for the mutation itself -- this function
/// grants no exclusivity of its own.
///
/// Call this from inside the SAME path-lock critical section as the
/// mutation, before the first mutating syscall, and after the decision to
/// mutate has been made (decision 3d: "where the bump sits relative to each
/// mutator"). `mutation_kind` is a short, human-readable label (e.g.
/// `"materialize"`, `"retire"`, `"hydrate"`, `"repair"`) recorded purely for
/// diagnostics -- it plays no role in any correctness check.
pub fn bump_mutation_fence(
    conn: &Connection,
    group_id: &str,
    path: &str,
    mutation_kind: &str,
    now_unix_nanos: i64,
) -> Result<i64, SyncSqliteError> {
    conn.query_row(
        "INSERT INTO path_actual_mutation_fences
            (group_id, path, mutation_generation, last_mutation_kind, last_mutation_at)
         VALUES (?1, ?2, 1, ?3, ?4)
         ON CONFLICT (group_id, path) DO UPDATE SET
            mutation_generation = mutation_generation + 1,
            last_mutation_kind = ?3,
            last_mutation_at = ?4
         RETURNING mutation_generation",
        rusqlite::params![group_id, path, mutation_kind, now_unix_nanos],
        |r| r.get(0),
    )
    .map_err(SyncSqliteError::from)
}

/// Reads `(group_id, path)`'s current mutation-fence value WITHOUT bumping
/// it, creating the row at generation 0 first if none exists yet (`INSERT
/// ... ON CONFLICT DO NOTHING`, then read) -- so the returned value is
/// always a concrete epoch a later publication can CAS against, even for a
/// path that has never been mutated.
///
/// For a content-identical verification only: it changes no bytes, so it
/// must not advance the fence (decision 3d: "verification snapshots, it
/// does not bump"). The observation of disk and this snapshot MUST happen
/// as one atomic step under the path's lock -- reading the fence before or
/// after observing disk, or outside the lock, reopens exactly the race this
/// function exists to close. Also used internally by
/// [`record_materialized_generation`] to tag an unconditional write with
/// the fence value in effect at that instant, so an existing caller with no
/// knowledge of mutation fences still produces a row `lookup_materialized_
/// generation` can trust immediately after the write (and, correctly, no
/// longer once anything else bumps the fence).
pub fn snapshot_mutation_fence(
    conn: &Connection,
    group_id: &str,
    path: &str,
) -> Result<i64, SyncSqliteError> {
    conn.execute(
        "INSERT INTO path_actual_mutation_fences
            (group_id, path, mutation_generation, last_mutation_kind, last_mutation_at)
         VALUES (?1, ?2, 0, 'snapshot-created', 0)
         ON CONFLICT (group_id, path) DO NOTHING",
        rusqlite::params![group_id, path],
    )?;
    conn.query_row(
        "SELECT mutation_generation FROM path_actual_mutation_fences
          WHERE group_id = ?1 AND path = ?2",
        rusqlite::params![group_id, path],
        |r| r.get(0),
    )
    .map_err(SyncSqliteError::from)
}

/// The id [`crate::dag_store::intern_causal_basis`] returns, wrapped so a
/// `GenerationId` and a `CausalBasisId` -- both opaque strings -- cannot be
/// swapped positionally without a type error.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CausalBasisId(pub String);

/// What a materialized generation's path currently names. [`Absent`] is a
/// real, first-class member here -- see the module doc's "Absence is a
/// generation too" section -- not represented by `Option::None` at this
/// level, because the row itself is never optional.
///
/// [`Absent`]: MaterializedObjectKind::Absent
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaterializedObjectKind {
    RegularFile,
    Directory,
    Symlink,
    Absent,
}

impl MaterializedObjectKind {
    fn as_db_str(self) -> &'static str {
        match self {
            MaterializedObjectKind::RegularFile => "regular_file",
            MaterializedObjectKind::Directory => "directory",
            MaterializedObjectKind::Symlink => "symlink",
            MaterializedObjectKind::Absent => "absent",
        }
    }

    fn from_db_str(value: &str) -> Result<MaterializedObjectKind, SyncSqliteError> {
        match value {
            "regular_file" => Ok(MaterializedObjectKind::RegularFile),
            "directory" => Ok(MaterializedObjectKind::Directory),
            "symlink" => Ok(MaterializedObjectKind::Symlink),
            "absent" => Ok(MaterializedObjectKind::Absent),
            other => Err(SyncSqliteError::CorruptState(format!(
                "unknown materialized_object_kind {other:?} in path_materialized_generations"
            ))),
        }
    }
}

/// One row of `path_materialized_generations`, read back. Mirrors the
/// design's `DiskGenerationBasis` exactly; `group_id`/`path` are the row's
/// key and are passed alongside this rather than duplicated inside it.
#[derive(Debug, Clone, PartialEq)]
pub struct DiskGenerationBasis {
    pub generation_id: GenerationId,
    pub causal_basis_id: CausalBasisId,
    pub resolved_path_state_hash: [u8; 32],
    pub object_kind: MaterializedObjectKind,
    pub version: Option<VersionHash>,
    pub filesystem_identity: Option<FileIdentity>,
}

fn put_u32(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(&value.to_be_bytes());
}

fn put_str(buf: &mut Vec<u8>, value: &str) {
    put_u32(buf, value.len() as u32);
    buf.extend_from_slice(value.as_bytes());
}

const RESOLVED_PATH_STATE_DOMAIN_TAG: &[u8; 8] = b"YLNKrps\x01";

fn object_kind_tag(kind: MaterializedObjectKind) -> u8 {
    match kind {
        MaterializedObjectKind::RegularFile => 0,
        MaterializedObjectKind::Directory => 1,
        MaterializedObjectKind::Symlink => 2,
        MaterializedObjectKind::Absent => 3,
    }
}

/// The canonical encoding `resolved_path_state_hash` is derived from. This
/// is the reference definition: nothing in this crate computes a
/// desired-state `resolved_path_state_hash` yet (the resolver that turns a
/// DAG frontier into a desired target is not built), so whichever later
/// phase builds it must produce byte-identical input for the two hashes to
/// ever be comparable, and this function is where that shape lives.
fn canonical_resolved_path_state_encoding(
    group_id: &str,
    path: &str,
    object_kind: MaterializedObjectKind,
    version: Option<&VersionHash>,
) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(RESOLVED_PATH_STATE_DOMAIN_TAG);
    put_str(&mut buf, group_id);
    put_str(&mut buf, path);
    buf.push(object_kind_tag(object_kind));
    match version {
        Some(v) => {
            buf.push(1);
            buf.extend_from_slice(&v.0);
        }
        None => buf.push(0),
    }
    buf
}

/// Hashes what a path resolves to -- its kind and, when it has one, its
/// version -- independent of which causal frontier produced that
/// resolution. Two different bases that happen to resolve to the same
/// object and version hash to the same value on purpose: that is what lets
/// a future comparison ask "does disk match desired?" without caring which
/// route either side took to get there.
pub fn compute_resolved_path_state_hash(
    group_id: &str,
    path: &str,
    object_kind: MaterializedObjectKind,
    version: Option<&VersionHash>,
) -> [u8; 32] {
    Sha256::digest(canonical_resolved_path_state_encoding(group_id, path, object_kind, version))
        .into()
}

fn new_generation_id(group_id: &str) -> GenerationId {
    let random: [u8; 16] = rand::random();
    GenerationId(format!("{group_id}:{}", hex::encode(random)))
}

/// Records a new materialized generation for `(group_id, path)`. Always
/// replaces the row wholesale under a freshly minted [`GenerationId`] --
/// see the module doc's immutability section for why there is no separate
/// "update the basis" entry point. `causal_basis` is the complete frontier
/// this generation reflects; it is interned via
/// [`crate::dag_store::intern_causal_basis`], so a path sharing a frontier
/// with a million others shares one basis row, not a million copies.
///
/// `object_kind: Absent` and `version: None`/`filesystem_identity: None`
/// together record an absent path's generation -- there is no separate
/// function for that case; see the module doc.
///
/// C4-12: this is an UNCONDITIONAL write, used today by the (disabled)
/// forward filesystem-transaction engine and by tests, neither of which
/// knows about the mutation fence [`bump_mutation_fence`]/decision 3d
/// introduces. It stamps the row with [`snapshot_mutation_fence`]'s
/// current value automatically, so [`lookup_materialized_generation`]
/// trusts it immediately after this call -- and, correctly, no longer
/// once anything else bumps the fence for this path. Stage 3's actual
/// mutator-facing publish API is [`publish_materialized_generation_if_
/// fence_current`], which CASes against a specific PRE-CAPTURED epoch
/// instead of trusting whatever the fence happens to say right now; use
/// that one for a real physical mutation's publication, not this
/// function, which can never fail a staleness check by construction.
#[allow(clippy::too_many_arguments)]
pub fn record_materialized_generation(
    conn: &Connection,
    group_id: &str,
    path: &str,
    causal_basis: &[ChangeHash],
    object_kind: MaterializedObjectKind,
    version: Option<&VersionHash>,
    filesystem_identity: Option<&FileIdentity>,
    now_unix_nanos: i64,
) -> Result<DiskGenerationBasis, SyncSqliteError> {
    let fence = snapshot_mutation_fence(conn, group_id, path)?;
    write_generation_row(
        conn,
        group_id,
        path,
        causal_basis,
        object_kind,
        version,
        filesystem_identity,
        fence,
        now_unix_nanos,
    )
}

/// CAS-publish for a real physical mutation (C4-12 decision 3e): writes the
/// row only if `(group_id, path)`'s CURRENT mutation-fence value still
/// equals `expected_mutation_generation` -- the epoch the caller captured
/// via [`bump_mutation_fence`] before it started mutating. Returns `Ok(None)`
/// (not an error) when the CAS fails: some other mutator has already bumped
/// the fence since, so this attempt's evidence is stale and must not be
/// published as current. Returns `Ok(Some(_))` with the row that was
/// written on success.
///
/// This does not, by itself, decide whether the OBLIGATION that triggered
/// this publish may close -- that is a separate, later compound check
/// (decision 3e) re-reading this same fence at the moment of completion,
/// not merely at the moment of publication.
#[allow(clippy::too_many_arguments)]
pub fn publish_materialized_generation_if_fence_current(
    conn: &Connection,
    group_id: &str,
    path: &str,
    causal_basis: &[ChangeHash],
    object_kind: MaterializedObjectKind,
    version: Option<&VersionHash>,
    filesystem_identity: Option<&FileIdentity>,
    expected_mutation_generation: i64,
    now_unix_nanos: i64,
) -> Result<Option<DiskGenerationBasis>, SyncSqliteError> {
    let live: Option<i64> = conn
        .query_row(
            "SELECT mutation_generation FROM path_actual_mutation_fences \
             WHERE group_id = ?1 AND path = ?2",
            rusqlite::params![group_id, path],
            |r| r.get(0),
        )
        .optional()?;
    if live != Some(expected_mutation_generation) {
        return Ok(None);
    }
    Ok(Some(write_generation_row(
        conn,
        group_id,
        path,
        causal_basis,
        object_kind,
        version,
        filesystem_identity,
        expected_mutation_generation,
        now_unix_nanos,
    )?))
}

/// Adopts an externally-authored filesystem state -- one local capture just
/// durably observed and is committing to the DAG/index in this SAME
/// transaction -- as `(group_id, path)`'s current actual-state generation.
///
/// **E's meaning, generalized**: E (the mutation-fence epoch) is the
/// durable actual-state epoch known to YadoriLink. It advances in two
/// legitimate ways. An INTERNAL mutator (unchanged by this function)
/// captures E via [`bump_mutation_fence`] *before* its first mutating
/// syscall, then CASes its publish against that pre-captured value via
/// [`publish_materialized_generation_if_fence_current`] -- it controls
/// when the mutation happens, so it can bump-then-mutate-then-publish. An
/// EXTERNAL mutation (an editor, any process other than this daemon) has
/// already performed the syscall before the watcher could know about it
/// -- there is no "before the syscall" moment to retroactively bump
/// against. This function is the second legitimate way: local capture,
/// having durably observed and revalidated the resulting state, ADOPTS it
/// as current by minting a fresh epoch for it directly (there is nothing
/// to CAS against) and writing the generation row under that same fresh
/// value in one call, so the row is immediately usable via
/// [`lookup_materialized_generation`].
///
/// Deliberately not a call to [`bump_mutation_fence`] + [`write_generation_
/// row`] open-coded at the call site: giving this its own name keeps the
/// inverted ordering (mutate-then-observe-then-mint, not bump-then-mutate)
/// visible to a reader instead of looking like an ordinary internal
/// mutator that merely forgot to CAS.
///
/// Call this from inside the SAME transaction as the local Change
/// admission/index commit, with the path lock already held, only after
/// every other pre-commit revalidation (disk fingerprint, index state,
/// authoring identity) has already passed -- see the call site's own
/// documentation for the full precondition list. Never call this outside
/// a transaction that also durably commits the admitted local Change: a
/// crash between the two must never leave one without the other (a
/// desired-state bump with no actual-state proof is merely the ordinary,
/// already-handled "not yet zero-work-closeable" case; the reverse -- a
/// proof with no corresponding admitted Change -- is a correctness bug
/// this atomicity exists to rule out).
///
/// **External-writer consistency boundary**: this adopts the state local
/// capture durably observed, not a live guarantee about the filesystem at
/// every subsequent instant. A normal watcher cannot make YadoriLink
/// linearizable against an arbitrary external process at every
/// instruction -- an editor does not acquire this daemon's path lock or
/// bump E before writing. The resulting proof is exact relative to the
/// latest filesystem state durably observed and adopted by YadoriLink,
/// not relative to whatever the filesystem physically contains at the
/// instant a later reader consults it. This is already inherent in the
/// existing local-edit architecture (an observe-then-commit design, not a
/// stronger one), not a new weakness this function introduces.
#[allow(clippy::too_many_arguments)]
pub fn adopt_observed_actual_generation_in_tx(
    conn: &Connection,
    group_id: &str,
    path: &str,
    causal_basis: &[ChangeHash],
    object_kind: MaterializedObjectKind,
    version: Option<&VersionHash>,
    filesystem_identity: Option<&FileIdentity>,
    now_unix_nanos: i64,
) -> Result<DiskGenerationBasis, SyncSqliteError> {
    let adopted_epoch =
        bump_mutation_fence(conn, group_id, path, "external-actual-state-adopted", now_unix_nanos)?;
    write_generation_row(
        conn,
        group_id,
        path,
        causal_basis,
        object_kind,
        version,
        filesystem_identity,
        adopted_epoch,
        now_unix_nanos,
    )
}

#[allow(clippy::too_many_arguments)]
fn write_generation_row(
    conn: &Connection,
    group_id: &str,
    path: &str,
    causal_basis: &[ChangeHash],
    object_kind: MaterializedObjectKind,
    version: Option<&VersionHash>,
    filesystem_identity: Option<&FileIdentity>,
    published_under_mutation_generation: i64,
    now_unix_nanos: i64,
) -> Result<DiskGenerationBasis, SyncSqliteError> {
    let causal_basis_id = CausalBasisId(intern_causal_basis(conn, group_id, causal_basis)?);
    let resolved_path_state_hash =
        compute_resolved_path_state_hash(group_id, path, object_kind, version);
    let generation_id = new_generation_id(group_id);
    let filesystem_identity_blob = filesystem_identity.map(encode_file_identity);
    let metadata_fingerprint_blob = filesystem_identity.map(|id| id.metadata_fingerprint.to_vec());
    let version_blob = version.map(|v| v.0.to_vec());

    conn.execute(
        "INSERT INTO path_materialized_generations
            (group_id, path, generation_id, causal_basis_id, resolved_path_state_hash,
             object_kind, version_hash, filesystem_identity, metadata_fingerprint,
             hardlink_group_id, encoding_version, updated_at_unix_nanos,
             published_under_mutation_generation)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL, ?10, ?11, ?12)
         ON CONFLICT (group_id, path) DO UPDATE SET
            generation_id = excluded.generation_id,
            causal_basis_id = excluded.causal_basis_id,
            resolved_path_state_hash = excluded.resolved_path_state_hash,
            object_kind = excluded.object_kind,
            version_hash = excluded.version_hash,
            filesystem_identity = excluded.filesystem_identity,
            metadata_fingerprint = excluded.metadata_fingerprint,
            hardlink_group_id = NULL,
            encoding_version = excluded.encoding_version,
            updated_at_unix_nanos = excluded.updated_at_unix_nanos,
            published_under_mutation_generation = excluded.published_under_mutation_generation",
        rusqlite::params![
            group_id,
            path,
            generation_id.0,
            causal_basis_id.0,
            &resolved_path_state_hash[..],
            object_kind.as_db_str(),
            version_blob,
            filesystem_identity_blob,
            metadata_fingerprint_blob,
            MATERIALIZED_GENERATION_ENCODING_VERSION,
            now_unix_nanos,
            published_under_mutation_generation,
        ],
    )?;

    Ok(DiskGenerationBasis {
        generation_id,
        causal_basis_id,
        resolved_path_state_hash,
        object_kind,
        version: version.copied(),
        filesystem_identity: filesystem_identity.copied(),
    })
}

#[allow(clippy::type_complexity)]
fn decode_generation_row(
    row: (String, String, Vec<u8>, String, Option<Vec<u8>>, Option<Vec<u8>>),
    group_id: &str,
    path: &str,
) -> Result<DiskGenerationBasis, SyncSqliteError> {
    let (generation_id, causal_basis_id, hash_blob, kind_str, version_blob, identity_blob) = row;
    let resolved_path_state_hash: [u8; 32] = hash_blob.try_into().map_err(|_| {
        SyncSqliteError::CorruptState(format!(
            "invalid resolved_path_state_hash length for {group_id}/{path}"
        ))
    })?;
    let object_kind = MaterializedObjectKind::from_db_str(&kind_str)?;
    let version = version_blob
        .map(|bytes| {
            let hash: [u8; 32] = bytes.try_into().map_err(|_| {
                SyncSqliteError::CorruptState(format!(
                    "invalid version_hash length for {group_id}/{path}"
                ))
            })?;
            Ok::<_, SyncSqliteError>(VersionHash(hash))
        })
        .transpose()?;
    let filesystem_identity =
        identity_blob.map(|bytes| decode_file_identity(&bytes)).transpose()?;
    Ok(DiskGenerationBasis {
        generation_id: GenerationId(generation_id),
        causal_basis_id: CausalBasisId(causal_basis_id),
        resolved_path_state_hash,
        object_kind,
        version,
        filesystem_identity,
    })
}

/// Reads back the current materialized generation for `(group_id, path)` --
/// but ONLY if it is still *usable*: its stored `published_under_mutation_
/// generation` must still equal the path's CURRENT mutation-fence value.
/// `None` for a path that has never had one recorded, that has no fence row
/// at all, or whose fence has moved since this row was published -- these
/// three cases are indistinguishable to a caller, and deliberately so
/// (decision 3d/PROJ-7: "unknown is not absent," a caller must never be
/// able to tell "no data" apart from "stale data" and be tempted to treat
/// the latter as good enough). This is the crate's single fail-closed read
/// entry point (C4-12 decision 3d) -- every reader, including the
/// (disabled) forward engine's own `resolution_planning::is_done`, goes
/// through it without needing to know the mutation-fence concept exists.
/// [`lookup_materialized_generation_diagnostic`] is the escape hatch for
/// tooling that specifically wants to see a stale row anyway.
pub fn lookup_materialized_generation(
    conn: &Connection,
    group_id: &str,
    path: &str,
) -> Result<Option<DiskGenerationBasis>, SyncSqliteError> {
    #[allow(clippy::type_complexity)]
    let row: Option<(String, String, Vec<u8>, String, Option<Vec<u8>>, Option<Vec<u8>>)> = conn
        .query_row(
            "SELECT g.generation_id, g.causal_basis_id, g.resolved_path_state_hash, \
                    g.object_kind, g.version_hash, g.filesystem_identity \
               FROM path_materialized_generations g \
               JOIN path_actual_mutation_fences f \
                 ON f.group_id = g.group_id AND f.path = g.path \
              WHERE g.group_id = ?1 AND g.path = ?2 \
                AND g.published_under_mutation_generation = f.mutation_generation",
            rusqlite::params![group_id, path],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
        )
        .optional()?;
    row.map(|r| decode_generation_row(r, group_id, path)).transpose()
}

/// Diagnostic-only counterpart to [`lookup_materialized_generation`]: reads
/// the raw row regardless of whether it is still usable against the
/// current mutation fence. Never call this from a correctness-relevant
/// decision (a skip-physical-work decision, an obligation close) -- it
/// exists so tooling/logging can see "what did we last publish here, even
/// if it's stale" without that visibility leaking into a path that would
/// treat staleness as good enough.
pub fn lookup_materialized_generation_diagnostic(
    conn: &Connection,
    group_id: &str,
    path: &str,
) -> Result<Option<DiskGenerationBasis>, SyncSqliteError> {
    #[allow(clippy::type_complexity)]
    let row: Option<(String, String, Vec<u8>, String, Option<Vec<u8>>, Option<Vec<u8>>)> = conn
        .query_row(
            "SELECT generation_id, causal_basis_id, resolved_path_state_hash, object_kind, \
                    version_hash, filesystem_identity \
             FROM path_materialized_generations WHERE group_id = ?1 AND path = ?2",
            rusqlite::params![group_id, path],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
        )
        .optional()?;
    row.map(|r| decode_generation_row(r, group_id, path)).transpose()
}

/// The outcome of [`revalidate_identity_against_disk`]. `Confirmed` is the
/// ONLY verdict that may ever authorize skipping a physical mutation --
/// every other outcome, including every I/O error, is folded into
/// `NotAMatch` rather than propagated, since this check must never fail
/// the worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityRevalidation {
    /// Disk still holds exactly what `basis` claims: the object's identity
    /// still matches (a real object), or the path is still genuinely
    /// absent (an `Absent` basis). A caller may treat this as
    /// authorization to skip physical work for THIS decision only -- it
    /// makes no new causal claim and must never republish or refresh the
    /// record (0.5.6's own rule).
    Confirmed,
    /// Disk does not (or cannot be proven to still) match `basis`: a real
    /// identity mismatch (`IdentityComparison::DefinitelyDifferent`), an
    /// inconclusive comparison (`IdentityComparison::Ambiguous`, e.g. a
    /// coarse volume clock with no reuse discriminator to fall back on), a
    /// path that is unexpectedly present when `basis` claims `Absent` (or
    /// vice versa), or any I/O error observing the path. Fail closed: the
    /// caller must do real physical work, never treat this as a proof
    /// failure worth propagating.
    NotAMatch,
}

/// Re-observes `out_path`'s current on-disk identity and compares it
/// against `basis`, for a worker's zero-work-close decision to consult
/// before skipping physical work for a path whose `DiskGenerationBasis`
/// is otherwise usable (already fail-closed via
/// `lookup_materialized_generation`'s own mutation-fence check).
///
/// This is defense in depth for staleness the fence did not cause -- e.g.
/// a `chmod`/rename this device's own watcher has not reconciled into a
/// fresh DAG admission yet -- **not** what closes the ABA gap (the fence
/// CAS already does that structurally). `IdentityComparison::
/// Ambiguous` is reachable in ordinary conditions (a coarse volume clock),
/// so relying on this check alone for correctness would be probabilistic;
/// treat it as an additional, optional safety net a caller may apply, not
/// a required step the fence CAS's own guarantee depends on.
///
/// A passing (`Confirmed`) result authorizes SKIPPING physical work for
/// this decision only -- it is not itself a completion proof and must
/// never republish or refresh `basis`'s own row; the compound completion
/// check re-establishes usability at the actual moment of close, since
/// this revalidation cannot speak for that later instant.
pub fn revalidate_identity_against_disk(
    basis: &DiskGenerationBasis,
    out_path: &std::path::Path,
    birth_time_granularity: yadorilink_root_authority::fs_identity::TimestampGranularity,
) -> IdentityRevalidation {
    if basis.object_kind == MaterializedObjectKind::Absent {
        return match std::fs::symlink_metadata(out_path) {
            // Genuinely still absent: `basis`'s claim still holds.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => IdentityRevalidation::Confirmed,
            // Present (contradicts `Absent`), or an I/O error that leaves
            // absence unproven -- fail closed either way.
            Ok(_) | Err(_) => IdentityRevalidation::NotAMatch,
        };
    }
    let Some(expected) = basis.filesystem_identity else {
        // No identity was ever recorded for this non-Absent basis -- there
        // is nothing to revalidate against, so this check cannot confirm
        // anything.
        return IdentityRevalidation::NotAMatch;
    };
    let Ok(observed) = FileIdentity::observe_path(out_path) else {
        return IdentityRevalidation::NotAMatch;
    };
    match observed.compare(&expected, birth_time_granularity) {
        yadorilink_root_authority::fs_identity::IdentityComparison::SameObject => {
            IdentityRevalidation::Confirmed
        }
        yadorilink_root_authority::fs_identity::IdentityComparison::DefinitelyDifferent
        | yadorilink_root_authority::fs_identity::IdentityComparison::Ambiguous(_) => {
            IdentityRevalidation::NotAMatch
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use yadorilink_root_authority::fs_identity::{
        ObjectKind, PlatformObjectId, Timestamp, VolumeIdentity,
    };

    fn open() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        crate::dag_store::init_dag_schema(&conn).unwrap();
        init_materialized_generation_schema(&conn).unwrap();
        conn
    }

    fn h(byte: u8) -> ChangeHash {
        ChangeHash([byte; 32])
    }

    fn sample_identity() -> FileIdentity {
        FileIdentity {
            volume_identity: VolumeIdentity::Unix { device_id: 7 },
            object_id: PlatformObjectId::Unix { inode: 42 },
            object_kind: ObjectKind::RegularFile,
            generation_or_usn: Some(3),
            birth_or_creation_time: Some(Timestamp {
                seconds_since_unix_epoch: 1_700_000_000,
                subsec_nanos: 123,
            }),
            observed_size: 1024,
            metadata_fingerprint: [9; 32],
            link_count: Some(1),
            symlink_target_digest: None,
        }
    }

    fn sample_basis(
        object_kind: MaterializedObjectKind,
        filesystem_identity: Option<FileIdentity>,
    ) -> DiskGenerationBasis {
        DiskGenerationBasis {
            generation_id: GenerationId("g:1".to_string()),
            causal_basis_id: CausalBasisId("g:cb1".to_string()),
            resolved_path_state_hash: [0; 32],
            object_kind,
            version: None,
            filesystem_identity,
        }
    }

    /// An `Absent` basis whose path is genuinely still missing on disk is
    /// confirmed -- the trivial, common case.
    #[test]
    fn revalidate_confirms_a_still_absent_path() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("never-existed.txt");
        let basis = sample_basis(MaterializedObjectKind::Absent, None);
        assert_eq!(
            revalidate_identity_against_disk(
                &basis,
                &missing,
                yadorilink_root_authority::fs_identity::TimestampGranularity::Fine,
            ),
            IdentityRevalidation::Confirmed
        );
    }

    /// An `Absent` basis whose path now genuinely has something on disk
    /// must fail closed -- the exact case this helper
    /// exists to catch as defense in depth (some mutator wrote the path
    /// without this device's own admission/fence machinery noticing yet).
    #[test]
    fn revalidate_rejects_an_absent_basis_whose_path_now_exists() {
        let dir = tempfile::tempdir().unwrap();
        let now_present = dir.path().join("surprise.txt");
        std::fs::write(&now_present, b"unexpected content").unwrap();
        let basis = sample_basis(MaterializedObjectKind::Absent, None);
        assert_eq!(
            revalidate_identity_against_disk(
                &basis,
                &now_present,
                yadorilink_root_authority::fs_identity::TimestampGranularity::Fine,
            ),
            IdentityRevalidation::NotAMatch
        );
    }

    /// A real object whose CURRENT on-disk identity still matches the
    /// recorded one is confirmed.
    #[test]
    fn revalidate_confirms_a_matching_real_object_identity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("still-there.txt");
        std::fs::write(&path, b"unchanged content").unwrap();
        let observed = FileIdentity::observe_path(&path).unwrap();
        let basis = sample_basis(MaterializedObjectKind::RegularFile, Some(observed));
        assert_eq!(
            revalidate_identity_against_disk(
                &basis,
                &path,
                yadorilink_root_authority::fs_identity::TimestampGranularity::Fine,
            ),
            IdentityRevalidation::Confirmed
        );
    }

    /// The recorded identity no longer matches disk (the object was
    /// deleted and recreated, an unrelated file now occupies
    /// this path) -- fail closed rather than trust a stale record.
    #[test]
    fn revalidate_rejects_when_the_observed_identity_no_longer_matches() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("replaced.txt");
        std::fs::write(&path, b"new content after replacement").unwrap();
        // A synthetic, definitely-mismatched identity -- not this file's own.
        let basis = sample_basis(MaterializedObjectKind::RegularFile, Some(sample_identity()));
        assert_eq!(
            revalidate_identity_against_disk(
                &basis,
                &path,
                yadorilink_root_authority::fs_identity::TimestampGranularity::Fine,
            ),
            IdentityRevalidation::NotAMatch
        );
    }

    /// A non-`Absent` basis with NO recorded filesystem identity has
    /// nothing to revalidate against -- fail closed, never
    /// treat the mere existence of a real file as confirmation.
    #[test]
    fn revalidate_rejects_a_non_absent_basis_with_no_recorded_identity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("exists-but-unrecorded.txt");
        std::fs::write(&path, b"content").unwrap();
        let basis = sample_basis(MaterializedObjectKind::RegularFile, None);
        assert_eq!(
            revalidate_identity_against_disk(
                &basis,
                &path,
                yadorilink_root_authority::fs_identity::TimestampGranularity::Fine,
            ),
            IdentityRevalidation::NotAMatch
        );
    }

    #[test]
    fn a_new_generation_can_be_looked_up_back_exactly() {
        let conn = open();
        let version = VersionHash([5; 32]);
        let identity = sample_identity();
        let written = record_materialized_generation(
            &conn,
            "g",
            "a.txt",
            &[h(1), h(2)],
            MaterializedObjectKind::RegularFile,
            Some(&version),
            Some(&identity),
            1000,
        )
        .unwrap();
        let read = lookup_materialized_generation(&conn, "g", "a.txt").unwrap().unwrap();
        assert_eq!(read, written);
        assert_eq!(read.version, Some(version));
        assert_eq!(read.filesystem_identity, Some(identity));
    }

    #[test]
    fn an_absent_path_is_recorded_as_its_own_object_kind_not_a_missing_row() {
        let conn = open();
        record_materialized_generation(
            &conn,
            "g",
            "gone.txt",
            &[h(9)],
            MaterializedObjectKind::Absent,
            None,
            None,
            1000,
        )
        .unwrap();
        let read = lookup_materialized_generation(&conn, "g", "gone.txt").unwrap().unwrap();
        assert_eq!(read.object_kind, MaterializedObjectKind::Absent);
        assert!(read.version.is_none());
        assert!(read.filesystem_identity.is_none());
    }

    #[test]
    fn lookup_of_a_never_recorded_path_is_none() {
        let conn = open();
        assert!(lookup_materialized_generation(&conn, "g", "never.txt").unwrap().is_none());
    }

    #[test]
    fn recording_a_new_generation_replaces_the_row_under_a_fresh_id_not_in_place() {
        // The immutability rule: a later generation is a NEW row under a
        // new id, never an edit of the old basis in place. Proven
        // here by writing two different bases at the same path and
        // confirming the second call's `generation_id` differs from the
        // first's, and that a lookup only ever sees the latest, complete
        // row -- never a hybrid of the two.
        let conn = open();
        let first = record_materialized_generation(
            &conn,
            "g",
            "a.txt",
            &[h(1)],
            MaterializedObjectKind::RegularFile,
            Some(&VersionHash([1; 32])),
            None,
            1000,
        )
        .unwrap();
        let second = record_materialized_generation(
            &conn,
            "g",
            "a.txt",
            &[h(2)],
            MaterializedObjectKind::RegularFile,
            Some(&VersionHash([2; 32])),
            None,
            2000,
        )
        .unwrap();
        assert_ne!(first.generation_id, second.generation_id);
        assert_ne!(first.causal_basis_id, second.causal_basis_id);
        let read = lookup_materialized_generation(&conn, "g", "a.txt").unwrap().unwrap();
        assert_eq!(read, second, "must read back exactly the latest generation, not a merge");
    }

    #[test]
    fn a_million_paths_sharing_one_frontier_intern_one_basis_row() {
        let conn = open();
        for i in 0..1000 {
            record_materialized_generation(
                &conn,
                "g",
                &format!("path-{i}.txt"),
                &[h(1), h(2)],
                MaterializedObjectKind::RegularFile,
                Some(&VersionHash([1; 32])),
                None,
                1000,
            )
            .unwrap();
        }
        let count: i64 =
            conn.query_row("SELECT COUNT(*) FROM causal_basis_sets", [], |r| r.get(0)).unwrap();
        assert_eq!(count, 1, "1000 paths sharing one frontier must intern to one basis row");
        let rows: i64 = conn
            .query_row("SELECT COUNT(*) FROM path_materialized_generations", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rows, 1000, "each path still gets its own generation row");
    }

    #[test]
    fn different_paths_with_the_same_content_share_a_resolved_path_state_hash_only_if_the_path_matches(
    ) {
        // `resolved_path_state_hash` is keyed by path (a symlink named `a`
        // pointing at content X is not interchangeable with one named `b`
        // pointing at the same content) -- confirmed here as a property of
        // the hash itself, not the table.
        let a = compute_resolved_path_state_hash(
            "g",
            "a.txt",
            MaterializedObjectKind::RegularFile,
            Some(&VersionHash([1; 32])),
        );
        let b = compute_resolved_path_state_hash(
            "g",
            "b.txt",
            MaterializedObjectKind::RegularFile,
            Some(&VersionHash([1; 32])),
        );
        assert_ne!(a, b);
    }

    #[test]
    fn resolved_path_state_hash_distinguishes_absent_from_every_present_kind() {
        let absent =
            compute_resolved_path_state_hash("g", "a", MaterializedObjectKind::Absent, None);
        let file = compute_resolved_path_state_hash(
            "g",
            "a",
            MaterializedObjectKind::RegularFile,
            Some(&VersionHash([1; 32])),
        );
        let dir =
            compute_resolved_path_state_hash("g", "a", MaterializedObjectKind::Directory, None);
        assert_ne!(absent, file);
        assert_ne!(absent, dir);
    }

    // The filesystem-side mutation fence.

    #[test]
    fn bump_mutation_fence_starts_at_one_and_increments_on_each_call() {
        let conn = open();
        assert_eq!(bump_mutation_fence(&conn, "g", "a.txt", "materialize", 1000).unwrap(), 1);
        assert_eq!(bump_mutation_fence(&conn, "g", "a.txt", "materialize", 2000).unwrap(), 2);
        assert_eq!(bump_mutation_fence(&conn, "g", "a.txt", "retire", 3000).unwrap(), 3);
    }

    #[test]
    fn bump_mutation_fence_never_touches_an_unrelated_path() {
        let conn = open();
        bump_mutation_fence(&conn, "g", "a.txt", "materialize", 1000).unwrap();
        bump_mutation_fence(&conn, "g", "b.txt", "materialize", 1000).unwrap();
        assert_eq!(bump_mutation_fence(&conn, "g", "a.txt", "materialize", 2000).unwrap(), 2);
        // b.txt's own fence must still read back at 1, not have been bumped
        // by a.txt's second bump.
        let b = snapshot_mutation_fence(&conn, "g", "b.txt").unwrap();
        assert_eq!(b, 1);
    }

    #[test]
    fn snapshot_mutation_fence_creates_a_row_at_generation_zero_without_bumping_it() {
        let conn = open();
        let first = snapshot_mutation_fence(&conn, "g", "never-mutated.txt").unwrap();
        assert_eq!(first, 0);
        // A second snapshot of the same never-mutated path reads the same
        // value back -- snapshotting must never itself advance the fence.
        let second = snapshot_mutation_fence(&conn, "g", "never-mutated.txt").unwrap();
        assert_eq!(second, 0);
    }

    #[test]
    fn snapshot_mutation_fence_reads_the_live_value_after_a_real_bump() {
        let conn = open();
        bump_mutation_fence(&conn, "g", "a.txt", "materialize", 1000).unwrap();
        bump_mutation_fence(&conn, "g", "a.txt", "materialize", 2000).unwrap();
        assert_eq!(snapshot_mutation_fence(&conn, "g", "a.txt").unwrap(), 2);
    }

    #[test]
    fn record_materialized_generation_is_immediately_usable_via_lookup() {
        // The unification property this design relies on: an existing
        // caller with no knowledge of mutation fences (record_materialized_
        // generation's own contract, unchanged) still produces a row the
        // new fail-closed lookup trusts right away.
        let conn = open();
        let version = VersionHash([5; 32]);
        record_materialized_generation(
            &conn,
            "g",
            "a.txt",
            &[h(1)],
            MaterializedObjectKind::RegularFile,
            Some(&version),
            None,
            1000,
        )
        .unwrap();
        assert!(lookup_materialized_generation(&conn, "g", "a.txt").unwrap().is_some());
    }

    #[test]
    fn a_row_becomes_unusable_the_moment_something_else_bumps_the_fence() {
        // PROJ-7/PROJ-8's whole point: a published proof must stop being
        // usable the instant a physical mutation touches the path again,
        // even one this module knows nothing about the origin of.
        let conn = open();
        record_materialized_generation(
            &conn,
            "g",
            "a.txt",
            &[h(1)],
            MaterializedObjectKind::RegularFile,
            Some(&VersionHash([5; 32])),
            None,
            1000,
        )
        .unwrap();
        assert!(lookup_materialized_generation(&conn, "g", "a.txt").unwrap().is_some());

        bump_mutation_fence(&conn, "g", "a.txt", "some-other-mutator", 2000).unwrap();

        assert!(
            lookup_materialized_generation(&conn, "g", "a.txt").unwrap().is_none(),
            "a row published under a now-superseded fence generation must not be returned as usable"
        );
        assert!(
            lookup_materialized_generation_diagnostic(&conn, "g", "a.txt").unwrap().is_some(),
            "the diagnostic accessor must still be able to see the stale row"
        );
    }

    #[test]
    fn publish_if_fence_current_succeeds_when_the_claimed_epoch_is_still_live() {
        let conn = open();
        let claimed = bump_mutation_fence(&conn, "g", "a.txt", "materialize", 1000).unwrap();
        let published = publish_materialized_generation_if_fence_current(
            &conn,
            "g",
            "a.txt",
            &[h(1)],
            MaterializedObjectKind::RegularFile,
            Some(&VersionHash([5; 32])),
            None,
            claimed,
            2000,
        )
        .unwrap();
        assert!(published.is_some());
        assert!(lookup_materialized_generation(&conn, "g", "a.txt").unwrap().is_some());
    }

    /// The headline regression this whole mechanism exists for: an attempt
    /// whose claimed epoch has been superseded by an independent mutator
    /// must have its publication rejected, regardless of the DAG frontier
    /// (which this test never even touches) -- Context finding 8's race.
    #[test]
    fn publish_if_fence_current_is_rejected_once_an_independent_mutator_has_bumped_it() {
        let conn = open();
        let claimed = bump_mutation_fence(&conn, "g", "c.txt", "materialize", 1000).unwrap();

        // An independent mutator (e.g. retirement) acts on the same path
        // before the first attempt's publication runs.
        bump_mutation_fence(&conn, "g", "c.txt", "retire", 1500).unwrap();

        let published = publish_materialized_generation_if_fence_current(
            &conn,
            "g",
            "c.txt",
            &[h(1)],
            MaterializedObjectKind::RegularFile,
            Some(&VersionHash([5; 32])),
            None,
            claimed,
            2000,
        )
        .unwrap();
        assert!(published.is_none(), "a stale publication must be rejected, not silently accepted");
        assert!(
            lookup_materialized_generation(&conn, "g", "c.txt").unwrap().is_none(),
            "the rejected publication must not have written anything usable"
        );
    }

    #[test]
    fn publish_if_fence_current_is_rejected_when_no_fence_row_exists_at_all() {
        // The "no row yet" variant of the same race: an attempt claiming an
        // epoch for a path with no fence row at all (e.g. it never actually
        // called bump_mutation_fence, or the row was never created) must
        // fail the same way as a superseded epoch, not succeed vacuously.
        let conn = open();
        let published = publish_materialized_generation_if_fence_current(
            &conn,
            "g",
            "never-fenced.txt",
            &[h(1)],
            MaterializedObjectKind::RegularFile,
            Some(&VersionHash([5; 32])),
            None,
            1,
            2000,
        )
        .unwrap();
        assert!(published.is_none());
    }

    #[test]
    fn a_path_with_no_admission_or_mutation_ever_has_no_usable_generation() {
        let conn = open();
        assert!(lookup_materialized_generation(&conn, "g", "never.txt").unwrap().is_none());
        assert!(lookup_materialized_generation_diagnostic(&conn, "g", "never.txt")
            .unwrap()
            .is_none());
    }

    /// An invalidated `Absent` proof must be exactly as unusable as no
    /// proof at all -- "unknown" must never be conflated with "absent," so
    /// a caller must never be tempted to treat "was Absent, since invalidated"
    /// as good enough to short-circuit real verification. A freshly
    /// republished Absent record, by contrast, is usable again.
    #[test]
    fn an_invalidated_absent_generation_is_unusable_exactly_like_no_proof_while_a_fresh_one_is_usable(
    ) {
        let conn = open();
        record_materialized_generation(
            &conn,
            "g",
            "gone.txt",
            &[h(9)],
            MaterializedObjectKind::Absent,
            None,
            None,
            1000,
        )
        .unwrap();
        assert_eq!(
            lookup_materialized_generation(&conn, "g", "gone.txt").unwrap().map(|b| b.object_kind),
            Some(MaterializedObjectKind::Absent),
            "a fresh Absent record must be usable"
        );

        // An independent mutator touches the path without republishing.
        bump_mutation_fence(&conn, "g", "gone.txt", "some-other-mutator", 2000).unwrap();

        assert!(
            lookup_materialized_generation(&conn, "g", "gone.txt").unwrap().is_none(),
            "an invalidated Absent proof must not be returned as usable"
        );
        assert_eq!(
            lookup_materialized_generation(&conn, "g", "gone.txt").unwrap(),
            lookup_materialized_generation(&conn, "g", "truly-never-recorded.txt").unwrap(),
            "invalidated-Absent must be indistinguishable from no-proof-at-all to a caller"
        );
        let diag =
            lookup_materialized_generation_diagnostic(&conn, "g", "gone.txt").unwrap().unwrap();
        assert_eq!(
            diag.object_kind,
            MaterializedObjectKind::Absent,
            "diagnostic still sees it was Absent"
        );

        // Republishing under the now-current fence makes it usable again.
        let current_fence = snapshot_mutation_fence(&conn, "g", "gone.txt").unwrap();
        let republished = publish_materialized_generation_if_fence_current(
            &conn,
            "g",
            "gone.txt",
            &[h(9)],
            MaterializedObjectKind::Absent,
            None,
            None,
            current_fence,
            3000,
        )
        .unwrap();
        assert!(republished.is_some());
        assert_eq!(
            lookup_materialized_generation(&conn, "g", "gone.txt").unwrap().map(|b| b.object_kind),
            Some(MaterializedObjectKind::Absent),
            "a genuinely fresh Absent record must be usable again"
        );
    }

    /// A generation row that predates the mutation-fence machinery
    /// entirely (no corresponding `path_actual_mutation_fences`
    /// row at all -- the pre-migration/backfill case) must be unusable,
    /// never vacuously trusted.
    #[test]
    fn a_generation_row_with_no_fence_row_at_all_is_unusable_the_pre_migration_backfill_case() {
        let conn = open();
        let causal_basis_id = CausalBasisId(intern_causal_basis(&conn, "g", &[h(1)]).unwrap());
        let hash = compute_resolved_path_state_hash(
            "g",
            "pre-migration.txt",
            MaterializedObjectKind::RegularFile,
            None,
        );
        conn.execute(
            "INSERT INTO path_materialized_generations
                (group_id, path, generation_id, causal_basis_id, resolved_path_state_hash,
                 object_kind, version_hash, filesystem_identity, metadata_fingerprint,
                 hardlink_group_id, encoding_version, updated_at_unix_nanos,
                 published_under_mutation_generation)
             VALUES ('g', 'pre-migration.txt', 'g:old', ?1, ?2, 'regular_file', NULL, NULL, NULL,
                     NULL, 1, 500, NULL)",
            rusqlite::params![causal_basis_id.0, &hash[..]],
        )
        .unwrap();
        // Deliberately never call bump_mutation_fence/snapshot_mutation_fence
        // for this path -- no row in path_actual_mutation_fences exists at all.

        assert!(
            lookup_materialized_generation(&conn, "g", "pre-migration.txt").unwrap().is_none(),
            "a row with no fence row at all must be unusable"
        );
        assert!(
            lookup_materialized_generation_diagnostic(&conn, "g", "pre-migration.txt")
                .unwrap()
                .is_some(),
            "the diagnostic accessor must still see the raw pre-migration row"
        );
    }

    /// Bumping the fence invalidates a row for
    /// `lookup_materialized_generation` (covered elsewhere) but must not
    /// mutate the row's own content -- causal basis, kind, version, hash
    /// all survive unchanged, visible via the diagnostic accessor.
    #[test]
    fn bumping_the_fence_leaves_the_proof_rows_own_content_untouched() {
        let conn = open();
        let version = VersionHash([7; 32]);
        let identity = sample_identity();
        record_materialized_generation(
            &conn,
            "g",
            "a.txt",
            &[h(3), h(4)],
            MaterializedObjectKind::RegularFile,
            Some(&version),
            Some(&identity),
            1000,
        )
        .unwrap();
        let before =
            lookup_materialized_generation_diagnostic(&conn, "g", "a.txt").unwrap().unwrap();

        bump_mutation_fence(&conn, "g", "a.txt", "some-other-mutator", 2000).unwrap();

        let after =
            lookup_materialized_generation_diagnostic(&conn, "g", "a.txt").unwrap().unwrap();
        assert_eq!(before, after, "a fence bump must not mutate the proof row's own content");
        assert_eq!(after.object_kind, MaterializedObjectKind::RegularFile);
        assert_eq!(after.version, Some(version));
        assert_eq!(after.filesystem_identity, Some(identity));
    }

    /// The "no row yet" variant: a first-time materialization attempt's
    /// evidence (fence bumped once, never
    /// published) is rejected on the fence alone once an independent
    /// mutator bumps past it -- even though NO `path_materialized_
    /// generations` row has ever existed for this path, so there is
    /// nothing for the rejection to compare against or invalidate except
    /// the fence table itself. Distinguishes from `publish_if_fence_
    /// current_is_rejected_once_an_independent_mutator_has_bumped_it`
    /// (which already proves the identical mechanism) only by also
    /// asserting the diagnostic accessor sees NO row at all -- not even a
    /// stale one -- proving the fence exists independently of the proof
    /// row's own lifecycle.
    #[test]
    fn stale_first_publication_is_rejected_when_no_proof_row_existed_yet() {
        let conn = open();
        let first_attempt_epoch =
            bump_mutation_fence(&conn, "g", "c.txt", "materialize", 1000).unwrap();
        bump_mutation_fence(&conn, "g", "c.txt", "independent-mutator", 1500).unwrap();

        let published = publish_materialized_generation_if_fence_current(
            &conn,
            "g",
            "c.txt",
            &[h(5)],
            MaterializedObjectKind::RegularFile,
            None,
            None,
            first_attempt_epoch,
            2000,
        )
        .unwrap();

        assert!(
            published.is_none(),
            "a stale first publication must be rejected on the fence alone"
        );
        assert!(lookup_materialized_generation(&conn, "g", "c.txt").unwrap().is_none());
        assert!(
            lookup_materialized_generation_diagnostic(&conn, "g", "c.txt").unwrap().is_none(),
            "no row of any kind -- not even a stale one -- may ever be created by a rejected \
             first publication"
        );
    }
}
