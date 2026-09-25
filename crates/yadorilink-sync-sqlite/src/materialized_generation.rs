//! `path_materialized_generations`: the durable record of what the engine
//! believes the disk currently reflects for a path, kept separate from
//! what the change DAG resolves that path to (`DiskGenerationBasis`). This
//! module is deliberately narrow: it records and reads one row per
//! `(group_id, path)`. Nothing here decides *when* a generation should
//! change -- that is a caller's job, restated here because it is easy to
//! get backwards: a new admission (desired state) must never touch this
//! table; a row here changes only after a filesystem placement has been
//! observed committed and durably recorded. # Immutability A generation's
//! causal basis is fixed for its lifetime: if the frontier a path reflects
//! moves, that is a *new* generation, never an edit to the old one's
//! basis. This module has exactly one write entry point,
//! [`record_materialized_generation`], and it always replaces every column
//! together under a freshly minted [`GenerationId`] -- there is no "update
//! just the basis" function to reach for by mistake. Basis membership
//! itself is even more strongly protected: interned causal bases
//! (`crate::dag_store::causal_basis`) are never mutated once written, only
//! ever referenced by a new row. # Absence is a generation too A path with
//! nothing on disk is not "no row" -- it is a row whose `object_kind` is
//! [`MaterializedObjectKind::Absent`], `version` is `None`, and
//! `filesystem_identity` is `None`. The basis is still the frontier whose
//! resolution produced that absence (a tombstone or a move-away).
//! [`record_materialized_generation`] does not special-case this: an
//! absent generation is written through the exact same call as a present
//! one, with `object_kind: Absent`, so there is no separate path to forget
//! to handle it on. The module lives alongside `dag_store` in this crate so
//! both can share one transaction.

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
            -- The filesystem-side fence value this row's publisher observed
            -- when it wrote. `lookup_materialized_generation` trusts a row
            -- only while this still equals the path's CURRENT fence.
            published_under_mutation_generation INTEGER,
            PRIMARY KEY (group_id, path)
        );

        -- The filesystem-side fence, independent
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

/// Advances `(group_id, path)`'s fence for the sole purpose of making
/// every proof already published for it unusable, and returns the new
/// value -- or `None` when the path has no fence row, in which case there
/// was nothing to invalidate.
///
/// For a writer that has just changed what the path means WITHOUT being
/// able to say what is on disk now: an adopted new version whose content
/// nobody verified, a tombstone written without revalidating absence. It
/// is the honest counterpart of [`adopt_observed_actual_generation_in_tx`]
/// -- that one mints an epoch and publishes a proof under it; this one
/// mints an epoch and publishes nothing, so
/// [`lookup_materialized_generation`]'s join stops matching the row that
/// is already there. The old proof is not deleted: it stays readable
/// through [`lookup_materialized_generation_diagnostic`] as the record of
/// what this device last believed, which is exactly the distinction those
/// two readers exist to draw.
///
/// Deliberately an `UPDATE` with no `INSERT` fallback, unlike
/// [`bump_mutation_fence`] and [`snapshot_mutation_fence`]. A path with no
/// fence row can have no usable generation either -- the lookup's join
/// requires both -- so creating one here would write a row per path on
/// the hot local-capture path to invalidate something that cannot exist.
pub fn invalidate_published_generations(
    conn: &Connection,
    group_id: &str,
    path: &str,
    mutation_kind: &str,
    now_unix_nanos: i64,
) -> Result<Option<i64>, SyncSqliteError> {
    advance_existing_fence(conn, group_id, path, mutation_kind, now_unix_nanos)
}

/// Retires the materialized basis of every path a local emission just
/// wrote, in the emission's own transaction (`conn` is that transaction).
///
/// The emission has moved each path past whatever basis it held, and
/// nothing at the emission knows what is on disk for it now. A basis left
/// standing would still read as current, and a later local edit of the path
/// would be parented on it -- beside the new change instead of on it, so one
/// author would hold two heads of one path. So each path's fence advances
/// and nothing is published, exactly as [`invalidate_published_generations`]
/// does for one path; a caller that did observe the result publishes a fresh
/// proof afterwards, in the same transaction, whose basis contains the
/// change.
///
/// The per-path sibling of [`forget_group_materialized_generations`]: the
/// emission knows exactly which paths moved, so it retires those and keeps
/// every other path's proof.
pub fn retire_bases_after_local_emission(
    conn: &Connection,
    group_id: &str,
    paths: &[&str],
    now_unix_nanos: i64,
) -> Result<(), SyncSqliteError> {
    for path in paths {
        advance_existing_fence(conn, group_id, path, "local-emission", now_unix_nanos)?;
    }
    Ok(())
}

/// The fence advance behind [`invalidate_published_generations`] and
/// [`retire_bases_after_local_emission`]; see the former for why there is
/// no `INSERT` fallback.
fn advance_existing_fence(
    conn: &Connection,
    group_id: &str,
    path: &str,
    mutation_kind: &str,
    now_unix_nanos: i64,
) -> Result<Option<i64>, SyncSqliteError> {
    conn.query_row(
        "UPDATE path_actual_mutation_fences
            SET mutation_generation = mutation_generation + 1,
                last_mutation_kind = ?3,
                last_mutation_at = ?4
          WHERE group_id = ?1 AND path = ?2
         RETURNING mutation_generation",
        rusqlite::params![group_id, path, mutation_kind, now_unix_nanos],
        |r| r.get(0),
    )
    .optional()
    .map_err(SyncSqliteError::from)
}

/// Drops every published generation of `group_id` and advances every one
/// of its fences, for a writer that has just removed or replaced history
/// those generations' causal bases may name -- a prune, or a base install.
///
/// A generation's basis is what a local edit of its path is parented on,
/// so a basis naming a change the group no longer holds must not read as
/// current. The rows are deleted outright rather than merely fenced off:
/// what they name is gone, so they are not even a useful record of what
/// this device last believed. The fences are advanced as well because a
/// physical writer may be in flight with an epoch captured before this
/// transaction and a basis resolved before it; its compare-and-set must
/// fail rather than publish that basis afterwards. Fence rows themselves
/// are kept -- a fence only ever moves forward.
///
/// Group-wide rather than per basis: after a prune almost every recorded
/// basis predates the checkpoint, and an in-flight writer's basis is not
/// visible here to be checked at all.
pub fn forget_group_materialized_generations(
    conn: &Connection,
    group_id: &str,
    mutation_kind: &str,
    now_unix_nanos: i64,
) -> Result<(), SyncSqliteError> {
    conn.execute(
        "UPDATE path_actual_mutation_fences
            SET mutation_generation = mutation_generation + 1,
                last_mutation_kind = ?2,
                last_mutation_at = ?3
          WHERE group_id = ?1",
        rusqlite::params![group_id, mutation_kind, now_unix_nanos],
    )?;
    conn.execute("DELETE FROM path_materialized_generations WHERE group_id = ?1", [group_id])?;
    Ok(())
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
    /// An explicit directory: a replicated Directory entry, with a version.
    Directory,
    Symlink,
    Absent,
    /// A directory that exists only to hold live descendants. It is not a
    /// replicated entry, so it has no version: the only thing it can match
    /// is "a directory is required here and none is explicit".
    StructuralDirectory,
}

impl MaterializedObjectKind {
    fn as_db_str(self) -> &'static str {
        match self {
            MaterializedObjectKind::RegularFile => "regular_file",
            MaterializedObjectKind::Directory => "directory",
            MaterializedObjectKind::Symlink => "symlink",
            MaterializedObjectKind::Absent => "absent",
            MaterializedObjectKind::StructuralDirectory => "structural_directory",
        }
    }

    fn from_db_str(value: &str) -> Result<MaterializedObjectKind, SyncSqliteError> {
        match value {
            "regular_file" => Ok(MaterializedObjectKind::RegularFile),
            "directory" => Ok(MaterializedObjectKind::Directory),
            "symlink" => Ok(MaterializedObjectKind::Symlink),
            "absent" => Ok(MaterializedObjectKind::Absent),
            "structural_directory" => Ok(MaterializedObjectKind::StructuralDirectory),
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
        MaterializedObjectKind::StructuralDirectory => 4,
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
/// An UNCONDITIONAL write, with no production caller left: every one is a
/// test that wants a generation row to exist without modelling the epoch
/// it would have been published under. It stamps the row with
/// [`snapshot_mutation_fence`]'s current value automatically, so
/// [`lookup_materialized_generation`] trusts it immediately after this
/// call -- and, correctly, no longer once anything else bumps the fence
/// for this path.
///
/// It is deliberately not the API a real mutation publishes through, and
/// cannot become one: it can never fail a staleness check, by
/// construction, so a writer using it would overwrite whatever a
/// concurrent mutator had established. The two real lanes are
/// [`publish_materialized_generation_if_fence_current`], which CASes
/// against a specific PRE-CAPTURED epoch (wrapped by
/// [`crate::exact_materialized_commit::commit_internal_materialized_state_
/// if_fence_current`], which is what a physical writer should actually
/// call), and [`adopt_observed_actual_generation_in_tx`], for a state
/// someone else wrote that this device has just observed.
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

/// CAS-publish for a real physical mutation: writes the
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
    // Neither versionless kind can carry a version: that would be a proof
    // of a replicated entry for a path whose state names none.
    if matches!(
        object_kind,
        MaterializedObjectKind::Absent | MaterializedObjectKind::StructuralDirectory
    ) && version.is_some()
    {
        return Err(SyncSqliteError::InvalidInput(format!(
            "a {} generation for {group_id}/{path} cannot carry a version",
            object_kind.as_db_str()
        )));
    }
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
/// three cases are indistinguishable to a caller, and deliberately so:
/// "unknown is not absent" -- a caller must never be able to tell "no data"
/// apart from "stale data" and be tempted to treat the latter as good
/// enough. The guarantee is the join predicate itself, so every reader gets
/// it without needing to know the mutation fence exists.
/// [`lookup_materialized_generation_diagnostic`] is the escape hatch for
/// tooling that specifically wants to see a stale row anyway.
///
/// A present object with no `version_hash` is treated as absent here for
/// the same reason (a structural directory aside: it has no version to
/// carry). Producers can no longer write one -- the adoption and
/// internal-commit APIs both take the version by value -- but rows written
/// before that are still in existing databases, and such a row is worse
/// than no row: `resolved_path_state_hash` encodes version presence, so it
/// matches no desired resolution and can settle nothing, while reading back
/// as a healthy proof to anything that only checks for one. Returning it as
/// absent puts those paths back on the repair and rehydrate paths that can
/// actually fix them.
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
                AND g.published_under_mutation_generation = f.mutation_generation \
                AND (g.object_kind IN (?3, ?4) OR g.version_hash IS NOT NULL)",
            rusqlite::params![
                group_id,
                path,
                MaterializedObjectKind::Absent.as_db_str(),
                MaterializedObjectKind::StructuralDirectory.as_db_str()
            ],
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
/// fresh DAG admission yet, or an external writer that never took this
/// daemon's path lock at all -- **not** what closes the ABA gap (the fence
/// CAS already does that structurally). `IdentityComparison::
/// Ambiguous` is reachable in ordinary conditions (a coarse volume clock),
/// so relying on this check alone for correctness would be probabilistic;
/// treat it as an additional, optional safety net a caller may apply, not
/// a required step the fence CAS's own guarantee depends on.
///
/// Confirms on the object's identity AND on its metadata token (see the
/// body): "the same object" is not the same claim as "the same object,
/// untouched", and it is the second one a caller skipping physical work
/// depends on.
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
    revalidate_identity_against_projected_disk(
        basis,
        out_path,
        birth_time_granularity,
        ProjectedAtPath::NoStructuralDirectory,
    )
}

/// What the namespace projection places at a path beyond the path's own
/// explicit state, as far as revalidating an `Absent` basis cares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectedAtPath {
    /// Nothing: an explicitly absent path is absent on disk too.
    NoStructuralDirectory,
    /// A structural directory: the path has no explicit entry, but live
    /// descendants need it as their container.
    StructuralDirectory,
}

/// [`revalidate_identity_against_disk`] for a caller that knows what the
/// namespace projection places at the path.
///
/// An `Absent` basis says the path has no explicit entry. When the
/// projection holds a structural directory there, a directory on disk is
/// exactly what that state looks like, not a contradiction of it: the basis
/// is confirmed. Only a real directory counts -- a symlink to one, a file,
/// or an unobservable path is still a mismatch. Every other basis is
/// revalidated exactly as [`revalidate_identity_against_disk`] does.
pub fn revalidate_identity_against_projected_disk(
    basis: &DiskGenerationBasis,
    out_path: &std::path::Path,
    birth_time_granularity: yadorilink_root_authority::fs_identity::TimestampGranularity,
    projected: ProjectedAtPath,
) -> IdentityRevalidation {
    if basis.object_kind == MaterializedObjectKind::Absent {
        return match std::fs::symlink_metadata(out_path) {
            // Genuinely still absent: `basis`'s claim still holds.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => IdentityRevalidation::Confirmed,
            // Explicitly absent, physically the structural container the
            // projection requires.
            Ok(metadata)
                if metadata.is_dir() && projected == ProjectedAtPath::StructuralDirectory =>
            {
                IdentityRevalidation::Confirmed
            }
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
    // Same object is necessary and NOT sufficient. `compare` asks whether
    // two observations name the same object, which an in-place overwrite
    // does not change: the inode is the same inode, and a writer that
    // restores the mtime leaves every field `compare` consults agreeing
    // while the bytes the basis vouches for are gone. A basis that
    // revalidates in that state does not merely go stale, it stays usable
    // and authorizes skipping physical work for content that is not there.
    //
    // `metadata_fingerprint` is the token that separates the two
    // questions. It digests the tracked metadata subset, which on Unix
    // includes ctime -- moved by every write and restorable by no
    // userspace API, unlike mtime. Requiring it to match as well turns
    // this from "still the same object" into "still the same object, and
    // nothing has touched it since the basis was recorded", which is the
    // claim a zero-work close actually rests on.
    //
    // Fail-closed by construction: a fingerprint mismatch is a mismatch,
    // never an ambiguity to resolve in the caller's favour. The cost of a
    // false mismatch is real physical work, which is always safe; the cost
    // of a false match is the wrong bytes left on disk with nothing left
    // that would notice.
    if observed.metadata_fingerprint != expected.metadata_fingerprint {
        return IdentityRevalidation::NotAMatch;
    }
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
mod tests;
