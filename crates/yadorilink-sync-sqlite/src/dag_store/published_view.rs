//! Storage-layer half of the publication invariant:
//! `ExternallyObservable(change) ⇒ HasValidAuthorizationEvidence(change)`.
//!
//! This module does not verify anything cryptographically — that lives in
//! `yadorilink-daemon::authorization_checkpoint::verify_change_admission`,
//! a crate this one cannot depend on (the dependency runs the other way),
//! exactly the same layering `admit_change` already has with a Change's
//! own signature: this crate stores what it is given and trusts the
//! caller verified it first.
//!
//! What this module owns is making publication status itself a DERIVED
//! FACT rather than a second variable sitting next to the real one:
//! there is no `pending`/`published` column anywhere on `changes`. A
//! Change is published if and only if a `change_authorization` row exists
//! for it — attaching evidence and becoming externally visible are the
//! SAME write, not two writes that could desync. This is deliberate: "the
//! same fact represented in two places, only one of which gets updated"
//! is a failure class this module makes structurally impossible for
//! publication status, not just discouraged by convention.
//!
//! Callers (`yadorilink-daemon`) MUST call
//! `verify_change_admission` before calling
//! [`attach_authorization_evidence`]. This module has no way to check
//! that they did, the same way `admit_change` has no way to check a
//! `Change`'s signature was already verified by its own caller.
//!
//! The raw readers (`frontier_index::group_heads`,
//! `retained_history_integrity::get_encoded`, and
//! `frontier_index::set_device_frontier`) are publication-unaware by
//! design and expose every admitted Change; any path that makes content
//! externally observable (outbound serving, block-serving authorization,
//! re-bootstrap snapshots) reads through the `published_*` functions
//! here instead.

use rusqlite::{Connection, OptionalExtension};

use super::retained_history_integrity::hash_from_blob;
use crate::error::SyncSqliteError;
use yadorilink_replica_domain::ids::ChangeHash;

/// Whether `change_hash` has authorization evidence attached — the SOLE
/// definition of "published" under this design. Absence means Pending,
/// regardless of how long ago the Change was admitted.
pub fn is_published(conn: &Connection, change_hash: &ChangeHash) -> Result<bool, SyncSqliteError> {
    let present: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM change_authorization WHERE change_hash = ?1",
            [&change_hash.0[..]],
            |r| r.get(0),
        )
        .optional()?;
    Ok(present.is_some())
}

/// One remotely-received Change's already-verified evidence, ready to
/// attach in the SAME transaction as its DAG admission -- see
/// `dag_store::admit_change`'s own doc comment for why this is a
/// parameter to that function rather than a separate call the receive
/// path makes afterward: a remote Change must never be observably
/// admitted-but-not-yet-published, even for the instant between two
/// separate transactions, since a crash in that instant would strand it
/// exactly as Pending -- indistinguishable from a genuinely local,
/// not-yet-checkpointed edit, an ambiguity admission must never create.
pub struct PublishedEvidence<'a> {
    pub checkpoint_hash: [u8; 32],
    pub checkpoint_seq: u64,
    /// `authorization_checkpoint::canonical_signing_bytes`'s exact output
    /// -- only actually written if this checkpoint isn't already known
    /// locally; harmlessly re-verified-identical via
    /// `attach_authorization_evidence`'s own idempotency check otherwise.
    pub checkpoint_encoded: &'a [u8],
    pub checkpoint_signature: &'a [u8],
    pub author_signing_public_key: [u8; 32],
    /// This one Change's own opaque Merkle-proof bytes (`authorization_
    /// checkpoint::encode_merkle_proof`'s output).
    pub merkle_proof_encoded: Vec<u8>,
}

/// Atomically attaches one checkpoint's authorization evidence to every
/// Change in `entries` it covers.
///
/// `checkpoint_hash` identifies the checkpoint (callers compute this
/// themselves — e.g. SHA-256 of the checkpoint's canonical signing bytes
/// plus signature — so the SAME checkpoint arriving via two different
/// peers, or covering Changes attached in two separate calls, is
/// recognized as one row via `INSERT OR IGNORE`, never duplicated).
/// `checkpoint_encoded`/`checkpoint_signature` are stored opaquely; this
/// module does not decode them. `entries` need not be the checkpoint's
/// FULL batch — a receiver only attaches evidence for the Changes it
/// actually holds.
///
/// One transaction: the checkpoint row and every `change_authorization`
/// row commit together, or none do. This is what rules out both crash
/// cases — "checkpoint persisted, evidence
/// rows not" and "evidence rows claim a checkpoint that never landed" —
/// as states this function has to separately guard against: a single
/// committed SQLite transaction cannot produce either.
///
/// The `change_authorization_requires_checkpoint`/
/// `authorization_checkpoints_protect_referenced` triggers (schema, in
/// `dag_store/mod.rs`) enforce the referential link between these two
/// tables independent of this function and independent of any
/// connection's `PRAGMA foreign_keys` setting — an earlier revision
/// tried a `REFERENCES` constraint gated by turning that pragma on here,
/// which does not actually scope to this call: `foreign_keys` is a
/// per-connection setting that, once turned on, stays on for that
/// connection's remaining lifetime (past this function returning), and
/// backstops nothing on a DIFFERENT connection that never turned it on.
/// A trigger fires unconditionally on every connection regardless of any
/// pragma, which is what an invariant these two tables must always hold
/// actually requires.
///
/// Idempotency is content-aware, not merely presence-aware: re-attaching
/// the exact same checkpoint (byte-identical `group_id`/`device_id`/
/// `checkpoint_seq`/`encoded`/`signature` for an already-known
/// `checkpoint_hash`) is a no-op, matching the rule that "a later
/// revocation cannot retroactively invalidate an already-issued
/// checkpoint." A DIFFERENT payload arriving under an already-used
/// `checkpoint_hash` is `SyncSqliteError::CorruptState`, not silently
/// ignored — `checkpoint_hash` is meant to be a content hash the caller
/// computes, so this should never legitimately happen; if it does, that
/// is a hash collision, a caller bug, or tampering, and none of those
/// should resolve to quietly keeping whichever payload happened to
/// arrive first. Same reasoning for `change_authorization`: an already-
/// published Change re-attached under a DIFFERENT `checkpoint_hash` or
/// `merkle_proof` is `CorruptState`, never a silent overwrite or a
/// silent no-op that hides the mismatch.
pub fn attach_authorization_evidence(
    conn: &Connection,
    checkpoint_hash: &[u8; 32],
    group_id: &str,
    device_id: &str,
    checkpoint_seq: u64,
    checkpoint_encoded: &[u8],
    checkpoint_signature: &[u8],
    author_signing_public_key: &[u8; 32],
    entries: &[(ChangeHash, Vec<u8>)],
) -> Result<(), SyncSqliteError> {
    let tx = conn.unchecked_transaction()?;
    attach_authorization_evidence_on_conn(
        &tx,
        checkpoint_hash,
        group_id,
        device_id,
        checkpoint_seq,
        checkpoint_encoded,
        checkpoint_signature,
        author_signing_public_key,
        entries,
    )?;
    tx.commit()?;
    Ok(())
}

/// [`attach_authorization_evidence`]'s body, taking a plain `&Connection`
/// (no transaction of its own) so a caller that is ALREADY inside one
/// outer transaction -- `dag_store::admit_change`, admitting a remotely-
/// received Change and its evidence atomically -- can call this without
/// SQLite rejecting a nested `BEGIN`. The public function above is this
/// plus its own transaction, for a caller (local checkpoint flush) that
/// has nothing else to enlist it in.
pub(crate) fn attach_authorization_evidence_on_conn(
    conn: &Connection,
    checkpoint_hash: &[u8; 32],
    group_id: &str,
    device_id: &str,
    checkpoint_seq: u64,
    checkpoint_encoded: &[u8],
    checkpoint_signature: &[u8],
    author_signing_public_key: &[u8; 32],
    entries: &[(ChangeHash, Vec<u8>)],
) -> Result<(), SyncSqliteError> {
    let tx = conn;

    let existing_checkpoint: Option<(String, String, i64, Vec<u8>, Vec<u8>, Vec<u8>)> = tx
        .query_row(
            "SELECT group_id, device_id, checkpoint_seq, encoded, signature, \
             author_signing_public_key FROM authorization_checkpoints WHERE checkpoint_hash = ?1",
            [&checkpoint_hash[..]],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
        )
        .optional()?;
    match existing_checkpoint {
        None => {
            tx.execute(
                "INSERT INTO authorization_checkpoints \
                 (checkpoint_hash, group_id, device_id, checkpoint_seq, encoded, signature, \
                  author_signing_public_key) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                rusqlite::params![
                    &checkpoint_hash[..],
                    group_id,
                    device_id,
                    checkpoint_seq as i64,
                    checkpoint_encoded,
                    checkpoint_signature,
                    &author_signing_public_key[..],
                ],
            )?;
        }
        Some((g, d, seq, enc, sig, key)) => {
            let identical = g == group_id
                && d == device_id
                && seq == checkpoint_seq as i64
                && enc == checkpoint_encoded
                && sig == checkpoint_signature
                && key == author_signing_public_key;
            if !identical {
                return Err(SyncSqliteError::CorruptState(format!(
                    "authorization_checkpoints already has a DIFFERENT payload for \
                     checkpoint_hash {checkpoint_hash:x?} -- refusing to silently pick a winner"
                )));
            }
        }
    }

    for (change_hash, proof_encoded) in entries {
        let existing_evidence: Option<(Vec<u8>, Vec<u8>)> = tx
            .query_row(
                "SELECT checkpoint_hash, merkle_proof FROM change_authorization \
                 WHERE change_hash = ?1",
                [&change_hash.0[..]],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        match existing_evidence {
            None => {
                tx.execute(
                    "INSERT INTO change_authorization \
                     (change_hash, checkpoint_hash, merkle_proof) VALUES (?1, ?2, ?3)",
                    rusqlite::params![&change_hash.0[..], &checkpoint_hash[..], proof_encoded],
                )?;
            }
            Some((existing_checkpoint_hash, existing_proof)) => {
                let identical =
                    existing_checkpoint_hash == checkpoint_hash && existing_proof == *proof_encoded;
                if !identical {
                    return Err(SyncSqliteError::CorruptState(format!(
                        "change_authorization already has DIFFERENT evidence for change_hash \
                         {change_hash:?} -- refusing to silently overwrite published evidence"
                    )));
                }
            }
        }
    }
    Ok(())
}

/// One published Change's evidence reference: which checkpoint covers it,
/// and its own Merkle inclusion proof (opaque bytes -- see
/// [`attach_authorization_evidence`]'s own doc comment on why this module
/// never decodes them). `None` if `change_hash` is not published.
pub fn change_evidence(
    conn: &Connection,
    change_hash: &ChangeHash,
) -> Result<Option<([u8; 32], Vec<u8>)>, SyncSqliteError> {
    let row: Option<(Vec<u8>, Vec<u8>)> = conn
        .query_row(
            "SELECT checkpoint_hash, merkle_proof FROM change_authorization WHERE change_hash = ?1",
            [&change_hash.0[..]],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let Some((checkpoint_hash, merkle_proof)) = row else { return Ok(None) };
    let checkpoint_hash: [u8; 32] = checkpoint_hash
        .try_into()
        .map_err(|_| SyncSqliteError::CorruptState("checkpoint_hash is not 32 bytes".into()))?;
    Ok(Some((checkpoint_hash, merkle_proof)))
}

/// One checkpoint's full self-contained envelope, as stored by
/// [`attach_authorization_evidence`] -- everything a peer needs to carry
/// this checkpoint on the wire (`AuthorizationCheckpointEnvelope` in
/// `sync.proto`): the canonical signing bytes, the authority signature,
/// and the author's raw public key. `None` if `checkpoint_hash` is
/// unknown.
pub fn checkpoint_envelope(
    conn: &Connection,
    checkpoint_hash: &[u8; 32],
) -> Result<Option<(Vec<u8>, Vec<u8>, [u8; 32])>, SyncSqliteError> {
    let row: Option<(Vec<u8>, Vec<u8>, Vec<u8>)> = conn
        .query_row(
            "SELECT encoded, signature, author_signing_public_key \
             FROM authorization_checkpoints WHERE checkpoint_hash = ?1",
            [&checkpoint_hash[..]],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    let Some((encoded, signature, author_key)) = row else { return Ok(None) };
    let author_key: [u8; 32] = author_key.try_into().map_err(|_| {
        SyncSqliteError::CorruptState("author_signing_public_key is not 32 bytes".into())
    })?;
    Ok(Some((encoded, signature, author_key)))
}

/// The published subgraph's heads: a published Change with no PUBLISHED
/// child. Mirrors `frontier_index::repair`'s "leaf = admitted change with
/// no admitted child" shape exactly, restricted to the published subset.
///
/// The child-side join through `change_authorization` (`ca2`) is the part
/// a naive "just filter the existing `group_heads` table by a pending
/// flag" implementation would get wrong: an UNPUBLISHED child must never
/// make its published parent stop counting as a published head, because
/// from a receiver's point of view that child does not exist yet. Filter
/// the *table* instead of recomputing the frontier within the published
/// subgraph and a published change with only unpublished children would
/// vanish from `published_group_heads` entirely — neither the true head
/// (already excluded, wrongly, for having a child at all) nor the correct
/// answer (it IS the frontier of what a receiver may see).
pub fn published_group_heads(
    conn: &Connection,
    group_id: &str,
) -> Result<Vec<ChangeHash>, SyncSqliteError> {
    let mut stmt = conn.prepare(
        "SELECT c.change_hash FROM changes c \
         JOIN change_authorization ca ON ca.change_hash = c.change_hash \
         WHERE c.group_id = ?1 \
         AND NOT EXISTS ( \
             SELECT 1 FROM change_parents cp \
             JOIN change_authorization ca2 ON ca2.change_hash = cp.child_hash \
             WHERE cp.parent_hash = c.change_hash) \
         ORDER BY c.change_hash",
    )?;
    let rows = stmt.query_map([group_id], |r| r.get::<_, Vec<u8>>(0))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(hash_from_blob(row?)?);
    }
    Ok(out)
}

/// `retained_history_integrity::get_encoded`, gated on publication —
/// `None` for an admitted-but-Pending Change exactly as if it did not
/// exist at all, which is the property that actually matters: a device
/// asking "give me this Change's bytes" through this function can never
/// distinguish "never admitted" from "admitted but not yet published."
pub fn published_encoded_change(
    conn: &Connection,
    change_hash: &ChangeHash,
) -> Result<Option<Vec<u8>>, SyncSqliteError> {
    Ok(conn
        .query_row(
            "SELECT c.encoded FROM changes c \
             JOIN change_authorization ca ON ca.change_hash = c.change_hash \
             WHERE c.change_hash = ?1",
            [&change_hash.0[..]],
            |r| r.get(0),
        )
        .optional()?)
}

/// [`published_encoded_change`], decoded. `None` for the same two cases
/// `published_encoded_change` already collapses into one (never admitted,
/// or admitted but still Pending) -- a caller building outbound wire
/// content from this can never distinguish them, which is exactly the
/// property the publication invariant requires.
pub fn published_change(
    conn: &Connection,
    change_hash: &ChangeHash,
) -> Result<Option<yadorilink_replica_domain::change::Change>, SyncSqliteError> {
    match published_encoded_change(conn, change_hash)? {
        Some(bytes) => {
            Ok(Some(yadorilink_replica_domain::change::Change::from_wire_bytes(&bytes).map_err(
                |error| {
                    SyncSqliteError::CorruptState(format!("published change is corrupt: {error}"))
                },
            )?))
        }
        None => Ok(None),
    }
}

/// The published view of `file_index::FileIndexRepository::get_file`.
///
/// `get_file` returns the `state = 'current'` row for `(group, path)`
/// unconditionally — but "current" is a materialization/versioning
/// concept, not an authorization one. If the current row's own authoring
/// Change is Pending, `get_file`'s answer describes content that must not
/// be externally observable at all. The correct published answer
/// is not `None` in that case either — a receiver should see whatever
/// the LATEST version at this path was among the ones actually backed by
/// published authorization, which may be an OLDER, `superseded` row:
///
/// ```text
/// v1 = published  (version_seq 1)
/// v2 = pending     (version_seq 2, files.state = 'current')
/// published_file_at_path(...) -> v1, not None and not v2
/// ```
///
/// Implemented as "among rows for this path whose `authoring_change_hash`
/// has evidence attached, the one with the greatest `version_seq`" —
/// deliberately NOT "the `state = 'current'` row, filtered by whether
/// it's published," which is exactly the query shape that gets the v1/v2
/// case above wrong. A row with a NULL `authoring_change_hash` (a
/// pre-authorization-model row, or one written before this column
/// existed) never matches the join and is therefore never treated as
/// published — fail closed on missing provenance, consistent with every
/// other check in this design, though this does mean any content
/// recorded before this mechanism existed reads as unpublished under this
/// function until it goes through a real checkpoint; that transition
/// cost belongs to checkpoint issuance, not something this primitive
/// should paper over.
///
/// Returns the SAME `FileRecord` type `get_file` does, so a call site
/// moves between the raw and published reads without a type change.
pub fn published_file_at_path(
    conn: &Connection,
    group_id: &str,
    path: &str,
) -> Result<Option<yadorilink_replica_domain::file::FileRecord>, SyncSqliteError> {
    let row: Option<(u64, i64, String, i64)> = conn
        .query_row(
            "SELECT f.size, f.mtime_unix_nanos, f.blocks_json, f.deleted \
             FROM files f \
             JOIN change_authorization ca ON ca.change_hash = f.authoring_change_hash \
             WHERE f.group_id = ?1 AND f.path = ?2 \
             ORDER BY f.version_seq DESC LIMIT 1",
            rusqlite::params![group_id, path],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?;
    row.map(|(size, mtime, blocks_json, deleted)| {
        crate::file_index::row_to_record(path.to_string(), size, mtime, &blocks_json, deleted)
    })
    .transpose()
}

/// The published view of `rebootstrap_store::read_snapshot_files`.
///
/// The raw function enumerates EVERY retained version-history row for a
/// group — deliberately not just `state = 'current'`, since a rebootstrap
/// snapshot needs the full retained history a fresh joiner is entitled
/// to. This is the same enumeration, restricted to rows whose
/// `authoring_change_hash` has evidence attached — a straight filter is
/// correct here (unlike [`published_file_at_path`]'s "recompute the
/// latest," since this function's job is "list every version," not "pick
/// one").
///
/// This is the read half of the re-bootstrap surface. The more important
/// half is the WRITE half: a snapshot
/// builder (`rebootstrap_store::build_compaction_snapshot`) that composes
/// its heads from [`published_group_heads`] and its files from this
/// function would never be ABLE to commit a snapshot containing Pending
/// content in the first place — a snapshot containing Pending content
/// must be impossible to commit, not merely filtered out of an
/// already-committed snapshot at serve time. `checkpoint_snapshot`'s later lookup
/// (`rebootstrap_store.rs:249`) reads an opaque, already-serialized blob
/// and cannot retroactively fix a snapshot that was built wrong; the
/// swap that matters is at snapshot CONSTRUCTION, not at its later
/// lookup.
pub fn published_snapshot_files(
    conn: &Connection,
    group_id: &str,
) -> Result<Vec<yadorilink_replica_engine::rebootstrap_snapshot::SnapshotFile>, SyncSqliteError> {
    use yadorilink_replica_engine::rebootstrap_snapshot::{SnapshotFile, SnapshotVersionState};

    let mut stmt = conn.prepare(
        "SELECT f.path, f.size, f.mtime_unix_nanos, f.blocks_json, f.deleted, \
                f.version_seq, f.state, f.origin_device_id, f.record_kind, f.symlink_target, \
                f.unix_mode, f.symlink_out_of_root, f.xattrs_json, f.authoring_change_hash \
         FROM files f \
         JOIN change_authorization ca ON ca.change_hash = f.authoring_change_hash \
         WHERE f.group_id = ?1 ORDER BY f.path, f.version_seq",
    )?;
    let rows = stmt.query_map([group_id], |row| {
        let blocks_json: String = row.get(3)?;
        let blocks: Vec<yadorilink_replica_domain::file::BlockInfo> =
            serde_json::from_str(&blocks_json).map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    3,
                    rusqlite::types::Type::Text,
                    Box::new(error),
                )
            })?;
        let state_text: String = row.get(6)?;
        let state = SnapshotVersionState::from_db_str(&state_text).ok_or_else(|| {
            rusqlite::Error::FromSqlConversionFailure(
                6,
                rusqlite::types::Type::Text,
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("unknown file version state {state_text}"),
                )),
            )
        })?;
        Ok(SnapshotFile {
            record: yadorilink_replica_domain::file::FileRecord {
                path: row.get(0)?,
                size: row.get::<_, i64>(1)? as u64,
                mtime_unix_nanos: row.get(2)?,
                blocks,
                deleted: row.get::<_, i64>(4)? != 0,
            },
            version_seq: row.get(5)?,
            state,
            origin_device_id: row.get(7)?,
            record_kind: yadorilink_replica_domain::file::RecordKind::from_db_str(
                &row.get::<_, String>(8)?,
            ),
            symlink_target: row.get(9)?,
            unix_mode: crate::file_index::decode_unix_mode_column(row.get::<_, i64>(10)?),
            symlink_out_of_root: row.get::<_, i64>(11)? != 0,
            xattrs: {
                let xattrs_json: String = row.get(12)?;
                crate::file_index::decode_xattrs_column(&xattrs_json).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        12,
                        rusqlite::types::Type::Text,
                        Box::new(error),
                    )
                })?
            },
            // NOT NULL here: the inner join above requires
            // `ca.change_hash = f.authoring_change_hash` to have matched,
            // which is impossible for a NULL `authoring_change_hash`.
            authoring_change_hash: {
                let bytes: Vec<u8> = row.get(13)?;
                let array: [u8; 32] = bytes.try_into().map_err(|_| {
                    rusqlite::Error::FromSqlConversionFailure(
                        13,
                        rusqlite::types::Type::Blob,
                        Box::new(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "authoring_change_hash is not 32 bytes",
                        )),
                    )
                })?;
                Some(ChangeHash(array))
            },
        })
    })?;
    let mut rows: Vec<SnapshotFile> = rows.collect::<Result<Vec<_>, _>>()?;
    reproject_published_current_state(&mut rows);
    Ok(rows)
}

/// Re-derives `SnapshotVersionState::Current`/`Superseded` within the
/// PUBLISHED subset, rather than trusting each row's raw `state` label.
///
/// The raw `state` column answers "is this the actual current version,"
/// which is a question about the full (Pending-inclusive) history. A
/// straight filter that keeps a published row's raw label can be wrong
/// in exactly this scenario: `v1` published and
/// raw-`superseded` (because `v2` came along and took `current`), `v2`
/// still Pending. Filtering alone returns `[v1: Superseded]` — correct
/// row count, WRONG semantics, since no observer in the published world
/// has ever seen anything newer than `v1`; it IS their current state.
///
/// Requires `rows` sorted by `(path, version_seq)` ascending, which
/// [`published_snapshot_files`]'s query already guarantees. Within each
/// path's published run, the greatest `version_seq` becomes `Current` —
/// UNLESS it is itself genuinely `Trashed`, in which case it stays
/// `Trashed`: `Trashed` is an ordering-independent terminal state (a
/// deliberate deletion, not "there is something newer"), and being the
/// greatest published `version_seq` at a path does not make a trashed
/// version un-trashed. Every other row in the run keeps `Trashed` if it
/// was already `Trashed`, otherwise becomes `Superseded` — covering the
/// "was raw-`current`, but a newer Pending version already displaced it"
/// case as well as the ordinary "was already raw-`superseded`" case
/// identically, since both must read the same way once projected into
/// the published-only world.
fn reproject_published_current_state(
    rows: &mut [yadorilink_replica_engine::rebootstrap_snapshot::SnapshotFile],
) {
    use yadorilink_replica_engine::rebootstrap_snapshot::SnapshotVersionState;

    let mut start = 0;
    while start < rows.len() {
        let mut end = start;
        while end + 1 < rows.len() && rows[end + 1].record.path == rows[start].record.path {
            end += 1;
        }
        for row in &mut rows[start..end] {
            if row.state != SnapshotVersionState::Trashed {
                row.state = SnapshotVersionState::Superseded;
            }
        }
        if rows[end].state != SnapshotVersionState::Trashed {
            rows[end].state = SnapshotVersionState::Current;
        }
        start = end + 1;
    }
}

/// The published view of
/// `serving_authorization_index::group_file_version_references_block` —
/// the codebase's own doc comment on that module calls
/// `change_file_versions` "the block-service authorization boundary,"
/// which makes this the security-critical block-serving surface, more so
/// than `published_file_at_path`. Same restriction: only a version
/// reached through a PUBLISHED authoring Change counts.
///
/// A version whose only referencing (authoring) change was compacted away
/// falls through to `pruned_published_change_versions` -- the link
/// `change_file_versions` would otherwise carry, preserved past that
/// change's own row being pruned (`commit_prune` deletes `change_file_
/// versions`/`changes` for a pruned change, but deliberately leaves its
/// `change_authorization`/`authorization_checkpoints` evidence alone, until
/// `authorization_witness_gc` collects it once nothing retained names the
/// change).
/// This is the published, evidence-backed replacement for the removed,
/// evidence-FREE `compacted_file_version_authorization` lookup: a pruned
/// version stays servable only while its authorization evidence is
/// retained.
pub fn published_group_file_version_references_block(
    conn: &Connection,
    group_id: &str,
    block_hash: &[u8],
) -> Result<bool, SyncSqliteError> {
    if versions_reference_block(
        conn,
        "SELECT DISTINCT fv.encoded \
         FROM change_file_versions cfv \
         JOIN change_authorization ca ON ca.change_hash = cfv.change_hash \
         JOIN file_versions fv ON fv.group_id = cfv.group_id \
                              AND fv.version_hash = cfv.version_hash \
         WHERE cfv.group_id = ?1",
        group_id,
        block_hash,
    )? {
        return Ok(true);
    }
    versions_reference_block(
        conn,
        "SELECT DISTINCT fv.encoded \
         FROM pruned_published_change_versions w \
         JOIN change_authorization ca ON ca.change_hash = w.authoring_change_hash \
         JOIN file_versions fv ON fv.group_id = w.group_id \
                              AND fv.version_hash = w.version_hash \
         WHERE w.group_id = ?1",
        group_id,
        block_hash,
    )
}

fn versions_reference_block(
    conn: &Connection,
    query: &str,
    group_id: &str,
    block_hash: &[u8],
) -> Result<bool, SyncSqliteError> {
    let mut stmt = conn.prepare(query)?;
    let mut rows = stmt.query([group_id])?;
    while let Some(row) = rows.next()? {
        let encoded: Vec<u8> = row.get(0)?;
        let version =
            yadorilink_replica_domain::file::FileVersion::from_canonical_encoding(&encoded)
                .map_err(|_| {
                    SyncSqliteError::CorruptState("stored file version is corrupt".into())
                })?;
        if version.blocks.iter().any(|block| block.hash.0.as_slice() == block_hash) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Filters `hashes` down to the ones that are published — the primitive
/// a future `device_frontier`/pruning caller needs to make sure it never
/// records or acts on a Pending Change's hash as acknowledgment,
/// dominance, or compaction justification. Deliberately NOT part of
/// `frontier_index::set_device_frontier` itself, whose contract stays
/// publication-unaware (pinned by
/// `device_frontier_can_be_set_from_an_unpublished_hash` below): a
/// caller that needs the published subset filters through this first.
pub fn published_heads_among(
    conn: &Connection,
    hashes: &[ChangeHash],
) -> Result<Vec<ChangeHash>, SyncSqliteError> {
    let mut out = Vec::with_capacity(hashes.len());
    for hash in hashes {
        if is_published(conn, hash)? {
            out.push(*hash);
        }
    }
    Ok(out)
}

/// Every admitted Change **authored by `device_id`** in `group_id` with
/// NO `change_authorization` row — the exact set the checkpoint-batching
/// flow builds a batch from.
///
/// Scoped to `device_id`, not the whole group: a checkpoint authorizes
/// ONE device's batch (`AuthorizationCheckpoint.device_id`, and the
/// writer check `decideCheckpointIssuance` performs is specifically
/// "is THIS device currently a writer") — a Change some other device
/// authored and this device merely admitted (received and stored) must
/// never be folded into this device's own batch, since this device
/// requesting a checkpoint for content it didn't author would bind an
/// authorization decision about itself to bytes it has no standing to
/// vouch for. Querying by `group_id` alone would silently include every
/// admitted-but-unpublished Change in the group regardless of author.
///
/// Ordered by `change_hash` so a caller building a Merkle tree from this
/// list gets a deterministic leaf order across repeated calls with the
/// same underlying set — which matters for the checkpoint request's
/// `request_id` derivation (same pending set must hash to the same id on a retry).
pub fn pending_local_changes_for_group(
    conn: &Connection,
    group_id: &str,
    device_id: &str,
) -> Result<Vec<ChangeHash>, SyncSqliteError> {
    let mut stmt = conn.prepare(
        "SELECT c.change_hash FROM changes c \
         WHERE c.group_id = ?1 AND c.device_id = ?2 \
         AND NOT EXISTS (SELECT 1 FROM change_authorization ca WHERE ca.change_hash = c.change_hash) \
         ORDER BY c.change_hash",
    )?;
    let rows =
        stmt.query_map(rusqlite::params![group_id, device_id], |r| r.get::<_, Vec<u8>>(0))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(hash_from_blob(row?)?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests;
