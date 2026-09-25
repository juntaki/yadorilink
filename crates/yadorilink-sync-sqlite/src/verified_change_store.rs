//! Proof-verified possession, separate from canonical admission.
//!
//! # The three boundaries
//!
//! ```text
//! received  ≠  verified  ≠  canonical  ≠  projected
//! ```
//!
//! This module owns the second of those. A Change that arrives from a peer
//! and passes verification in full is *possessed*: network delivery for it is
//! complete, and it must never be transferred again. Whether it has been
//! promoted into the canonical Published DAG is a separate question, answered
//! later and for different reasons — a missing parent, an unsettled local
//! capture barrier — that have nothing to do with delivery.
//!
//! Keeping those two apart is the whole point. If reconciliation membership
//! meant *canonical* admission, then a Change that was received, verified, and
//! parked waiting on a barrier would still read as missing to the peer that
//! sent it, which would send it again, and again. That is the retransmission
//! storm in a new shape. So membership is possession:
//!
//! ```text
//! servable verified set  =  staged verified objects
//!                        ∪  canonical Changes carrying authorization evidence
//! ```
//!
//! # Promotion never withdraws possession
//!
//! Promotion moves a Change from the left side of that union to the right. It
//! happens inside one transaction, so no reader on any connection can observe
//! the hash absent from both. There is no window in which a promoted Change
//! looks un-possessed and gets re-requested.
//!
//! # Same database, separate tables
//!
//! These tables live in the same SQLite database and the same transaction
//! domain as the canonical schema. The isolation wanted here is semantic, not
//! transactional: promotion has to be one atomic commit spanning both, which a
//! second database file would make impossible.
//!
//! # What is durable, and what is derived
//!
//! The only durable semantic facts are *this object is verified* and *this
//! object is (not) canonical*. There is deliberately no admission-obligation
//! table, no `WaitingForParent`/`WaitingForCapture`/`Retrying`/`Backoff`
//! status column, and no retry bookkeeping. A staged row **is** the pending
//! admission, because promotion deletes it in the same transaction that makes
//! the Change canonical. Why a particular staged Change cannot be promoted
//! right now is computed from current state every time it is asked, never
//! stored — a stored reason is a second copy of a derivable fact, and the two
//! copies drift.
//!
//! `verified_change_parents` is an index, not a truth: every row in it is
//! recoverable by decoding the corresponding `verified_change_objects.encoded`.
//! It exists so the ready-to-promote query does not have to decode the whole
//! staging area.
//!
//! # This module verifies nothing
//!
//! Exactly as with `changes.encoded` and `change_authorization`, signature,
//! checkpoint and Merkle-proof verification happen in the daemon before
//! anything here is called; this crate cannot depend on that code. What this
//! module does enforce is self-consistency it can check cheaply — that a
//! staged hash really is the hash of the bytes staged under it, that the
//! group binding agrees, and that the parent index matches the decoded
//! Change — so a caller bug cannot quietly poison the possession set.

use rusqlite::Connection;
use yadorilink_replica_domain::change::Change;
use yadorilink_replica_domain::ids::{ChangeHash, FolderGroupId};
use yadorilink_replica_domain::rebootstrap::HistoryEpoch;

use crate::dag_store;
use crate::error::SyncSqliteError;

/// A checkpoint envelope, staged alongside the Changes it authorizes.
///
/// Held in the staging area's own table rather than written straight into
/// `authorization_checkpoints`, so that staging touches no canonical table at
/// all. It is copied across at promotion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedCheckpoint {
    pub checkpoint_hash: [u8; 32],
    pub group_id: FolderGroupId,
    pub device_id: String,
    pub checkpoint_seq: u64,
    pub encoded: Vec<u8>,
    pub signature: Vec<u8>,
    pub author_signing_public_key: [u8; 32],
}

/// One fully verified Change together with the evidence that authorizes it.
#[derive(Clone, Debug)]
pub struct VerifiedChangeBundle {
    /// The Change's own signed bytes, exactly as received.
    pub encoded: Vec<u8>,
    /// The decoded form. Must decode from `encoded`.
    pub change: Change,
    /// The checkpoint this Change's authorization rests on.
    pub checkpoint: VerifiedCheckpoint,
    /// The Merkle inclusion proof binding the Change to that checkpoint.
    pub merkle_proof: Vec<u8>,
    /// Every file version this Change refers to directly.
    ///
    /// Exactly the set, neither more nor less -- see
    /// `yadorilink_replica_domain::proof_carrying::verify_carried_versions`,
    /// which is where that contract is defined and enforced.
    ///
    /// These are here because canonical admission needs them: a `Put` whose
    /// version metadata is absent cannot be installed into the DAG at all. If
    /// they had to be fetched instead, a staged Change would have a third
    /// waiting condition -- one that only more network traffic can clear --
    /// alongside "waiting for a parent" and "waiting for a capture barrier",
    /// and the boundary between *delivery complete* and *admissible* would
    /// stop being durable.
    ///
    /// Block *content* is deliberately not here. A version names block
    /// hashes; the bytes behind them travel on the block lane, which is what
    /// keeps that lane's separate flow-control domain meaningful and keeps a
    /// bundle roughly the size of the metadata the legacy `ChangeBatch`
    /// already carried.
    pub versions: Vec<yadorilink_replica_domain::file::FileVersion>,
}

impl VerifiedChangeBundle {
    pub fn change_hash(&self) -> ChangeHash {
        self.change.compute_hash()
    }
}

/// Why a bundle was refused before anything was staged.
#[derive(Debug, PartialEq, Eq)]
pub enum StagingRejection {
    /// The staged bytes do not decode to the Change presented with them.
    EncodingMismatch { change_hash: ChangeHash },
    /// The Change and its checkpoint disagree about which group they belong to.
    GroupMismatch {
        change_hash: ChangeHash,
        change_group: FolderGroupId,
        checkpoint_group: FolderGroupId,
    },
    /// Two bundles in one batch stage different bytes under one checkpoint hash.
    ConflictingCheckpoint { checkpoint_hash: [u8; 32] },
}

impl std::fmt::Display for StagingRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StagingRejection::EncodingMismatch { change_hash } => {
                write!(f, "staged bytes do not decode to the presented change {change_hash:?}")
            }
            StagingRejection::GroupMismatch { change_hash, change_group, checkpoint_group } => {
                write!(
                    f,
                    "change {change_hash:?} is bound to group {change_group:?} but its \
                     checkpoint is bound to {checkpoint_group:?}"
                )
            }
            StagingRejection::ConflictingCheckpoint { checkpoint_hash } => {
                write!(f, "one batch staged two different payloads under checkpoint {checkpoint_hash:02x?}")
            }
        }
    }
}

/// Creates the staging schema. Idempotent, like every other `init_*_schema`
/// in this crate, so it is safe to run on every open.
pub fn init_verified_change_schema(conn: &Connection) -> Result<(), SyncSqliteError> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS verified_checkpoints (
            checkpoint_hash           BLOB PRIMARY KEY,
            group_id                  TEXT NOT NULL,
            device_id                 TEXT NOT NULL,
            checkpoint_seq            INTEGER NOT NULL,
            encoded                   BLOB NOT NULL,
            signature                 BLOB NOT NULL,
            author_signing_public_key BLOB NOT NULL
        );

        CREATE TABLE IF NOT EXISTS verified_change_objects (
            change_hash            BLOB PRIMARY KEY,
            group_id               TEXT NOT NULL,
            encoded                BLOB NOT NULL,
            checkpoint_hash        BLOB NOT NULL,
            merkle_proof           BLOB NOT NULL,
            verified_at_unix_nanos INTEGER NOT NULL,
            -- The base the Change's signed `history_epoch` names, NULL for
            -- genesis: what `encoded` already says, copied out so
            -- `admissible_now` can tell a Change from another history apart
            -- without decoding the staging area.
            history_base           BLOB,
            -- The Change's signed dot and author predecessor, copied out for
            -- the same reason: so `admissible_now` can hold a Change that
            -- waits on its author's previous Change without decoding it.
            -- NULL only in a row written around `stage_verified_bundles`,
            -- which the selection then treats as not waiting on anything.
            device_id              TEXT,
            author_seq             INTEGER,
            author_prev            BLOB
        );
        CREATE INDEX IF NOT EXISTS verified_change_objects_by_group
            ON verified_change_objects(group_id);

        -- An index over what `encoded` already says, not a second source of
        -- truth. Kept so the ready-to-promote query need not decode the
        -- whole staging area on every pass.
        CREATE TABLE IF NOT EXISTS verified_change_parents (
            child_hash  BLOB NOT NULL,
            parent_hash BLOB NOT NULL,
            PRIMARY KEY (child_hash, parent_hash)
        );
        CREATE INDEX IF NOT EXISTS verified_change_parents_by_parent
            ON verified_change_parents(parent_hash);

        -- The file versions a staged Change refers to, carried with it and
        -- kept here until promotion copies them into the canonical
        -- `file_versions` table.
        --
        -- Staged separately rather than written straight into `file_versions`
        -- for the same reason the checkpoints are: staging must touch no
        -- canonical table. These rows are cryptographically safe to store
        -- early -- they are content-addressed, and the address is recomputed
        -- from the bytes -- but `file_versions` is read by retention, GC and
        -- block-liveness logic, and an early insert would mean proving what
        -- each of those does with a version no canonical Change references
        -- yet. That is a much larger question than this boundary needs to
        -- answer.
        --
        -- Keyed by version hash, not by change: two staged Changes referring
        -- to the same version store it once, and the bytes are identical by
        -- construction because the key is their hash.
        CREATE TABLE IF NOT EXISTS verified_change_versions (
            version_hash BLOB NOT NULL,
            group_id     TEXT NOT NULL,
            encoded      BLOB NOT NULL,
            PRIMARY KEY (version_hash, group_id)
        );

        -- A staged object must always name a staged checkpoint. Enforced by
        -- trigger rather than by REFERENCES + PRAGMA foreign_keys: that
        -- pragma is per-connection and, once set, stays set for that
        -- connection's whole remaining life while backstopping nothing on a
        -- different (e.g. pooled) connection. A trigger fires on every
        -- connection regardless of any pragma, which is what an invariant
        -- these tables must always hold actually requires.
        CREATE TRIGGER IF NOT EXISTS verified_change_requires_checkpoint
        BEFORE INSERT ON verified_change_objects
        FOR EACH ROW
        WHEN NOT EXISTS (
            SELECT 1 FROM verified_checkpoints
             WHERE checkpoint_hash = NEW.checkpoint_hash
        )
        BEGIN
            SELECT RAISE(ABORT, 'verified change references an unstaged checkpoint');
        END;

        CREATE TRIGGER IF NOT EXISTS verified_checkpoints_protect_referenced
        BEFORE DELETE ON verified_checkpoints
        FOR EACH ROW
        WHEN EXISTS (
            SELECT 1 FROM verified_change_objects
             WHERE checkpoint_hash = OLD.checkpoint_hash
        )
        BEGIN
            SELECT RAISE(ABORT, 'checkpoint is still referenced by a staged change');
        END;
        "#,
    )?;
    Ok(())
}

/// Durably stage a whole wire batch, or none of it.
///
/// Every bundle is decoded and structurally checked before a single row is
/// written. This is the same principle the reconciliation engine needed: a
/// peer must not be able to get a valid item at the front of a batch applied
/// by putting a malformed one behind it. A wire batch never leaves a
/// half-meaningful state behind.
///
/// Returns the hashes newly staged by this call. Redelivery is idempotent:
/// a bundle whose hash is already staged, or already canonical, is accepted
/// and does no work, so a peer repeating a Change costs a lookup rather than
/// a re-verification and a re-write.
pub fn stage_verified_bundles(
    conn: &Connection,
    bundles: &[VerifiedChangeBundle],
    now_unix_nanos: i64,
) -> Result<Vec<ChangeHash>, SyncSqliteError> {
    // The "one transaction" this function's comments rely on is checked,
    // not assumed: `&Transaction` and `&Connection` are the same type to
    // the compiler, so a caller holding no transaction at all compiled and
    // ran identically -- which is exactly what `commit_admission`'s
    // caller turned out to be doing.
    if conn.is_autocommit() {
        return Err(SyncSqliteError::CorruptState(
            "stage_verified_bundles requires an open transaction: a hash becomes servable when \
             its object row lands, so its versions must land with it or not at all"
                .to_owned(),
        ));
    }

    // --- Validate the entire batch first. Nothing is written below this. ---
    let mut checkpoints: std::collections::HashMap<[u8; 32], &VerifiedCheckpoint> =
        std::collections::HashMap::new();

    for bundle in bundles {
        let change_hash = bundle.change_hash();

        let decoded = Change::from_wire_bytes(&bundle.encoded).map_err(|error| {
            SyncSqliteError::CorruptState(format!(
                "staged bytes for {change_hash:?} do not decode: {error}"
            ))
        })?;
        if decoded.compute_hash() != change_hash {
            return Err(SyncSqliteError::CorruptState(
                StagingRejection::EncodingMismatch { change_hash }.to_string(),
            ));
        }

        if bundle.change.group_id != bundle.checkpoint.group_id {
            return Err(SyncSqliteError::CorruptState(
                StagingRejection::GroupMismatch {
                    change_hash,
                    change_group: bundle.change.group_id.clone(),
                    checkpoint_group: bundle.checkpoint.group_id.clone(),
                }
                .to_string(),
            ));
        }

        // The bundle must be self-contained: exactly the versions this
        // Change refers to, each hashing to what it claims. Enforced here as
        // well as at the wire boundary, because this function is what defines
        // possession -- a hash becomes servable when its row lands, and a row
        // that landed without its versions would advertise a Change that can
        // never be admitted and will never be re-sent.
        yadorilink_replica_domain::proof_carrying::verify_carried_versions(
            &bundle.change,
            &bundle.versions,
        )
        .map_err(|error| SyncSqliteError::CorruptState(error.to_string()))?;

        match checkpoints.get(&bundle.checkpoint.checkpoint_hash) {
            Some(seen) if **seen != bundle.checkpoint => {
                return Err(SyncSqliteError::CorruptState(
                    StagingRejection::ConflictingCheckpoint {
                        checkpoint_hash: bundle.checkpoint.checkpoint_hash,
                    }
                    .to_string(),
                ));
            }
            _ => {
                checkpoints.insert(bundle.checkpoint.checkpoint_hash, &bundle.checkpoint);
            }
        }
    }

    // --- Write. The caller owns the transaction. ---
    let mut newly_staged = Vec::new();

    for checkpoint in checkpoints.values() {
        conn.execute(
            "INSERT OR IGNORE INTO verified_checkpoints \
             (checkpoint_hash, group_id, device_id, checkpoint_seq, encoded, signature, \
              author_signing_public_key) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                &checkpoint.checkpoint_hash[..],
                checkpoint.group_id.as_str(),
                checkpoint.device_id.as_str(),
                checkpoint.checkpoint_seq as i64,
                &checkpoint.encoded,
                &checkpoint.signature,
                &checkpoint.author_signing_public_key[..],
            ],
        )?;
    }

    for bundle in bundles {
        let change_hash = bundle.change_hash();

        // Already possessed by either route: nothing to do, and in
        // particular nothing to re-verify.
        if is_canonical(conn, &change_hash)? || is_staged(conn, &change_hash)? {
            continue;
        }

        conn.execute(
            "INSERT INTO verified_change_objects \
             (change_hash, group_id, encoded, checkpoint_hash, merkle_proof, \
              verified_at_unix_nanos, history_base, device_id, author_seq, author_prev) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            rusqlite::params![
                &change_hash.0[..],
                bundle.change.group_id.as_str(),
                &bundle.encoded,
                &bundle.checkpoint.checkpoint_hash[..],
                &bundle.merkle_proof,
                now_unix_nanos,
                history_base_column(bundle.change.history_epoch),
                bundle.change.device_id.as_str(),
                bundle.change.author_seq.get() as i64,
                bundle.change.author_prev.map(|prev| prev.0),
            ],
        )?;

        // Written in the same transaction as the object row above, which is
        // what makes possession and admissibility land together. There is no
        // instant at which this hash is servable while the metadata a
        // promotion needs is still absent -- which is exactly the state that
        // would be unrecoverable, since a peer would then never send it
        // again.
        //
        // `INSERT OR IGNORE`: the key is the content hash, so an existing row
        // holds the same bytes by construction. Two Changes referring to one
        // version store it once.
        for version in &bundle.versions {
            conn.execute(
                "INSERT OR IGNORE INTO verified_change_versions (version_hash, group_id, encoded) \
                 VALUES (?1, ?2, ?3)",
                rusqlite::params![
                    &version.version_hash.0[..],
                    bundle.change.group_id.as_str(),
                    version.canonical_encoding(),
                ],
            )?;
        }

        for parent in &bundle.change.parents {
            conn.execute(
                "INSERT OR IGNORE INTO verified_change_parents (child_hash, parent_hash) \
                 VALUES (?1, ?2)",
                rusqlite::params![&change_hash.0[..], &parent.0[..]],
            )?;
        }

        newly_staged.push(change_hash);
    }

    Ok(newly_staged)
}

/// Whether this node possesses `change_hash` for reconciliation purposes.
///
/// True for a staged verified object and for a canonical Change carrying
/// authorization evidence. Promotion moves a hash from the first to the
/// second inside one transaction, so this never transiently returns `false`
/// for something already delivered.
pub fn is_servable(conn: &Connection, change_hash: &ChangeHash) -> Result<bool, SyncSqliteError> {
    Ok(is_staged(conn, change_hash)? || is_canonical(conn, change_hash)?)
}

/// Every hash this node can serve for `group`, ascending.
///
/// This is the set reconciliation compares. Disclosure to a particular peer
/// is a separate filter applied above this: a fingerprint leaks a set's
/// existence and size, so it must not be computed for a peer whose
/// entitlement to the group has not already been settled.
pub fn servable_change_hashes(
    conn: &Connection,
    group: &FolderGroupId,
) -> Result<Vec<ChangeHash>, SyncSqliteError> {
    let mut stmt = conn.prepare(
        "SELECT change_hash FROM verified_change_objects WHERE group_id = ?1 \
         UNION \
         SELECT c.change_hash FROM changes c \
           JOIN change_authorization a ON a.change_hash = c.change_hash \
          WHERE c.group_id = ?1 \
         ORDER BY 1",
    )?;
    let rows = stmt.query_map(rusqlite::params![group.as_str()], |row| row.get::<_, Vec<u8>>(0))?;

    let mut hashes = Vec::new();
    for row in rows {
        let bytes = row?;
        let mut hash = [0u8; 32];
        if bytes.len() != 32 {
            return Err(SyncSqliteError::CorruptState(format!(
                "servable set holds a {}-byte change hash",
                bytes.len()
            )));
        }
        hash.copy_from_slice(&bytes);
        hashes.push(ChangeHash(hash));
    }
    Ok(hashes)
}

/// The staged Changes of `group` that a promotion attempt can settle: those
/// on this replica's history whose parents are all canonical and whose
/// author position is decidable, those on it with a parent -- or, parents
/// all canonical, an author predecessor -- that is permanently refused here,
/// and every one written on another history.
///
/// Derived from current state on every call. There is no stored "ready" flag
/// and no stored blocking reason: a Change becomes promotable the moment its
/// last parent lands, with nothing to wake, invalidate or reconcile.
///
/// The second kind can only be refused, but nothing else would ever select
/// it: its parent will never be canonical, and a staged Change counts as
/// possessed, so no peer is asked for it again. Left out, it would sit here
/// possessed and servable for good. Its rows are preselected in SQL by the
/// refused parent's rules stamp and then confirmed one by one, since a
/// refusal that rests on another change's is current only while that one
/// is (see `dag_store::current_rejection_domain`).
pub fn admissible_now(
    conn: &Connection,
    group: &FolderGroupId,
    limit: usize,
) -> Result<Vec<ChangeHash>, SyncSqliteError> {
    let current =
        history_base_column(crate::rebootstrap_store::current_history_epoch(conn, group.as_str())?);
    // On this history with every parent canonical, and not held on its
    // author's previous Change. Held is exactly the case the author chain
    // answers with a hold rather than a verdict (see
    // `dag_store::author_chain::check_admission`): a named predecessor that
    // is neither held here nor refused here, at a sequence past the next one
    // this replica can fill. The author's recorded tip is decided here even
    // once a base has absorbed it: its position is the watermark. Every
    // other position is already decidable, so it is selected and settled
    // -- admitted, or refused with the
    // contradiction already known. A held Change left in this selection
    // would be re-planned stale on every pass, and, sorting ahead of the
    // predecessor it waits for, could fill the whole window and keep that
    // predecessor from ever being selected. A Change behind a refused
    // predecessor is held here too and left to the refused-dependency
    // selection below: only that selection confirms the rejection row is
    // current, and a row that is not -- superseded rules, or a basis now
    // held -- refuses nothing, so the author chain holds such a Change
    // exactly as if the row were absent.
    let mut ready = staged_hashes(
        conn,
        "SELECT v.change_hash, v.verified_at_unix_nanos FROM verified_change_objects v \
          WHERE v.group_id = ?1 \
            AND v.history_base IS ?3 \
            AND NOT EXISTS ( \
                  SELECT 1 FROM verified_change_parents p \
                   WHERE p.child_hash = v.change_hash \
                     AND NOT EXISTS ( \
                           SELECT 1 FROM changes c WHERE c.change_hash = p.parent_hash \
                         ) \
                ) \
            AND NOT ( \
                  v.author_prev IS NOT NULL \
                  AND NOT EXISTS ( \
                        SELECT 1 FROM changes c \
                         WHERE c.group_id = v.group_id AND c.change_hash = v.author_prev \
                      ) \
                  AND NOT EXISTS ( \
                        SELECT 1 FROM pruned_changes pc \
                         WHERE pc.group_id = v.group_id AND pc.change_hash = v.author_prev \
                      ) \
                  AND NOT EXISTS ( \
                        SELECT 1 FROM author_chain_state s \
                         WHERE s.group_id = v.group_id AND s.device_id = v.device_id \
                           AND s.tip_change_hash = v.author_prev \
                      ) \
                  AND v.author_seq > 1 + COALESCE(( \
                        SELECT s.watermark FROM author_chain_state s \
                         WHERE s.group_id = v.group_id AND s.device_id = v.device_id \
                      ), 0) \
                ) \
          ORDER BY v.verified_at_unix_nanos, v.change_hash \
          LIMIT ?2",
        rusqlite::params![group.as_str(), limit as i64, current],
        limit,
        |_| Ok(true),
    )?;

    // A Change written on another history, whatever its parents: it is
    // refused for the history it names, which its own signed bytes settle,
    // and nothing that arrives later could make it promotable. Left to the
    // parent-based selections it would never be picked if its parents are
    // absent -- and a foreign history's parents are exactly the ones that
    // never arrive here -- so it would stay staged, possessed and servable,
    // for good. Measured against the base held now, not at staging: a base
    // switch turns what was staged on the old history into foreign history.
    ready.extend(staged_hashes(
        conn,
        "SELECT v.change_hash, v.verified_at_unix_nanos FROM verified_change_objects v \
          WHERE v.group_id = ?1 \
            AND v.history_base IS NOT ?3 \
          ORDER BY v.verified_at_unix_nanos, v.change_hash \
          LIMIT ?2",
        rusqlite::params![group.as_str(), limit as i64, current],
        limit,
        |_| Ok(true),
    )?);

    let [(first_domain, first_version), (second_domain, second_version)] =
        dag_store::current_rules_stamps();
    // No SQL limit here: a row the stamp preselects can still fail the
    // confirmation below, and such a row is never consumed, since its child
    // stays staged behind a parent that is not canonical. Counted against a
    // SQL limit, enough of them sorting first would crowd out every real
    // candidate for good. Rows are read lazily and only confirmed ones count.
    ready.extend(staged_hashes(
        conn,
        "SELECT v.change_hash, v.verified_at_unix_nanos FROM verified_change_objects v \
          WHERE v.group_id = ?1 \
            AND v.history_base IS ?6 \
            AND (EXISTS ( \
                  SELECT 1 FROM verified_change_parents p \
                    JOIN rejected_changes r ON r.change_hash = p.parent_hash \
                   WHERE p.child_hash = v.change_hash \
                     AND NOT EXISTS ( \
                           SELECT 1 FROM changes c WHERE c.change_hash = p.parent_hash \
                         ) \
                     AND ((r.rejection_domain = ?2 AND r.rules_version = ?3) \
                       OR (r.rejection_domain = ?4 AND r.rules_version = ?5)) \
                ) \
              OR (NOT EXISTS ( \
                    SELECT 1 FROM verified_change_parents p \
                     WHERE p.child_hash = v.change_hash \
                       AND NOT EXISTS ( \
                             SELECT 1 FROM changes c WHERE c.change_hash = p.parent_hash \
                           ) \
                  ) \
                  AND EXISTS ( \
                    SELECT 1 FROM rejected_changes r \
                     WHERE r.change_hash = v.author_prev \
                       AND ((r.rejection_domain = ?2 AND r.rules_version = ?3) \
                         OR (r.rejection_domain = ?4 AND r.rules_version = ?5)) \
                  ))) \
          ORDER BY v.verified_at_unix_nanos, v.change_hash",
        rusqlite::params![
            group.as_str(),
            first_domain,
            first_version,
            second_domain,
            second_version,
            current
        ],
        limit,
        |hash| {
            Ok(has_currently_refused_parent(conn, group, hash)?
                || has_currently_refused_author_prev(conn, group, hash)?)
        },
    )?);

    // A Change on another history is in no other selection. Of the rest, a
    // Change whose every parent is canonical and whose author predecessor
    // is currently refused can be in both the first and the last -- the
    // first takes it when its position is decidable anyway -- so the same
    // hash is kept once.
    ready.sort_unstable_by_key(|(hash, verified_at)| (*verified_at, hash.0));
    ready.dedup_by_key(|(hash, _)| *hash);
    ready.truncate(limit);
    Ok(ready.into_iter().map(|(hash, _)| hash).collect())
}

/// The `history_base` column's value for `epoch`: the base's bytes, or NULL
/// for genesis. Compared with `IS` / `IS NOT`, which treat two NULLs as equal.
fn history_base_column(epoch: HistoryEpoch) -> Option<[u8; 32]> {
    match epoch {
        HistoryEpoch::Genesis => None,
        HistoryEpoch::Base(base) => Some(base.0),
    }
}

/// Whether the author predecessor `child` names is refused here, by the
/// test the author chain applies before refusing a Change behind it: a
/// predecessor held here, canonical or pruned, is never a refused one,
/// whatever its own row still says. Only asked of a Change whose parents are
/// all canonical, so that every Change it selects is one a promotion
/// attempt settles: the author chain is consulted only once the parents
/// are present.
fn has_currently_refused_author_prev(
    conn: &Connection,
    group: &FolderGroupId,
    child: &ChangeHash,
) -> Result<bool, SyncSqliteError> {
    let prev: Option<Vec<u8>> = conn
        .prepare_cached("SELECT author_prev FROM verified_change_objects WHERE change_hash = ?1")?
        .query_row(rusqlite::params![&child.0[..]], |row| row.get(0))?;
    let Some(prev) = prev else { return Ok(false) };
    let prev = ChangeHash(fixed32(&prev, "verified_change_objects.author_prev")?);
    Ok(!dag_store::has_change_or_pruned(conn, group.as_str(), &prev)?
        && dag_store::current_rejection_domain(conn, &prev)?.is_some())
}

/// The same test `dag_store::refuse_behind_rejected_parent` applies, so
/// every Change selected here is one a promotion attempt refuses: a parent
/// held here, canonical or pruned, is never a refused one, whatever its own
/// row still says.
fn has_currently_refused_parent(
    conn: &Connection,
    group: &FolderGroupId,
    child: &ChangeHash,
) -> Result<bool, SyncSqliteError> {
    let mut stmt = conn
        .prepare_cached("SELECT parent_hash FROM verified_change_parents WHERE child_hash = ?1")?;
    let parents = stmt
        .query_map(rusqlite::params![&child.0[..]], |row| row.get::<_, Vec<u8>>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    for parent in parents {
        let parent = ChangeHash(fixed32(&parent, "verified_change_parents.parent_hash")?);
        if !dag_store::has_change_or_pruned(conn, group.as_str(), &parent)?
            && dag_store::current_rejection_domain(conn, &parent)?.is_some()
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn staged_hashes(
    conn: &Connection,
    sql: &str,
    params: impl rusqlite::Params,
    limit: usize,
    mut keep: impl FnMut(&ChangeHash) -> Result<bool, SyncSqliteError>,
) -> Result<Vec<(ChangeHash, i64)>, SyncSqliteError> {
    let mut stmt = conn.prepare(sql)?;
    let rows =
        stmt.query_map(params, |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)))?;

    let mut hashes = Vec::new();
    for row in rows {
        if hashes.len() >= limit {
            break;
        }
        let (bytes, verified_at) = row?;
        if bytes.len() != 32 {
            return Err(SyncSqliteError::CorruptState(format!(
                "staging area holds a {}-byte change hash",
                bytes.len()
            )));
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&bytes);
        let hash = ChangeHash(hash);
        if keep(&hash)? {
            hashes.push((hash, verified_at));
        }
    }
    Ok(hashes)
}

/// The versions a servable bundle must carry, gathered from wherever this
/// device currently holds them.
///
/// Staged first, then canonical: a Change on either side of the promotion
/// boundary is served identically, so the versions have to be found on either
/// side too. Both stores are content-addressed, so "wherever" cannot change
/// what is returned -- only whether it is found.
///
/// A version that cannot be found at all is an error rather than an omission.
/// Serving a bundle short of a version would hand a peer something it must
/// reject, and it would reject it correctly; better to fail here, where the
/// cause is visible, than to make the far end diagnose it.
fn gather_versions(
    conn: &Connection,
    change: &Change,
) -> Result<Vec<yadorilink_replica_domain::file::FileVersion>, SyncSqliteError> {
    let required = yadorilink_replica_domain::proof_carrying::directly_referenced_versions(change);
    let group = change.group_id.as_str();

    let mut versions = Vec::with_capacity(required.len());
    for hash in &required {
        let encoded: Option<Vec<u8>> = conn
            .query_row(
                "SELECT encoded FROM verified_change_versions \
                  WHERE version_hash = ?1 AND group_id = ?2",
                rusqlite::params![&hash.0[..], group],
                |row| row.get(0),
            )
            .map(Some)
            .or_else(|error| match error {
                rusqlite::Error::QueryReturnedNoRows => Ok(None),
                other => Err(SyncSqliteError::from(other)),
            })?;

        let encoded = match encoded {
            Some(encoded) => encoded,
            None => conn
                .query_row(
                    "SELECT encoded FROM file_versions WHERE version_hash = ?1 AND group_id = ?2",
                    rusqlite::params![&hash.0[..], group],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .map_err(|error| match error {
                    rusqlite::Error::QueryReturnedNoRows => SyncSqliteError::NotFound(format!(
                        "cannot serve a change without the file version {hash:?} it refers to"
                    )),
                    other => SyncSqliteError::from(other),
                })?,
        };

        versions.push(
            yadorilink_replica_domain::file::FileVersion::from_canonical_encoding(&encoded)
                .map_err(|error| {
                    SyncSqliteError::CorruptState(format!(
                        "stored file version {hash:?} is corrupt: {error}"
                    ))
                })?,
        );
    }

    Ok(versions)
}

/// A staged object, decoded, ready to be planned for promotion.
pub fn load_staged(
    conn: &Connection,
    change_hash: &ChangeHash,
) -> Result<Option<VerifiedChangeBundle>, SyncSqliteError> {
    let row = conn
        .query_row(
            "SELECT o.encoded, o.merkle_proof, c.checkpoint_hash, c.group_id, c.device_id, \
                    c.checkpoint_seq, c.encoded, c.signature, c.author_signing_public_key \
               FROM verified_change_objects o \
               JOIN verified_checkpoints c ON c.checkpoint_hash = o.checkpoint_hash \
              WHERE o.change_hash = ?1",
            rusqlite::params![&change_hash.0[..]],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                    row.get::<_, Vec<u8>>(8)?,
                ))
            },
        )
        .map(Some)
        .or_else(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            other => Err(SyncSqliteError::from(other)),
        })?;

    let Some((
        encoded,
        merkle_proof,
        checkpoint_hash,
        checkpoint_group,
        device_id,
        checkpoint_seq,
        checkpoint_encoded,
        signature,
        author_key,
    )) = row
    else {
        return Ok(None);
    };

    let change = Change::from_wire_bytes(&encoded).map_err(|error| {
        SyncSqliteError::CorruptState(format!("staged change {change_hash:?} is corrupt: {error}"))
    })?;
    let change_for_versions = change.clone();

    Ok(Some(VerifiedChangeBundle {
        encoded,
        change,
        checkpoint: VerifiedCheckpoint {
            checkpoint_hash: fixed32(&checkpoint_hash, "checkpoint_hash")?,
            group_id: FolderGroupId(checkpoint_group),
            device_id,
            checkpoint_seq: checkpoint_seq as u64,
            encoded: checkpoint_encoded,
            signature,
            author_signing_public_key: fixed32(&author_key, "author_signing_public_key")?,
        },
        merkle_proof,
        versions: gather_versions(conn, &change_for_versions)?,
    }))
}

/// A servable bundle by either route: staged, or canonical with its
/// authorization evidence attached.
///
/// This is the read side of the possession union. A peer asking for a hash
/// does not know, and must not need to know, which side of the promotion
/// boundary it currently sits on: the same bytes are served either way.
pub fn load_servable(
    conn: &Connection,
    change_hash: &ChangeHash,
) -> Result<Option<VerifiedChangeBundle>, SyncSqliteError> {
    if let Some(staged) = load_staged(conn, change_hash)? {
        return Ok(Some(staged));
    }
    load_canonical(conn, change_hash)
}

/// The canonical half of [`load_servable`].
///
/// A canonical Change with no `change_authorization` row is Pending — locally
/// authored and not yet covered by a checkpoint. It is deliberately not
/// servable: without evidence there is nothing for a receiver to verify, and
/// serving it would be asking a peer to trust the carrier.
fn load_canonical(
    conn: &Connection,
    change_hash: &ChangeHash,
) -> Result<Option<VerifiedChangeBundle>, SyncSqliteError> {
    let row = conn
        .query_row(
            "SELECT c.encoded, a.merkle_proof, k.checkpoint_hash, k.group_id, k.device_id, \
                    k.checkpoint_seq, k.encoded, k.signature, k.author_signing_public_key \
               FROM changes c \
               JOIN change_authorization a ON a.change_hash = c.change_hash \
               JOIN authorization_checkpoints k ON k.checkpoint_hash = a.checkpoint_hash \
              WHERE c.change_hash = ?1",
            rusqlite::params![&change_hash.0[..]],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                    row.get::<_, Vec<u8>>(8)?,
                ))
            },
        )
        .map(Some)
        .or_else(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            other => Err(SyncSqliteError::from(other)),
        })?;

    let Some((
        encoded,
        merkle_proof,
        checkpoint_hash,
        checkpoint_group,
        device_id,
        checkpoint_seq,
        checkpoint_encoded,
        signature,
        author_key,
    )) = row
    else {
        return Ok(None);
    };

    let change = Change::from_wire_bytes(&encoded).map_err(|error| {
        SyncSqliteError::CorruptState(format!(
            "canonical change {change_hash:?} is corrupt: {error}"
        ))
    })?;
    let change_for_versions = change.clone();

    Ok(Some(VerifiedChangeBundle {
        encoded,
        change,
        checkpoint: VerifiedCheckpoint {
            checkpoint_hash: fixed32(&checkpoint_hash, "checkpoint_hash")?,
            group_id: FolderGroupId(checkpoint_group),
            device_id,
            checkpoint_seq: checkpoint_seq as u64,
            encoded: checkpoint_encoded,
            signature,
            author_signing_public_key: fixed32(&author_key, "author_signing_public_key")?,
        },
        merkle_proof,
        versions: gather_versions(conn, &change_for_versions)?,
    }))
}

/// Remove a staged object once it is canonical.
///
/// Called only from inside the promotion transaction, never on its own: it is
/// the second half of moving a hash across the possession union, and the two
/// halves must commit together.
pub(crate) fn discard_staged(
    conn: &Connection,
    change_hash: &ChangeHash,
) -> Result<(), SyncSqliteError> {
    conn.execute(
        "DELETE FROM verified_change_parents WHERE child_hash = ?1",
        rusqlite::params![&change_hash.0[..]],
    )?;
    conn.execute(
        "DELETE FROM verified_change_objects WHERE change_hash = ?1",
        rusqlite::params![&change_hash.0[..]],
    )?;
    Ok(())
}

pub(crate) fn is_staged(
    conn: &Connection,
    change_hash: &ChangeHash,
) -> Result<bool, SyncSqliteError> {
    Ok(conn
        .query_row(
            "SELECT 1 FROM verified_change_objects WHERE change_hash = ?1",
            rusqlite::params![&change_hash.0[..]],
            |_| Ok(()),
        )
        .is_ok())
}

pub(crate) fn is_canonical(
    conn: &Connection,
    change_hash: &ChangeHash,
) -> Result<bool, SyncSqliteError> {
    Ok(conn
        .query_row(
            "SELECT 1 FROM changes WHERE change_hash = ?1",
            rusqlite::params![&change_hash.0[..]],
            |_| Ok(()),
        )
        .is_ok())
}

fn fixed32(bytes: &[u8], what: &str) -> Result<[u8; 32], SyncSqliteError> {
    if bytes.len() != 32 {
        return Err(SyncSqliteError::CorruptState(format!(
            "{what} is {} bytes, expected 32",
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    Ok(out)
}

#[cfg(test)]
pub(crate) mod test_support;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod carried_version_tests;
