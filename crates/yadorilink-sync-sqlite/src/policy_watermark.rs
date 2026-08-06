//! `PolicyWatermarkRepository` owns the `group_policy_watermark` table -- the
//! persisted anti-rollback watermark for each group's signed policy log.
//!
//! Moved from `yadorilink-sync-core::repository::policy_watermark` (Phase
//! 7D-9E) -- a plain `Arc<SyncDatabase>`-backed repository with no
//! `SyncState` coupling of its own, same shape as `handoff_lease`'s and
//! `rebootstrap_store`'s earlier moves. `PolicyWatermark` (the persisted
//! value type) moved alongside it for the same reason `RestoreOperation`
//! moved to `yadorilink-filesystem-sync` in 7D-9C: a type this repository's
//! own signature names cannot keep living in a crate that depends on this
//! one. Re-exported at `yadorilink_sync_core::index::PolicyWatermark` (via
//! the now-deleted `state_model.rs` at the time of this move, Phase
//! 7D-10.1) so every existing caller keeps resolving unchanged.

use std::sync::Arc;

use rusqlite::OptionalExtension;

use crate::error::SyncSqliteError;
use yadorilink_sqlite_runtime::SyncDatabase;

/// The persisted anti-rollback watermark for one group's signed policy log
/// -- the highest verified sequence/head this device has adopted, plus the
/// authority key generation/fingerprint that verified it.
///
/// `authority_key_fingerprint` is the SHA-256 of the group's authority public
/// key at that head. It pins WHICH trust root was verified, not just how many
/// times it rotated (`authority_key_generation`), so the daemon can catch a
/// fork that swaps the authority key without advancing the generation, and an
/// audit can name the exact key that was trusted. It is `None` for a row
/// written before this column existed (see the read path); such a row is
/// treated as "fingerprint unknown", not as a fork, and is backfilled from the
/// next verified snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyWatermark {
    pub highest_verified_seq: u64,
    pub highest_verified_head: [u8; 32],
    pub authority_key_generation: u64,
    pub authority_key_fingerprint: Option<[u8; 32]>,
}

pub struct PolicyWatermarkRepository {
    database: Arc<SyncDatabase>,
}

impl PolicyWatermarkRepository {
    pub fn new(database: Arc<SyncDatabase>) -> Self {
        Self { database }
    }

    /// Reads the persisted anti-rollback watermark for `group_id`, or `None`
    /// if the group has never been recorded (its first-ever verified snapshot
    /// is always accepted). See [`PolicyWatermark`]. Survives a daemon restart,
    /// which is the whole point: the in-memory verified/stale policy maps are
    /// rebuilt from scratch after a restart, so without this an older
    /// signature-valid chain would be re-adopted, silently dropping a later
    /// revoke.
    pub fn policy_watermark(
        &self,
        group_id: &str,
    ) -> Result<Option<PolicyWatermark>, SyncSqliteError> {
        self.database.read::<_, SyncSqliteError>(|conn| {
            // `authority_key_fingerprint` is NULL for a row written before that
            // column existed, so read it as an `Option<Vec<u8>>` — a legacy row
            // yields `None`, which the daemon's verifier treats as "unknown", not
            // as a fork. Row shape: `(highest_verified_seq, highest_verified_head,
            // authority_key_generation, authority_key_fingerprint)`.
            type WatermarkRow = (i64, Vec<u8>, i64, Option<Vec<u8>>);
            let row: Option<WatermarkRow> = conn
            .query_row(
                "SELECT highest_verified_seq, highest_verified_head, authority_key_generation, \
                 authority_key_fingerprint \
                 FROM group_policy_watermark WHERE group_id = ?1",
                [group_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?;
            match row {
                None => Ok(None),
                Some((seq, head_blob, generation, fingerprint_blob)) => {
                    let highest_verified_head: [u8; 32] =
                        head_blob.as_slice().try_into().map_err(|_| {
                            SyncSqliteError::CorruptState(
                                "stored policy watermark head is not 32 bytes".into(),
                            )
                        })?;
                    let authority_key_fingerprint = fingerprint_blob
                        .map(|blob| {
                            blob.as_slice().try_into().map_err(|_| {
                                SyncSqliteError::CorruptState(
                                "stored policy watermark authority key fingerprint is not 32 bytes"
                                    .into(),
                            )
                            })
                        })
                        .transpose()?;
                    Ok(Some(PolicyWatermark {
                        highest_verified_seq: seq as u64,
                        highest_verified_head,
                        authority_key_generation: generation as u64,
                        authority_key_fingerprint,
                    }))
                }
            }
        })
    }

    /// Writes (creating or replacing) the anti-rollback watermark for
    /// `group_id`. The forward-only invariant — never lower the watermark — is
    /// enforced by the daemon against the freshly verified chain before it
    /// calls this; this method is the plain persistence sink and does not
    /// itself compare against the stored row.
    pub fn upsert_policy_watermark(
        &self,
        group_id: &str,
        watermark: &PolicyWatermark,
    ) -> Result<(), SyncSqliteError> {
        self.database.write::<_, SyncSqliteError>(|conn| {
            conn.execute(
                "INSERT OR REPLACE INTO group_policy_watermark \
                 (group_id, highest_verified_seq, highest_verified_head, authority_key_generation, \
                  authority_key_fingerprint) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    group_id,
                    watermark.highest_verified_seq as i64,
                    watermark.highest_verified_head.as_slice(),
                    watermark.authority_key_generation as i64,
                    // `None` stores SQL NULL — a verified snapshot always carries a
                    // fingerprint, so a NULL here only ever comes from persisting a
                    // legacy watermark unchanged, never from a fresh verification.
                    watermark.authority_key_fingerprint.as_ref().map(|fp| fp.as_slice()),
                ],
            )?;
            Ok(())
        })
    }
}
