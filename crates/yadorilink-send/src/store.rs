//! Track Send's own, wholly separate local store: two small tables in
//! their own database file (never `yadorilink-sync-sqlite`'s index
//! database, never opened by anything in this file but this crate), built
//! on `yadorilink-sqlite-runtime::SyncDatabase` -- the generic pooled-
//! connection/WAL/writer-gate/retry runtime the sync engine also builds
//! on, supplying only its OWN schema-bootstrap closure below. No DAG
//! table (`change_parents`, `dag_group_heads`, ...) is created, read, or
//! referenced anywhere in this file.
//!
//! Chunk-level resume progress is deliberately NOT a table here: it is the
//! local `SegmentBlockStore`'s own on-disk content, checked via
//! `BlockContentStore::present_blocks`. What this store durably owns is
//! session-level state -- which transfers exist, for/from which device,
//! and (for an inbound transfer) which directory it is materializing
//! into once that decision has been made -- exactly the state a crash
//! between deciding and finishing needs to survive.

use std::path::Path;

use prost::Message;
use rusqlite::{params, OptionalExtension};
use yadorilink_ipc_proto::send::SendManifest;
use yadorilink_sqlite_runtime::SyncDatabase;

use crate::error::{Result, SendError};

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS send_outbound_transfers (
    transfer_id TEXT PRIMARY KEY,
    target_device_id TEXT NOT NULL,
    -- Captured once, at offer time, from the device directory's
    -- resolution of `target_device_id` -- never re-resolved later.
    -- Authorizing a pull compares the connection's authenticated peer key
    -- directly against this column, so a device's key changing (a
    -- re-enrollment) after an offer was made can never let a DIFFERENT
    -- key satisfy an old offer.
    target_signing_key BLOB NOT NULL,
    source_path TEXT NOT NULL,
    manifest_encoded BLOB NOT NULL,
    status TEXT NOT NULL,
    created_at_unix_nanos INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS send_outbound_transfers_by_source_target
    ON send_outbound_transfers(source_path, target_device_id);

CREATE TABLE IF NOT EXISTS send_inbound_transfers (
    transfer_id TEXT PRIMARY KEY,
    sender_device_id TEXT NOT NULL,
    manifest_encoded BLOB NOT NULL,
    status TEXT NOT NULL,
    destination_dir TEXT,
    offered_at_unix_nanos INTEGER NOT NULL
);
";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboundStatus {
    Offered,
    Acked,
    /// The receiver explicitly declined this offer
    /// (`SendManifestAck{accepted:false}`). Terminal: a rejected offer is
    /// never retried under the same transfer id -- `find_outbound_by_
    /// source_and_target` skips rows in this state, so `offer_send`
    /// re-running against the same (source, target) after a rejection
    /// always mints a fresh transfer id rather than reusing and mutating
    /// this row -- and -- critically --
    /// [`SendService::handle_pull`](crate::session::SendService::handle_pull)
    /// requires `Acked` before serving any chunk, so a transfer parked here
    /// can never be pulled. Distinct from `Offered` (still awaiting the
    /// receiver's ack) so a rejected offer can eventually be reaped or
    /// reported as declined rather than looking like it is still pending.
    Rejected,
}

impl OutboundStatus {
    fn as_str(&self) -> &'static str {
        match self {
            OutboundStatus::Offered => "offered",
            OutboundStatus::Acked => "acked",
            OutboundStatus::Rejected => "rejected",
        }
    }

    fn parse(s: &str) -> Self {
        match s {
            "acked" => OutboundStatus::Acked,
            "rejected" => OutboundStatus::Rejected,
            _ => OutboundStatus::Offered,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InboundStatus {
    Pending,
    InProgress,
    Completed,
}

impl InboundStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            InboundStatus::Pending => "pending",
            InboundStatus::InProgress => "in_progress",
            InboundStatus::Completed => "completed",
        }
    }

    fn parse(s: &str) -> Self {
        match s {
            "in_progress" => InboundStatus::InProgress,
            "completed" => InboundStatus::Completed,
            _ => InboundStatus::Pending,
        }
    }
}

#[derive(Debug, Clone)]
pub struct OutboundTransfer {
    pub transfer_id: String,
    pub target_device_id: String,
    pub target_signing_key: [u8; 32],
    pub source_path: String,
    pub manifest: SendManifest,
    pub status: OutboundStatus,
}

#[derive(Debug, Clone)]
pub struct InboundTransfer {
    pub transfer_id: String,
    pub sender_device_id: String,
    pub manifest: SendManifest,
    pub status: InboundStatus,
    pub destination_dir: Option<String>,
    pub offered_at_unix_nanos: i64,
}

pub struct SendStore {
    db: SyncDatabase,
}

impl SendStore {
    /// Opens (creating if needed) this device's Track Send database at
    /// `path` -- WAL mode, `synchronous = FULL`, and the writer-gate
    /// `yadorilink-sqlite-runtime` already provides, running only the
    /// schema above. Never call `yadorilink_sqlite_runtime::init_schema`
    /// here -- that is the sync engine's own DDL, for a different
    /// database file entirely.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let db = SyncDatabase::open(path, |conn| {
            conn.execute_batch(SCHEMA)?;
            Ok(())
        })
        .map_err(SendError::Database)?;
        Ok(Self { db })
    }

    /// Durably records a new outbound offer before anything is dialed --
    /// the "record intent before the first mutating action" step for
    /// `send`: once this returns `Ok`, a crash before any byte reaches the
    /// network still leaves a resumable, re-drivable offer behind (see
    /// `find_outbound_by_source_and_target`).
    #[allow(clippy::too_many_arguments)]
    pub fn insert_outbound_offered(
        &self,
        transfer_id: &str,
        target_device_id: &str,
        target_signing_key: &[u8; 32],
        source_path: &str,
        manifest: &SendManifest,
        created_at_unix_nanos: i64,
    ) -> Result<()> {
        let encoded = manifest.encode_to_vec();
        self.db.write(|conn| -> Result<()> {
            conn.execute(
                "INSERT INTO send_outbound_transfers
                    (transfer_id, target_device_id, target_signing_key, source_path, manifest_encoded, status, created_at_unix_nanos)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    transfer_id,
                    target_device_id,
                    target_signing_key.as_slice(),
                    source_path,
                    encoded,
                    OutboundStatus::Offered.as_str(),
                    created_at_unix_nanos,
                ],
            )?;
            Ok(())
        })
    }

    /// An existing outbound offer for the exact same (source path, target
    /// device) pair, if one is already on record -- `send`'s idempotency
    /// check: re-running the same `send` command after a crash or a
    /// failed dial re-drives THIS transfer id rather than minting a new
    /// one and re-chunking the source a second time.
    ///
    /// Deliberately excludes rows in [`OutboundStatus::Rejected`]: that
    /// status is terminal, so a row in it must never be handed back here
    /// for `offer_send` to reuse and mutate (e.g. via `mark_outbound_acked`)
    /// -- a re-send after a rejection has to mint a genuinely new transfer
    /// id instead. Only the source/target pair is deduplicated; a rejected
    /// row simply becomes invisible to this lookup and is left in place.
    pub fn find_outbound_by_source_and_target(
        &self,
        source_path: &str,
        target_device_id: &str,
    ) -> Result<Option<OutboundTransfer>> {
        self.db.read(|conn| -> Result<Option<OutboundTransfer>> {
            Ok(conn
                .query_row(
                    "SELECT transfer_id, target_device_id, target_signing_key, source_path, manifest_encoded, status
                 FROM send_outbound_transfers
                 WHERE source_path = ?1 AND target_device_id = ?2 AND status != ?3
                 ORDER BY created_at_unix_nanos DESC LIMIT 1",
                    params![source_path, target_device_id, OutboundStatus::Rejected.as_str()],
                    row_to_outbound,
                )
                .optional()?)
        })
    }

    pub fn get_outbound(&self, transfer_id: &str) -> Result<Option<OutboundTransfer>> {
        self.db.read(|conn| -> Result<Option<OutboundTransfer>> {
            Ok(conn
                .query_row(
                    "SELECT transfer_id, target_device_id, target_signing_key, source_path, manifest_encoded, status
                 FROM send_outbound_transfers WHERE transfer_id = ?1",
                    params![transfer_id],
                    row_to_outbound,
                )
                .optional()?)
        })
    }

    /// Whether any offer to the device holding `target_signing_key` has been
    /// accepted -- the receiver of an accepted offer may dial back to pull
    /// it at any later time.
    pub fn has_acked_outbound_for(&self, target_signing_key: &[u8; 32]) -> Result<bool> {
        self.db.read(|conn| -> Result<bool> {
            Ok(conn
                .query_row(
                    "SELECT 1 FROM send_outbound_transfers
                 WHERE target_signing_key = ?1 AND status = ?2 LIMIT 1",
                    params![&target_signing_key[..], OutboundStatus::Acked.as_str()],
                    |_| Ok(()),
                )
                .optional()?
                .is_some())
        })
    }

    pub fn mark_outbound_acked(&self, transfer_id: &str) -> Result<()> {
        self.db.write(|conn| -> Result<()> {
            conn.execute(
                "UPDATE send_outbound_transfers SET status = ?1 WHERE transfer_id = ?2",
                params![OutboundStatus::Acked.as_str(), transfer_id],
            )?;
            Ok(())
        })
    }

    /// Marks a declined offer terminal -- called once `offer_send` has
    /// observed `SendManifestAck{accepted:false}`. Leaves the offered
    /// chunks in the block store (nothing here reaps them) but moves the
    /// row itself to `Rejected`, which is what
    /// [`SendService::handle_pull`](crate::session::SendService::handle_pull)
    /// checks before serving any chunk pull for this transfer id.
    pub fn mark_outbound_rejected(&self, transfer_id: &str) -> Result<()> {
        self.db.write(|conn| -> Result<()> {
            conn.execute(
                "UPDATE send_outbound_transfers SET status = ?1 WHERE transfer_id = ?2",
                params![OutboundStatus::Rejected.as_str(), transfer_id],
            )?;
            Ok(())
        })
    }

    /// Durably records a freshly-offered inbound transfer -- called BEFORE
    /// the manifest's sender is acknowledged, so `accepted = true` on the
    /// wire is never sent for an offer this device has not actually
    /// retained. Idempotent: a duplicate offer for a `transfer_id` already
    /// on record (a sender retry after its own ack never arrived) is a
    /// no-op, reported via the returned `bool`.
    pub fn insert_inbound_if_new(
        &self,
        transfer_id: &str,
        sender_device_id: &str,
        manifest: &SendManifest,
        offered_at_unix_nanos: i64,
    ) -> Result<bool> {
        let encoded = manifest.encode_to_vec();
        let rows = self.db.write(|conn| -> Result<usize> {
            Ok(conn.execute(
                "INSERT OR IGNORE INTO send_inbound_transfers
                    (transfer_id, sender_device_id, manifest_encoded, status, destination_dir, offered_at_unix_nanos)
                 VALUES (?1, ?2, ?3, ?4, NULL, ?5)",
                params![
                    transfer_id,
                    sender_device_id,
                    encoded,
                    InboundStatus::Pending.as_str(),
                    offered_at_unix_nanos,
                ],
            )?)
        })?;
        Ok(rows > 0)
    }

    pub fn get_inbound(&self, transfer_id: &str) -> Result<Option<InboundTransfer>> {
        self.db.read(|conn| -> Result<Option<InboundTransfer>> {
            Ok(conn
                .query_row(
                    "SELECT transfer_id, sender_device_id, manifest_encoded, status, destination_dir, offered_at_unix_nanos
                 FROM send_inbound_transfers WHERE transfer_id = ?1",
                    params![transfer_id],
                    row_to_inbound,
                )
                .optional()?)
        })
    }

    pub fn list_inbound(&self) -> Result<Vec<InboundTransfer>> {
        self.db.read(|conn| -> Result<Vec<InboundTransfer>> {
            let mut stmt = conn.prepare(
                "SELECT transfer_id, sender_device_id, manifest_encoded, status, destination_dir, offered_at_unix_nanos
                 FROM send_inbound_transfers ORDER BY offered_at_unix_nanos ASC",
            )?;
            let rows = stmt.query_map([], row_to_inbound)?;
            Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
        })
    }

    /// The "acquire authority, durably before the first mutating action"
    /// step for `receive`: if this transfer has no destination directory
    /// on record yet, atomically claims `requested_dir` as its destination
    /// and moves it to `in_progress`. If a destination is ALREADY on
    /// record (this is a resume, or a second `receive` call), the
    /// requested directory is ignored and the recorded one is returned --
    /// a transfer materializes into exactly one place for its whole
    /// lifetime, decided once, durably, before any chunk is pulled.
    pub fn claim_inbound_destination(
        &self,
        transfer_id: &str,
        requested_dir: &str,
    ) -> Result<String> {
        self.db.write_immediate(|tx| -> Result<String> {
            let existing: Option<String> = tx
                .query_row(
                    "SELECT destination_dir FROM send_inbound_transfers WHERE transfer_id = ?1",
                    params![transfer_id],
                    |row| row.get::<_, Option<String>>(0),
                )
                .optional()?
                .flatten();
            if let Some(dir) = existing {
                return Ok(dir);
            }
            tx.execute(
                "UPDATE send_inbound_transfers
                 SET destination_dir = ?1, status = ?2
                 WHERE transfer_id = ?3",
                params![requested_dir, InboundStatus::InProgress.as_str(), transfer_id],
            )?;
            Ok(requested_dir.to_string())
        })
    }

    pub fn mark_inbound_completed(&self, transfer_id: &str) -> Result<()> {
        self.db.write(|conn| -> Result<()> {
            conn.execute(
                "UPDATE send_inbound_transfers SET status = ?1 WHERE transfer_id = ?2",
                params![InboundStatus::Completed.as_str(), transfer_id],
            )?;
            Ok(())
        })
    }
}

fn row_to_outbound(row: &rusqlite::Row<'_>) -> rusqlite::Result<OutboundTransfer> {
    let key_bytes: Vec<u8> = row.get(2)?;
    let target_signing_key: [u8; 32] = key_bytes.try_into().map_err(|bytes: Vec<u8>| {
        rusqlite::Error::FromSqlConversionFailure(
            2,
            rusqlite::types::Type::Blob,
            format!("signing key column has {} bytes, expected 32", bytes.len()).into(),
        )
    })?;
    let encoded: Vec<u8> = row.get(4)?;
    let manifest = SendManifest::decode(encoded.as_slice()).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(4, rusqlite::types::Type::Blob, Box::new(e))
    })?;
    let status: String = row.get(5)?;
    Ok(OutboundTransfer {
        transfer_id: row.get(0)?,
        target_device_id: row.get(1)?,
        target_signing_key,
        source_path: row.get(3)?,
        manifest,
        status: OutboundStatus::parse(&status),
    })
}

fn row_to_inbound(row: &rusqlite::Row<'_>) -> rusqlite::Result<InboundTransfer> {
    let encoded: Vec<u8> = row.get(2)?;
    let manifest = SendManifest::decode(encoded.as_slice()).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(2, rusqlite::types::Type::Blob, Box::new(e))
    })?;
    let status: String = row.get(3)?;
    Ok(InboundTransfer {
        transfer_id: row.get(0)?,
        sender_device_id: row.get(1)?,
        manifest,
        status: InboundStatus::parse(&status),
        destination_dir: row.get(4)?,
        offered_at_unix_nanos: row.get(5)?,
    })
}

#[cfg(test)]
mod tests;
