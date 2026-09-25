//! What this device advertises about its history for a group, read out of
//! the state the store already keeps.
//!
//! See `yadorilink_replica_domain::base_negotiation` for what the
//! advertisement is for and what a peer's advertisement may decide. This
//! module only answers "what do we stand on": the installed base (or
//! none), the checkpoint that base derives from, the identity of the
//! summary it carries, and the group's active heads.

use rusqlite::{Connection, OptionalExtension};
use yadorilink_replica_domain::base_negotiation::{
    AdvertisedBase, BaseAdvertisement, SummaryIdentity,
};
use yadorilink_replica_domain::ids::FolderGroupId;
use yadorilink_replica_domain::rebootstrap::{Checkpoint, HistoryBase};

use crate::rebootstrap_store::{self, GroupHistorySummary};
use crate::SyncSqliteError;

/// The identity of `summary`, over its canonical order: authors ascending
/// by device id, heads ascending by path and then change hash.
pub fn summary_identity(summary: &GroupHistorySummary) -> SummaryIdentity {
    yadorilink_replica_engine::rebootstrap_snapshot::summary_identity_of(
        &summary.author_state,
        &summary.path_heads,
        summary.lamport_ceiling,
    )
}

/// This device's advertisement for `group_id`.
///
/// Run inside one read snapshot, so the base, its checkpoint, its summary
/// and the heads all describe the same moment.
///
/// Fails closed on any inconsistency in what is stored -- a base with no
/// checkpoint row, a checkpoint that does not derive the base, a base with
/// no summary -- rather than advertising something this device cannot
/// stand behind.
pub fn local_base_advertisement(
    conn: &Connection,
    group_id: &str,
) -> Result<BaseAdvertisement, SyncSqliteError> {
    let base = match rebootstrap_store::history_base(conn, group_id)? {
        None => AdvertisedBase::Genesis,
        Some(base) => {
            let checkpoint = installed_checkpoint(conn, group_id, base)?;
            let summary =
                rebootstrap_store::history_base_summary(conn, group_id)?.ok_or_else(|| {
                    SyncSqliteError::CorruptState(format!(
                        "group {group_id} has an installed base with no summary"
                    ))
                })?;
            AdvertisedBase::Installed {
                checkpoint: Box::new(checkpoint),
                summary: summary_identity(&summary),
            }
        }
    };
    let heads = crate::dag_store::group_heads(conn, group_id)?;
    Ok(BaseAdvertisement::new(FolderGroupId(group_id.to_owned()), base, heads)?)
}

/// The checkpoint the installed base derives from, re-derived and checked
/// rather than taken on the row's word.
pub(crate) fn installed_checkpoint(
    conn: &Connection,
    group_id: &str,
    base: HistoryBase,
) -> Result<Checkpoint, SyncSqliteError> {
    let encoded: Option<Vec<u8>> = conn
        .query_row(
            "SELECT c.encoded FROM group_history_bases b \
             JOIN change_checkpoints c ON c.checkpoint_hash = b.checkpoint_hash \
             WHERE b.group_id = ?1",
            [group_id],
            |row| row.get(0),
        )
        .optional()?;
    let encoded = encoded.ok_or_else(|| {
        SyncSqliteError::CorruptState(format!(
            "group {group_id} has an installed base whose checkpoint is not retained"
        ))
    })?;
    let checkpoint = Checkpoint::decode(&encoded)?;
    if checkpoint.group_id.as_str() != group_id || HistoryBase::from_checkpoint(&checkpoint) != base
    {
        return Err(SyncSqliteError::CorruptState(format!(
            "group {group_id}'s installed base does not derive from its retained checkpoint"
        )));
    }
    Ok(checkpoint)
}

#[cfg(test)]
mod tests;
