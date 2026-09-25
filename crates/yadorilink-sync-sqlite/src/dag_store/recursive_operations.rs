//! `recursive_operations` / `recursive_operation_parts`: the durable record
//! of every recursive delete or directory rename this replica has admitted
//! a part of, keyed by `(group, author device, operation_id)`.
//!
//! The grouping is signed into each part's `Change`, but it must not live
//! only there. Compaction reduces old changes to causal stubs and a sealed
//! history drops them entirely, and restoring a deleted folder has to keep
//! working afterwards: "which explicit entries did this `rm -rf` remove" is
//! answered from here, never by re-reading the changes. So each part is
//! recorded, in the same transaction that admits its change, as
//!
//! * the operation-wide descriptor, once per operation (kind, scope paths,
//!   part count, effect-set hash), and
//! * the part itself: its index, the change that carried it, and that
//!   change's effect ops in their canonical encoding.
//!
//! Nothing that compacts, prunes or seals history deletes from these
//! tables, so they outlive the history the parts were written on. Each row
//! also names the history epoch its part was written on, and a lookup by
//! author and operation id reads every epoch: an operation cut while its
//! author's history was sealed has parts on both sides of the seal.
//!
//! Admission enforces the rules that need more than one part: every part
//! of one operation agrees on the operation-wide descriptor, and each part
//! index is carried by exactly one change. Both are final author-chain
//! refusals of the later part, recorded like any other, which is sound
//! because only the author can sign a part keyed under its own device id: a
//! disagreement is the author contradicting itself, never a third party
//! interfering with it. The author chain admits an author's changes in
//! sequence order, so "later" is the same change on every replica.
//!
//! That holds only among parts written on one history, so a part is
//! measured only against those. A replica that joined a history by
//! installing its base never saw the parts written below it, while a
//! long-lived replica kept its records of them; refusing against records
//! from another history would have the two disagree about one change, and
//! the replica that refused it could never admit what was built on it.

use rusqlite::{params, Connection, OptionalExtension};

use crate::error::SyncSqliteError;
use yadorilink_replica_domain::admission::AuthorChainRefusal;
use yadorilink_replica_domain::change::{decode_op_list, encode_op_list, Change, Op};
use yadorilink_replica_domain::ids::{ChangeHash, DeviceId};
use yadorilink_replica_domain::rebootstrap::HistoryEpoch;
use yadorilink_replica_domain::recursive_operation::{
    effect_ops, EffectSetHash, RecursiveOperationDescriptor, RecursiveOperationId,
    RecursiveOperationRef,
};

/// Creates both tables. Pure `CREATE ... IF NOT EXISTS`.
pub fn init_recursive_operations_schema(conn: &Connection) -> Result<(), SyncSqliteError> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS recursive_operations (
            group_id          TEXT NOT NULL,
            author_device_id  TEXT NOT NULL,
            operation_id      BLOB NOT NULL,
            -- The history the recorded parts were written on: empty for
            -- genesis, the base's bytes above one.
            history_epoch     BLOB NOT NULL,
            -- `RecursiveOperationDescriptor::to_bytes`: the fields every
            -- part of the operation carries identically.
            descriptor        BLOB NOT NULL,
            part_count        INTEGER NOT NULL,
            PRIMARY KEY (group_id, author_device_id, operation_id, history_epoch)
        );
        CREATE TABLE IF NOT EXISTS recursive_operation_parts (
            group_id          TEXT NOT NULL,
            author_device_id  TEXT NOT NULL,
            operation_id      BLOB NOT NULL,
            history_epoch     BLOB NOT NULL,
            part_index        INTEGER NOT NULL,
            change_hash       BLOB NOT NULL,
            -- `encode_op_list` of the part's effect ops, so the effect set
            -- can be rebuilt after the change itself is gone.
            effect_ops        BLOB NOT NULL,
            PRIMARY KEY (group_id, author_device_id, operation_id, history_epoch, part_index)
        );
        CREATE INDEX IF NOT EXISTS recursive_operation_parts_by_change
            ON recursive_operation_parts(change_hash);
        "#,
    )?;
    Ok(())
}

/// The `history_epoch` column value for `epoch`: empty for genesis, the
/// base's bytes above one.
fn epoch_column(epoch: HistoryEpoch) -> Vec<u8> {
    epoch.base().map(|base| base.0.to_vec()).unwrap_or_default()
}

/// The refusal `change`'s part earns against the parts of its operation
/// already recorded on the history it was written on, or `None` when it
/// agrees with them (or is not a part). Records nothing.
///
/// Asked by [`super::admission_verdict`], so a contradicting part is
/// refused finally and durably on every admission path, the orphan
/// promotion included, rather than failing the transaction it arrives in.
pub(crate) fn recursive_operation_part_refusal(
    conn: &Connection,
    change: &Change,
) -> Result<Option<AuthorChainRefusal>, SyncSqliteError> {
    let Some(part) = &change.recursive_operation else { return Ok(None) };
    let group_id = change.group_id.as_str();
    let author = change.device_id.as_str();
    let id = &part.operation_id.0[..];
    let epoch = epoch_column(change.history_epoch);
    let recorded: Option<Vec<u8>> = conn
        .prepare_cached(
            "SELECT descriptor FROM recursive_operations \
             WHERE group_id = ?1 AND author_device_id = ?2 AND operation_id = ?3 \
               AND history_epoch = ?4",
        )?
        .query_row(params![group_id, author, id, epoch], |r| r.get(0))
        .optional()?;
    if recorded.is_some_and(|recorded| recorded != part.descriptor().to_bytes()) {
        return Ok(Some(AuthorChainRefusal::RecursiveOperationContradicted {
            operation: part.operation_id,
            part_index: part.part_index,
        }));
    }
    let holder: Option<Vec<u8>> = conn
        .prepare_cached(
            "SELECT change_hash FROM recursive_operation_parts \
             WHERE group_id = ?1 AND author_device_id = ?2 AND operation_id = ?3 \
               AND history_epoch = ?4 AND part_index = ?5",
        )?
        .query_row(params![group_id, author, id, epoch, i64::from(part.part_index)], |r| r.get(0))
        .optional()?;
    if let Some(holder) = holder {
        if holder[..] != change.compute_hash().0[..] {
            let held = ChangeHash(holder.try_into().map_err(|_| {
                SyncSqliteError::CorruptState("recursive-operation part change hash".into())
            })?);
            return Ok(Some(AuthorChainRefusal::RecursiveOperationPartHeld {
                operation: part.operation_id,
                part_index: part.part_index,
                held,
            }));
        }
    }
    Ok(None)
}

/// [`recursive_operation_part_refusal`] as an error, for a caller that must
/// settle it before it signs or appends, like local emission.
pub fn check_recursive_operation_part(
    conn: &Connection,
    change: &Change,
) -> Result<(), SyncSqliteError> {
    match recursive_operation_part_refusal(conn, change)? {
        None => Ok(()),
        Some(refusal) => Err(SyncSqliteError::InvalidInput(format!(
            "change {} by {}: {refusal}",
            change.compute_hash().to_hex(),
            change.device_id.as_str(),
        ))),
    }
}

/// Checks and records `change`'s part. Idempotent for a redelivery of the
/// same change. Callers admitting or authoring a change call this in the
/// same transaction that appends it, so a part is never held without its
/// record or recorded without being held.
pub fn record_recursive_operation_part(
    conn: &Connection,
    change: &Change,
) -> Result<(), SyncSqliteError> {
    let Some(part) = &change.recursive_operation else { return Ok(()) };
    check_recursive_operation_part(conn, change)?;
    let group_id = change.group_id.as_str();
    let author = change.device_id.as_str();
    let id = &part.operation_id.0[..];
    let epoch = epoch_column(change.history_epoch);
    conn.prepare_cached(
        "INSERT OR IGNORE INTO recursive_operations \
         (group_id, author_device_id, operation_id, history_epoch, descriptor, part_count) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    )?
    .execute(params![
        group_id,
        author,
        id,
        epoch,
        part.descriptor().to_bytes(),
        i64::from(part.part_count)
    ])?;
    let effects: Vec<Op> = effect_ops(&change.ops).cloned().collect();
    conn.prepare_cached(
        "INSERT OR IGNORE INTO recursive_operation_parts \
         (group_id, author_device_id, operation_id, history_epoch, part_index, change_hash, \
          effect_ops) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
    )?
    .execute(params![
        group_id,
        author,
        id,
        epoch,
        i64::from(part.part_index),
        &change.compute_hash().0[..],
        encode_op_list(&effects),
    ])?;
    Ok(())
}

/// One recorded part of a recursive operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordedRecursivePart {
    pub part_index: u32,
    /// The change that carried this part. It may since have been
    /// compacted away; nothing here depends on it still being held.
    pub change_hash: ChangeHash,
    pub effect_ops: Vec<Op>,
}

/// Whether every part of an operation is here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecursiveOperationCompleteness {
    /// Every part is recorded, and the union of their effect ops hashes to
    /// the operation's effect-set hash: [`RecordedRecursiveOperation::effect_set`]
    /// is exactly the set the author observed.
    Complete,
    /// Some parts have not been received (or will never be). The effect
    /// set is only the recorded parts' share of the observed set, and
    /// anything acting on it, like a folder restore, is partial.
    Partial { missing_part_indexes: Vec<u32> },
    /// Every part is recorded, but their union does not hash to the
    /// signed effect-set hash: the author cut parts that do not add up to
    /// the set it declared. Also the answer when the author contradicted
    /// itself across two histories (see [`RecordedRecursiveOperation`]).
    /// Never treated as complete.
    Inconsistent,
}

/// Everything recorded about one recursive operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordedRecursiveOperation {
    pub author: DeviceId,
    pub descriptor: RecursiveOperationDescriptor,
    /// Recorded parts in part-index order, from every history whose record
    /// agrees with `descriptor`.
    pub parts: Vec<RecordedRecursivePart>,
    /// The author recorded this operation differently on two histories:
    /// another descriptor, or another change at one part index. Each
    /// history's admission refused nothing, since neither saw the other,
    /// but the union is not one operation.
    pub contradicted: bool,
}

impl RecordedRecursiveOperation {
    /// Every recorded effect op, in part order.
    pub fn effect_set(&self) -> Vec<Op> {
        self.parts.iter().flat_map(|part| part.effect_ops.iter().cloned()).collect()
    }

    pub fn completeness(&self) -> RecursiveOperationCompleteness {
        if self.contradicted {
            return RecursiveOperationCompleteness::Inconsistent;
        }
        let mut have = self.parts.iter().map(|part| part.part_index).peekable();
        let mut missing = Vec::new();
        for index in 0..self.descriptor.part_count {
            if have.peek() == Some(&index) {
                have.next();
            } else {
                missing.push(index);
            }
        }
        if !missing.is_empty() {
            return RecursiveOperationCompleteness::Partial { missing_part_indexes: missing };
        }
        let effects = self.effect_set();
        if EffectSetHash::of_effects(&effects) == self.descriptor.effect_set_hash {
            RecursiveOperationCompleteness::Complete
        } else {
            RecursiveOperationCompleteness::Inconsistent
        }
    }
}

/// Looks one operation up by its author and id, across every history its
/// parts were recorded on.
///
/// The descriptor is the one recorded on the earliest-ordered history
/// (genesis first, then by base bytes), so the answer is the same however
/// the rows arrived; parts on a history that disagrees with it are left
/// out and mark the operation contradicted.
pub fn recursive_operation(
    conn: &Connection,
    group_id: &str,
    operation: &RecursiveOperationRef,
) -> Result<Option<RecordedRecursiveOperation>, SyncSqliteError> {
    let author = &operation.author;
    let operation_id = &operation.operation_id;
    let key = params![group_id, author.as_str(), &operation_id.0[..]];
    let descriptors: Vec<(Vec<u8>, Vec<u8>)> = conn
        .prepare_cached(
            "SELECT history_epoch, descriptor FROM recursive_operations \
             WHERE group_id = ?1 AND author_device_id = ?2 AND operation_id = ?3 \
             ORDER BY history_epoch",
        )?
        .query_map(key, |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<Result<_, _>>()?;
    let Some((_, chosen)) = descriptors.first() else { return Ok(None) };
    let mut contradicted = false;
    let mut agreeing = std::collections::HashSet::new();
    for (epoch, descriptor) in &descriptors {
        if descriptor == chosen {
            agreeing.insert(epoch.clone());
        } else {
            contradicted = true;
        }
    }
    let descriptor = RecursiveOperationDescriptor::from_bytes(chosen).map_err(|e| {
        SyncSqliteError::CorruptState(format!("corrupt recursive-operation descriptor: {e}"))
    })?;
    let mut statement = conn.prepare_cached(
        "SELECT history_epoch, part_index, change_hash, effect_ops \
         FROM recursive_operation_parts \
         WHERE group_id = ?1 AND author_device_id = ?2 AND operation_id = ?3 \
         ORDER BY part_index, history_epoch",
    )?;
    let rows = statement
        .query_map(key, |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, Vec<u8>>(2)?,
                r.get::<_, Vec<u8>>(3)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let mut parts: Vec<RecordedRecursivePart> = Vec::with_capacity(rows.len());
    for (epoch, part_index, change_hash, effect_ops) in rows {
        if !agreeing.contains(&epoch) {
            continue;
        }
        let part_index = u32::try_from(part_index).map_err(|_| {
            SyncSqliteError::CorruptState(format!("recursive-operation part index {part_index}"))
        })?;
        let change_hash = ChangeHash(change_hash.try_into().map_err(|_| {
            SyncSqliteError::CorruptState("recursive-operation part change hash".into())
        })?);
        if let Some(previous) = parts.last().filter(|p| p.part_index == part_index) {
            // One index filled on two histories: the same part seen twice
            // is fine, two different changes are not one operation.
            contradicted |= previous.change_hash != change_hash;
            continue;
        }
        let effect_ops = decode_op_list(&effect_ops).map_err(|e| {
            SyncSqliteError::CorruptState(format!("corrupt recursive-operation part ops: {e}"))
        })?;
        parts.push(RecordedRecursivePart { part_index, change_hash, effect_ops });
    }
    Ok(Some(RecordedRecursiveOperation { author: author.clone(), descriptor, parts, contradicted }))
}

/// The operation a change was a part of, or `None` when it was not a
/// part of any.
pub fn recursive_operation_of_change(
    conn: &Connection,
    change_hash: &ChangeHash,
) -> Result<Option<RecursiveOperationRef>, SyncSqliteError> {
    let row: Option<(String, Vec<u8>)> = conn
        .prepare_cached(
            "SELECT author_device_id, operation_id FROM recursive_operation_parts \
             WHERE change_hash = ?1",
        )?
        .query_row([&change_hash.0[..]], |r| Ok((r.get(0)?, r.get(1)?)))
        .optional()?;
    row.map(|(author, id)| {
        let id: [u8; 16] = id.try_into().map_err(|_| {
            SyncSqliteError::CorruptState("recursive-operation id is not 16 bytes".into())
        })?;
        Ok(RecursiveOperationRef {
            author: DeviceId(author),
            operation_id: RecursiveOperationId(id),
        })
    })
    .transpose()
}

#[cfg(test)]
mod tests;
