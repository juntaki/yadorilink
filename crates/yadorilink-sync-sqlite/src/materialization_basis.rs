//! What a materialization proof records as the history state its physical
//! write realized, and how a reader decides that the proof is still
//! current.
//!
//! A proof records the signed deltas of every head the path holds on its own
//! account and, when the physical name is a conflict copy or a relocated
//! entry, the exact head it was placed for together with every head of that
//! source path. A copy name has no head of its own -- its head belongs to
//! another source path -- so the path's own heads alone would be empty and
//! would never go stale. A proof is current while that whole value is
//! unchanged; movement elsewhere in the group never stales it. The functions
//! below are the only readers and writers of that value.

use rusqlite::types::{FromSql, FromSqlError, FromSqlResult, ToSql, ToSqlOutput, ValueRef};
use rusqlite::Connection;
use yadorilink_replica_domain::ids::{FolderGroupId, SyncPath};

use crate::error::SyncSqliteError;

/// The stored value: the signed deltas of the heads the path holds on its own
/// account (sorted, concatenated), then a separator, then the identity of the
/// entry the plan places at the path (empty when the plan places none).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ReflectedHeads(pub Vec<u8>);

impl ReflectedHeads {
    /// The encoding of the own-account `provenances` (in any order) and the
    /// placed entry's `identity` bytes.
    pub fn of(provenances: &[[u8; 32]], identity: &[u8]) -> Self {
        let mut sorted: Vec<[u8; 32]> = provenances.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        let mut out = sorted.concat();
        out.push(0xFF);
        out.extend_from_slice(identity);
        Self(out)
    }
}

impl ToSql for ReflectedHeads {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        Ok(ToSqlOutput::Borrowed(ValueRef::Blob(&self.0)))
    }
}

impl FromSql for ReflectedHeads {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        match value {
            ValueRef::Blob(bytes) => Ok(Self(bytes.to_vec())),
            _ => Err(FromSqlError::InvalidType),
        }
    }
}

/// The path's current basis, read in the publishing transaction: a proof
/// names what the path stands for when it is published, which the publishing
/// transaction's own checks (the obligation and the mutation fence) tie to
/// the write.
pub fn record(
    conn: &Connection,
    group_id: &str,
    path: &str,
) -> Result<ReflectedHeads, SyncSqliteError> {
    current_basis(conn, group_id, path)
}

/// The basis of a path that holds exactly the heads with these `provenances` and has no
/// placement recorded for it: what [`record`] reads for such a path. For a caller that holds the
/// path's heads from the install that wrote them and knows no placement names the path.
pub(crate) fn of_unplaced_heads(provenances: &[[u8; 32]]) -> ReflectedHeads {
    ReflectedHeads::of(provenances, &[])
}

/// The basis the path has now. Read-only: recording a basis must not plan,
/// because planning places entries.
fn current_basis(
    conn: &Connection,
    group_id: &str,
    path: &str,
) -> Result<ReflectedHeads, SyncSqliteError> {
    let group = FolderGroupId(group_id.to_owned());
    let provenances = |at: &str| -> Result<Vec<[u8; 32]>, SyncSqliteError> {
        Ok(crate::native_store::native_heads_at(conn, &group, &SyncPath(at.to_owned()))?
            .iter()
            .map(|head| head.payload.provenance.0)
            .collect())
    };
    let mut own = provenances(path)?;
    let mut identity = Vec::new();
    // A physical name with no head of its own can stand for another path's
    // head (a conflict copy or a relocated entry). The recorded placement says
    // which exact head, and that head's source path is part of the basis: when
    // any head of the source moves, what the name stands for may move with it.
    if let Some(placement) =
        crate::stable_projection_binding::native_placement_at(conn, group_id, path)?
    {
        own.extend(provenances(&placement.source_path)?);
        let live = crate::native_store::native_heads_at(
            conn,
            &group,
            &SyncPath(placement.source_path.clone()),
        )?
        .iter()
        .any(|head| head.payload.provenance.0 == placement.provenance);
        if live {
            identity.extend_from_slice(&placement.provenance);
            identity.extend_from_slice(&placement.seq.to_be_bytes());
            identity.extend_from_slice(placement.author.as_bytes());
            identity.push(0);
            identity.extend_from_slice(placement.source_path.as_bytes());
        }
    }
    Ok(ReflectedHeads::of(&own, &identity))
}

/// Whether the path's basis is still exactly the reflected one.
pub fn is_current(
    conn: &Connection,
    group_id: &str,
    path: &str,
    stored: &ReflectedHeads,
) -> Result<bool, SyncSqliteError> {
    Ok(*stored == current_basis(conn, group_id, path)?)
}

#[cfg(test)]
mod tests;
