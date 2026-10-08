//! The native projection state a recovery bundle carries beside the heads:
//! kept copies and stable names, built from what this replica recorded and
//! installed into a receiver.

use rusqlite::Connection;

use crate::error::SyncSqliteError;

use yadorilink_replica_engine::native_snapshot::{
    NativeBindingEntry, NativeKeptHead, NativeSnapshotState,
};

/// The native half of a bundle for `group_id`: the group's whole native
/// projection state. Index rows are the sender's own projection and are not
/// carried, so there is no row evidence in it.
pub(crate) fn carried_native_state(
    conn: &Connection,
    group_id: &str,
) -> Result<NativeSnapshotState, SyncSqliteError> {
    let (kept_heads, bindings) = carried_projection(conn, group_id)?;
    Ok(NativeSnapshotState { row_witnesses: Vec::new(), kept_heads, bindings })
}

/// The projection facts a bundle carries for `group_id`: kept heads and stable
/// names. Placements are not carried. A conflict copy and a relocated winner
/// are placed from the heads when the receiver arms the paths it installs, and a
/// reconciliation hold records a reason only the disk of the device that made it
/// knows.
fn carried_projection(
    conn: &Connection,
    group_id: &str,
) -> Result<(Vec<NativeKeptHead>, Vec<NativeBindingEntry>), SyncSqliteError> {
    let kept_heads = crate::stable_projection_binding::native_kept_heads_of_group(conn, group_id)?;
    let live = crate::stable_projection_binding::native_live_bindings(conn, group_id)?;
    let bindings = live
        .into_iter()
        .map(|((source_path, author, incarnation, seq), stable_path)| NativeBindingEntry {
            source_path,
            author,
            incarnation,
            seq,
            stable_path,
        })
        .collect();
    Ok((kept_heads, bindings))
}

/// The digest a checkpoint of `group_id` commits to for the projection facts a
/// bundle carries beside it (see [`NativeSnapshotState::projection_digest`]).
pub(crate) fn carried_projection_digest(
    conn: &Connection,
    group_id: &str,
) -> Result<yadorilink_replica_domain::native_checkpoint::ProjectionDigest, SyncSqliteError> {
    Ok(carried_native_state(conn, group_id)?.projection_digest())
}

/// Installs the native half of a bundle: the projection state, added to the
/// group's.
pub(crate) fn install_native_snapshot_state(
    tx: &Connection,
    group_id: &str,
    native: &NativeSnapshotState,
) -> Result<(), SyncSqliteError> {
    // Added to what the group holds: the join into a replica with no native
    // state clears the group's stale derived facts before it calls this.
    for kept in &native.kept_heads {
        crate::stable_projection_binding::native_keep_head(
            tx,
            group_id,
            &kept.source_path,
            &kept.author,
            &kept.incarnation,
            kept.seq,
            &kept.provenance,
        )?;
    }
    for binding in &native.bindings {
        let key =
            (binding.source_path.clone(), binding.author.clone(), binding.incarnation, binding.seq);
        crate::stable_projection_binding::native_bind(tx, group_id, &key, &binding.stable_path)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use rusqlite::Connection;

    use super::*;

    const GROUP: &str = "g1";

    fn conn() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        crate::replica_tables::init(&c).unwrap();
        c
    }

    fn put_head(conn: &Connection, path: &str, seq: i64, provenance: u8) {
        conn.execute(
            "INSERT INTO native_heads \
                 (group_id, path, author, incarnation, seq, version, provenance) \
             VALUES (?1, ?2, 'device-a', ?3, ?4, ?5, ?6)",
            rusqlite::params![
                GROUP,
                path,
                &[1u8; 16][..],
                seq,
                &[8u8; 32][..],
                &[provenance; 32][..]
            ],
        )
        .unwrap();
    }

    /// What one replica builds, another installs, and installing again changes
    /// nothing and never removes what is local. A keep installs only against a
    /// live head with the carried provenance.
    #[test]
    fn a_built_native_section_installs_on_a_fresh_replica() {
        use crate::stable_projection_binding::{native_keep_head, native_kept_heads_of_group};
        let source = conn();
        put_head(&source, "a", 1, 5);
        assert!(native_keep_head(&source, GROUP, "a", "device-a", &[1; 16], 1, &[5; 32]).unwrap());
        let built = carried_native_state(&source, GROUP).unwrap();
        assert!(built.row_witnesses.is_empty());
        assert_eq!(built.kept_heads.len(), 1);

        let fresh = conn();
        put_head(&fresh, "a", 1, 5);
        let tx = fresh.unchecked_transaction().unwrap();
        install_native_snapshot_state(&tx, GROUP, &built).unwrap();
        tx.commit().unwrap();
        assert_eq!(native_kept_heads_of_group(&fresh, GROUP).unwrap(), built.kept_heads);

        put_head(&fresh, "b", 2, 6);
        assert!(native_keep_head(&fresh, GROUP, "b", "device-a", &[1; 16], 2, &[6; 32]).unwrap());
        let tx = fresh.unchecked_transaction().unwrap();
        install_native_snapshot_state(&tx, GROUP, &built).unwrap();
        tx.commit().unwrap();
        assert_eq!(native_kept_heads_of_group(&fresh, GROUP).unwrap().len(), 2);

        // A carried keep whose head is not live here (or whose head has another
        // provenance) records nothing: no row ever names a head that is not live.
        let other = conn();
        put_head(&other, "a", 1, 9);
        let tx = other.unchecked_transaction().unwrap();
        install_native_snapshot_state(&tx, GROUP, &built).unwrap();
        tx.commit().unwrap();
        assert!(native_kept_heads_of_group(&other, GROUP).unwrap().is_empty());
    }
}
