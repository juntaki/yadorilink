//! Write-through: which entry a local operation on a copy name is an
//! operation on.
//!
//! The namespace projection can place a path's File or Symlink under a
//! conflict-copy name of that path: relocated because the path has to be a
//! directory (a live descendant, or an explicit Directory, which keeps its
//! path), or held there on this device (a directory it may not
//! remove, or a case-fold collision). The index then holds the entry's row
//! under the copy name, written by the change that put the entry at its
//! own path. No change ever authored anything at the copy name.
//!
//! A user who deletes or edits that copy is deleting or editing the entry,
//! so the capture authors `Delete(a)` / `Put(a)` for its source `a` and
//! never an op at the copy name ([`write_through_source`]). A copy some
//! change did author as an entry of its own (a conflict copy made durable,
//! or any file someone wrote under such a name) is that entry, and an
//! operation on it is an ordinary one at its own path.
//!
//! A losing version of the source, held at its conflict-copy name, is the
//! same, whether the current history wrote it concurrently with the
//! winner or an installed base carries it: no change authored that copy,
//! and the user acting on it is acting on that version of the source
//! (decided 2026-09-26: a write never supersedes a version its author did
//! not observe, so the visible winner is never named by it). The winner
//! and the edit then stay live side by side -- one author may hold two
//! versions of the path for a while -- until the user resolves them; a
//! seal refuses that state (`TwoHeadsFromOneAuthor`) and holds the group's
//! compaction until then.
//!
//! The change authored for it supersedes only the source's head the
//! copy's row was written from. Everything else live at the source -- the
//! explicit Directory that keeps the path, a peer's newer write, a losing
//! File -- stays concurrent with it: the commit seam signs it onto the
//! frontier without the source's unseen heads (see
//! `file_index::emit_local_write_onto_frontier`).
//!
//! A recursive delete or directory rename that observed such a copy
//! writes it through the same way ([`write_recursive_operation_through`]):
//! `rm -rf p` deletes `p/a`, and `mv p q` deletes `p/a` and puts `q/a`,
//! never an op at the copy name. When `p/a` held a winner and a loser, both
//! move: `q/a` receives two puts, and the copy's name at `q` is derived anew
//! from the heads there. A directory made where the copy was (a
//! type change) deletes the source first, then is a new entry of its own.

use rusqlite::Connection;

use yadorilink_replica_domain::file::RecordKind;

use crate::error::SyncSqliteError;

/// The source entry a local operation on the physical path `path` is an
/// operation on, or `None` when `path` is an entry of its own.
///
/// `path` is a copy of a source only when native's physical placement
/// authority says its index row shows one
/// ([`crate::native_projection_binding::resolve_native_physical_path`]):
/// the placement, or failing that the native head the row was produced from,
/// names the logical path and the exact head the row displays, and holds
/// until the row is replaced, whether or not that head is still live. The
/// path's name is never inspected. A path whose own entry holds the content
/// the row shows is that entry whatever it is placed as, and the index row
/// must be a live File or Symlink.
pub fn write_through_source(
    conn: &Connection,
    group_id: &str,
    path: &str,
) -> Result<Option<String>, SyncSqliteError> {
    use yadorilink_replica_domain::ids::{FolderGroupId, SyncPath};

    let Some(target) =
        crate::native_projection_binding::resolve_native_physical_path(conn, group_id, path)?
    else {
        return Ok(None);
    };
    let Some(row) = crate::store::read_canonical_current_row(conn, group_id, path)? else {
        return Ok(None);
    };
    if row.snapshot.deleted
        || !matches!(row.snapshot.record_kind, RecordKind::File | RecordKind::Symlink)
    {
        return Ok(None);
    }
    // An entry of the path's own that holds the very content the row shows is
    // what the row is. Another entry of the path (one a copy's name happens
    // to coincide with) is not: the row shows the copy's content, so it is
    // the copy.
    let group = FolderGroupId(group_id.to_owned());
    let shown = row.version_hash();
    if crate::native_store::native_heads_at(conn, &group, &SyncPath(path.to_owned()))?
        .iter()
        .any(|head| head.payload.version == shown)
    {
        return Ok(None);
    }
    Ok(Some(target.source_path.as_str().to_owned()))
}

/// One mutation of a recursive operation after write-through, in the
/// order the operation commits them.
pub(crate) struct WrittenMutation {
    /// Its position in the operation as captured (what its evidence is
    /// aligned with).
    pub index: usize,
    pub mutation: yadorilink_replica_domain::session_state::PreparedLocalMutation,
    /// A copy's delete folded into its source's delete: its op names the
    /// source, the change carries the source's op once, and the version the
    /// copy showed counts as seen at the source (and its causal past as
    /// consumed). It directly follows the mutation that took the source.
    pub absorbed: bool,
}

/// [`write_recursive_operation_through`] over native heads:
/// each copy's source is decided by [`write_through_source`].
pub(crate) fn write_recursive_operation_through(
    conn: &Connection,
    group_id: &str,
    kind: &yadorilink_replica_domain::recursive_operation::RecursiveOperationKind,
    mutations: &[yadorilink_replica_domain::session_state::PreparedLocalMutation],
) -> Result<Vec<WrittenMutation>, SyncSqliteError> {
    write_recursive_operation_through_with(kind, mutations, |path| {
        write_through_source(conn, group_id, path)
    })
}

/// The write-through of a recursive operation's `mutations`, deciding each
/// copy's source with `source_of` (see [`write_recursive_operation_through`]).
fn write_recursive_operation_through_with(
    kind: &yadorilink_replica_domain::recursive_operation::RecursiveOperationKind,
    mutations: &[yadorilink_replica_domain::session_state::PreparedLocalMutation],
    mut source_of: impl FnMut(&str) -> Result<Option<String>, SyncSqliteError>,
) -> Result<Vec<WrittenMutation>, SyncSqliteError> {
    use yadorilink_replica_domain::ids::SyncPath;
    use yadorilink_replica_domain::local_op::Op;
    use yadorilink_replica_domain::recursive_operation::RecursiveOperationKind;
    use yadorilink_replica_domain::session_state::PreparedLocalMutation;

    let op_path = |op: &Op| match op {
        Op::Put { path, .. } | Op::Delete { path } => Some(path.as_str().to_string()),
        Op::Move { .. } => None,
    };
    let mut out = mutations.to_vec();
    // The source each delete of a copy is written through to. Decided before
    // any op is rewritten: a copy's own name is no longer an op path once its
    // delete names its source, and another copy's source may be that very
    // name (an ordinary entry whose name a copy of the same directory
    // coincides with on this device).
    let mut sources: std::collections::HashMap<usize, String> = std::collections::HashMap::new();
    for (index, mutation) in out.iter().enumerate() {
        let PreparedLocalMutation::Delete { record, op, .. } = mutation else { continue };
        if op_path(op).as_deref() != Some(record.path.as_str()) {
            continue;
        }
        if let Some(source) = source_of(&record.path)? {
            sources.insert(index, source);
        }
    }
    let mut taken: std::collections::HashSet<String> = mutations
        .iter()
        .enumerate()
        .filter(|(index, _)| !sources.contains_key(index))
        .filter_map(|(_, m)| op_path(m.op()))
        .collect();
    // Old copy path -> the source its delete was written through to.
    let mut written: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    // Copy index -> the source path its delete is folded into.
    let mut folded: std::collections::HashMap<usize, String> = std::collections::HashMap::new();
    for (index, mutation) in out.iter_mut().enumerate() {
        let PreparedLocalMutation::Delete { record, op, .. } = mutation else { continue };
        let Some(source) = sources.remove(&index) else { continue };
        *op = Op::Delete { path: SyncPath(source.clone()) };
        if !taken.insert(source.clone()) {
            folded.insert(index, source.clone());
        }
        written.insert(record.path.clone(), source);
    }
    if let RecursiveOperationKind::RenameTree { from, to } = kind {
        let (from, to) = (from.as_str(), to.as_str());
        for mutation in &mut out {
            let PreparedLocalMutation::Upsert { record, op, .. } = mutation else { continue };
            let Op::Put { path, .. } = op else { continue };
            let Some(rest) = path.as_str().strip_prefix(to) else { continue };
            if path.as_str() != record.path {
                continue;
            }
            // The copy moved with its directory: its source moves the same
            // way, so the new source is the old one under `to`.
            let Some(old_source) = written.get(&format!("{from}{rest}")) else { continue };
            let Some(source_rest) = old_source.strip_prefix(from) else { continue };
            // The destination may already hold the winner's put: the copy's
            // put is a second put at that source, a head concurrent with the
            // winner's, which the authoring signs as a follow-up delta.
            *path = SyncPath(format!("{to}{source_rest}"));
        }
    }
    // The mutation each source's op belongs to: the first delete of it
    // that is not folded.
    let mut owner: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for (index, mutation) in out.iter().enumerate() {
        if folded.contains_key(&index) {
            continue;
        }
        if let Op::Delete { path } = mutation.op() {
            owner.entry(path.as_str().to_string()).or_insert(index);
        }
    }
    let mut followers: std::collections::BTreeMap<usize, Vec<usize>> =
        std::collections::BTreeMap::new();
    for (&index, source) in &folded {
        let Some(&owner) = owner.get(source) else {
            // The source's op is a put: nothing to fold into, and the
            // change cannot carry a second op there.
            return Err(SyncSqliteError::InvalidInput(format!(
                "a recursive operation deletes a copy of {source:?} and writes {source:?} itself"
            )));
        };
        followers.entry(owner).or_default().push(index);
    }
    for indices in followers.values_mut() {
        indices.sort_unstable();
    }
    let mut ordered = Vec::with_capacity(out.len());
    let mut slots: Vec<Option<PreparedLocalMutation>> = out.into_iter().map(Some).collect();
    for index in 0..slots.len() {
        if folded.contains_key(&index) {
            continue;
        }
        let mutation = slots[index].take().expect("each mutation is placed once");
        ordered.push(WrittenMutation { index, mutation, absorbed: false });
        for &follower in followers.get(&index).into_iter().flatten() {
            let mutation = slots[follower].take().expect("each mutation is placed once");
            ordered.push(WrittenMutation { index: follower, mutation, absorbed: true });
        }
    }
    Ok(ordered)
}

/// Whether a single-op local write of the row at `record_path` whose op
/// is at `op_path` is a write-through: the op is at another path, and
/// `record_path` is bound as a copy of it.
pub(crate) fn write_through_op_path(
    conn: &Connection,
    group_id: &str,
    record_path: &str,
    op_path: &str,
) -> Result<bool, SyncSqliteError> {
    if op_path == record_path {
        return Ok(false);
    }
    Ok(crate::native_projection_binding::resolve_native_physical_path(conn, group_id, record_path)?
        .is_some_and(|target| target.source_path.as_str() == op_path))
}

#[cfg(test)]
mod tests {
    use yadorilink_replica_domain::file::{FileMeta, FileRecord, FileVersion, RecordKind};
    use yadorilink_replica_domain::ids::{SyncPath, VersionHash};
    use yadorilink_replica_domain::local_op::Op;
    use yadorilink_replica_domain::recursive_operation::RecursiveOperationKind;
    use yadorilink_replica_domain::session_state::PreparedLocalMutation;

    use super::*;

    fn version(mtime: i64) -> FileVersion {
        FileVersion::new(
            Vec::new(),
            0,
            FileMeta {
                mtime_unix_nanos: mtime,
                unix_mode: Some(0o644),
                symlink_target: None,
                record_kind: RecordKind::File,
                xattrs: Vec::new(),
            },
        )
    }

    fn record(path: &str, deleted: bool) -> FileRecord {
        FileRecord { path: path.into(), size: 0, mtime_unix_nanos: 1, blocks: Vec::new(), deleted }
    }

    fn delete(path: &str) -> PreparedLocalMutation {
        PreparedLocalMutation::Delete {
            record: record(path, true),
            op: Op::Delete { path: SyncPath(path.into()) },
            native_witness: None,
        }
    }

    fn upsert(path: &str, version: &FileVersion) -> PreparedLocalMutation {
        PreparedLocalMutation::Upsert {
            record: record(path, false),
            op: Op::Put { path: SyncPath(path.into()), version: version.version_hash },
            version: version.clone(),
            meta: None,
            native_witness: None,
        }
    }

    /// A copy whose name is also an ordinary entry's logical path: the copy's
    /// delete is written through to its source, which frees that name for the
    /// ordinary entry's own copy-shaped delete to name it as its source. The
    /// operation must not read the freed name as a second op at it.
    #[test]
    fn a_copys_name_that_is_another_entrys_source_is_not_a_second_op_at_it() {
        let (winner, loser, ordinary) = (version(1), version(2), version(3));
        let mutations = vec![
            delete("p/f"),
            delete("p/f (copy)"),
            delete("p/f (copy) (moved)"),
            upsert("q/f", &winner),
            upsert("q/f (copy)", &loser),
            upsert("q/f (copy) (moved)", &ordinary),
        ];
        let kind = RecursiveOperationKind::RenameTree {
            from: SyncPath("p".into()),
            to: SyncPath("q".into()),
        };

        let written = write_recursive_operation_through_with(&kind, &mutations, |path| {
            Ok(match path {
                "p/f (copy)" => Some("p/f".to_owned()),
                "p/f (copy) (moved)" => Some("p/f (copy)".to_owned()),
                _ => None,
            })
        })
        .unwrap();

        let ops: Vec<(String, String)> = written
            .iter()
            .map(|w| {
                let op = match w.mutation.op() {
                    Op::Put { path, .. } => format!("put {}", path.as_str()),
                    Op::Delete { path } => format!("delete {}", path.as_str()),
                    other => format!("{other:?}"),
                };
                (op, w.mutation.record().path.clone())
            })
            .collect();
        assert!(
            ops.iter().any(|(op, row)| op == "delete p/f (copy)" && row == "p/f (copy) (moved)"),
            "the displaced entry is deleted at its own source: {ops:?}"
        );
        assert!(
            ops.iter().any(|(op, row)| op == "put q/f (copy)" && row == "q/f (copy) (moved)"),
            "and moves to its own source under q: {ops:?}"
        );
    }

    /// `mv p q` over `p/f` held as a winner plus a conflict loser shown at a
    /// copy name: the loser moves with its directory, so its put is written
    /// through to the source `q/f` beside the winner's, never left at a name
    /// of its own that would make it an independent entry.
    #[test]
    fn a_directory_rename_writes_the_conflict_loser_through_beside_the_winner() {
        let (winner, loser) = (version(1), version(2));
        let mutations = vec![
            delete("p/f"),
            delete("p/f (copy)"),
            upsert("q/f", &winner),
            upsert("q/f (copy)", &loser),
        ];
        let kind = RecursiveOperationKind::RenameTree {
            from: SyncPath("p".into()),
            to: SyncPath("q".into()),
        };

        let written = write_recursive_operation_through_with(&kind, &mutations, |path| {
            Ok((path == "p/f (copy)").then(|| "p/f".to_owned()))
        })
        .unwrap();

        let puts: Vec<(&str, &str, VersionHash)> = written
            .iter()
            .filter_map(|w| match w.mutation.op() {
                Op::Put { path, version } => {
                    Some((path.as_str(), w.mutation.record().path.as_str(), *version))
                }
                _ => None,
            })
            .collect();
        assert_eq!(
            puts,
            vec![("q/f", "q/f", winner.version_hash), ("q/f", "q/f (copy)", loser.version_hash)],
            "both heads of the contested path move to the destination"
        );
    }
}
