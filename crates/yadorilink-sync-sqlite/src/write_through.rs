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
//! never an op at the copy name. A directory made where the copy was (a
//! type change) deletes the source first, then is a new entry of its own.

use rusqlite::{params, Connection, OptionalExtension};

use yadorilink_replica_domain::conflict::{conflict_copy_source_path, is_conflict_copy_path};
use yadorilink_replica_domain::file::RecordKind;
use yadorilink_replica_engine::conflict::PathHead;

use crate::dag_store::{get_file_version, path_gamma_heads};
use crate::error::SyncSqliteError;

/// The source entry a local operation on `path` is an operation on, when
/// `path` is a copy name at which the projection places one of the
/// source's live File or Symlink versions: `path`'s live row is that
/// version's content under the change that wrote it at the source (the
/// winner relocated or held there, a loser the current history wrote, or
/// a loser an installed base carries that nothing has named since), and
/// no change authored anything at `path` itself. `None` for every other
/// path, which authors at its own name.
///
/// The source's heads are its live path frontier, or, for a path no live
/// change has touched since a HistoryBase install, the installed base's
/// heads (the install relocates such a row the same way).
pub fn write_through_source(
    conn: &Connection,
    group_id: &str,
    path: &str,
) -> Result<Option<String>, SyncSqliteError> {
    if !is_conflict_copy_path(path) {
        return Ok(None);
    }
    let source = conflict_copy_source_path(path);
    if source == path {
        return Ok(None);
    }
    let Some(row) = crate::store::read_canonical_current_row(conn, group_id, path)? else {
        return Ok(None);
    };
    if row.snapshot.deleted
        || !matches!(row.snapshot.record_kind, RecordKind::File | RecordKind::Symlink)
    {
        return Ok(None);
    }
    let Some(authoring) = row.authoring_change_hash else { return Ok(None) };
    // Authored at its own name: an entry of its own, whatever it is named.
    if !path_gamma_heads(conn, group_id, path)?.is_empty() {
        return Ok(None);
    }
    let version = row.version_hash().0;
    let source_heads = path_gamma_heads(conn, group_id, &source)?;
    // The copy holds one of the source's live versions, under the change
    // that wrote it there: the placed winner, a version the current
    // history wrote concurrently with the one at the source, or one an
    // installed base carries that nothing has named since. Nothing
    // authored the copy; it is where that version is visible, and the
    // user deleting or editing it is acting on that version of the
    // source. The write names exactly that head and leaves every other
    // version of the source live beside it.
    let live = source_heads.iter().any(|head| {
        head.change_hash == authoring.0
            && head.content.as_ref().is_some_and(|content| content.version_hash == version)
    });
    if live {
        return Ok(Some(source));
    }
    let known = (version, row.snapshot.record_kind);
    let Some(leaves) = leaf_heads(conn, group_id, &source_heads, known)? else {
        return Ok(None);
    };
    // The copy still shows an earlier version of one of the source's
    // leaves: a later write of the source that descends from the one the
    // copy holds is admitted, and the reconcile has not yet moved the copy
    // -- whether that write now holds the source or itself sits at a copy
    // name. The user is still acting on that entry; the write is signed
    // without the heads the copy has not seen, so it stays concurrent with
    // them.
    if !wrote_version_at(conn, group_id, &authoring.0, &source, &version)? {
        return Ok(None);
    }
    for leaf in leaves {
        let leaf = yadorilink_replica_domain::ids::ChangeHash(leaf.change_hash);
        if crate::dag_store::path_frontier::is_ancestor_bounded(conn, &authoring, &leaf)? {
            return Ok(Some(source));
        }
    }
    Ok(None)
}

/// Whether `change` wrote `version` at `path` (its content effect there).
fn wrote_version_at(
    conn: &Connection,
    group_id: &str,
    change: &[u8; 32],
    path: &str,
    version: &[u8; 32],
) -> Result<bool, SyncSqliteError> {
    let written: Option<Option<Vec<u8>>> = conn
        .query_row(
            "SELECT version_hash FROM change_path_effects \
              WHERE group_id = ?1 AND path = ?2 AND change_hash = ?3",
            params![group_id, path, &change[..]],
            |row| row.get(0),
        )
        .optional()?;
    Ok(written.flatten().is_some_and(|written| written.as_slice() == version.as_slice()))
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

/// The recursive operation's `mutations` with every op on a copy name
/// written through to its source (see [`write_through_source`]): the
/// delete of a copy a recursive delete or rename observed is authored at
/// the entry the copy is, and a rename's put of that copy under the new
/// name at the entry's own new path. The rows stay where they are.
///
/// A copy whose source already has a delete in the operation (the version
/// at the source, or an explicit Directory there, deleted or moved with
/// it) is folded into that delete ([`WrittenMutation::absorbed`]): one
/// change carries one op per path, and that one delete supersedes every
/// version of the source the user was shown, at the source and at its
/// copies, and nothing else. A rename's put of such a copy stays at the
/// copy's new name, an entry of its own: the source's new path already
/// has the put of the version that was at the source.
pub(crate) fn write_recursive_operation_through(
    conn: &Connection,
    group_id: &str,
    kind: &yadorilink_replica_domain::recursive_operation::RecursiveOperationKind,
    mutations: &[yadorilink_replica_domain::session_state::PreparedLocalMutation],
) -> Result<Vec<WrittenMutation>, SyncSqliteError> {
    use yadorilink_replica_domain::change::Op;
    use yadorilink_replica_domain::ids::SyncPath;
    use yadorilink_replica_domain::recursive_operation::RecursiveOperationKind;
    use yadorilink_replica_domain::session_state::PreparedLocalMutation;

    let op_path = |op: &Op| match op {
        Op::Put { path, .. } | Op::Delete { path } => Some(path.as_str().to_string()),
        Op::Move { .. } => None,
    };
    let mut taken: std::collections::HashSet<String> =
        mutations.iter().filter_map(|m| op_path(m.op())).collect();
    let mut out = mutations.to_vec();
    // Old copy path -> the source its delete was written through to.
    let mut written: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    // Copy index -> the source path its delete is folded into.
    let mut folded: std::collections::HashMap<usize, String> = std::collections::HashMap::new();
    for (index, mutation) in out.iter_mut().enumerate() {
        let PreparedLocalMutation::Delete { record, op } = mutation else { continue };
        if op_path(op).as_deref() != Some(record.path.as_str()) {
            continue;
        }
        let Some(source) = write_through_source(conn, group_id, &record.path)? else { continue };
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
            if path.as_str() != record.path || !written.contains_key(&format!("{from}{rest}")) {
                continue;
            }
            let copy_source =
                yadorilink_replica_domain::conflict::conflict_copy_source_path(&record.path);
            let Some(source) = write_through_op_path(&record.path, &copy_source) else {
                continue;
            };
            if !taken.insert(source.to_string()) {
                continue;
            }
            *path = SyncPath(source.to_string());
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
/// `record_path` is a copy name of it. Returns the op path when it is.
pub(crate) fn write_through_op_path<'a>(record_path: &str, op_path: &'a str) -> Option<&'a str> {
    (op_path != record_path
        && is_conflict_copy_path(record_path)
        && conflict_copy_source_path(record_path) == op_path)
        .then_some(op_path)
}

/// The File and Symlink content heads: the versions the projection places
/// as the path's leaf (at the path, or relocated) or at a copy name of it.
/// `None` when a content head's kind is not known here (undecidable: never
/// a reason to write through). `known` is the kind of the version the
/// copy's row holds, which an installed base's head may name without this
/// replica holding the version itself.
fn leaf_heads(
    conn: &Connection,
    group_id: &str,
    heads: &[PathHead],
    known: ([u8; 32], RecordKind),
) -> Result<Option<Vec<PathHead>>, SyncSqliteError> {
    let mut leaves = Vec::new();
    for head in heads {
        let Some(content) = head.content.as_ref() else { continue };
        let kind = if content.version_hash == known.0 {
            known.1
        } else {
            let version = yadorilink_replica_domain::ids::VersionHash(content.version_hash);
            match get_file_version(conn, group_id, &version)? {
                Some(file_version) => file_version.meta.record_kind,
                None => return Ok(None),
            }
        };
        if matches!(kind, RecordKind::File | RecordKind::Symlink) {
            leaves.push(head.clone());
        }
    }
    Ok(Some(leaves))
}
