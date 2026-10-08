//! Authors a native `NativeDelta` for each local mutation (or one multi-op
//! delta for a bulk-captured run of them) and installs it via
//! `native_store::install_verified_delta`, under the device's own author.
//!
//! This runs inside the *same transaction* as the `files` row write
//! (`file_index::commit_local_mutation_in_tx` propagates this function's
//! `Result` with `?`, exactly like every other step of that commit) --
//! deliberately, not caught and swallowed: this crate's crash-sweep tests
//! assert every write step commits fully or not at all, and an authoring
//! failure silently absorbed mid-transaction while the rest of the
//! transaction still commits would violate that invariant. A failure here
//! therefore refuses the local mutation too.
//!
//! Scope: `Op::Put` (an ordinary edit/create), `Op::Delete`, and a
//! single-file `Op::Move` (the single-head rename: remove at the source, put
//! at the destination).
//!
//! # Write-through conflict-copy edits/deletes
//!
//! A conflict copy is *never* a durable authored entity -- it is a
//! losing head merely *displayed* at a copy-shaped name, recomputed fresh by
//! materialization on every pass (the name embeds mtime/content hash, so it
//! is not stable across edits). `write_through.rs` translates a user's
//! edit/delete of that displayed name into an ordinary `Op::Put`/`Op::Delete`
//! **at the source path**, naming only the specific loser it supersedes
//! (`crate::write_through::write_through_source`). So the `Op` this module
//! receives for a conflict-copy edit targets the *source* path, and the
//! actual on-disk row path (passed separately, since `Op` alone cannot
//! distinguish this from an ordinary edit) is the current display name of
//! the copy.
//!
//! To translate this, this module resolves the winner at the source path
//! (`resolve_winner`, the same decided tie-break as everywhere else) and
//! treats whichever other live head exists there as "the loser being
//! edited/deleted via its copy" -- `write_through_source` only ever fires
//! when there is exactly one entry not authored at its own name, so exactly
//! one non-winner candidate is the expected case. More than one cannot be
//! disambiguated from the recorded history and is skipped, not guessed at,
//! the same policy as any op this module cannot resolve.

use rusqlite::Connection;

use yadorilink_replica_domain::ids::{AuthorSeq, FolderGroupId, SyncPath, VersionHash};
use yadorilink_replica_domain::local_op::Op;
use yadorilink_replica_domain::native_state::{
    DeltaHash, Dot, HeadPayload, NativeCaptureWitness, NativeState, PathEdit,
};
use yadorilink_replica_domain::signed_delta::{DeltaOp, DeltaPut, HeadRef, NativeDelta};

use crate::error::SyncSqliteError;
use crate::local_author::LocalAuthor;
use crate::native_store;

/// The most ops one bulk-captured delta carries: a batch of local mutations at
/// distinct paths is signed as one delta of at most this many ops. The same
/// bound the initial import and the startup reconcile cut their chunks by, far
/// inside the decode limit on ops per delta.
pub const BULK_DELTA_MAX_OPS: usize = yadorilink_replica_domain::local_op::IMPORT_BATCH_OP_LIMIT;

/// The most bytes (estimated, never under the encoded size) the ops of one
/// bulk-captured delta may take on the wire: the bound the import and reconcile
/// chunks already share. A delta travels in one `DeltaBatch` entry beside its
/// proof under a per-item budget of a few MiB, so a batch of long paths is
/// signed as several deltas instead of one that could not be delivered.
pub const BULK_DELTA_MAX_BYTES: usize = yadorilink_replica_domain::local_op::MAX_CHANGE_OP_BYTES;

/// The native heads one authored mutation put, by the logical path
/// each landed at: what a `files` row produced by that mutation shows.
#[derive(Debug, Default, Clone)]
pub struct AuthoredPuts {
    puts: std::collections::BTreeMap<
        SyncPath,
        yadorilink_replica_domain::native_plan::NativeRowIdentity,
    >,
    /// Heads put in follow-up deltas, by the path and content they landed.
    follow_ups: std::collections::BTreeMap<
        (SyncPath, VersionHash),
        yadorilink_replica_domain::native_plan::NativeRowIdentity,
    >,
    /// The live heads at every path an authored delta touched, as the installs left them: the
    /// state each install computed and wrote, so what the transaction holds at those paths now.
    installed: std::collections::BTreeMap<SyncPath, crate::native_store::PathHeadsMap>,
    /// The obligation each touched path holds as the arming of its last delta left it.
    armed: std::collections::BTreeMap<String, crate::projection_obligations::ArmedObligation>,
    /// What authoring read for each row path before it wrote: the head the row is a copy of
    /// (`None` for an ordinary path).
    placed: std::collections::BTreeMap<SyncPath, Option<VersionHash>>,
}

impl AuthoredPuts {
    /// The head the mutation put at `path`, when it put one.
    pub fn put_at(
        &self,
        path: &SyncPath,
    ) -> Option<&yadorilink_replica_domain::native_plan::NativeRowIdentity> {
        self.puts.get(path)
    }

    /// The head the mutation put at `path` with content `version`: like
    /// [`Self::put_at`], but also finding a head signed as a follow-up when
    /// two mutations of one part put different content at the same path.
    pub fn put_of(
        &self,
        path: &SyncPath,
        version: &VersionHash,
    ) -> Option<&yadorilink_replica_domain::native_plan::NativeRowIdentity> {
        self.follow_ups.get(&(path.clone(), *version)).or_else(|| self.puts.get(path))
    }

    /// The live heads at `path` as the authoring left them, when a delta touched it.
    pub(crate) fn installed_heads_at(
        &self,
        path: &SyncPath,
    ) -> Option<&crate::native_store::PathHeadsMap> {
        self.installed.get(path)
    }

    /// The obligation at `path` as the arming of the last delta that touched it left it.
    pub(crate) fn armed_obligation_at(
        &self,
        path: &str,
    ) -> Option<&crate::projection_obligations::ArmedObligation> {
        self.armed.get(path)
    }

    /// What authoring found `row_path` to be a copy of before it wrote: `Some(None)` for an
    /// ordinary path, `None` when it did not read the path.
    pub(crate) fn placed_head_of(&self, row_path: &SyncPath) -> Option<Option<VersionHash>> {
        self.placed.get(row_path).copied()
    }

    /// Adds another part's puts.
    pub fn extend(&mut self, other: AuthoredPuts) {
        self.puts.extend(other.puts);
        self.follow_ups.extend(other.follow_ups);
        self.installed.extend(other.installed);
        self.armed.extend(other.armed);
        self.placed.extend(other.placed);
    }
}

/// Authors a delta for `op` as `author`, inside
/// `tx`. `row_path` is the actual on-disk row the mutation acts on
/// (`PreparedLocalMutation::record().path`) — equal to `op`'s own path for
/// an ordinary edit, and the conflict copy's current display name when
/// `write_through.rs` retargeted `op` to the source path (see the module
/// doc's write-through section). See the module doc for scope and the atomicity
/// contract.
pub fn author_op(
    tx: &Connection,
    group_id: &FolderGroupId,
    author: &LocalAuthor<'_>,
    op: &Op,
    row_path: &SyncPath,
) -> Result<AuthoredPuts, SyncSqliteError> {
    author_op_witnessed(tx, group_id, author, op, row_path, None)
}

/// [`author_op`] for a mutation captured earlier under `witness`: the
/// heads it supersedes are those of the content it displayed that the
/// capture saw (see [`NativeCaptureWitness::shown_class`]).
pub fn author_op_witnessed(
    tx: &Connection,
    group_id: &FolderGroupId,
    author: &LocalAuthor<'_>,
    op: &Op,
    row_path: &SyncPath,
    witness: Option<&NativeCaptureWitness>,
) -> Result<AuthoredPuts, SyncSqliteError> {
    let shown = shown_versions(tx, group_id, std::slice::from_ref(op), &[witness])?.remove(0);
    author_op_shown(tx, group_id, author, op, row_path, &shown)
}

/// One mutation of a bulk capture: the op, the row it acts on, and the
/// witness its capture recorded.
pub struct BulkOp<'a> {
    pub op: &'a Op,
    pub row_path: &'a SyncPath,
    pub witness: Option<&'a NativeCaptureWitness>,
}

/// Every path whose rows or heads authoring `item` reads or edits.
fn bulk_touched_paths<'a>(item: &'a BulkOp<'a>) -> Vec<&'a SyncPath> {
    let mut paths = op_paths(item.op);
    paths.push(item.row_path);
    if let Some(witness) = item.witness {
        paths.push(&witness.logical_source_path);
    }
    paths
}

/// Cuts `items` (in order) into the runs a bulk capture signs as one delta
/// each: consecutive mutations that touch pairwise unrelated paths -- no
/// shared path, and no path under another (a file and the directory it would
/// live in) -- at most [`BULK_DELTA_MAX_OPS`] of them. A mutation that touches
/// a path an earlier one of the run touches starts a new run, so per-path
/// ordering is exactly that of authoring them one by one. Each run is a
/// complete, independent edit set: it depends on no later run.
pub fn bulk_groups(items: &[BulkOp<'_>]) -> Vec<std::ops::Range<usize>> {
    let mut groups = Vec::new();
    let mut start = 0;
    let mut touched: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    for (index, item) in items.iter().enumerate() {
        let paths = bulk_touched_paths(item);
        let related = index - start >= BULK_DELTA_MAX_OPS
            || paths.iter().any(|path| paths_related(&touched, path.as_str()));
        if related {
            groups.push(start..index);
            start = index;
            touched.clear();
        }
        touched.extend(paths.iter().map(|path| path.as_str()));
    }
    if start < items.len() {
        groups.push(start..items.len());
    }
    groups
}

/// Whether `path` is, is under, or is above a path of `touched`.
fn paths_related(touched: &std::collections::BTreeSet<&str>, path: &str) -> bool {
    if touched.contains(path) {
        return true;
    }
    let mut ancestor = path;
    while let Some(slash) = ancestor.rfind('/') {
        ancestor = &ancestor[..slash];
        if touched.contains(ancestor) {
            return true;
        }
    }
    let below = format!("{path}/");
    touched.range::<&str, _>(below.as_str()..).next().is_some_and(|next| next.starts_with(&below))
}

/// The bytes an op for `edit` is estimated to take on the wire, with the kept
/// copies it may declare. Every head at the path the edit leaves in place may
/// be declared kept (an op declares at most [`MAX_KEEPS_PER_OP`] of them), so
/// those are counted without reading which of them the author's tree shows as
/// copies: an over-estimate only cuts a run sooner. A removal or a keep names
/// its head exactly (a length-prefixed device id, the incarnation, the sequence
/// and the header hash), so its size depends on the device id's length: the op
/// is charged for the longest names it could carry, never the first ones met.
///
/// [`MAX_KEEPS_PER_OP`]: yadorilink_replica_domain::signed_delta::MAX_KEEPS_PER_OP
fn estimated_edit_bytes(state: &NativeState, edit: &PathEdit) -> usize {
    use yadorilink_replica_domain::signed_delta::{MAX_KEEPS_PER_OP, MAX_REMOVES_PER_OP};
    /// What naming a head takes: 4 (length) + device id + 16 + 8 + 32.
    fn named_head_bytes(dot: &Dot) -> usize {
        60 + dot.author.device.0.len()
    }
    fn largest(mut sizes: Vec<usize>, limit: usize) -> usize {
        sizes.sort_unstable_by(|a, b| b.cmp(a));
        sizes.into_iter().take(limit).sum()
    }
    let removes = largest(edit.observed.iter().map(named_head_bytes).collect(), MAX_REMOVES_PER_OP);
    let kept = largest(
        state
            .heads_at(&edit.path)
            .filter(|head| !edit.observed.contains(&head.dot))
            .map(|head| named_head_bytes(&head.dot))
            .collect(),
        MAX_KEEPS_PER_OP,
    );
    // The path (length-prefixed), the counts, the put and the own-put flag.
    edit.path.as_str().len() + 64 + removes + kept
}

/// Authors one bulk capture run (see [`bulk_groups`]) as a single multi-op
/// delta: every mutation's edits are computed against the same pre-state and
/// signed together. A run whose ops would exceed
/// [`BULK_DELTA_MAX_BYTES`] is signed as consecutive deltas, a mutation's own
/// edits (a move's removal and put) never split across them. One mutation is
/// signed exactly as [`author_op_witnessed`] signs it.
pub fn author_bulk_group(
    tx: &Connection,
    group_id: &FolderGroupId,
    author: &LocalAuthor<'_>,
    items: &[BulkOp<'_>],
) -> Result<AuthoredPuts, SyncSqliteError> {
    if items.is_empty() {
        return Ok(AuthoredPuts::default());
    }
    let ops: Vec<Op> = items.iter().map(|item| item.op.clone()).collect();
    let witnesses: Vec<Option<&NativeCaptureWitness>> =
        items.iter().map(|item| item.witness).collect();
    let shown = shown_versions(tx, group_id, &ops, &witnesses)?;
    let state = native_store::load_heads_at_paths(tx, group_id, &paths_of_ops(&ops))?;
    let mut per_op: Vec<Vec<PathEdit>> = Vec::with_capacity(items.len());
    let mut authored = AuthoredPuts::default();
    for (item, shown) in items.iter().zip(&shown) {
        let placed = placed_head(tx, group_id, item.row_path)?;
        let edits = edits_for_op(&state, item.op, item.row_path, placed.as_ref(), shown)
            .ok_or_else(|| unauthorable(item.op, item.row_path))?;
        authored.placed.insert(item.row_path.clone(), placed);
        per_op.push(edits);
    }
    let mut pack: Vec<PathEdit> = Vec::new();
    let mut pack_bytes = 0usize;
    let flush = |pack: &mut Vec<PathEdit>| -> Result<AuthoredPuts, SyncSqliteError> {
        author_and_install(
            tx,
            group_id,
            author,
            &state,
            PartEdits { edits: std::mem::take(pack), follow_ups: Vec::new() },
            None,
            native_store::load_heads_at_paths,
        )
    };
    for edits in per_op {
        let bytes: usize = edits.iter().map(|edit| estimated_edit_bytes(&state, edit)).sum();
        if !pack.is_empty()
            && (pack.len() + edits.len() > BULK_DELTA_MAX_OPS
                || pack_bytes + bytes > BULK_DELTA_MAX_BYTES)
        {
            authored.extend(flush(&mut pack)?);
            pack_bytes = 0;
        }
        pack_bytes += bytes;
        pack.extend(edits);
    }
    if !pack.is_empty() {
        authored.extend(flush(&mut pack)?);
    }
    Ok(authored)
}

/// How authoring reads the live heads at the paths an operation names: a
/// `NativeState` holding at least those paths' heads. Admission reads nothing
/// of the state but the heads at the paths it edits, so production loads
/// exactly those ([`native_store::load_heads_at_paths`]) and the cost of a
/// mutation does not grow with the group.
type ReadHeads =
    fn(&Connection, &FolderGroupId, &[&SyncPath]) -> Result<NativeState, SyncSqliteError>;

/// The paths an op reads or edits.
fn op_paths(op: &Op) -> Vec<&SyncPath> {
    match op {
        Op::Put { path, .. } | Op::Delete { path } => vec![path],
        Op::Move { from, to, .. } => vec![from, to],
    }
}

/// The distinct paths of `ops`.
fn paths_of_ops<'a>(ops: impl IntoIterator<Item = &'a Op>) -> Vec<&'a SyncPath> {
    let mut paths: Vec<&SyncPath> = ops.into_iter().flat_map(op_paths).collect();
    paths.sort();
    paths.dedup();
    paths
}

/// [`author_op`] with what the writer was shown given rather than read.
fn author_op_shown(
    tx: &Connection,
    group_id: &FolderGroupId,
    author: &LocalAuthor<'_>,
    op: &Op,
    row_path: &SyncPath,
    shown: &Shown,
) -> Result<AuthoredPuts, SyncSqliteError> {
    author_op_shown_reading(
        tx,
        group_id,
        author,
        op,
        row_path,
        shown,
        native_store::load_heads_at_paths,
    )
}

fn author_op_shown_reading(
    tx: &Connection,
    group_id: &FolderGroupId,
    author: &LocalAuthor<'_>,
    op: &Op,
    row_path: &SyncPath,
    shown: &Shown,
    read_heads: ReadHeads,
) -> Result<AuthoredPuts, SyncSqliteError> {
    let state = read_heads(tx, group_id, &op_paths(op))?;
    let placed = placed_head(tx, group_id, row_path)?;
    let edits = edits_for_op(&state, op, row_path, placed.as_ref(), shown)
        .ok_or_else(|| unauthorable(op, row_path))?;
    author_and_install(
        tx,
        group_id,
        author,
        &state,
        PartEdits { edits, follow_ups: Vec::new() },
        None,
        read_heads,
    )
}

/// The refusal for an op native cannot author: writing the index row without
/// the delta would leave this device showing a change no peer ever receives.
fn unauthorable(op: &Op, row_path: &SyncPath) -> SyncSqliteError {
    SyncSqliteError::InvalidInput(format!(
        "{op:?} at the row {:?} cannot be authored natively (an unmodeled origin, or a write \
         through a copy that has no placement)",
        row_path.as_str()
    ))
}

/// The content the index row at `row_path` displays, when that row is a copy
/// of another path's entry (physical placement authority). Read before the
/// mutation rewrites the row.
fn placed_head(
    tx: &Connection,
    group_id: &FolderGroupId,
    row_path: &SyncPath,
) -> Result<Option<VersionHash>, SyncSqliteError> {
    Ok(crate::native_projection_binding::resolve_native_physical_path(
        tx,
        group_id.as_str(),
        row_path.as_str(),
    )?
    .map(|identity| identity.payload.version))
}

/// [`author_recursive_part`] with each op's capture-time witness, in
/// the same order as `ops_and_row_paths`.
pub fn author_recursive_part_witnessed(
    tx: &Connection,
    group_id: &FolderGroupId,
    author: &LocalAuthor<'_>,
    ops_and_row_paths: &[(Op, SyncPath)],
    witnesses: &[Option<&NativeCaptureWitness>],
) -> Result<AuthoredPuts, SyncSqliteError> {
    author_recursive_part_tagged(tx, group_id, author, ops_and_row_paths, witnesses, None)
}

/// [`author_recursive_part_witnessed`] naming the operation the part
/// belongs to in the deltas it signs. `recursive_part.part_index` is the index
/// of the part's first delta; each further delta of the part's chain takes the
/// next index (see [`recursive_part_delta_count`]).
pub fn author_recursive_part_tagged(
    tx: &Connection,
    group_id: &FolderGroupId,
    author: &LocalAuthor<'_>,
    ops_and_row_paths: &[(Op, SyncPath)],
    witnesses: &[Option<&NativeCaptureWitness>],
    recursive_part: Option<yadorilink_replica_domain::signed_delta::RecursivePart>,
) -> Result<AuthoredPuts, SyncSqliteError> {
    let ops: Vec<Op> = ops_and_row_paths.iter().map(|(op, _)| op.clone()).collect();
    let shown = shown_versions(tx, group_id, &ops, witnesses)?;
    author_part_shown(tx, group_id, author, ops_and_row_paths, &shown, recursive_part)
}

fn author_part_shown(
    tx: &Connection,
    group_id: &FolderGroupId,
    author: &LocalAuthor<'_>,
    ops_and_row_paths: &[(Op, SyncPath)],
    shown: &[Shown],
    recursive_part: Option<yadorilink_replica_domain::signed_delta::RecursivePart>,
) -> Result<AuthoredPuts, SyncSqliteError> {
    author_part_shown_reading(
        tx,
        group_id,
        author,
        ops_and_row_paths,
        shown,
        recursive_part,
        native_store::load_heads_at_paths,
    )
}

fn author_part_shown_reading(
    tx: &Connection,
    group_id: &FolderGroupId,
    author: &LocalAuthor<'_>,
    ops_and_row_paths: &[(Op, SyncPath)],
    shown: &[Shown],
    recursive_part: Option<yadorilink_replica_domain::signed_delta::RecursivePart>,
    read_heads: ReadHeads,
) -> Result<AuthoredPuts, SyncSqliteError> {
    if ops_and_row_paths.is_empty() {
        return Ok(AuthoredPuts::default());
    }
    let state =
        read_heads(tx, group_id, &paths_of_ops(ops_and_row_paths.iter().map(|(op, _)| op)))?;
    let PartEdits { edits, follow_ups } =
        part_edits(tx, group_id, &state, ops_and_row_paths, shown)?;
    author_and_install(
        tx,
        group_id,
        author,
        &state,
        PartEdits { edits, follow_ups },
        recursive_part,
        read_heads,
    )
}

/// The edits of one recursive part. A delta carries one op per path, so a
/// second put at a path the part already puts (a conflict loser that moved
/// with its directory, beside the winner) cannot ride in the same delta: it is
/// signed in a follow-up delta of the same author.
struct PartEdits {
    edits: Vec<PathEdit>,
    follow_ups: Vec<PathEdit>,
}

fn part_edits(
    tx: &Connection,
    group_id: &FolderGroupId,
    state: &NativeState,
    ops_and_row_paths: &[(Op, SyncPath)],
    shown: &[Shown],
) -> Result<PartEdits, SyncSqliteError> {
    let mut edits = Vec::with_capacity(ops_and_row_paths.len());
    // Puts of a copy that moved with its directory: a copy row with no
    // placement yet, written at the destination by this very operation.
    let mut moved_copies = Vec::new();
    for ((op, row_path), shown) in ops_and_row_paths.iter().zip(shown) {
        let placed = placed_head(tx, group_id, row_path)?;
        if let Op::Put { path, version } = op {
            if path != row_path && placed.is_none() {
                moved_copies.push((path.clone(), *version));
                continue;
            }
        }
        match edits_for_op(state, op, row_path, placed.as_ref(), shown) {
            Some(op_edits) => edits.extend(op_edits),
            None => return Err(unauthorable(op, row_path)),
        }
    }
    let mut put_paths: std::collections::BTreeSet<SyncPath> =
        edits.iter().filter(|edit| edit.put.is_some()).map(|edit| edit.path.clone()).collect();
    let mut follow_ups = Vec::new();
    for (path, version) in moved_copies {
        let edit = PathEdit {
            path: path.clone(),
            observed: Vec::new(),
            put: Some(HeadPayload { version, provenance: DeltaHash::default() }),
        };
        if put_paths.insert(path) {
            edits.push(edit);
        } else {
            follow_ups.push(edit);
        }
    }
    Ok(PartEdits { edits, follow_ups })
}

/// How many deltas authoring this recursive part would sign: none when every
/// op has nothing left to remove or put, otherwise its follow-up puts and its
/// chain of removals. The operation's part count is the sum over its parts, so
/// an operation whose deltas all authored is complete.
pub fn recursive_part_delta_count(
    tx: &Connection,
    group_id: &FolderGroupId,
    ops_and_row_paths: &[(Op, SyncPath)],
    witnesses: &[Option<&NativeCaptureWitness>],
) -> Result<u32, SyncSqliteError> {
    recursive_part_delta_count_reading(
        tx,
        group_id,
        ops_and_row_paths,
        witnesses,
        native_store::load_heads_at_paths,
    )
}

fn recursive_part_delta_count_reading(
    tx: &Connection,
    group_id: &FolderGroupId,
    ops_and_row_paths: &[(Op, SyncPath)],
    witnesses: &[Option<&NativeCaptureWitness>],
    read_heads: ReadHeads,
) -> Result<u32, SyncSqliteError> {
    let ops: Vec<Op> = ops_and_row_paths.iter().map(|(op, _)| op.clone()).collect();
    let shown = shown_versions(tx, group_id, &ops, witnesses)?;
    let state = read_heads(tx, group_id, &paths_of_ops(&ops))?;
    let PartEdits { edits, follow_ups } =
        part_edits(tx, group_id, &state, ops_and_row_paths, &shown)?;
    if edits.is_empty() {
        return Ok(0);
    }
    let edits = merge_edits(edits)?;
    Ok(plan_chain(tx, group_id, &state, edits, &follow_ups)?.steps.len() as u32)
}

/// The `PathEdit`s one op contributes, against a fixed pre-state `state`.
/// `None` means "skip" — a write-through conflict-copy resolution this
/// slice cannot disambiguate (see
/// [`conflict_copy_edits`]).
fn edits_for_op(
    state: &NativeState,
    op: &Op,
    row_path: &SyncPath,
    placed: Option<&VersionHash>,
    shown: &Shown,
) -> Option<Vec<PathEdit>> {
    match op {
        Op::Put { path, version } if path == row_path => {
            Some(vec![put_edit(state, path, *version, shown)])
        }
        Op::Put { path, version } => {
            conflict_copy_edits(state, path, row_path, Some(*version), placed, shown)
        }
        // A delete of a version native no longer shows has nothing to remove:
        // that entry authors nothing, and the rest of its part still does.
        Op::Delete { path } if path == row_path => {
            Some(delete_edit(state, path, shown).into_iter().collect())
        }
        Op::Delete { path } => conflict_copy_edits(state, path, row_path, None, placed, shown),
        Op::Move { from, to, version } => Some(
            delete_edit(state, from, shown)
                .into_iter()
                .chain(std::iter::once(put_edit(state, to, *version, shown)))
                .collect(),
        ),
    }
}

/// An edit or delete through a copy row
/// removes exactly the head that row shows (its physical placement) at
/// `source_path` and, for an edit, puts the new content at `source_path`, one
/// atomic mutation. Returns `None` when the row is no placed copy (no
/// placement: nothing to name, so nothing is guessed).
fn conflict_copy_edits(
    state: &NativeState,
    source_path: &SyncPath,
    _copy_path: &SyncPath,
    new_content: Option<VersionHash>,
    placed: Option<&VersionHash>,
    shown: &Shown,
) -> Option<Vec<PathEdit>> {
    // The copy row shows one piece of content (its placement's version), and
    // that content is what the operation supersedes: every head of it at
    // `source_path` the writer's capture held, wherever native currently orders
    // them, and the edited content lands at the logical source. No placement,
    // no guess. The heads may already be gone from the live set: then there is
    // nothing to remove, and an edit still lands its content beside whatever
    // is live, superseding nothing it was not shown.
    let placed = placed?;
    let observed = heads_of_shown_class(state, source_path, placed, shown.class_at(source_path));
    match new_content {
        Some(version) => {
            let payload = HeadPayload { version, provenance: DeltaHash::default() };
            Some(vec![PathEdit { path: source_path.clone(), observed, put: Some(payload) }])
        }
        None if observed.is_empty() => Some(Vec::new()),
        None => Some(vec![PathEdit { path: source_path.clone(), observed, put: None }]),
    }
}

/// What the writer was looking at when it made ONE op: for each path the op
/// touches, the version the index row displayed, and -- when a capture-time
/// witness is known -- the exact heads of the version at the op's source path
/// that the writer's state held. One per op: two ops of a recursive part can
/// act on the same source path with different rows (a winner and a folded
/// copy) and must not share what they were shown.
#[derive(Default, Debug)]
struct Shown {
    versions: std::collections::BTreeMap<SyncPath, Option<VersionHash>>,
    /// Restricts the heads of the shown version at this path that an edit
    /// supersedes to these. Unrestricted (every live head of the version) when
    /// absent, which is right when nothing was captured earlier than the
    /// authoring itself.
    class: Option<(SyncPath, std::collections::BTreeSet<Dot>)>,
}

impl Shown {
    /// The captured class for `path`, when this op has one for that path.
    fn class_at(&self, path: &SyncPath) -> Option<&std::collections::BTreeSet<Dot>> {
        self.class.as_ref().filter(|(source, _)| source == path).map(|(_, class)| class)
    }
}

fn shown_versions(
    tx: &Connection,
    group_id: &FolderGroupId,
    ops: &[Op],
    witnesses: &[Option<&NativeCaptureWitness>],
) -> Result<Vec<Shown>, SyncSqliteError> {
    let distinct: Vec<&str> = paths_of_ops(ops).into_iter().map(|path| path.as_str()).collect();
    let rows = crate::store::read_canonical_current_rows(tx, group_id.as_str(), &distinct)?;
    let mut all = Vec::with_capacity(ops.len());
    for (index, op) in ops.iter().enumerate() {
        let mut out = Shown::default();
        for path in op_paths(op) {
            out.versions.insert(
                path.clone(),
                rows.get(path.as_str())
                    .filter(|row| !row.snapshot.deleted)
                    .map(|row| row.version_hash()),
            );
        }
        // The witness names the source path the op acts on (for a write
        // through a copy row, the copy's source). What it recorded is what the
        // writer saw: the row is not read again, since it may have changed
        // since the capture.
        if let Some(Some(witness)) = witnesses.get(index) {
            if witness.shown_version.is_some() {
                out.versions.insert(witness.logical_source_path.clone(), witness.shown_version);
            }
            if !witness.shown_class.is_empty() {
                out.class = Some((
                    witness.logical_source_path.clone(),
                    witness.shown_class.iter().cloned().collect(),
                ));
            }
        }
        all.push(out);
    }
    Ok(all)
}

/// Every live head at `path` of the version its index row displayed -- the
/// content the writer saw, which is one piece of content however many heads
/// hold it (identical-content collapse) -- limited to the writer's captured
/// class when one is known, so a head that arrived after the capture is not
/// superseded by an edit that never saw it. Superseding is per exact head
/// (each removal names its `(path, dot, provenance)`). Nothing when the
/// row's version is not live in native (a new file, or content a peer
/// already superseded): the edit is then concurrent with what is live.
fn observed_target(state: &NativeState, path: &SyncPath, shown: &Shown) -> Vec<Dot> {
    let Some(Some(version)) = shown.versions.get(path) else { return Vec::new() };
    heads_of_shown_class(state, path, version, shown.class_at(path))
}

fn heads_of_shown_class(
    state: &NativeState,
    path: &SyncPath,
    version: &VersionHash,
    class: Option<&std::collections::BTreeSet<Dot>>,
) -> Vec<Dot> {
    let mut dots: Vec<Dot> = state
        .heads_at(path)
        .filter(|head| head.payload.version == *version)
        .filter(|head| class.is_none_or(|class| class.contains(&head.dot)))
        .map(|head| head.dot)
        .collect();
    dots.sort();
    // Every head of the class: a head left behind would resolve present again.
    // One op carries at most `MAX_REMOVES_PER_OP` removals on the wire, so a
    // larger class is signed as a chain of deltas by [`author_and_install`].
    dots
}

/// `None` when there is nothing to delete: the version the writer deleted is
/// not live in native, so no head is removed and no delta is owed.
fn delete_edit(state: &NativeState, path: &SyncPath, shown: &Shown) -> Option<PathEdit> {
    let observed = observed_target(state, path, shown);
    (!observed.is_empty()).then(|| PathEdit { path: path.clone(), observed, put: None })
}

fn put_edit(state: &NativeState, path: &SyncPath, version: VersionHash, shown: &Shown) -> PathEdit {
    let observed = observed_target(state, path, shown);
    PathEdit {
        path: path.clone(),
        observed,
        put: Some(HeadPayload { version, provenance: DeltaHash::default() }),
    }
}

/// Combines multiple `PathEdit`s at the same path into one, unioning their
/// observed dots -- needed because `NativeState::author` refuses more than one
/// edit per path in a single mutation, but a recursive-operation part can
/// legitimately produce two edits at the same source path (e.g. a directory
/// move's winner and a concurrent unresolved loser both removing their own dot
/// at the same pre-move path). A delta carries one put per path, so two edits
/// that both put are refused rather than one put being dropped; a caller that
/// has a second put chains it as a follow-up delta.
fn merge_edits(edits: Vec<PathEdit>) -> Result<Vec<PathEdit>, SyncSqliteError> {
    let mut merged: std::collections::BTreeMap<SyncPath, PathEdit> =
        std::collections::BTreeMap::new();
    for edit in edits {
        match merged.entry(edit.path.clone()) {
            std::collections::btree_map::Entry::Vacant(slot) => {
                slot.insert(edit);
            }
            std::collections::btree_map::Entry::Occupied(mut slot) => {
                let existing = slot.get_mut();
                if existing.put.is_some() && edit.put.is_some() {
                    return Err(SyncSqliteError::InvalidInput(format!(
                        "two puts at {:?} cannot share one delta",
                        edit.path.as_str()
                    )));
                }
                for dot in &edit.observed {
                    if !existing.observed.contains(dot) {
                        existing.observed.push(dot.clone());
                    }
                }
                if existing.put.is_none() {
                    existing.put = edit.put;
                }
            }
        }
    }
    Ok(merged.into_values().collect())
}

/// Refuses to sign as `author` unless it is this replica's current author
/// incarnation, and refuses when a peer has reported that incarnation ahead
/// in `group_id`. With no incarnation record at all nothing has ever been
/// rotated away, so no author can be a retired one and only the report check
/// applies (it finds nothing without a record). A rotation retires the
/// previous incarnation for good, including for handles built before it.
fn refuse_unless_current_author(
    conn: &Connection,
    group_id: &str,
    author: &yadorilink_replica_domain::author::AuthorId,
) -> Result<(), SyncSqliteError> {
    use yadorilink_replica_domain::author::AuthoringRefusal;
    let Some(current) = crate::author_incarnation::incarnation_record(conn)? else {
        return Ok(());
    };
    if current.author != *author {
        return Err(SyncSqliteError::AuthoringRefused {
            refusal: AuthoringRefusal::StaleAuthor {
                author: author.clone(),
                current: current.author,
            },
        });
    }
    if let Some(report) = crate::author_incarnation::own_author_ahead(conn, group_id)? {
        return Err(SyncSqliteError::AuthoringRefused {
            refusal: AuthoringRefusal::OwnAuthorAhead {
                author: report.author,
                local: report.local,
                reported: report.reported,
            },
        });
    }
    Ok(())
}

fn author_and_install(
    tx: &Connection,
    group_id: &FolderGroupId,
    author: &LocalAuthor<'_>,
    state: &NativeState,
    PartEdits { edits, follow_ups }: PartEdits,
    recursive_part: Option<yadorilink_replica_domain::signed_delta::RecursivePart>,
    read_heads: ReadHeads,
) -> Result<AuthoredPuts, SyncSqliteError> {
    refuse_unless_current_author(tx, group_id.as_str(), &author.author)?;
    if edits.is_empty() {
        // Every op deleted a version native no longer shows: nothing to author.
        return Ok(AuthoredPuts::default());
    }
    let edits = merge_edits(edits)?;
    // A put that would leave more than `MAX_SELF_HEADS` of this author's own
    // heads at a path is refused as such, so the caller can preserve the edit
    // as a conflict copy; left to fail at install, it surfaces as an opaque
    // invalid-input error and the same write is retried forever.
    if let Err(yadorilink_replica_domain::native_state::AuthorError::SelfHeadBound { path }) =
        state.check_edits(&author.author, &edits)
    {
        return Err(SyncSqliteError::AuthoringRefused {
            refusal: yadorilink_replica_domain::author::AuthoringRefusal::OwnBucketOverCap {
                path,
                count: yadorilink_replica_domain::author::MAX_SELF_HEADS + 1,
            },
        });
    }
    let current = native_store::frontier_entry_get(tx, group_id, &author.author)?;
    let mut seq = match &current {
        None => AuthorSeq::FIRST,
        Some(entry) => entry.seq.checked_next().ok_or_else(|| {
            SyncSqliteError::InvalidInput("author has reached the highest storable sequence".into())
        })?,
    };
    let mut prev = current.map(|entry| entry.tip);

    // A second put at a path another edit of this mutation puts (a conflict
    // loser that moved with its directory, beside the winner) cannot ride in the
    // same delta, so it is signed in a delta of its own, observing nothing at
    // the path, so it stays concurrent with the put it accompanies. These
    // deltas come FIRST in the chain: the main deltas below remove the source
    // heads, so a peer that has admitted only a prefix of the chain still holds
    // every piece of content it held before, never fewer.
    //
    // One op carries at most `MAX_REMOVES_PER_OP` removals, and one delta may
    // not name a path twice, so a class larger than that is removed by a chain
    // of this author's consecutive deltas, all signed and installed in this
    // transaction. Only the last delta carries the puts, so a peer that has
    // admitted a prefix of the chain still shows the content as present, never
    // as lost, and the path is absent (or holds the put) only once every head
    // of the class is gone. When the mutation is part of a recursive operation
    // every delta of the chain is tagged with consecutive part indexes.
    let max_removes = yadorilink_replica_domain::signed_delta::MAX_REMOVES_PER_OP;
    let max_keeps = yadorilink_replica_domain::signed_delta::MAX_KEEPS_PER_OP;
    let ChainPlan { planned, rounds, steps } = plan_chain(tx, group_id, state, edits, &follow_ups)?;
    let total = steps.len();
    // The kept heads of the follow-up being signed, read before its put is
    // installed and cut into chunks across its deltas.
    let mut follow_up_keeps: Vec<HeadRef> = Vec::new();

    let mut puts = std::collections::BTreeMap::new();
    let mut moved = std::collections::BTreeMap::new();
    let mut installed = std::collections::BTreeMap::new();
    let mut obligations = std::collections::BTreeMap::new();
    for (ordinal, step) in steps.iter().enumerate() {
        let ops = if let ChainStep::FollowUp { index, chunk } = *step {
            let edit = &follow_ups[index];
            let Some(payload) = &edit.put else { continue };
            let installed = read_heads(tx, group_id, &[&edit.path])?;
            if chunk > 0 {
                // Heads of the content beyond the first op's bound, kept by deltas
                // that follow the one that put it.
                vec![DeltaOp {
                    path: edit.path.clone(),
                    removes: Vec::new(),
                    put: None,
                    keeps: follow_up_keeps
                        .chunks(max_keeps)
                        .nth(chunk)
                        .unwrap_or_default()
                        .to_vec(),
                    keep_put: false,
                }]
            } else {
                if let Err(yadorilink_replica_domain::native_state::AuthorError::SelfHeadBound {
                    path,
                }) = installed.check_edits(&author.author, std::slice::from_ref(edit))
                {
                    return Err(SyncSqliteError::AuthoringRefused {
                        refusal:
                            yadorilink_replica_domain::author::AuthoringRefusal::OwnBucketOverCap {
                                path,
                                count: yadorilink_replica_domain::author::MAX_SELF_HEADS + 1,
                            },
                    });
                }
                // The author's own tree shows this content as a copy, and so every
                // head it holds of the same content at this path.
                follow_up_keeps = same_version_heads(&installed, &edit.path, payload.version);
                check_follow_up_keeps(&steps, index, follow_up_keeps.len(), &edit.path)?;
                vec![DeltaOp {
                    path: edit.path.clone(),
                    removes: Vec::new(),
                    put: Some(DeltaPut { version: payload.version }),
                    keeps: follow_up_keeps.chunks(max_keeps).next().unwrap_or_default().to_vec(),
                    keep_put: true,
                }]
            }
        } else {
            let ChainStep::Round(round) = *step else { unreachable!("a follow-up step") };
            let last_round = round + 1 == rounds;
            let mut ops = Vec::new();
            for (edit, keeps) in &planned {
                let removes: Vec<HeadRef> = edit
                    .observed
                    .chunks(max_removes)
                    .nth(round)
                    .unwrap_or_default()
                    .iter()
                    .map(|dot| HeadRef {
                        dot: dot.clone(),
                        provenance: provenance_of(state, &edit.path, dot),
                    })
                    .collect();
                let put = edit
                    .put
                    .as_ref()
                    .filter(|_| last_round)
                    .map(|payload| DeltaPut { version: payload.version });
                // Every kept head is named exactly once across the chain, at most
                // `MAX_KEEPS_PER_OP` per op; the head an op puts is kept by its own flag.
                let kept: Vec<HeadRef> =
                    keeps.heads.chunks(max_keeps).nth(round).unwrap_or_default().to_vec();
                if removes.is_empty() && put.is_none() && kept.is_empty() {
                    continue;
                }
                let keep_put = keeps.keep_put && put.is_some();
                ops.push(DeltaOp { path: edit.path.clone(), removes, put, keeps: kept, keep_put });
            }
            ops
        };
        let mut delta = NativeDelta {
            recursive_part: recursive_part.map(|part| {
                yadorilink_replica_domain::signed_delta::RecursivePart {
                    part_index: part.part_index + ordinal as u32,
                    ..part
                }
            }),
            group_id: group_id.clone(),
            author: author.author.clone(),
            seq,
            prev,
            ops,
            signature: [0u8; 64],
        };
        delta.sign(author.signing_key);
        let (_, installed_heads) = native_store::install_authored_delta(
            tx,
            group_id,
            &delta,
            &author.signing_key.verifying_key(),
            native_store::Admission::of(author.capture),
        )?;
        let armed = crate::native_desired_state::arm_projection_for_delta(
            tx,
            group_id.as_str(),
            &delta,
            true,
        )?;
        installed.extend(installed_heads);
        obligations.extend(armed);
        let (dot, provenance) = (delta.dot(), delta.delta_hash());
        if let ChainStep::FollowUp { index, chunk } = *step {
            let edit = &follow_ups[index];
            if let (0, Some(payload)) = (chunk, &edit.put) {
                moved.insert(
                    (edit.path.clone(), payload.version),
                    yadorilink_replica_domain::native_plan::NativeRowIdentity {
                        source_path: edit.path.clone(),
                        dot,
                        provenance,
                    },
                );
            }
        } else {
            puts.extend(delta.ops.iter().filter(|op| op.put.is_some()).map(|op| {
                (
                    op.path.clone(),
                    yadorilink_replica_domain::native_plan::NativeRowIdentity {
                        source_path: op.path.clone(),
                        dot: dot.clone(),
                        provenance,
                    },
                )
            }));
        }
        if ordinal + 1 < total {
            seq = seq.checked_next().ok_or_else(|| {
                SyncSqliteError::InvalidInput(
                    "author has reached the highest storable sequence".into(),
                )
            })?;
            prev = Some(provenance);
        }
    }
    Ok(AuthoredPuts {
        puts,
        follow_ups: moved,
        installed,
        armed: obligations,
        ..AuthoredPuts::default()
    })
}

/// The number of consecutive deltas the removals of `edits` need: one per
/// `MAX_REMOVES_PER_OP` of the largest class, and at least one.
fn chain_rounds(edits: &[PathEdit]) -> usize {
    let max_removes = yadorilink_replica_domain::signed_delta::MAX_REMOVES_PER_OP;
    edits.iter().map(|edit| edit.observed.len().div_ceil(max_removes)).max().unwrap_or(0).max(1)
}

/// One delta of a mutation's chain.
#[derive(Clone, Copy, Debug)]
enum ChainStep {
    /// The `chunk`th delta of follow-up `index`: the first puts the content, any
    /// further one keeps the heads of it the first op could not name.
    FollowUp { index: usize, chunk: usize },
    /// The `round`th delta of the main chain.
    Round(usize),
}

/// Refuses a follow-up whose kept heads outgrew the deltas planned for them,
/// which would leave some unnamed.
fn check_follow_up_keeps(
    steps: &[ChainStep],
    index: usize,
    kept: usize,
    path: &SyncPath,
) -> Result<(), SyncSqliteError> {
    let planned = steps
        .iter()
        .filter(|step| matches!(step, ChainStep::FollowUp { index: i, .. } if *i == index))
        .count();
    if kept.div_ceil(yadorilink_replica_domain::signed_delta::MAX_KEEPS_PER_OP) > planned {
        return Err(SyncSqliteError::InvalidInput(format!(
            "the heads of {:?} grew while its copies were being kept",
            path.as_str()
        )));
    }
    Ok(())
}

/// The deltas a mutation is signed as, and the kept copies each edit declares.
struct ChainPlan {
    planned: Vec<(PathEdit, DeclaredKeeps)>,
    rounds: usize,
    steps: Vec<ChainStep>,
}

/// Plans the chain of deltas for `edits` and `follow_ups` against `state`: one
/// main round per `MAX_REMOVES_PER_OP` removals or `MAX_KEEPS_PER_OP` kept
/// heads of the largest edit, and a follow-up's own deltas for the heads of its
/// content beyond one op's bound. Nothing is refused or cut short.
fn plan_chain(
    tx: &Connection,
    group_id: &FolderGroupId,
    state: &NativeState,
    edits: Vec<PathEdit>,
    follow_ups: &[PathEdit],
) -> Result<ChainPlan, SyncSqliteError> {
    let max_keeps = yadorilink_replica_domain::signed_delta::MAX_KEEPS_PER_OP;
    let mut rounds = chain_rounds(&edits);
    let mut planned = Vec::with_capacity(edits.len());
    for edit in edits {
        let keeps = declared_keeps(tx, group_id, state, &edit)?;
        rounds = rounds.max(keeps.heads.len().div_ceil(max_keeps));
        planned.push((edit, keeps));
    }
    let mut steps = Vec::new();
    for (index, edit) in follow_ups.iter().enumerate() {
        let Some(payload) = &edit.put else { continue };
        let kept = same_version_heads(state, &edit.path, payload.version).len();
        for chunk in 0..kept.div_ceil(max_keeps).max(1) {
            steps.push(ChainStep::FollowUp { index, chunk });
        }
    }
    steps.extend((0..rounds).map(ChainStep::Round));
    Ok(ChainPlan { planned, rounds, steps })
}

/// The kept-copy declaration one edit signs.
#[derive(Debug, Default)]
struct DeclaredKeeps {
    /// Exact heads at the edit's path the author's tree shows as conflict
    /// copies and the edit leaves in place.
    heads: Vec<HeadRef>,
    /// The edit was made through a copy: the head it puts is a kept copy too.
    keep_put: bool,
}

/// The live heads at `path` in `state` with `version`, as exact references.
fn same_version_heads(state: &NativeState, path: &SyncPath, version: VersionHash) -> Vec<HeadRef> {
    state
        .heads_at(path)
        .filter(|head| head.payload.version == version)
        .map(|head| HeadRef { dot: head.dot.clone(), provenance: head.payload.provenance })
        .collect()
}

/// What this author's own tree shows as conflict copies at `edit`'s path and
/// the edit leaves in place, plus whether an edit made through such a copy
/// puts a kept copy: the copies the author's user could see. The delta signs
/// each kept head exactly (`DeltaOp::keeps`, `DeltaOp::keep_put`), the whole
/// same-version cohort the author holds, so a replica that never saw the
/// contest still keeps them at their copy names while they live. A head put
/// later with the same content is not covered: its author declares it or it
/// is not kept.
fn declared_keeps(
    tx: &Connection,
    group_id: &FolderGroupId,
    state: &NativeState,
    edit: &PathEdit,
) -> Result<DeclaredKeeps, SyncSqliteError> {
    let copies = crate::native_projection_binding::shown_copy_versions(
        tx,
        group_id.as_str(),
        edit.path.as_str(),
    )?;
    if copies.is_empty() {
        return Ok(DeclaredKeeps::default());
    }
    let mut versions = std::collections::BTreeSet::new();
    let mut through_a_copy = false;
    for head in state.heads_at(&edit.path) {
        if !copies.contains(&head.payload.version) {
            continue;
        }
        if edit.observed.contains(&head.dot) {
            through_a_copy = true;
        } else {
            versions.insert(head.payload.version);
        }
    }
    let keep_put = through_a_copy && edit.put.is_some();
    if let (true, Some(put)) = (keep_put, &edit.put) {
        versions.insert(put.version);
    }
    let heads: Vec<HeadRef> = state
        .heads_at(&edit.path)
        .filter(|head| {
            versions.contains(&head.payload.version) && !edit.observed.contains(&head.dot)
        })
        .map(|head| HeadRef { dot: head.dot.clone(), provenance: head.payload.provenance })
        .collect();
    Ok(DeclaredKeeps { heads, keep_put })
}

fn provenance_of(state: &NativeState, path: &SyncPath, dot: &Dot) -> DeltaHash {
    state.heads_at(path).find(|h| h.dot == *dot).map(|h| h.payload.provenance).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use rusqlite::Connection;

    use yadorilink_replica_domain::author::{AuthorId, IncarnationId};
    use yadorilink_replica_domain::ids::DeviceId;

    use super::*;

    fn conn() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        crate::replica_tables::init(&c).unwrap();
        c
    }

    /// Records that the row at `copy_path` shows the head of `source` whose
    /// version is `[version; 32]` (what the reconciler does when it writes a
    /// copy).
    fn place_copy(c: &Connection, copy_path: &SyncPath, source: &str, version: u8) {
        place_copy_of(c, copy_path, source, VersionHash([version; 32]));
    }

    fn place_copy_of(c: &Connection, copy_path: &SyncPath, source: &str, version: VersionHash) {
        let state = native_store::load_state(c, &group()).unwrap();
        let head = state
            .heads_at(&SyncPath(source.into()))
            .find(|h| h.payload.version == version)
            .expect("the copy's head is live");
        crate::stable_projection_binding::native_placement_put(
            c,
            "g1",
            &crate::stable_projection_binding::NativePlacementRow {
                physical_path: copy_path.as_str().to_owned(),
                source_path: source.to_owned(),
                author: head.dot.author.device.0.clone(),
                incarnation: head.dot.author.incarnation.0,
                seq: head.dot.seq.get(),
                provenance: head.payload.provenance.0,
                version: head.payload.version.0,
                origin: "conflict_copy".to_owned(),
            },
        )
        .unwrap();
    }

    fn group() -> FolderGroupId {
        FolderGroupId("g1".into())
    }

    fn author() -> (LocalAuthorOwned, ed25519_dalek::SigningKey) {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
        let author = yadorilink_replica_domain::author::AuthorId {
            device: DeviceId("device-a".into()),
            incarnation: IncarnationId([1u8; 16]),
        };
        (LocalAuthorOwned { author }, signing_key)
    }

    /// `LocalAuthor` borrows its signing key; this test-only owned twin
    /// lets each test build one `SigningKey` and hand out `LocalAuthor`
    /// borrows from it without fighting the borrow checker across
    /// multiple `author_op` calls.
    struct LocalAuthorOwned {
        author: AuthorId,
    }

    impl LocalAuthorOwned {
        fn as_local<'a>(&self, key: &'a ed25519_dalek::SigningKey) -> LocalAuthor<'a> {
            LocalAuthor { author: self.author.clone(), signing_key: key, capture: None }
        }
    }

    /// The versions the writer was looking at: the native winner of every
    /// path the op touches, as an index row showing the current winner would
    /// say.
    fn seeing_winner(c: &Connection, ops: &[Op]) -> Vec<Shown> {
        use yadorilink_replica_domain::native_state::{resolve_winner, LiveHead};
        let state = native_store::load_state(c, &group()).unwrap();
        ops.iter()
            .map(|op| {
                let mut shown = Shown::default();
                let paths: Vec<&SyncPath> = match op {
                    Op::Put { path, .. } | Op::Delete { path } => vec![path],
                    Op::Move { from, to, .. } => vec![from, to],
                };
                for path in paths {
                    let heads: Vec<LiveHead> = state.heads_at(path).collect();
                    shown.versions.insert(
                        path.clone(),
                        resolve_winner(heads.iter()).map(|h| h.payload.version),
                    );
                }
                shown
            })
            .collect()
    }

    fn author_local_op(
        c: &Connection,
        local: &LocalAuthor<'_>,
        op: &Op,
        row_path: &SyncPath,
    ) -> Result<(), SyncSqliteError> {
        author_op_shown(
            c,
            &group(),
            local,
            op,
            row_path,
            &seeing_winner(c, std::slice::from_ref(op))[0],
        )
        .map(|_| ())
    }

    fn author_local_part(
        c: &Connection,
        local: &LocalAuthor<'_>,
        part: &[(Op, SyncPath)],
    ) -> Result<(), SyncSqliteError> {
        let ops: Vec<Op> = part.iter().map(|(op, _)| op.clone()).collect();
        author_part_shown(c, &group(), local, part, &seeing_winner(c, &ops), None).map(|_| ())
    }

    fn shown_of(path: &SyncPath, version: VersionHash) -> Shown {
        Shown { versions: [(path.clone(), Some(version))].into(), class: None }
    }

    fn direct_put(path: &str, version_byte: u8) -> Op {
        Op::Put { path: SyncPath(path.into()), version: VersionHash([version_byte; 32]) }
    }

    #[test]
    fn create_edit_delete_reflected_in_native_state_and_frontier_advances() {
        let c = conn();
        let (owned, key) = author();
        let local = owned.as_local(&key);

        author_local_op(&c, &local, &direct_put("x", 1), &SyncPath("x".into())).unwrap();
        let state = native_store::load_state(&c, &group()).unwrap();
        assert_eq!(state.heads_at(&SyncPath("x".into())).count(), 1);
        let frontier = native_store::load_frontier(&c, &group()).unwrap();
        assert_eq!(frontier[&owned.author].seq, AuthorSeq(1));

        author_local_op(&c, &local, &direct_put("x", 2), &SyncPath("x".into())).unwrap();
        let state = native_store::load_state(&c, &group()).unwrap();
        let heads: Vec<_> = state.heads_at(&SyncPath("x".into())).collect();
        assert_eq!(
            heads.len(),
            1,
            "an ordinary edit supersedes the prior head, not adds beside it"
        );
        assert_eq!(heads[0].payload.version, VersionHash([2u8; 32]));
        let frontier = native_store::load_frontier(&c, &group()).unwrap();
        assert_eq!(frontier[&owned.author].seq, AuthorSeq(2));

        author_local_op(
            &c,
            &local,
            &Op::Delete { path: SyncPath("x".into()) },
            &SyncPath("x".into()),
        )
        .unwrap();
        let state = native_store::load_state(&c, &group()).unwrap();
        assert_eq!(state.heads_at(&SyncPath("x".into())).count(), 0);
        let frontier = native_store::load_frontier(&c, &group()).unwrap();
        assert_eq!(frontier[&owned.author].seq, AuthorSeq(3));
    }

    /// An author whose own two heads at a path are versions the writer was
    /// not shown cannot put a third: the refusal is the typed one the capture
    /// layer turns into a conflict copy, and nothing is written.
    #[test]
    fn a_third_own_head_at_a_path_is_refused_as_over_cap() {
        let c = conn();
        let (owned, key) = author();
        let local = owned.as_local(&key);
        let x = SyncPath("x".into());
        let blind = Shown { versions: [(x.clone(), None)].into(), class: None };

        for version in [1u8, 2] {
            author_op_shown(&c, &group(), &local, &direct_put("x", version), &x, &blind).unwrap();
        }
        let before = native_store::load_frontier(&c, &group()).unwrap();
        let refused =
            author_op_shown(&c, &group(), &local, &direct_put("x", 3), &x, &blind).unwrap_err();

        assert!(
            matches!(
                refused,
                SyncSqliteError::AuthoringRefused {
                    refusal:
                        yadorilink_replica_domain::author::AuthoringRefusal::OwnBucketOverCap { .. }
                }
            ),
            "{refused:?}"
        );
        assert_eq!(native_store::load_frontier(&c, &group()).unwrap(), before, "nothing written");
    }

    #[test]
    fn rename_removes_at_source_and_puts_at_destination() {
        let c = conn();
        let (owned, key) = author();
        let local = owned.as_local(&key);

        author_local_op(&c, &local, &direct_put("old", 1), &SyncPath("old".into())).unwrap();
        author_local_op(
            &c,
            &local,
            &Op::Move {
                from: SyncPath("old".into()),
                to: SyncPath("new".into()),
                version: VersionHash([1u8; 32]),
            },
            &SyncPath("new".into()),
        )
        .unwrap();

        let state = native_store::load_state(&c, &group()).unwrap();
        assert_eq!(
            state.heads_at(&SyncPath("old".into())).count(),
            0,
            "source must be empty after the rename"
        );
        let new_heads: Vec<_> = state.heads_at(&SyncPath("new".into())).collect();
        assert_eq!(new_heads.len(), 1);
        assert_eq!(new_heads[0].payload.version, VersionHash([1u8; 32]));
    }

    #[test]
    fn chain_advances_correctly_across_many_authored_ops() {
        let c = conn();
        let (owned, key) = author();
        let local = owned.as_local(&key);

        for i in 1..=5u8 {
            author_local_op(&c, &local, &direct_put("x", i), &SyncPath("x".into())).unwrap();
        }
        let frontier = native_store::load_frontier(&c, &group()).unwrap();
        assert_eq!(frontier[&owned.author].seq, AuthorSeq(5));
        let state = native_store::load_state(&c, &group()).unwrap();
        assert_eq!(state.context_of(&owned.author), Some(AuthorSeq(5)));
    }

    fn author_b() -> (LocalAuthorOwned, ed25519_dalek::SigningKey) {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[4u8; 32]);
        let author =
            AuthorId { device: DeviceId("device-b".into()), incarnation: IncarnationId([1u8; 16]) };
        (LocalAuthorOwned { author }, signing_key)
    }

    /// Directly installs a create at `path` with an *empty* observed set,
    /// bypassing `author_op`'s ordinary-edit assumption
    /// (`observed = everything currently shown`) -- needed to simulate a
    /// genuinely concurrent write on a single shared `NativeState` (as two
    /// independent replicas would each capture their own write before
    /// either has seen the other's), the same way P1V's differential tests
    /// built a real two-head conflict.
    fn concurrent_create(
        c: &Connection,
        local: &LocalAuthor<'_>,
        path: &SyncPath,
        version_byte: u8,
    ) {
        concurrent_create_version(c, local, path, VersionHash([version_byte; 32]));
    }

    fn concurrent_create_version(
        c: &Connection,
        local: &LocalAuthor<'_>,
        path: &SyncPath,
        version: VersionHash,
    ) {
        let mut delta = NativeDelta {
            recursive_part: None,
            group_id: group(),
            author: local.author.clone(),
            seq: AuthorSeq::FIRST,
            prev: None,
            ops: vec![DeltaOp {
                path: path.clone(),
                removes: vec![],
                put: Some(DeltaPut { version }),
                keeps: Vec::new(),
                keep_put: false,
            }],
            signature: [0u8; 64],
        };
        delta.sign(local.signing_key);
        native_store::install_verified_delta(
            c,
            &group(),
            &delta,
            &local.signing_key.verifying_key(),
        )
        .unwrap();
    }

    /// Via write-through: a concurrent write leaves two live
    /// heads at "x"; editing the loser's on-disk copy name arrives here as
    /// `Op::Put(path="x", ...)` with `row_path` set to the copy's display
    /// name, distinct from "x". Must remove only the loser at "x" and put
    /// the new content at the copy's own path -- the winner untouched.
    #[test]
    fn write_through_edit_of_a_conflict_copy_resolves_the_loser_only() {
        let c = conn();
        let (owned_a, key_a) = author();
        let (owned_b, key_b) = author_b();
        let a = owned_a.as_local(&key_a);
        let b = owned_b.as_local(&key_b);

        // Two concurrent writes at "x", neither observing the other.
        concurrent_create(&c, &a, &SyncPath("x".into()), 1);
        concurrent_create(&c, &b, &SyncPath("x".into()), 2);

        let copy_path = SyncPath("x (conflicted copy, b)".into());
        place_copy(&c, &copy_path, "x", 2);
        // b edits its own loser's on-disk copy: write-through retargets the
        // op to the source path "x", naming only the head the copy shows.
        author_local_op(&c, &b, &direct_put("x", 3), &copy_path).unwrap();

        let state = native_store::load_state(&c, &group()).unwrap();
        let mut versions: Vec<_> =
            state.heads_at(&SyncPath("x".into())).map(|h| h.payload.version).collect();
        versions.sort();
        assert_eq!(
            versions,
            vec![VersionHash([1u8; 32]), VersionHash([3u8; 32])],
            "the winner stays and the edit lands at the real name; the shown loser is gone"
        );
        assert_eq!(state.heads_at(&copy_path).count(), 0, "a copy is not a path of its own");
    }

    /// Via write-through: deleting a conflict copy removes only
    /// the loser at the real name; nothing is put anywhere.
    #[test]
    fn write_through_delete_of_a_conflict_copy_removes_only_the_loser() {
        let c = conn();
        let (owned_a, key_a) = author();
        let (owned_b, key_b) = author_b();
        let a = owned_a.as_local(&key_a);
        let b = owned_b.as_local(&key_b);

        concurrent_create(&c, &a, &SyncPath("x".into()), 1);
        concurrent_create(&c, &b, &SyncPath("x".into()), 2);

        let copy_path = SyncPath("x (conflicted copy, b)".into());
        place_copy(&c, &copy_path, "x", 2);
        author_local_op(&c, &b, &Op::Delete { path: SyncPath("x".into()) }, &copy_path).unwrap();

        let state = native_store::load_state(&c, &group()).unwrap();
        let x_heads: Vec<_> = state.heads_at(&SyncPath("x".into())).collect();
        assert_eq!(x_heads.len(), 1, "the winner must survive the loser's copy being deleted");
        assert_eq!(x_heads[0].payload.version, VersionHash([1u8; 32]));
        assert_eq!(state.heads_at(&copy_path).count(), 0, "nothing should exist at the copy path");
    }

    /// With several losers live, the copy row's placement names exactly one
    /// of them; the operation removes that head and no other.
    #[test]
    fn a_placed_copy_among_several_losers_removes_exactly_its_head() {
        let c = conn();
        let (owned_a, key_a) = author();
        let a = owned_a.as_local(&key_a);
        let (owned_b, key_b) = author_b();
        let b = owned_b.as_local(&key_b);
        let (owned_c, key_c) = {
            let signing_key = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]);
            let author = AuthorId {
                device: DeviceId("device-c".into()),
                incarnation: IncarnationId([1u8; 16]),
            };
            (LocalAuthorOwned { author }, signing_key)
        };
        let c_author = owned_c.as_local(&key_c);

        concurrent_create(&c, &a, &SyncPath("x".into()), 1);
        concurrent_create(&c, &b, &SyncPath("x".into()), 2);
        concurrent_create(&c, &c_author, &SyncPath("x".into()), 3);
        let copy_path = SyncPath("x (conflicted copy, b)".into());
        place_copy(&c, &copy_path, "x", 2);

        author_local_op(&c, &b, &Op::Delete { path: SyncPath("x".into()) }, &copy_path).unwrap();

        let state = native_store::load_state(&c, &group()).unwrap();
        let mut versions: Vec<_> =
            state.heads_at(&SyncPath("x".into())).map(|h| h.payload.version).collect();
        versions.sort();
        assert_eq!(versions, vec![VersionHash([1u8; 32]), VersionHash([3u8; 32])]);
    }

    /// Two edits through the same copy row in a row: the second supersedes
    /// the head the first authored (the placement follows the row), so no
    /// stale edit stays live beside it.
    #[test]
    fn a_second_edit_through_a_copy_supersedes_the_first_edit() {
        let c = conn();
        let (owned_a, key_a) = author();
        let a = owned_a.as_local(&key_a);
        let (owned_b, key_b) = author_b();
        let b = owned_b.as_local(&key_b);
        concurrent_create(&c, &a, &SyncPath("x".into()), 1);
        concurrent_create(&c, &b, &SyncPath("x".into()), 2);
        let copy_path = SyncPath("x (conflicted copy, b)".into());
        place_copy(&c, &copy_path, "x", 2);

        author_local_op(&c, &b, &direct_put("x", 3), &copy_path).unwrap();
        crate::native_projection_binding::follow_write_through_edit(
            &c,
            "g1",
            copy_path.as_str(),
            &b.author,
            &VersionHash([3u8; 32]),
        )
        .unwrap();
        author_local_op(&c, &b, &direct_put("x", 4), &copy_path).unwrap();

        let state = native_store::load_state(&c, &group()).unwrap();
        let mut versions: Vec<_> =
            state.heads_at(&SyncPath("x".into())).map(|h| h.payload.version).collect();
        versions.sort();
        assert_eq!(versions, vec![VersionHash([1u8; 32]), VersionHash([4u8; 32])]);
    }

    /// The delta an author signed last, as decoded from the body it stored.
    fn last_delta(c: &Connection, author: &AuthorId) -> NativeDelta {
        let entry = native_store::frontier_entry_get(c, &group(), author).unwrap().unwrap();
        let body = native_store::fetch_delta_body(c, &group(), author, entry.seq).unwrap().unwrap();
        NativeDelta::from_wire_bytes(&body).unwrap()
    }

    /// Removing the winner while the loser is shown as a copy declares the
    /// loser kept, so a replica that never saw the contest keeps its name.
    #[test]
    fn removing_the_winner_declares_the_shown_copy_kept() {
        let c = conn();
        let (owned_a, key_a) = author();
        let a = owned_a.as_local(&key_a);
        let (owned_b, key_b) = author_b();
        let b = owned_b.as_local(&key_b);
        concurrent_create(&c, &a, &SyncPath("x".into()), 1);
        concurrent_create(&c, &b, &SyncPath("x".into()), 2);
        place_copy(&c, &SyncPath("x (conflicted copy, b)".into()), "x", 2);

        let state = native_store::load_state(&c, &group()).unwrap();
        let winner = state
            .heads_at(&SyncPath("x".into()))
            .find(|head| head.payload.version == VersionHash([1u8; 32]))
            .unwrap();
        let edit = PathEdit { path: SyncPath("x".into()), observed: vec![winner.dot], put: None };
        let keeps = declared_keeps(&c, &group(), &state, &edit).unwrap();
        let loser = state
            .heads_at(&SyncPath("x".into()))
            .find(|head| head.payload.version == VersionHash([2u8; 32]))
            .unwrap();
        assert_eq!(
            keeps.heads,
            vec![HeadRef { dot: loser.dot.clone(), provenance: loser.payload.provenance }],
            "the exact head shown as a copy is kept, not its version"
        );
        assert!(!keeps.keep_put);

        // A path with no copy shown declares nothing.
        let other = PathEdit { path: SyncPath("y".into()), observed: Vec::new(), put: None };
        let none = declared_keeps(&c, &group(), &state, &other).unwrap();
        assert!(none.heads.is_empty() && !none.keep_put);
    }

    /// More copies than one op can declare are planned as a chain of ops, never
    /// refused or cut short: every head is declared exactly once.
    #[test]
    fn more_shown_copies_than_an_op_can_keep_are_declared_across_a_chain() {
        let c = conn();
        let (owned_a, key_a) = author();
        let a = owned_a.as_local(&key_a);
        concurrent_create(&c, &a, &SyncPath("x".into()), 1);
        let many = yadorilink_replica_domain::signed_delta::MAX_KEEPS_PER_OP + 1;
        let mut state = native_store::load_state(&c, &group()).unwrap();
        for i in 0..many {
            let author_id = AuthorId {
                device: DeviceId(format!("device-{i}")),
                incarnation: IncarnationId([1u8; 16]),
            };
            let mut version = [0u8; 32];
            version[..8].copy_from_slice(&(i as u64 + 10).to_le_bytes());
            state
                .put(
                    &author_id,
                    SyncPath("x".into()),
                    &[],
                    HeadPayload {
                        version: VersionHash(version),
                        provenance: DeltaHash([i as u8; 32]),
                    },
                )
                .unwrap();
        }
        native_store::install_state(&c, &group(), &state).unwrap();
        for (i, head) in state
            .heads_at(&SyncPath("x".into()))
            .filter(|head| head.payload.version != VersionHash([1u8; 32]))
            .enumerate()
        {
            crate::stable_projection_binding::native_placement_put(
                &c,
                "g1",
                &crate::stable_projection_binding::NativePlacementRow {
                    physical_path: format!("x (copy {i})"),
                    source_path: "x".to_owned(),
                    author: head.dot.author.device.0.clone(),
                    incarnation: head.dot.author.incarnation.0,
                    seq: head.dot.seq.get(),
                    provenance: head.payload.provenance.0,
                    version: head.payload.version.0,
                    origin: "conflict_copy".to_owned(),
                },
            )
            .unwrap();
        }
        let winner = state
            .heads_at(&SyncPath("x".into()))
            .find(|head| head.payload.version == VersionHash([1u8; 32]))
            .unwrap();
        let edit = PathEdit { path: SyncPath("x".into()), observed: vec![winner.dot], put: None };
        let keeps = declared_keeps(&c, &group(), &state, &edit).unwrap();
        assert_eq!(keeps.heads.len(), many, "every shown copy is declared");
        let plan = plan_chain(&c, &group(), &state, vec![edit], &[]).unwrap();
        assert_eq!(plan.rounds, 2, "the declaration needs two ops");
    }

    /// A follow-up put whose content is held by more heads than one op can name is
    /// planned as the put and further deltas that keep the rest.
    #[test]
    fn a_follow_up_of_content_held_by_many_heads_is_planned_as_a_chain() {
        let c = conn();
        let many = yadorilink_replica_domain::signed_delta::MAX_KEEPS_PER_OP * 2 + 1;
        let mut state = native_store::load_state(&c, &group()).unwrap();
        for i in 0..many {
            let author_id = AuthorId {
                device: DeviceId(format!("device-{i}")),
                incarnation: IncarnationId([1u8; 16]),
            };
            let payload = HeadPayload {
                version: VersionHash([5u8; 32]),
                provenance: DeltaHash([i as u8; 32]),
            };
            state.put(&author_id, SyncPath("x".into()), &[], payload).unwrap();
        }
        let follow_up = PathEdit {
            path: SyncPath("x".into()),
            observed: Vec::new(),
            put: Some(HeadPayload {
                version: VersionHash([5u8; 32]),
                provenance: DeltaHash::default(),
            }),
        };
        let plan = plan_chain(&c, &group(), &state, Vec::new(), &[follow_up]).unwrap();
        let chunks: Vec<usize> = plan
            .steps
            .iter()
            .filter_map(|step| match step {
                ChainStep::FollowUp { chunk, .. } => Some(*chunk),
                ChainStep::Round(_) => None,
            })
            .collect();
        assert_eq!(chunks, vec![0, 1, 2], "every head of the content is named by a delta");
    }

    /// The longest device id the replication layer accepts.
    const MAX_DEVICE_ID_BYTES: usize = 256;

    fn author_named(index: usize, device_bytes: usize) -> AuthorId {
        AuthorId {
            device: DeviceId(format!("{index:0>device_bytes$}")),
            incarnation: IncarnationId([1u8; 16]),
        }
    }

    /// The bytes one op takes in the canonical delta encoding: a delta of that op
    /// less a delta of none.
    fn encoded_op_bytes(op: DeltaOp) -> usize {
        let delta = |ops: Vec<DeltaOp>| NativeDelta {
            recursive_part: None,
            group_id: group(),
            author: author_named(0, 1),
            seq: AuthorSeq::FIRST,
            prev: None,
            ops,
            signature: [0u8; 64],
        };
        delta(vec![op]).to_wire_bytes().len() - delta(Vec::new()).to_wire_bytes().len()
    }

    /// The estimate that cuts a bulk run is never under the canonical encoding of
    /// the op it stands for, whatever the lengths of the device ids the removals
    /// and the kept heads name, however many there are, and whichever of the
    /// heads an op declares: the estimate is checked against the largest op
    /// that can be signed from the heads at the path.
    #[test]
    fn the_estimate_of_an_edit_is_never_under_its_encoded_op() {
        use yadorilink_replica_domain::native_keep_model::Rng;
        use yadorilink_replica_domain::signed_delta::{MAX_KEEPS_PER_OP, MAX_REMOVES_PER_OP};
        let mut rng = Rng(21);
        for round in 0..200 {
            let heads = rng.below(2 * (MAX_KEEPS_PER_OP + MAX_REMOVES_PER_OP) + 1);
            let path = SyncPath("p".repeat(1 + rng.below(4000)));
            let mut state = NativeState::default();
            let mut dots = Vec::new();
            for i in 0..heads {
                // Mostly the longest ids, so a cut that took the first heads met would fall short.
                let len = if rng.chance(70) { MAX_DEVICE_ID_BYTES } else { 1 + rng.below(255) };
                let payload = HeadPayload {
                    version: VersionHash([1u8; 32]),
                    provenance: DeltaHash([i as u8; 32]),
                };
                dots.push(
                    state.put(&author_named(i, len), path.clone(), &[], payload).expect("put"),
                );
            }
            let observed: Vec<Dot> = dots
                .iter()
                .filter(|_| rng.chance(40))
                .take(2 * MAX_REMOVES_PER_OP)
                .cloned()
                .collect();
            let put = rng.chance(50).then(|| HeadPayload {
                version: VersionHash([2u8; 32]),
                provenance: DeltaHash::default(),
            });
            let edit =
                PathEdit { path: path.clone(), observed: observed.clone(), put: put.clone() };

            let removes_of = |dots: &[Dot]| -> Vec<HeadRef> {
                let mut sorted: Vec<&Dot> = dots.iter().collect();
                sorted.sort_by_key(|dot| std::cmp::Reverse(dot.author.device.0.len()));
                sorted
                    .into_iter()
                    .take(MAX_REMOVES_PER_OP)
                    .map(|dot| HeadRef {
                        dot: dot.clone(),
                        provenance: provenance_of(&state, &path, dot),
                    })
                    .collect()
            };
            let mut unobserved: Vec<HeadRef> = state
                .heads_at(&path)
                .filter(|head| !observed.contains(&head.dot))
                .map(|head| HeadRef { dot: head.dot.clone(), provenance: head.payload.provenance })
                .collect();
            unobserved.sort_by_key(|k| std::cmp::Reverse(k.dot.author.device.0.len()));
            unobserved.truncate(MAX_KEEPS_PER_OP);
            let op = DeltaOp {
                path: path.clone(),
                removes: removes_of(&observed),
                put: put.map(|payload| DeltaPut { version: payload.version }),
                keeps: unobserved,
                keep_put: edit.put.is_some(),
            };
            let encoded = encoded_op_bytes(op);
            let estimated = estimated_edit_bytes(&state, &edit);
            assert!(
                estimated >= encoded,
                "round {round}: estimated {estimated} < encoded {encoded}"
            );
        }
    }

    /// A bulk run at long paths, each op superseding a full class
    /// of heads and declaring a full cohort kept, with the longest device ids, is
    /// signed as deltas that each sum to no more than their estimate and fit one
    /// replication item: nothing authored can fail to be delivered.
    #[test]
    fn a_worst_case_bulk_run_is_signed_within_the_estimate_and_the_item_budget() {
        use yadorilink_replica_domain::signed_delta::{MAX_KEEPS_PER_OP, MAX_REMOVES_PER_OP};
        let c = conn();
        let (owned, key) = author();
        let local = owned.as_local(&key);
        // Enough ops of full cohorts to need several deltas; the bound on ops per
        // delta is covered by the property above and the bulk tests.
        let paths: Vec<SyncPath> =
            (0..128).map(|i| SyncPath(format!("{}/{i:04}", "d".repeat(3000)))).collect();
        let (old, copy) = (VersionHash([1u8; 32]), VersionHash([2u8; 32]));
        let mut state = native_store::load_state(&c, &group()).unwrap();
        let mut classes = Vec::new();
        for path in &paths {
            let mut class = Vec::new();
            for i in 0..MAX_REMOVES_PER_OP + MAX_KEEPS_PER_OP {
                let version = if i < MAX_REMOVES_PER_OP { old } else { copy };
                let payload = HeadPayload { version, provenance: DeltaHash([i as u8; 32]) };
                let dot = state
                    .put(&author_named(i + 1, MAX_DEVICE_ID_BYTES), path.clone(), &[], payload)
                    .unwrap();
                if i < MAX_REMOVES_PER_OP {
                    class.push(dot);
                }
            }
            class.sort();
            classes.push(class);
        }
        native_store::install_state(&c, &group(), &state).unwrap();
        for path in &paths {
            let head = state.heads_at(path).find(|head| head.payload.version == copy).unwrap();
            crate::stable_projection_binding::native_placement_put(
                &c,
                "g1",
                &crate::stable_projection_binding::NativePlacementRow {
                    physical_path: format!("{} (copy)", path.as_str()),
                    source_path: path.as_str().to_owned(),
                    author: head.dot.author.device.0.clone(),
                    incarnation: head.dot.author.incarnation.0,
                    seq: head.dot.seq.get(),
                    provenance: head.payload.provenance.0,
                    version: head.payload.version.0,
                    origin: "conflict_copy".to_owned(),
                },
            )
            .unwrap();
        }
        let ops: Vec<Op> = paths
            .iter()
            .map(|path| Op::Put { path: path.clone(), version: VersionHash([3u8; 32]) })
            .collect();
        let witnesses: Vec<NativeCaptureWitness> = paths
            .iter()
            .zip(&classes)
            .map(|(path, class)| NativeCaptureWitness {
                physical_path: path.clone(),
                logical_source_path: path.clone(),
                shown_head: None,
                shown_class: class.clone(),
                shown_version: Some(old),
            })
            .collect();
        let items: Vec<BulkOp<'_>> = ops
            .iter()
            .zip(&paths)
            .zip(&witnesses)
            .map(|((op, row_path), witness)| BulkOp { op, row_path, witness: Some(witness) })
            .collect();
        author_bulk_group(&c, &group(), &local, &items).unwrap();

        let signed = native_store::load_frontier(&c, &group()).unwrap()[&owned.author].seq.get();
        assert!(signed >= 2, "a run this size is cut into several deltas: {signed}");
        let mut keeps_named = 0usize;
        for seq in 1..=signed {
            let body = native_store::fetch_delta_body(&c, &group(), &owned.author, AuthorSeq(seq))
                .unwrap()
                .unwrap();
            assert!(body.len() <= yadorilink_replica_domain::protocol5::MAX_BATCH_ITEM_BYTES);
            let delta = NativeDelta::from_wire_bytes(&body).unwrap();
            let estimated: usize = delta
                .ops
                .iter()
                .map(|op| {
                    let observed = op.removes.iter().map(|r| r.dot.clone()).collect();
                    let edit = PathEdit { path: op.path.clone(), observed, put: None };
                    estimated_edit_bytes(&state, &edit)
                })
                .sum();
            let header = NativeDelta { ops: Vec::new(), ..delta.clone() }.to_wire_bytes().len();
            let encoded_ops = body.len() - header;
            assert!(estimated >= encoded_ops, "delta {seq}: estimated {estimated} < {encoded_ops}");
            keeps_named += delta.ops.iter().map(|op| op.keeps.len()).sum::<usize>();
        }
        assert_eq!(keeps_named, paths.len() * MAX_KEEPS_PER_OP, "every cohort is declared kept");
    }

    /// An edit made through a copy declares the content it puts kept: the
    /// author's tree keeps showing it at the copy's name.
    #[test]
    fn an_edit_through_a_copy_declares_its_new_content_kept() {
        let c = conn();
        let (owned_a, key_a) = author();
        let a = owned_a.as_local(&key_a);
        let (owned_b, key_b) = author_b();
        let b = owned_b.as_local(&key_b);
        concurrent_create(&c, &a, &SyncPath("x".into()), 1);
        concurrent_create(&c, &b, &SyncPath("x".into()), 2);
        let copy_path = SyncPath("x (conflicted copy, b)".into());
        place_copy(&c, &copy_path, "x", 2);

        author_local_op(&c, &b, &direct_put("x", 3), &copy_path).unwrap();

        let delta = last_delta(&c, &b.author);
        assert!(delta.ops[0].keep_put, "the head the edit puts is a kept copy");
        assert!(delta.ops[0].keeps.is_empty());
    }

    /// A copy row with no placement names nothing: the operation is refused,
    /// never guessed at and never written without its delta.
    #[test]
    fn a_copy_row_without_a_placement_is_refused_not_guessed_at() {
        let c = conn();
        let (owned_a, key_a) = author();
        let a = owned_a.as_local(&key_a);
        let (owned_b, key_b) = author_b();
        let b = owned_b.as_local(&key_b);
        concurrent_create(&c, &a, &SyncPath("x".into()), 1);
        concurrent_create(&c, &b, &SyncPath("x".into()), 2);
        let before = native_store::load_state(&c, &group()).unwrap();

        let copy_path = SyncPath("x (conflicted copy, b)".into());
        let refused = author_local_op(&c, &b, &direct_put("x", 4), &copy_path).unwrap_err();

        assert!(refused.to_string().contains("cannot be authored natively"), "{refused}");
        assert_eq!(before, native_store::load_state(&c, &group()).unwrap());
    }

    fn delete_op(path: &str) -> Op {
        Op::Delete { path: SyncPath(path.into()) }
    }

    /// `rm -rf dir` captured as one part with a
    /// Delete per entry lands as one atomic native delta removing every
    /// entry under the prefix.
    #[test]
    fn recursive_delete_part_removes_every_entry_atomically() {
        let c = conn();
        let (owned, key) = author();
        let local = owned.as_local(&key);

        author_local_op(&c, &local, &direct_put("dir", 1), &SyncPath("dir".into())).unwrap();
        author_local_op(&c, &local, &direct_put("dir/a", 2), &SyncPath("dir/a".into())).unwrap();
        author_local_op(&c, &local, &direct_put("dir/b", 3), &SyncPath("dir/b".into())).unwrap();

        let part = vec![
            (delete_op("dir"), SyncPath("dir".into())),
            (delete_op("dir/a"), SyncPath("dir/a".into())),
            (delete_op("dir/b"), SyncPath("dir/b".into())),
        ];
        author_local_part(&c, &local, &part).unwrap();

        let state = native_store::load_state(&c, &group()).unwrap();
        assert_eq!(state.heads_at(&SyncPath("dir".into())).count(), 0);
        assert_eq!(state.heads_at(&SyncPath("dir/a".into())).count(), 0);
        assert_eq!(state.heads_at(&SyncPath("dir/b".into())).count(), 0);
        // One atomic delta for the whole part, not three.
        let frontier = native_store::load_frontier(&c, &group()).unwrap();
        assert_eq!(
            frontier[&owned.author].seq,
            AuthorSeq(4),
            "3 creates + 1 atomic recursive delete = seq 4"
        );
    }

    /// A single-file rename only ever touches the
    /// renamed entry -- the per-entry op expansion means this needs no
    /// special casing here, it falls out of `edits_for_op` applied once.
    #[test]
    fn single_file_rename_part_touches_only_the_renamed_entry() {
        let c = conn();
        let (owned, key) = author();
        let local = owned.as_local(&key);
        author_local_op(&c, &local, &direct_put("dir/a", 1), &SyncPath("dir/a".into())).unwrap();

        let part = vec![(
            Op::Move {
                from: SyncPath("dir/a".into()),
                to: SyncPath("dir2/a".into()),
                version: VersionHash([1u8; 32]),
            },
            SyncPath("dir2/a".into()),
        )];
        author_local_part(&c, &local, &part).unwrap();

        let state = native_store::load_state(&c, &group()).unwrap();
        assert_eq!(state.heads_at(&SyncPath("dir/a".into())).count(), 0);
        assert_eq!(state.heads_at(&SyncPath("dir2/a".into())).count(), 1);
    }

    /// A directory move is a per-entry Delete/Put expansion for
    /// several entries at once, atomically -- proving the multi-entry case
    /// (not just a single file) needs no logic beyond what `edits_for_op`
    /// already provides per entry.
    #[test]
    fn directory_move_part_moves_every_entry_atomically() {
        let c = conn();
        let (owned, key) = author();
        let local = owned.as_local(&key);
        author_local_op(&c, &local, &direct_put("dir/a", 1), &SyncPath("dir/a".into())).unwrap();
        author_local_op(&c, &local, &direct_put("dir/b", 2), &SyncPath("dir/b".into())).unwrap();

        let part = vec![
            (
                Op::Move {
                    from: SyncPath("dir/a".into()),
                    to: SyncPath("dir2/a".into()),
                    version: VersionHash([1u8; 32]),
                },
                SyncPath("dir2/a".into()),
            ),
            (
                Op::Move {
                    from: SyncPath("dir/b".into()),
                    to: SyncPath("dir2/b".into()),
                    version: VersionHash([2u8; 32]),
                },
                SyncPath("dir2/b".into()),
            ),
        ];
        author_local_part(&c, &local, &part).unwrap();

        let state = native_store::load_state(&c, &group()).unwrap();
        assert_eq!(state.heads_at(&SyncPath("dir/a".into())).count(), 0);
        assert_eq!(state.heads_at(&SyncPath("dir/b".into())).count(), 0);
        assert_eq!(state.heads_at(&SyncPath("dir2/a".into())).count(), 1);
        assert_eq!(state.heads_at(&SyncPath("dir2/b".into())).count(), 1);
    }

    /// A genuine unresolved conflict (2+ live heads, no materialized copy
    /// row) at a path: an *ordinary* edit/delete there must supersede only
    /// the winner, never the concurrent loser it never observed (a write never
    /// supersedes a version its author did not observe).
    #[test]
    fn ordinary_edit_at_a_conflicted_path_touches_only_the_winner() {
        let c = conn();
        let (owned_a, key_a) = author();
        let (owned_b, key_b) = author_b();
        let a = owned_a.as_local(&key_a);
        let b = owned_b.as_local(&key_b);

        concurrent_create(&c, &a, &SyncPath("x".into()), 2); // winner (higher version)
        concurrent_create(&c, &b, &SyncPath("x".into()), 1); // loser

        // a edits the file it sees (the winner) at its real name.
        author_local_op(&c, &a, &direct_put("x", 3), &SyncPath("x".into())).unwrap();

        let state = native_store::load_state(&c, &group()).unwrap();
        let heads: Vec<_> = state.heads_at(&SyncPath("x".into())).collect();
        assert_eq!(
            heads.len(),
            2,
            "the concurrent loser must survive an edit that never observed it"
        );
        let versions: std::collections::BTreeSet<VersionHash> =
            heads.iter().map(|h| h.payload.version).collect();
        assert!(versions.contains(&VersionHash([3u8; 32])), "the edit itself must be live");
        assert!(
            versions.contains(&VersionHash([1u8; 32])),
            "the untouched loser must still be live"
        );
    }

    /// A peer's head that arrived and has not been projected here is not
    /// something the writer saw: an edit of the content the row still shows
    /// leaves it live beside the edit, whatever its version.
    #[test]
    fn an_edit_never_supersedes_a_head_the_row_did_not_show() {
        let c = conn();
        let (owned_a, key_a) = author();
        let (owned_b, key_b) = author_b();
        let a = owned_a.as_local(&key_a);
        let b = owned_b.as_local(&key_b);
        let x = SyncPath("x".into());

        // The peer's newer head is live; the row this device edits still
        // shows version 1, which the peer already superseded (no longer live).
        author_local_op(&c, &b, &direct_put("x", 9), &x).unwrap();

        let shown = shown_of(&x, VersionHash([1u8; 32]));
        author_op_shown(&c, &group(), &a, &direct_put("x", 3), &x, &shown).unwrap();

        let state = native_store::load_state(&c, &group()).unwrap();
        let versions: std::collections::BTreeSet<VersionHash> =
            state.heads_at(&x).map(|h| h.payload.version).collect();
        assert_eq!(
            versions,
            [VersionHash([9u8; 32]), VersionHash([3u8; 32])].into_iter().collect()
        );
    }

    /// The head an edit supersedes is the one whose version the row shows,
    /// even when another head would win the name.
    #[test]
    fn an_edit_supersedes_the_head_of_the_shown_version_not_the_winner() {
        let c = conn();
        let (owned_a, key_a) = author();
        let (owned_b, key_b) = author_b();
        let a = owned_a.as_local(&key_a);
        let b = owned_b.as_local(&key_b);
        let x = SyncPath("x".into());
        concurrent_create(&c, &a, &x, 1); // shown, the lower version
        concurrent_create(&c, &b, &x, 2); // unseen, the winner

        let shown = shown_of(&x, VersionHash([1u8; 32]));
        author_op_shown(&c, &group(), &a, &direct_put("x", 3), &x, &shown).unwrap();

        let state = native_store::load_state(&c, &group()).unwrap();
        let versions: std::collections::BTreeSet<VersionHash> =
            state.heads_at(&x).map(|h| h.payload.version).collect();
        assert_eq!(
            versions,
            [VersionHash([2u8; 32]), VersionHash([3u8; 32])].into_iter().collect()
        );
    }

    /// Deleting content native no longer shows removes nothing and authors
    /// nothing.
    #[test]
    fn deleting_a_version_native_no_longer_shows_authors_no_delta() {
        let c = conn();
        let (owned_a, key_a) = author();
        let (owned_b, key_b) = author_b();
        let a = owned_a.as_local(&key_a);
        let b = owned_b.as_local(&key_b);
        let x = SyncPath("x".into());
        author_local_op(&c, &b, &direct_put("x", 9), &x).unwrap();
        let before = native_store::load_frontier(&c, &group()).unwrap();

        let shown = shown_of(&x, VersionHash([1u8; 32]));
        author_op_shown(&c, &group(), &a, &Op::Delete { path: x.clone() }, &x, &shown).unwrap();

        assert_eq!(native_store::load_frontier(&c, &group()).unwrap(), before);
        let state = native_store::load_state(&c, &group()).unwrap();
        assert_eq!(state.heads_at(&x).count(), 1, "the peer's head is untouched");
    }

    fn author_c() -> (LocalAuthorOwned, ed25519_dalek::SigningKey) {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]);
        let author =
            AuthorId { device: DeviceId("device-c".into()), incarnation: IncarnationId([1u8; 16]) };
        (LocalAuthorOwned { author }, signing_key)
    }

    fn dot_of_device(c: &Connection, path: &str, device: &str) -> Dot {
        native_store::load_state(c, &group())
            .unwrap()
            .heads_at(&SyncPath(path.into()))
            .find(|h| h.dot.author.device.0 == device)
            .expect("that device has a head there")
            .dot
    }

    fn versions_at(c: &Connection, path: &str) -> std::collections::BTreeSet<VersionHash> {
        native_store::load_state(c, &group())
            .unwrap()
            .heads_at(&SyncPath(path.into()))
            .map(|h| h.payload.version)
            .collect()
    }

    fn witness_of_class(copy: &SyncPath, source: &str, class: &[Dot]) -> NativeCaptureWitness {
        NativeCaptureWitness {
            physical_path: copy.clone(),
            logical_source_path: SyncPath(source.into()),
            shown_head: None,
            shown_class: class.to_vec(),
            shown_version: Some(VersionHash([2u8; 32])),
        }
    }

    /// Two devices hold the same content (v2) at `x` beside a winner (v1) and
    /// a copy row shows it once.
    fn a_copy_of_content_held_by_two_heads(c: &Connection) -> SyncPath {
        let (oa, ka) = author();
        let (ob, kb) = author_b();
        let (oc, kc) = author_c();
        let x = SyncPath("x".into());
        concurrent_create(c, &oa.as_local(&ka), &x, 1);
        concurrent_create(c, &ob.as_local(&kb), &x, 2);
        concurrent_create(c, &oc.as_local(&kc), &x, 2);
        let copy = SyncPath("x (copy)".into());
        place_copy(c, &copy, "x", 2);
        copy
    }

    /// Deleting the copy row deletes the content it shows: every head of it
    /// the writer's capture held, so it does not come back as a new copy.
    #[test]
    fn deleting_a_copy_removes_every_head_of_the_content_it_showed() {
        let c = conn();
        let copy = a_copy_of_content_held_by_two_heads(&c);
        let (oa, ka) = author();
        let class = [dot_of_device(&c, "x", "device-b"), dot_of_device(&c, "x", "device-c")];
        let witness = witness_of_class(&copy, "x", &class);

        author_op_witnessed(
            &c,
            &group(),
            &oa.as_local(&ka),
            &Op::Delete { path: SyncPath("x".into()) },
            &copy,
            Some(&witness),
        )
        .unwrap();

        assert_eq!(versions_at(&c, "x"), [VersionHash([1u8; 32])].into_iter().collect());
    }

    /// A head of the same content that arrived after the capture was never
    /// seen by the writer: it survives the delete.
    #[test]
    fn a_head_of_the_same_content_that_arrived_after_the_capture_survives() {
        let c = conn();
        let copy = a_copy_of_content_held_by_two_heads(&c);
        let (oa, ka) = author();
        let captured_only_b = [dot_of_device(&c, "x", "device-b")];
        let witness = witness_of_class(&copy, "x", &captured_only_b);

        author_op_witnessed(
            &c,
            &group(),
            &oa.as_local(&ka),
            &Op::Delete { path: SyncPath("x".into()) },
            &copy,
            Some(&witness),
        )
        .unwrap();

        let devices: Vec<String> = native_store::load_state(&c, &group())
            .unwrap()
            .heads_at(&SyncPath("x".into()))
            .map(|h| h.dot.author.device.0.clone())
            .collect();
        assert!(
            devices.iter().any(|d| d == "device-c"),
            "c's head arrived after the capture and must live: {devices:?}"
        );
        assert!(
            !devices.iter().any(|d| d == "device-b"),
            "b's head was captured and must be gone: {devices:?}"
        );
        assert!(versions_at(&c, "x").contains(&VersionHash([2u8; 32])));
    }

    /// Editing the copy row supersedes the whole class too; the new content
    /// lands at the source.
    #[test]
    fn editing_a_copy_supersedes_every_head_of_the_content_it_showed() {
        let c = conn();
        let copy = a_copy_of_content_held_by_two_heads(&c);
        let (oa, ka) = author();
        let class = [dot_of_device(&c, "x", "device-b"), dot_of_device(&c, "x", "device-c")];
        let witness = witness_of_class(&copy, "x", &class);

        author_op_witnessed(
            &c,
            &group(),
            &oa.as_local(&ka),
            &direct_put("x", 9),
            &copy,
            Some(&witness),
        )
        .unwrap();

        assert_eq!(
            versions_at(&c, "x"),
            [VersionHash([1u8; 32]), VersionHash([9u8; 32])].into_iter().collect()
        );
    }

    /// An ordinary edit of content two heads hold leaves no copy of the old
    /// content behind.
    #[test]
    fn editing_content_held_by_two_heads_leaves_no_copy_of_the_old_content() {
        let c = conn();
        let (oa, ka) = author();
        let (ob, kb) = author_b();
        let x = SyncPath("x".into());
        concurrent_create(&c, &oa.as_local(&ka), &x, 1);
        concurrent_create(&c, &ob.as_local(&kb), &x, 1);
        let shown = shown_of(&x, VersionHash([1u8; 32]));

        author_op_shown(&c, &group(), &oa.as_local(&ka), &direct_put("x", 3), &x, &shown).unwrap();

        assert_eq!(versions_at(&c, "x"), [VersionHash([3u8; 32])].into_iter().collect());
    }

    /// The index row is not read again at commit: what the capture recorded is
    /// what the writer saw, so a row that changed in between cannot redirect
    /// which content the edit supersedes.
    #[test]
    fn the_witness_not_the_row_at_commit_decides_which_content_was_shown() {
        let c = conn();
        let (oa, ka) = author();
        let (ob, kb) = author_b();
        let x = SyncPath("x".into());
        concurrent_create(&c, &oa.as_local(&ka), &x, 1);
        concurrent_create(&c, &ob.as_local(&kb), &x, 2);
        let seen_v1 = NativeCaptureWitness {
            physical_path: x.clone(),
            logical_source_path: x.clone(),
            shown_head: None,
            shown_class: vec![dot_of_device(&c, "x", "device-a")],
            shown_version: Some(VersionHash([1u8; 32])),
        };
        // The index row at x has meanwhile been replaced by content 2's.
        let shown =
            shown_versions(&c, &group(), &[Op::Delete { path: x.clone() }], &[Some(&seen_v1)])
                .unwrap();
        assert_eq!(shown[0].versions.get(&x), Some(&Some(VersionHash([1u8; 32]))));
    }

    /// 65 devices created identical content at `x`; one replica holds every head and its
    /// user deletes the single visible file. Every head goes, however many ops that takes, and
    /// a peer admitting the produced deltas one by one ends with `x` absent too.
    #[test]
    fn deleting_a_class_larger_than_an_op_can_carry_removes_every_head_on_both_replicas() {
        use yadorilink_replica_domain::signed_delta::MAX_REMOVES_PER_OP;
        let c = conn();
        let (oa, ka) = author();
        let x = SyncPath("x".into());
        let mut state = NativeState::new();
        for i in 0..(MAX_REMOVES_PER_OP + 1) {
            let who = AuthorId {
                device: DeviceId(format!("dev-{i:03}")),
                incarnation: IncarnationId([1u8; 16]),
            };
            state
                .put(
                    &who,
                    x.clone(),
                    &[],
                    HeadPayload {
                        version: VersionHash([1u8; 32]),
                        provenance: DeltaHash([i as u8 + 1; 32]),
                    },
                )
                .unwrap();
        }
        native_store::install_state(&c, &group(), &state).unwrap();
        let peer = conn();
        native_store::install_state(&peer, &group(), &state).unwrap();
        let shown = shown_of(&x, VersionHash([1u8; 32]));

        author_op_shown(
            &c,
            &group(),
            &oa.as_local(&ka),
            &Op::Delete { path: x.clone() },
            &x,
            &shown,
        )
        .unwrap();

        assert_eq!(native_store::load_state(&c, &group()).unwrap().heads_at(&x).count(), 0);

        // Every delta a peer can decode, admitted one by one in sequence order.
        let author_id = oa.author.clone();
        let last = native_store::load_frontier(&c, &group()).unwrap()[&author_id].seq.get();
        assert!(last >= 2, "the class needs more than one delta");
        for n in 1..=last {
            let body = native_store::fetch_delta_body(&c, &group(), &author_id, AuthorSeq(n))
                .unwrap()
                .expect("the delta body is stored");
            let delta =
                NativeDelta::from_wire_bytes(&body).expect("a peer can decode what was authored");
            assert!(delta.ops.iter().all(|op| op.removes.len() <= MAX_REMOVES_PER_OP));
            native_store::install_verified_delta(&peer, &group(), &delta, &ka.verifying_key())
                .unwrap();
            let remaining = native_store::load_state(&peer, &group()).unwrap();
            let expected = if n == last {
                0
            } else {
                MAX_REMOVES_PER_OP + 1 - n as usize * MAX_REMOVES_PER_OP
            };
            assert_eq!(remaining.heads_at(&x).count(), expected);
        }
    }

    /// Every delta of a chained delete is a part of the recursive operation it
    /// belongs to: the removal of each head, whichever chunk it was in, is
    /// attributed to the operation (a folder restore finds the operation by the
    /// head the trashed row showed), and a replica that has admitted only a
    /// prefix of the chain does not report the operation complete.
    #[test]
    fn every_delta_of_a_chained_recursive_delete_carries_the_operation() {
        use yadorilink_replica_domain::recursive_operation::{
            RecursiveOperationId, RecursiveOperationRef,
        };
        use yadorilink_replica_domain::signed_delta::{RecursivePart, MAX_REMOVES_PER_OP};
        let c = conn();
        let (oa, ka) = author();
        let x = SyncPath("x".into());
        let mut state = NativeState::new();
        for i in 0..(MAX_REMOVES_PER_OP + 1) {
            let who = AuthorId {
                device: DeviceId(format!("dev-{i:03}")),
                incarnation: IncarnationId([1u8; 16]),
            };
            let payload = HeadPayload {
                version: VersionHash([1u8; 32]),
                provenance: DeltaHash([i as u8 + 1; 32]),
            };
            state.put(&who, x.clone(), &[], payload).unwrap();
        }
        native_store::install_state(&c, &group(), &state).unwrap();
        let peer = conn();
        native_store::install_state(&peer, &group(), &state).unwrap();

        let operation_id = RecursiveOperationId([5u8; 16]);
        author_part_shown(
            &c,
            &group(),
            &oa.as_local(&ka),
            &[(Op::Delete { path: x.clone() }, x.clone())],
            &[shown_of(&x, VersionHash([1u8; 32]))],
            Some(RecursivePart { operation_id, part_index: 0, part_count: 2 }),
        )
        .unwrap();

        let operation = RecursiveOperationRef { author: oa.author.device.clone(), operation_id };
        let last = native_store::load_frontier(&c, &group()).unwrap()[&oa.author].seq.get();
        assert_eq!(last, 2, "the class takes two deltas");
        for n in 1..=last {
            let body = native_store::fetch_delta_body(&c, &group(), &oa.author, AuthorSeq(n))
                .unwrap()
                .unwrap();
            let delta = NativeDelta::from_wire_bytes(&body).unwrap();
            let part = delta.recursive_part.expect("every delta of the chain is tagged");
            assert_eq!(
                (part.operation_id, part.part_index, part.part_count),
                (operation_id, n as u32 - 1, 2)
            );
            for removal in delta.ops.iter().flat_map(|op| &op.removes) {
                assert_eq!(
                    crate::native_recursive_operation::operation_removing(
                        &c,
                        "g1",
                        "x",
                        &removal.provenance.0
                    )
                    .unwrap(),
                    Some(operation.clone()),
                    "the removal of {:?} is attributed",
                    removal.provenance
                );
            }
            native_store::install_verified_delta(&peer, &group(), &delta, &ka.verifying_key())
                .unwrap();
            let complete =
                crate::native_recursive_operation::completeness(&peer, "g1", &operation).unwrap();
            assert_eq!(
                complete
                    == crate::native_recursive_operation::NativeOperationCompleteness::Complete,
                n == last,
                "complete only after every delta of the chain"
            );
        }
    }

    /// Two ops of one recursive part can act on the same source path with
    /// different rows -- the winner's and a folded copy's -- and each removes
    /// the content ITS row showed.
    #[test]
    fn two_ops_of_a_part_on_one_source_path_each_remove_what_their_own_row_showed() {
        let c = conn();
        let (oa, ka) = author();
        let (ob, kb) = author_b();
        let x = SyncPath("x".into());
        concurrent_create(&c, &oa.as_local(&ka), &x, 1); // the winner's row shows v1
        concurrent_create(&c, &ob.as_local(&kb), &x, 2); // a folded copy row shows v2
        let copy = SyncPath("x (copy)".into());
        place_copy(&c, &copy, "x", 2);
        let winner_seen = NativeCaptureWitness {
            physical_path: x.clone(),
            logical_source_path: x.clone(),
            shown_head: None,
            shown_class: vec![dot_of_device(&c, "x", "device-a")],
            shown_version: Some(VersionHash([1u8; 32])),
        };
        let copy_seen = witness_of_class(&copy, "x", &[dot_of_device(&c, "x", "device-b")]);
        let part = vec![
            (Op::Delete { path: x.clone() }, x.clone()),
            (Op::Delete { path: x.clone() }, copy.clone()),
        ];

        author_recursive_part_witnessed(
            &c,
            &group(),
            &oa.as_local(&ka),
            &part,
            &[Some(&winner_seen), Some(&copy_seen)],
        )
        .unwrap();

        assert!(
            versions_at(&c, "x").is_empty(),
            "both rows' content is gone: {:?}",
            versions_at(&c, "x")
        );
    }

    fn file_version(mtime: i64) -> yadorilink_replica_domain::file::FileVersion {
        use yadorilink_replica_domain::file::{FileMeta, FileVersion, RecordKind};
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

    /// `p/f` holds a winner by device-a and a loser by device-b, the loser
    /// shown at a copy name. Returns the part a `mv p q` captures after
    /// write-through: both deletes at `p/f`, then both puts at `q/f`, the
    /// loser's from the row at its (moved) copy name.
    struct MovedContest {
        winner: VersionHash,
        loser: VersionHash,
        moved_copy: SyncPath,
        part: Vec<(Op, SyncPath)>,
        witnesses: Vec<Option<NativeCaptureWitness>>,
    }

    fn contested_directory(c: &Connection) -> MovedContest {
        let (oa, ka) = author();
        let (ob, kb) = author_b();
        // Concurrent heads are ordered by version hash: the larger one wins.
        let (mut winner, mut loser) = (file_version(1), file_version(2));
        if winner.version_hash < loser.version_hash {
            std::mem::swap(&mut winner, &mut loser);
        }
        for version in [&winner, &loser] {
            crate::dag_store::put_file_version(c, "g1", version).unwrap();
        }
        let (winner, loser) = (winner.version_hash, loser.version_hash);
        let from = SyncPath("p/f".into());
        concurrent_create_version(c, &oa.as_local(&ka), &from, winner);
        concurrent_create_version(c, &ob.as_local(&kb), &from, loser);
        let old_copy = SyncPath("p/f (copy)".into());
        place_copy_of(c, &old_copy, "p/f", loser);
        let witness = |physical: &SyncPath, device: &str, version: VersionHash| {
            Some(NativeCaptureWitness {
                physical_path: physical.clone(),
                logical_source_path: from.clone(),
                shown_head: None,
                shown_class: vec![dot_of_device(c, "p/f", device)],
                shown_version: Some(version),
            })
        };
        let to = SyncPath("q/f".into());
        let moved_copy = SyncPath("q/f (copy)".into());
        MovedContest {
            winner,
            loser,
            part: vec![
                (Op::Delete { path: from.clone() }, from.clone()),
                (Op::Delete { path: from.clone() }, old_copy.clone()),
                (Op::Put { path: to.clone(), version: winner }, to.clone()),
                (Op::Put { path: to, version: loser }, moved_copy.clone()),
            ],
            witnesses: vec![
                witness(&from, "device-a", winner),
                witness(&old_copy, "device-b", loser),
                None,
                None,
            ],
            moved_copy,
        }
    }

    fn author_contested_move(
        c: &Connection,
        contest: &MovedContest,
    ) -> Result<AuthoredPuts, SyncSqliteError> {
        let (oa, ka) = author();
        let witnesses: Vec<Option<&NativeCaptureWitness>> =
            contest.witnesses.iter().map(Option::as_ref).collect();
        author_recursive_part_witnessed(c, &group(), &oa.as_local(&ka), &contest.part, &witnesses)
    }

    /// Spec R7: a directory move carries both heads of a contested path. The
    /// loser is not an entry of its own at its copy name: it is a second head
    /// at the destination, concurrent with the winner, whose copy name is
    /// derived anew at `q`, and editing that copy edits the loser.
    #[test]
    fn a_directory_move_keeps_the_conflict_loser_competing_at_the_destination() {
        use yadorilink_replica_domain::native_state::resolve_winner;
        let c = conn();
        let contest = contested_directory(&c);

        let authored = author_contested_move(&c, &contest).unwrap();

        let state = native_store::load_state(&c, &group()).unwrap();
        assert_eq!(state.heads_at(&SyncPath("p/f".into())).count(), 0, "the source is vacated");
        assert_eq!(
            state.heads_at(&contest.moved_copy).count(),
            0,
            "a copy name is never a path of its own"
        );
        let to = SyncPath("q/f".into());
        let heads: Vec<_> = state.heads_at(&to).collect();
        assert_eq!(
            heads.iter().map(|h| h.payload.version).collect::<std::collections::BTreeSet<_>>(),
            [contest.winner, contest.loser].into(),
            "winner and loser both compete at q/f"
        );
        assert_eq!(
            resolve_winner(heads.iter()).map(|h| h.payload.version),
            Some(contest.winner),
            "the move does not change who wins"
        );
        let (won, lost) = (
            authored.put_of(&to, &contest.winner).expect("the winner's head"),
            authored.put_of(&to, &contest.loser).expect("the loser's head"),
        );
        assert_ne!(won.dot, lost.dot, "each row shows its own head");

        // The copy's name at `q` is derived from the heads there.
        let level =
            crate::native_desired_state::native_desired_level_projection(&c, "g1", "q").unwrap();
        let copies: Vec<_> = level
            .nodes()
            .iter()
            .filter_map(|(path, node)| match node {
                yadorilink_replica_engine::namespace::PhysicalNode::Entry(entry)
                    if entry.placement
                        == yadorilink_replica_engine::namespace::Placement::ConflictCopy =>
                {
                    Some((path.clone(), entry.version_hash, entry.source.clone()))
                }
                _ => None,
            })
            .collect();
        assert_eq!(copies.len(), 1, "{copies:?}");
        assert_eq!((copies[0].1, copies[0].2.as_str()), (contest.loser.0, "q/f"));

        // Editing that copy is an edit of the loser: the winner stays.
        let (oa, ka) = author();
        let copy_path = SyncPath(copies[0].0.clone());
        place_copy_of(&c, &copy_path, "q/f", contest.loser);
        let edited = Op::Put { path: to.clone(), version: VersionHash([9u8; 32]) };
        author_local_op(&c, &oa.as_local(&ka), &edited, &copy_path).unwrap();
        assert_eq!(
            versions_at(&c, "q/f"),
            [contest.winner, VersionHash([9u8; 32])].into(),
            "the edit supersedes the loser only"
        );
        assert_eq!(versions_at(&c, copy_path.as_str()).len(), 0);
    }

    /// A peer admitting the move's deltas one by one never holds less than it
    /// did: the loser's destination put comes first, so with only that delta
    /// admitted the loser is still live and the operation is incomplete; the
    /// move itself comes last, and only then is the operation complete.
    #[test]
    fn a_peer_admitting_a_directory_move_never_loses_the_loser_in_any_prefix() {
        use yadorilink_replica_domain::recursive_operation::{
            RecursiveOperationId, RecursiveOperationRef,
        };
        use yadorilink_replica_domain::signed_delta::RecursivePart;
        let c = conn();
        let contest = contested_directory(&c);
        let peer = conn();
        {
            let (oa, ka) = author();
            let (ob, kb) = author_b();
            let from = SyncPath("p/f".into());
            concurrent_create_version(&peer, &oa.as_local(&ka), &from, contest.winner);
            concurrent_create_version(&peer, &ob.as_local(&kb), &from, contest.loser);
        }
        let operation_id = RecursiveOperationId([7u8; 16]);
        let (oa, ka) = author();
        let witnesses: Vec<Option<&NativeCaptureWitness>> =
            contest.witnesses.iter().map(Option::as_ref).collect();
        author_recursive_part_tagged(
            &c,
            &group(),
            &oa.as_local(&ka),
            &contest.part,
            &witnesses,
            Some(RecursivePart { operation_id, part_index: 0, part_count: 2 }),
        )
        .unwrap();

        let tip = native_store::frontier_entry_get(&c, &group(), &oa.author).unwrap().unwrap();
        assert_eq!(tip.seq, AuthorSeq(3), "a create, the loser's put, and the move");
        let operation = RecursiveOperationRef { author: oa.author.device.clone(), operation_id };
        let admit = |n: u64| {
            let body = native_store::fetch_delta_body(&c, &group(), &oa.author, AuthorSeq(n))
                .unwrap()
                .expect("the delta body is stored");
            let delta = NativeDelta::from_wire_bytes(&body).expect("a peer decodes it");
            native_store::install_verified_delta(&peer, &group(), &delta, &ka.verifying_key())
                .unwrap();
        };

        admit(2);
        assert_eq!(
            versions_at(&peer, "p/f"),
            [contest.winner, contest.loser].into(),
            "the source heads are still there"
        );
        assert_eq!(versions_at(&peer, "q/f"), [contest.loser].into(), "the loser is live");
        assert!(matches!(
            crate::native_recursive_operation::completeness(&peer, "g1", &operation).unwrap(),
            crate::native_recursive_operation::NativeOperationCompleteness::Partial { .. }
        ));
        admit(3);
        assert_eq!(versions_at(&peer, "p/f").len(), 0, "the old path is removed");
        assert_eq!(versions_at(&peer, "q/f"), [contest.winner, contest.loser].into());
        assert_eq!(
            native_store::load_state(&peer, &group()).unwrap(),
            native_store::load_state(&c, &group()).unwrap(),
            "both replicas agree"
        );
        assert_eq!(
            crate::native_recursive_operation::completeness(&peer, "g1", &operation).unwrap(),
            crate::native_recursive_operation::NativeOperationCompleteness::Complete
        );
    }

    /// A replica admitting the same deltas reaches the author's own frontier entry.
    #[test]
    fn a_remote_admission_reaches_the_same_frontier_entry_as_the_author() {
        let c = conn();
        let contest = contested_directory(&c);
        let peer = conn();
        {
            let (oa, ka) = author();
            let (ob, kb) = author_b();
            let from = SyncPath("p/f".into());
            concurrent_create_version(&peer, &oa.as_local(&ka), &from, contest.winner);
            concurrent_create_version(&peer, &ob.as_local(&kb), &from, contest.loser);
        }
        author_contested_move(&c, &contest).unwrap();
        let (oa, ka) = author();
        for n in [2, 3] {
            let body = native_store::fetch_delta_body(&c, &group(), &oa.author, AuthorSeq(n))
                .unwrap()
                .unwrap();
            let delta = NativeDelta::from_wire_bytes(&body).unwrap();
            native_store::install_verified_delta(&peer, &group(), &delta, &ka.verifying_key())
                .unwrap();
        }
        let theirs =
            native_store::frontier_entry_get(&peer, &group(), &oa.author).unwrap().unwrap();
        let ours = native_store::frontier_entry_get(&c, &group(), &oa.author).unwrap().unwrap();
        assert_eq!(theirs, ours);
    }

    /// A delta carries one put per path: merging two edits that both put is
    /// refused, never resolved by dropping one of the puts.
    #[test]
    fn merging_two_puts_at_one_path_is_refused_not_dropped() {
        let put = |byte: u8| PathEdit {
            path: SyncPath("x".into()),
            observed: Vec::new(),
            put: Some(HeadPayload {
                version: VersionHash([byte; 32]),
                provenance: DeltaHash::default(),
            }),
        };
        assert!(merge_edits(vec![put(1), put(2)]).is_err());
        let removal = PathEdit { put: None, ..put(3) };
        let merged = merge_edits(vec![removal, put(1)]).unwrap();
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].put.as_ref().map(|p| p.version), Some(VersionHash([1u8; 32])));
    }

    /// An ambiguous or unmodeled op anywhere in a part refuses the *whole*
    /// part, not just that entry: a part is one atomic delta.
    #[test]
    fn one_unresolvable_op_in_a_part_refuses_the_whole_part() {
        let c = conn();
        let (owned, key) = author();
        let local = owned.as_local(&key);
        author_local_op(&c, &local, &direct_put("dir/a", 1), &SyncPath("dir/a".into())).unwrap();
        let before = native_store::load_state(&c, &group()).unwrap();

        let part = vec![
            (delete_op("dir/a"), SyncPath("dir/a".into())),
            // A delete through a row that shows no placed copy names no head
            // to remove, so this op is unresolvable.
            (delete_op("dir/b"), SyncPath("dir/b (copy)".into())),
        ];
        let refused = author_local_part(&c, &local, &part).unwrap_err();
        assert!(refused.to_string().contains("cannot be authored natively"), "{refused}");

        let after = native_store::load_state(&c, &group()).unwrap();
        assert_eq!(before, after, "one unresolvable op must leave the whole part left unauthored");
    }

    /// A local create can be the transition that first makes a path
    /// contested (another device's head it never saw stays live beside it):
    /// the loser's name is recorded with it, not left to a later comparison.
    #[test]
    fn a_local_create_that_first_contests_a_path_records_the_losers_name() {
        let c = conn();
        let (owned_a, key_a) = author();
        let a = owned_a.as_local(&key_a);
        let (owned_b, key_b) = author_b();
        let b = owned_b.as_local(&key_b);
        // b's head is live here but this device's create never observed it.
        concurrent_create(&c, &b, &SyncPath("x".into()), 2);
        assert!(crate::stable_projection_binding::native_placements(&c, "g1").unwrap().is_empty());

        let x = SyncPath("x".into());
        let shown_nothing = Shown { versions: [(x.clone(), None)].into(), class: None };
        author_op_shown(&c, &group(), &a, &direct_put("x", 1), &x, &shown_nothing).unwrap();

        let state = native_store::load_state(&c, &group()).unwrap();
        assert_eq!(state.heads_at(&x).count(), 2, "both heads are live");
        let placements = crate::stable_projection_binding::native_placements(&c, "g1").unwrap();
        assert_eq!(placements.len(), 1, "the loser has a copy name: {placements:?}");
    }
    /// The whole-group read authoring used before it read only the paths it
    /// edits: the reference the differential tests below hold it to.
    fn read_whole_group(
        c: &Connection,
        group_id: &FolderGroupId,
        _paths: &[&SyncPath],
    ) -> Result<NativeState, SyncSqliteError> {
        native_store::load_state(c, group_id)
    }

    fn remote_key(index: usize) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&[20 + index as u8; 32])
    }

    fn remote_author(index: usize) -> AuthorId {
        AuthorId {
            device: DeviceId(format!("remote-{index}")),
            incarnation: IncarnationId([index as u8 + 1; 16]),
        }
    }

    /// Installs one delta of remote author `index` on every connection of
    /// `conns`: a put of `version` at `path` superseding `removes` (each with
    /// its live provenance).
    fn remote_delta(
        conns: &[&Connection],
        index: usize,
        path: &SyncPath,
        version: Option<VersionHash>,
        removes: &[Dot],
    ) -> Vec<String> {
        let author = remote_author(index);
        let key = remote_key(index);
        let state = native_store::load_state(conns[0], &group()).unwrap();
        let frontier = native_store::load_frontier(conns[0], &group()).unwrap();
        let entry = frontier.get(&author);
        let live: Vec<_> = state.heads_at(path).collect();
        let removals: Vec<HeadRef> = removes
            .iter()
            .filter_map(|dot| live.iter().find(|head| head.dot == *dot))
            .map(|head| HeadRef { dot: head.dot.clone(), provenance: head.payload.provenance })
            .collect();
        let mut delta = NativeDelta {
            recursive_part: None,
            group_id: group(),
            author,
            seq: entry.map_or(AuthorSeq::FIRST, |e| e.seq.checked_next().unwrap()),
            prev: entry.map(|e| e.tip),
            ops: vec![DeltaOp {
                path: path.clone(),
                removes: removals,
                put: version.map(|version| DeltaPut { version }),
                keeps: Vec::new(),
                keep_put: false,
            }],
            signature: [0u8; 64],
        };
        delta.sign(&key);
        conns
            .iter()
            .map(|c| {
                format!(
                    "{:?}",
                    native_store::install_verified_delta(c, &group(), &delta, &key.verifying_key())
                        .map_err(|e| e.to_string())
                )
            })
            .collect()
    }

    /// What a writer looking at the current winner of each path of `ops` was
    /// shown, perturbed at random: another live version, nothing, or a
    /// restricted class of heads.
    fn random_shown(rng: &mut RngRef, c: &Connection, ops: &[Op]) -> Vec<Shown> {
        let state = native_store::load_state(c, &group()).unwrap();
        ops.iter()
            .map(|op| {
                let mut shown = Shown::default();
                for path in op_paths(op) {
                    let heads: Vec<_> = state.heads_at(path).collect();
                    let version = match rng.below(10) {
                        0 | 1 => None,
                        2 => Some(VersionHash([1 + rng.below(4) as u8; 32])),
                        _ if heads.is_empty() => None,
                        _ => Some(heads[rng.below(heads.len())].payload.version),
                    };
                    shown.versions.insert(path.clone(), version);
                }
                let source = op_paths(op)[0];
                if let Some(Some(version)) = shown.versions.get(source).cloned() {
                    if rng.below(10) < 3 {
                        let class: std::collections::BTreeSet<Dot> = state
                            .heads_at(source)
                            .filter(|head| head.payload.version == version)
                            .map(|head| head.dot)
                            .filter(|_| rng.below(10) < 7)
                            .collect();
                        shown.class = Some((source.clone(), class));
                    }
                }
                shown
            })
            .collect()
    }

    fn result_text(result: Result<AuthoredPuts, SyncSqliteError>) -> String {
        match result {
            Ok(puts) => format!("ok {puts:?}"),
            Err(error) => format!("err {error}"),
        }
    }

    type RngRef = crate::native_store_reference::support::Rng;

    const DIFF_PATHS: [&str; 7] = ["a", "a/b", "a/b/c", "a/d", "e", "e/f", "g"];

    fn random_op(rng: &mut RngRef) -> Op {
        let path = |rng: &mut RngRef| SyncPath(DIFF_PATHS[rng.below(DIFF_PATHS.len())].into());
        let version = VersionHash([1 + rng.below(4) as u8; 32]);
        match rng.below(10) {
            0..=4 => Op::Put { path: path(rng), version },
            5..=6 => Op::Delete { path: path(rng) },
            _ => Op::Move { from: path(rng), to: path(rng), version },
        }
    }

    /// What one differential step authored.
    #[derive(Default)]
    struct StepTally {
        authored: usize,
        copies_placed: usize,
        chained: usize,
    }

    fn live_dots(c: &Connection, path: &SyncPath) -> Vec<Dot> {
        let state = native_store::load_state(c, &group()).unwrap();
        state.heads_at(path).map(|head| head.dot).collect()
    }

    fn remote_step(rng: &mut RngRef, a: &Connection, b: &Connection, label: &str) {
        let path = SyncPath(DIFF_PATHS[rng.below(DIFF_PATHS.len())].into());
        let live: Vec<Dot> =
            live_dots(a, &path).into_iter().filter(|_| rng.below(10) < 6).collect();
        let version = (rng.below(10) < 8).then(|| VersionHash([1 + rng.below(4) as u8; 32]));
        let who = rng.below(2);
        let verdicts = remote_delta(&[a, b], who, &path, version, &live);
        assert_eq!(verdicts[0], verdicts[1], "{label}: remote");
    }

    fn place_copy_step(rng: &mut RngRef, a: &Connection, b: &Connection) -> usize {
        let state = native_store::load_state(a, &group()).unwrap();
        let heads: Vec<(SyncPath, VersionHash)> = state
            .heads
            .iter()
            .flat_map(|(path, heads)| heads.values().map(move |p| (path.clone(), p.version)))
            .collect();
        if heads.is_empty() {
            return 0;
        }
        let (source, version) = heads[rng.below(heads.len())].clone();
        let copy = SyncPath(format!("{} (copy {})", source.as_str(), rng.below(3)));
        for c in [a, b] {
            place_copy_of(c, &copy, source.as_str(), version);
        }
        1
    }

    fn single_op_step(
        rng: &mut RngRef,
        a: &Connection,
        b: &Connection,
        local: &LocalAuthor<'_>,
        label: &str,
    ) -> usize {
        let mut op = random_op(rng);
        // A write through a placed copy names the source, and the row is the copy.
        let mut row_path = op_paths(&op)[0].clone();
        let placements = crate::stable_projection_binding::native_placements(a, "g1").unwrap();
        if rng.below(10) < 4 && !placements.is_empty() {
            let placement = &placements[rng.below(placements.len())];
            row_path = SyncPath(placement.physical_path.clone());
            let source = SyncPath(placement.source_path.clone());
            op = match rng.below(2) {
                0 => Op::Delete { path: source },
                _ => Op::Put { path: source, version: VersionHash([1 + rng.below(4) as u8; 32]) },
            };
        }
        let shown = random_shown(rng, a, std::slice::from_ref(&op));
        let incremental = author_op_shown(a, &group(), local, &op, &row_path, &shown[0]);
        let reference = author_op_shown_reading(
            b,
            &group(),
            local,
            &op,
            &row_path,
            &shown[0],
            read_whole_group,
        );
        let (got, want) = (result_text(incremental), result_text(reference));
        assert_eq!(got, want, "{label}: {op:?} at {row_path:?}");
        usize::from(got.starts_with("ok"))
    }

    fn part_row(rng: &mut RngRef, op: &Op) -> SyncPath {
        if rng.below(10) < 3 {
            // A copy that moved with its directory: a row with no placement.
            SyncPath(format!("moved/{}", op_paths(op)[0].as_str()))
        } else {
            op_paths(op)[0].clone()
        }
    }

    /// Returns `(authored, chained)`.
    fn part_step(
        rng: &mut RngRef,
        a: &Connection,
        b: &Connection,
        local: &LocalAuthor<'_>,
        label: &str,
    ) -> (usize, usize) {
        let ops: Vec<Op> = (0..1 + rng.below(4)).map(|_| random_op(rng)).collect();
        let part: Vec<(Op, SyncPath)> =
            ops.iter().map(|op| (op.clone(), part_row(rng, op))).collect();
        let shown = random_shown(rng, a, &ops);
        let before = native_store::load_frontier(a, &group()).unwrap();
        let count_new = recursive_part_delta_count_reading(
            a,
            &group(),
            &part,
            &[],
            native_store::load_heads_at_paths,
        );
        let count_old =
            recursive_part_delta_count_reading(b, &group(), &part, &[], read_whole_group);
        assert_eq!(
            count_new.as_ref().map_err(|e| e.to_string()),
            count_old.as_ref().map_err(|e| e.to_string()),
            "{label}: delta count of {part:?}"
        );
        let incremental = author_part_shown(a, &group(), local, &part, &shown, None);
        let reference =
            author_part_shown_reading(b, &group(), local, &part, &shown, None, read_whole_group);
        let (got, want) = (result_text(incremental), result_text(reference));
        assert_eq!(got, want, "{label}: part {part:?}");
        let after = native_store::load_frontier(a, &group()).unwrap();
        let seq_of = |f: &yadorilink_replica_domain::native_frontier::NativeAuthorFrontier| {
            f.get(&local.author).map_or(0, |e| e.seq.get())
        };
        (usize::from(got.starts_with("ok")), usize::from(seq_of(&after) - seq_of(&before) > 1))
    }

    /// Authoring from the heads at the paths an operation touches signs, byte
    /// for byte, the deltas authoring from the whole group's state signs, and
    /// leaves every persisted row the same: over random sequences of local
    /// puts, deletes, moves, write-throughs of copies and multi-op parts,
    /// interleaved with concurrent remote authors' deltas that make conflicts.
    #[test]
    fn authoring_from_the_touched_heads_matches_authoring_from_the_whole_state() {
        use crate::native_store_reference::support::{dump_native, Rng};
        let (owned, key) = author();
        let local = owned.as_local(&key);
        let mut tally = StepTally::default();
        for seed in 0..300u64 {
            let mut rng = Rng(seed);
            let (a, b) = (conn(), conn());
            for step in 0..28 {
                let label = format!("seed {seed} step {step}");
                match rng.below(100) {
                    0..=39 => remote_step(&mut rng, &a, &b, &label),
                    40..=49 => tally.copies_placed += place_copy_step(&mut rng, &a, &b),
                    50..=79 => tally.authored += single_op_step(&mut rng, &a, &b, &local, &label),
                    _ => {
                        let (authored, chained) = part_step(&mut rng, &a, &b, &local, &label);
                        tally.authored += authored;
                        tally.chained += chained;
                    }
                }
                assert_eq!(dump_native(&a), dump_native(&b), "{label}: rows differ");
            }
        }
        assert!(tally.authored > 1500, "only {} authored steps", tally.authored);
        assert!(tally.copies_placed > 100, "only {} placed copies", tally.copies_placed);
        assert!(tally.chained > 20, "only {} chained-delta steps", tally.chained);
    }

    /// A class of more than one op's removal cap of same-version heads is
    /// removed by a chain of deltas; the chain is the same from the touched
    /// heads as from the whole state.
    #[test]
    fn a_class_beyond_the_removal_cap_signs_the_same_chain_from_the_touched_heads() {
        use crate::native_store_reference::support::dump_native;
        let (owned, key) = author();
        let local = owned.as_local(&key);
        let x = SyncPath("x".into());
        let version = VersionHash([7u8; 32]);
        let cap = yadorilink_replica_domain::signed_delta::MAX_REMOVES_PER_OP;
        // Edits of the class, as a lone op and as part of a move.
        for op in [
            Op::Put { path: x.clone(), version: VersionHash([8u8; 32]) },
            Op::Delete { path: x.clone() },
            Op::Move { from: x.clone(), to: SyncPath("y".into()), version },
        ] {
            let (a, b) = (conn(), conn());
            for index in 0..cap + 6 {
                let author = remote_author(index);
                let key = remote_key(index);
                let mut delta = NativeDelta {
                    recursive_part: None,
                    group_id: group(),
                    author,
                    seq: AuthorSeq::FIRST,
                    prev: None,
                    ops: vec![DeltaOp {
                        path: x.clone(),
                        removes: vec![],
                        put: Some(DeltaPut { version }),
                        keeps: Vec::new(),
                        keep_put: false,
                    }],
                    signature: [0u8; 64],
                };
                delta.sign(&key);
                for c in [&a, &b] {
                    native_store::install_verified_delta(c, &group(), &delta, &key.verifying_key())
                        .unwrap();
                }
            }
            let shown = Shown { versions: [(x.clone(), Some(version))].into(), class: None };
            let got = result_text(author_op_shown(&a, &group(), &local, &op, &x, &shown));
            let want = result_text(author_op_shown_reading(
                &b,
                &group(),
                &local,
                &op,
                &x,
                &shown,
                read_whole_group,
            ));
            assert!(got.starts_with("ok"), "{got}");
            assert_eq!(got, want, "{op:?}");
            assert_eq!(dump_native(&a), dump_native(&b), "{op:?}");
            assert!(
                native_store::load_frontier(&a, &group()).unwrap()[&owned.author].seq
                    > AuthorSeq(1),
                "the removal of {} heads was chained",
                cap + 6
            );
        }
    }
}
