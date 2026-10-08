//! Native's Projection Binding Authority: the
//! production mechanism that assigns, applies, and resolves stable
//! conflict-copy paths for native's own model, persisted in its own table
//! (per `stable_projection_binding.rs`'s own convention).
//!
//! **Closes a long-standing gap**: until this module, native's own
//! `native_materialize::project`/`project_own_node` never assigned a
//! losing head any path at all (confirmed by `apply_native_stable_binding_own_node`'s
//! own doc, which could only
//! *suppress* a promotion, never relocate one, because there was no real
//! naming step to relocate it TO). [`ensure_native_projection_bindings`]
//! is that naming step: the same `conflict_copy_path` +
//! numbered-disambiguator convention this codebase's own
//! `native_materialization_filesystem_e2e.rs` test already used, ad hoc,
//! for its own filesystem-comparison purposes — promoted here into real,
//! callable production code.
//!
//! Capture/write-through and materialization are both meant
//! to call THIS module's functions rather than duplicate the logic or
//! reverse-engineer a physical path's meaning from its own string (per the
//! product decision: a conflict-copy name is presentation state, resolved
//! through the binding table, never parsed).

use std::collections::{BTreeMap, BTreeSet};

use rusqlite::Connection;

use yadorilink_replica_domain::file::RecordKind;
use yadorilink_replica_domain::ids::{SyncPath, VersionHash};
use yadorilink_replica_domain::native_materialize::{PhysicalNode, PlacedEntry, Placement};
use yadorilink_replica_domain::native_state::{
    resolve_path, Dot, HeadPayload, LiveHead, PathHeads, PathMaterialization,
};

use yadorilink_replica_domain::native_resolver::{self as resolver, PlacementOrigin};

use crate::error::SyncSqliteError;
use crate::stable_projection_binding;

/// What the index row at a physical path shows: the logical path and the
/// exact head (identity, provenance, version) it is a copy of. This is
/// what the row displays, and it stays true until the materializer
/// replaces, moves or removes the row -- whether or not the head is still
/// live.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativePhysicalIdentity {
    pub source_path: SyncPath,
    pub dot: Dot,
    pub payload: HeadPayload,
    pub origin: PlacementOrigin,
}

fn placement_of(
    physical_path: &str,
    source_path: &SyncPath,
    dot: &Dot,
    payload: &HeadPayload,
    origin: PlacementOrigin,
) -> stable_projection_binding::NativePlacementRow {
    stable_projection_binding::NativePlacementRow {
        physical_path: physical_path.to_owned(),
        source_path: source_path.as_str().to_owned(),
        author: dot.author.device.0.clone(),
        incarnation: dot.author.incarnation.0,
        seq: dot.seq.get(),
        provenance: payload.provenance.0,
        version: payload.version.0,
        origin: stable_projection_binding::origin_text(origin).to_owned(),
    }
}

fn identity_of_placement(
    row: &stable_projection_binding::NativePlacementRow,
) -> Result<NativePhysicalIdentity, SyncSqliteError> {
    Ok(NativePhysicalIdentity {
        source_path: SyncPath(row.source_path.clone()),
        dot: Dot {
            author: yadorilink_replica_domain::author::AuthorId {
                device: yadorilink_replica_domain::ids::DeviceId(row.author.clone()),
                incarnation: yadorilink_replica_domain::author::IncarnationId(row.incarnation),
            },
            seq: yadorilink_replica_domain::ids::AuthorSeq(row.seq),
        },
        payload: HeadPayload {
            version: VersionHash(row.version),
            provenance: yadorilink_replica_domain::native_state::DeltaHash(row.provenance),
        },
        origin: stable_projection_binding::parse_origin(&row.origin)?,
    })
}

/// Whether the index row at `physical_path` is a live File or Symlink
/// showing exactly `version`.
fn row_shows(
    conn: &Connection,
    group_id: &str,
    physical_path: &str,
    version: &VersionHash,
) -> Result<bool, SyncSqliteError> {
    Ok(crate::store::read_canonical_current_row(conn, group_id, physical_path)?.is_some_and(
        |row| {
            !row.snapshot.deleted
                && matches!(row.snapshot.record_kind, RecordKind::File | RecordKind::Symlink)
                && row.version_hash() == *version
        },
    ))
}

/// A placement holds while its physical row still shows it. A conflict copy
/// whose row has not been written yet (no live row at the path) also holds
/// while its head is live; a live row showing something else means the
/// materializer replaced it, and the placement means nothing.
fn placement_is_live(
    conn: &Connection,
    group_id: &str,
    physical_path: &str,
    identity: &NativePhysicalIdentity,
) -> Result<bool, SyncSqliteError> {
    if row_shows(conn, group_id, physical_path, &identity.payload.version)? {
        return Ok(true);
    }
    if identity.origin != PlacementOrigin::ConflictCopy {
        return Ok(false);
    }
    let replaced = crate::store::read_canonical_current_row(conn, group_id, physical_path)?
        .is_some_and(|row| !row.snapshot.deleted);
    if replaced {
        return Ok(false);
    }
    let group = yadorilink_replica_domain::ids::FolderGroupId(group_id.to_owned());
    // A conflict copy stands for a version at a source path, not for the one
    // head that happened to represent it when it was named: it holds while any
    // head of that version is live.
    Ok(crate::native_store::native_heads_at(conn, &group, &identity.source_path)?
        .iter()
        .any(|head| head.payload.version == identity.payload.version))
}

fn find_head_by_dot<'a>(
    heads: &'a PathHeads,
    dot: &Dot,
) -> Option<(&'a Dot, &'a yadorilink_replica_domain::native_state::HeadPayload)> {
    heads.iter().find(|(d, _)| *d == dot)
}

/// Relocates `existing` (a genuinely different, colliding entry) off
/// `bound_path`, to a disambiguated name via the SAME numbered-copy
/// convention [`ensure_native_projection_bindings`] uses for fresh
/// assignment. Mirrors `desired_state.rs`'s `displace_colliding_entry`
/// exactly, including its directory-collision/self-healing behavior:
/// returns `false` (and touches nothing) if `existing` is a directory, or
/// its own source head can no longer be found -- "a directory beats a
/// file" already holds elsewhere in this pipeline.
fn displace_colliding_entry(
    raw: &mut BTreeMap<SyncPath, PhysicalNode>,
    heads_by_path: &BTreeMap<SyncPath, PathHeads>,
    bound_path: &str,
    existing: PhysicalNode,
) -> bool {
    let PhysicalNode::Entry(existing_entry) = existing else { return false };
    let Some((source_path, _)) = heads_by_path
        .iter()
        .find(|(_, heads)| find_head_by_dot(heads, &existing_entry.source_dot).is_some())
    else {
        return false;
    };
    let mut attempt = 2u32;
    let mut disambiguated =
        numbered_copy_name(source_path.as_str(), existing_entry.version.0, attempt);
    while raw.contains_key(&SyncPath(disambiguated.clone())) || disambiguated == bound_path {
        attempt += 1;
        disambiguated = numbered_copy_name(source_path.as_str(), existing_entry.version.0, attempt);
    }
    raw.remove(&SyncPath(bound_path.to_owned()));
    raw.insert(SyncPath(disambiguated), PhysicalNode::Entry(existing_entry));
    true
}

pub(crate) use yadorilink_replica_domain::native_resolver::numbered_copy_name;
#[cfg(test)]
pub(crate) use yadorilink_replica_domain::native_resolver::numbered_relocation_name;

/// Assigns a fresh binding for every NEWLY-observed native loser (a live
/// head [`resolve_path`] reports as a `conflict_copies` entry, with no
/// existing binding yet) -- the standalone naming step
/// that native's flat, own-account-only
/// resolver never computes on its own. Computes a genuine,
/// collision-disambiguated physical path via `conflict_copy_path`, the
/// same convention the materialization end-to-end tests use.
///
/// `raw` is whatever of native's projection the caller already has in
/// hand (a whole-group `native_materialize::project` result, or a
/// narrower scope) -- used only to check name collisions against nodes
/// already placed there; a caller with a narrower view may miss a
/// collision outside its own scope, exactly as `ensure_dcf_projection_bindings`'s
/// `raw` parameter already accepts.
pub fn ensure_native_projection_bindings(
    conn: &Connection,
    group_id: &str,
    heads_by_path: &BTreeMap<SyncPath, PathHeads>,
    raw: &BTreeMap<SyncPath, PhysicalNode>,
) -> Result<(), SyncSqliteError> {
    let raw_names: BTreeSet<String> = raw.keys().map(|p| p.as_str().to_owned()).collect();
    ensure_native_projection_bindings_with(
        conn,
        group_id,
        heads_by_path,
        &|name| Ok(raw_names.contains(name)),
        PlacementWrites::Record,
    )?;
    Ok(())
}

/// Whether bringing placements up to date may record what it finds missing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PlacementWrites {
    /// Record it, in the caller's transaction.
    Record,
    /// Record nothing, and report that something is missing. For a plan
    /// read outside any write transaction.
    Refuse,
}

/// [`ensure_native_projection_bindings`] with the names live entries hold
/// given as a lookup, for a caller that can answer it for the few names a plan
/// asks about without listing the whole level. `false` only under
/// [`PlacementWrites::Refuse`], when something was missing and is still not
/// recorded.
pub(crate) fn ensure_native_projection_bindings_with(
    conn: &Connection,
    group_id: &str,
    heads_by_path: &BTreeMap<SyncPath, PathHeads>,
    name_is_live: &dyn Fn(&str) -> Result<bool, SyncSqliteError>,
    writes: PlacementWrites,
) -> Result<bool, SyncSqliteError> {
    in_atomic_scope(conn, || {
        // The planner's predicate cannot fail: a failed lookup answers "taken"
        // (the cautious answer) and the error is raised once the plan is done.
        let failure = std::cell::RefCell::new(None);
        let snapshot = OwnedLevelSnapshot::read(conn, group_id, heads_by_path)?;
        let ops = resolver::plan_placements_with(&snapshot.view(heads_by_path), &|name| {
            name_is_live(name).unwrap_or_else(|error| {
                failure.borrow_mut().get_or_insert(error);
                true
            })
        });
        if let Some(error) = failure.into_inner() {
            return Err(error);
        }
        if writes == PlacementWrites::Refuse {
            return Ok(ops.iter().all(|op| snapshot.already_records(op)));
        }
        record_placement_ops(conn, group_id, &ops)?;
        Ok(true)
    })
}

/// The placements recorded for `group_id` that touch one of the levels
/// `parents`, as the resolver's records.
pub(crate) fn placement_records_in_levels(
    conn: &Connection,
    group_id: &str,
    parents: &BTreeSet<String>,
) -> Result<Vec<resolver::PlacementRecord>, SyncSqliteError> {
    placement_records_of(stable_projection_binding::native_placements_in_levels(
        conn, group_id, parents,
    )?)
}

/// Every placement recorded for `group_id`: the reference a level's scoped read
/// is compared with.
#[cfg(test)]
pub(crate) fn placement_records(
    conn: &Connection,
    group_id: &str,
) -> Result<Vec<resolver::PlacementRecord>, SyncSqliteError> {
    placement_records_of(stable_projection_binding::native_placements(conn, group_id)?)
}

fn placement_records_of(
    rows: Vec<stable_projection_binding::NativePlacementRow>,
) -> Result<Vec<resolver::PlacementRecord>, SyncSqliteError> {
    rows.iter()
        .map(|row| {
            let identity = identity_of_placement(row)?;
            Ok(resolver::PlacementRecord {
                physical_path: row.physical_path.clone(),
                source_path: identity.source_path,
                dot: identity.dot,
                payload: identity.payload,
                origin: identity.origin,
            })
        })
        .collect()
}

/// The directory levels the paths of `heads_by_path` live on.
fn levels_of<'a>(paths: impl IntoIterator<Item = &'a SyncPath>) -> BTreeSet<String> {
    paths
        .into_iter()
        .map(|path| stable_projection_binding::parent_of(path.as_str()).to_owned())
        .collect()
}

/// Runs `body` as one atomic, consistently-read unit: an `IMMEDIATE`
/// transaction when `conn` is in autocommit mode, a savepoint inside the
/// caller's transaction otherwise. Everything the body reads is one state, and
/// everything it writes commits together or not at all.
pub(crate) fn in_atomic_scope<R>(
    conn: &Connection,
    body: impl FnOnce() -> Result<R, SyncSqliteError>,
) -> Result<R, SyncSqliteError> {
    if conn.is_autocommit() {
        conn.execute_batch("BEGIN IMMEDIATE")?;
        match body() {
            Ok(value) => {
                conn.execute_batch("COMMIT")?;
                Ok(value)
            }
            Err(error) => {
                let _ = conn.execute_batch("ROLLBACK");
                Err(error)
            }
        }
    } else {
        conn.prepare_cached("SAVEPOINT native_placement_scope")?.execute([])?;
        match body() {
            Ok(value) => {
                conn.prepare_cached("RELEASE native_placement_scope")?.execute([])?;
                Ok(value)
            }
            Err(error) => {
                let _ = conn.execute_batch(
                    "ROLLBACK TO native_placement_scope; RELEASE native_placement_scope",
                );
                Err(error)
            }
        }
    }
}

/// Reads everything the resolver needs about `heads_by_path` into plain data:
/// the recorded placements and stable names, what the index shows at every
/// placed name, the kind of every version among the heads, and which paths
/// have a live descendant. The caller holds one consistent read (see
/// [`in_atomic_scope`]); a read that fails fails the whole call and is never
/// taken as "nothing there".
pub(crate) struct OwnedLevelSnapshot {
    placements: Vec<resolver::PlacementRecord>,
    bindings: BTreeMap<stable_projection_binding::NativeHeadIdentity, String>,
    rows: BTreeMap<String, resolver::RowFact>,
    kinds: std::collections::HashMap<VersionHash, RecordKind>,
    has_descendant: BTreeSet<SyncPath>,
    kept: resolver::KeptCopies,
}

impl OwnedLevelSnapshot {
    /// Whether recording `op` would leave what this snapshot read as it is:
    /// a stable name for a head that already has one (a head's name is never
    /// rebound, so recording another is ignored), or a placement recorded
    /// exactly as `op` would record it. The resolver emits both on every pass
    /// over a settled level, so "no ops" would never hold there.
    fn already_records(&self, op: &resolver::PlacementOp) -> bool {
        match op {
            resolver::PlacementOp::Delete(_) => false,
            resolver::PlacementOp::Put(record) => self.placements.contains(record),
            resolver::PlacementOp::Bind(key, _) => self.bindings.contains_key(key),
        }
    }
}

/// The versions of the kept heads at each of `paths`: a version is kept at a
/// path while a live head of it there is kept.
pub(crate) fn kept_copies_at<'a>(
    conn: &Connection,
    group_id: &str,
    paths: impl IntoIterator<Item = &'a SyncPath>,
) -> Result<resolver::KeptCopies, SyncSqliteError> {
    let mut kept = resolver::KeptCopies::new();
    for path in paths {
        for version in
            stable_projection_binding::native_kept_versions(conn, group_id, path.as_str())?
        {
            kept.insert((path.clone(), VersionHash(version)));
        }
    }
    Ok(kept)
}

/// The versions at `source_path` whose copy a placement currently shows: what
/// the author of an edit at that path sees as copies, and so what its delta
/// declares kept.
pub(crate) fn shown_copy_versions(
    conn: &Connection,
    group_id: &str,
    source_path: &str,
) -> Result<BTreeSet<VersionHash>, SyncSqliteError> {
    let mut versions = BTreeSet::new();
    for row in stable_projection_binding::native_placements_for_source(conn, group_id, source_path)?
    {
        let identity = identity_of_placement(&row)?;
        if identity.origin == PlacementOrigin::ConflictCopy
            && placement_is_live(conn, group_id, &row.physical_path, &identity)?
        {
            versions.insert(identity.payload.version);
        }
    }
    Ok(versions)
}

impl OwnedLevelSnapshot {
    pub(crate) fn read(
        conn: &Connection,
        group_id: &str,
        heads_by_path: &BTreeMap<SyncPath, PathHeads>,
    ) -> Result<Self, SyncSqliteError> {
        // Only the levels `heads_by_path` lives on: a name a plan chooses is a
        // sibling of its source, so nothing recorded elsewhere can matter to it.
        let levels = levels_of(heads_by_path.keys());
        let placements = placement_records_in_levels(conn, group_id, &levels)?;
        let bindings =
            stable_projection_binding::native_bindings_in_levels(conn, group_id, &levels)?;
        Self::read_with(conn, group_id, heads_by_path, placements, bindings)
    }

    /// [`Self::read`] over the given placements and stable names.
    pub(crate) fn read_with(
        conn: &Connection,
        group_id: &str,
        heads_by_path: &BTreeMap<SyncPath, PathHeads>,
        placements: Vec<resolver::PlacementRecord>,
        bindings: BTreeMap<stable_projection_binding::NativeHeadIdentity, String>,
    ) -> Result<Self, SyncSqliteError> {
        let group = yadorilink_replica_domain::ids::FolderGroupId(group_id.to_owned());
        let mut rows = BTreeMap::new();
        for record in &placements {
            if let Some(row) =
                crate::store::read_canonical_current_row(conn, group_id, &record.physical_path)?
            {
                rows.insert(
                    record.physical_path.clone(),
                    resolver::RowFact {
                        deleted: row.snapshot.deleted,
                        file_like: matches!(
                            row.snapshot.record_kind,
                            RecordKind::File | RecordKind::Symlink
                        ),
                        version: row.version_hash(),
                    },
                );
            }
        }
        let mut kinds = std::collections::HashMap::new();
        let mut has_descendant = BTreeSet::new();
        for (path, heads) in heads_by_path {
            for payload in heads.values() {
                if kinds.contains_key(&payload.version) {
                    continue;
                }
                if let Some(version) =
                    crate::dag_store::get_file_version(conn, group_id, &payload.version)?
                {
                    kinds.insert(payload.version, version.meta.record_kind);
                }
            }
            if crate::native_store::native_has_descendant_head(conn, &group, path)? {
                has_descendant.insert(path.clone());
            }
        }
        let kept = kept_copies_at(conn, group_id, heads_by_path.keys())?;
        Ok(Self { placements, bindings, rows, kinds, has_descendant, kept })
    }

    pub(crate) fn view<'a>(
        &'a self,
        heads_by_path: &'a BTreeMap<SyncPath, PathHeads>,
    ) -> resolver::LevelSnapshot<'a> {
        resolver::LevelSnapshot {
            heads_by_path,
            placements: &self.placements,
            bindings: &self.bindings,
            rows: &self.rows,
            kinds: &self.kinds,
            has_descendant: &self.has_descendant,
            kept: &self.kept,
        }
    }
}

/// Records `ops` in order.
pub(crate) fn record_placement_ops(
    conn: &Connection,
    group_id: &str,
    ops: &[resolver::PlacementOp],
) -> Result<(), SyncSqliteError> {
    for op in ops {
        match op {
            resolver::PlacementOp::Delete(physical_path) => {
                stable_projection_binding::native_placement_delete(conn, group_id, physical_path)?;
            }
            resolver::PlacementOp::Put(record) => {
                let origin = record.origin;
                stable_projection_binding::native_placement_put(
                    conn,
                    group_id,
                    &placement_of(
                        &record.physical_path,
                        &record.source_path,
                        &record.dot,
                        &record.payload,
                        origin,
                    ),
                )?;
            }
            resolver::PlacementOp::Bind(key, physical_path) => {
                stable_projection_binding::native_bind(conn, group_id, key, physical_path)?;
            }
        }
    }
    Ok(())
}

/// [`ensure_native_projection_bindings`] for `path` and each of its
/// ancestors: a head landing at `path` can make an ancestor a directory
/// that displaces the ancestor's own winner.
pub fn ensure_native_placements_around(
    conn: &Connection,
    group_id: &str,
    path: &str,
) -> Result<(), SyncSqliteError> {
    native_placements_around(conn, group_id, path, PlacementWrites::Record)?;
    Ok(())
}

/// [`ensure_native_placements_around`] under `writes`: `false` only when
/// refused writes left a placement missing.
pub(crate) fn native_placements_around(
    conn: &Connection,
    group_id: &str,
    path: &str,
    writes: PlacementWrites,
) -> Result<bool, SyncSqliteError> {
    // The heads and occupancy read here, the recorded placements the resolver
    // reads, and the ops it produces are one state: all of it happens in one
    // atomic scope.
    in_atomic_scope(conn, || {
        let group = yadorilink_replica_domain::ids::FolderGroupId(group_id.to_owned());
        let mut heads_by_path = BTreeMap::new();
        // A new stable name is chosen against the whole occupancy of the levels
        // the chain lives on, not against the heads of the few paths asked
        // about: otherwise the name a copy gets would depend on which query ran
        // first, and a live file already on that name would later be pushed off
        // it by the binding. The planner asks about the few names it considers,
        // so each is answered by an indexed lookup instead of listing the levels
        // (which would cost the size of the directory on every delta).
        let mut level_parents: BTreeSet<String> = BTreeSet::new();
        let mut current = Some(path);
        while let Some(candidate) = current {
            let sync = SyncPath(candidate.to_owned());
            let heads = crate::native_store::native_heads_at(conn, &group, &sync)?;
            if !heads.is_empty() {
                heads_by_path.insert(
                    sync,
                    heads.into_iter().map(|h| (h.dot, h.payload)).collect::<PathHeads>(),
                );
            }
            level_parents
                .insert(candidate.rsplit_once('/').map_or("", |(parent, _)| parent).to_owned());
            current = candidate.rsplit_once('/').map(|(parent, _)| parent);
        }
        let name_is_live = |name: &str| -> Result<bool, SyncSqliteError> {
            let parent = name.rsplit_once('/').map_or("", |(parent, _)| parent);
            if !level_parents.contains(parent) {
                return Ok(false);
            }
            let name = SyncPath(name.to_owned());
            Ok(!crate::native_store::native_heads_at(conn, &group, &name)?.is_empty()
                || crate::native_store::native_has_descendant_head(conn, &group, &name)?)
        };
        ensure_native_projection_bindings_with(
            conn,
            group_id,
            &heads_by_path,
            &name_is_live,
            writes,
        )
    })
}

/// [`desired_state::apply_dcf_stable_bindings`]'s exact native
/// counterpart: forces every existing binding's head to its
/// bound path (never wherever the raw resolver's memoryless logic placed
/// it, including a promoted lone-survivor), resolving directory collisions
/// and promoted-head-vanishing, then assigns fresh bindings via
/// [`ensure_native_projection_bindings`].
pub fn apply_native_stable_bindings(
    conn: &Connection,
    group_id: &str,
    heads_by_path: &BTreeMap<SyncPath, PathHeads>,
    mut raw: BTreeMap<SyncPath, PhysicalNode>,
    kind_of: &impl Fn(&VersionHash) -> Option<RecordKind>,
) -> Result<BTreeMap<SyncPath, PhysicalNode>, SyncSqliteError> {
    let bindings = stable_projection_binding::native_bindings(conn, group_id)?;

    for ((source_path, device, incarnation, seq), bound_path) in &bindings {
        let sync_source = SyncPath(source_path.clone());
        let Some(path_heads) = heads_by_path.get(&sync_source) else { continue };
        let Some((dot, payload)) = path_heads.iter().find(|(d, _)| {
            d.author.device.0 == *device
                && &d.author.incarnation.0 == incarnation
                && d.seq.get() == *seq
        }) else {
            continue;
        };
        let Some(kind) = kind_of(&payload.version) else { continue };
        let bound_entry = PhysicalNode::Entry(PlacedEntry {
            kind,
            version: payload.version,
            source_dot: dot.clone(),
            placement: Placement::ConflictCopy,
        });

        let bound_path_key = SyncPath(bound_path.clone());
        if let Some(existing) = raw.get(&bound_path_key).cloned() {
            let is_reasserting_itself = matches!(
                &existing,
                PhysicalNode::Entry(e) if e.source_dot == *dot && e.version == payload.version
            );
            if !is_reasserting_itself
                && !displace_colliding_entry(&mut raw, heads_by_path, bound_path, existing)
            {
                continue;
            }
        }

        // Only now, having committed to placing this head at bound_path,
        // is it safe to remove a promoted AtPath placement of it at
        // source_path -- see desired_state.rs's own fix (commit
        // `b45829eb`) for why this must not happen unconditionally.
        if let Some(PhysicalNode::Entry(entry)) = raw.get(&sync_source) {
            if entry.placement == Placement::AtPath
                && entry.source_dot == *dot
                && entry.version == payload.version
            {
                raw.remove(&sync_source);
            }
        }
        raw.insert(bound_path_key, bound_entry);
    }

    ensure_native_projection_bindings(conn, group_id, heads_by_path, &raw)?;
    Ok(raw)
}

/// [`apply_native_stable_bindings`], for [`native_materialize::project_own_node`]'s
/// single-node result at `path` -- suppression only, mirroring
/// `desired_state::apply_dcf_stable_binding_own_node` exactly: a
/// single-path view has nowhere to relocate a promoted head TO (that is
/// [`apply_native_stable_bindings`]'s job), it can only refuse to promote
/// it here.
pub fn apply_native_stable_binding_own_node(
    conn: &Connection,
    group_id: &str,
    path: &str,
    heads: &[LiveHead],
    node: Option<PhysicalNode>,
) -> Result<Option<PhysicalNode>, SyncSqliteError> {
    // Only a file entry can be promoted onto this path; a directory the
    // path has to be (explicit, or structural for a live descendant) is
    // never suppressed by where a file head was placed.
    if !matches!(node, Some(PhysicalNode::Entry(_))) {
        return Ok(node);
    }
    if let PathMaterialization::Present { winner, .. } = resolve_path(heads.iter().cloned()) {
        // The placements decide (a binding only reserves a name): a conflict
        // copy or a hold stays at its name whatever else became of the path,
        // unless a contested path's global winner has taken the real name
        // (that placement is gone); a relocation only holds while the path is a
        // directory, which a file node here is not.
        let winner_version = heads.iter().find(|h| h.dot == winner).map(|h| h.payload.version);
        let placed_elsewhere =
            stable_projection_binding::native_placements_for_source(conn, group_id, path)?
                .into_iter()
                .any(|row| {
                    row.physical_path != path
                        && row.origin
                            != stable_projection_binding::origin_text(
                                PlacementOrigin::TreeRelocation,
                            )
                        && winner_version.is_some_and(|version| row.version == version.0)
                });
        if placed_elsewhere {
            return Ok(None);
        }
    }
    Ok(node)
}

/// Reverse lookup: what does the index row at `physical_path` show? The
/// one authority for a physical path that is a copy of another logical
/// path -- a conflict copy, a relocated winner, a reconciler hold or an
/// ordinary entry a copy displaced from its own name -- `None` for an
/// ordinary path. Capture and write-through must call this instead of ever
/// parsing a conflict-copy filename string.
///
/// A recorded placement answers first. Without one the row's own native
/// identity does: a row produced from a head of another logical path is a
/// copy of that path's entry, whatever the name it was written under. The
/// name a replica gives a copy depends on what that replica knew when it
/// named it, so only the identity is the same on every replica.
pub fn resolve_native_physical_path(
    conn: &Connection,
    group_id: &str,
    physical_path: &str,
) -> Result<Option<NativePhysicalIdentity>, SyncSqliteError> {
    if let Some(row) =
        stable_projection_binding::native_placement_at(conn, group_id, physical_path)?
    {
        let identity = identity_of_placement(&row)?;
        if placement_is_live(conn, group_id, physical_path, &identity)? {
            return Ok(Some(identity));
        }
    }
    copy_shown_by_row(conn, group_id, physical_path)
}

/// The entry the live File or Symlink row at `physical_path` is a copy of,
/// read from the native head the row was produced from. `None` for a row
/// produced from no head, from a head of its own path, or no live row.
fn copy_shown_by_row(
    conn: &Connection,
    group_id: &str,
    physical_path: &str,
) -> Result<Option<NativePhysicalIdentity>, SyncSqliteError> {
    let Some(identity) = crate::file_index::row_authoring_in_tx(conn, group_id, physical_path)?
    else {
        return Ok(None);
    };
    if identity.source_path.as_str() == physical_path {
        return Ok(None);
    }
    let Some(row) = crate::store::read_canonical_current_row(conn, group_id, physical_path)? else {
        return Ok(None);
    };
    if row.snapshot.deleted
        || !matches!(row.snapshot.record_kind, RecordKind::File | RecordKind::Symlink)
    {
        return Ok(None);
    }
    Ok(Some(NativePhysicalIdentity {
        source_path: identity.source_path,
        dot: identity.dot,
        payload: HeadPayload { version: row.version_hash(), provenance: identity.provenance },
        origin: PlacementOrigin::ReconciliationHold,
    }))
}

/// A write-through edit of a copy row wrote new content: the row at
/// `physical_path` now shows `version`, and it keeps standing in for the
/// entry of the same source until the reconciler moves it. The placement
/// follows the row to the head `author` just authored with that version, so
/// the next edit through the same row supersedes that head and not the
/// retired one; when native authored no such head, only the displayed
/// version moves.
/// Whether a copy of `source_path` is being edited through its row right now:
/// a placement whose content no live head carries any more (the edit just
/// superseded it) while its row still shows that content. Such a copy keeps
/// its name and follows the row (`follow_write_through_edit`); naming its
/// new content a copy of its own would show the edit twice.
pub fn copy_awaits_write_through(
    conn: &Connection,
    group_id: &str,
    source_path: &str,
) -> Result<bool, SyncSqliteError> {
    let group = yadorilink_replica_domain::ids::FolderGroupId(group_id.to_owned());
    let live =
        crate::native_store::native_heads_at(conn, &group, &SyncPath(source_path.to_owned()))?;
    for row in stable_projection_binding::native_placements_for_source(conn, group_id, source_path)?
    {
        let identity = identity_of_placement(&row)?;
        if identity.origin == PlacementOrigin::TreeRelocation {
            continue;
        }
        let class_live = live.iter().any(|head| head.payload.version == identity.payload.version);
        if class_live {
            continue;
        }
        // The row still shows the content, or has not been written yet.
        let row_now = crate::store::read_canonical_current_row(conn, group_id, &row.physical_path)?;
        let follows = row_now.is_none_or(|current| {
            current.snapshot.deleted || current.version_hash() == identity.payload.version
        });
        if follows {
            return Ok(true);
        }
    }
    Ok(false)
}

pub fn follow_write_through_edit(
    conn: &Connection,
    group_id: &str,
    physical_path: &str,
    author: &yadorilink_replica_domain::author::AuthorId,
    version: &VersionHash,
) -> Result<(), SyncSqliteError> {
    let Some(mut row) =
        stable_projection_binding::native_placement_at(conn, group_id, physical_path)?
    else {
        return Ok(());
    };
    let group = yadorilink_replica_domain::ids::FolderGroupId(group_id.to_owned());
    let heads =
        crate::native_store::native_heads_at(conn, &group, &SyncPath(row.source_path.clone()))?;
    if let Some(head) = heads
        .iter()
        .filter(|head| head.dot.author == *author && head.payload.version == *version)
        .max_by_key(|head| head.dot.seq)
    {
        row.author = head.dot.author.device.0.clone();
        row.incarnation = head.dot.author.incarnation.0;
        row.seq = head.dot.seq.get();
        row.provenance = head.payload.provenance.0;
    }
    row.version = version.0;
    stable_projection_binding::native_placement_put(conn, group_id, &row)
}

/// Records that the reconciler put the entry of `source_path` whose version
/// the row at `physical_path` shows there for a reason only this device's
/// disk knows. The placement holds until that row is replaced or removed.
/// `false` when no live head at `source_path` has the row's version, so
/// nothing was recorded.
pub fn record_native_reconciliation_hold(
    conn: &Connection,
    group_id: &str,
    physical_path: &str,
    source_path: &str,
) -> Result<bool, SyncSqliteError> {
    let Some(row) = crate::store::read_canonical_current_row(conn, group_id, physical_path)? else {
        return Ok(false);
    };
    if row.snapshot.deleted
        || !matches!(row.snapshot.record_kind, RecordKind::File | RecordKind::Symlink)
    {
        return Ok(false);
    }
    let version = row.version_hash();
    let group = yadorilink_replica_domain::ids::FolderGroupId(group_id.to_owned());
    let source = SyncPath(source_path.to_owned());
    let heads = crate::native_store::native_heads_at(conn, &group, &source)?;
    // Heads of one version are one class (`resolve_path` names one
    // representative per version): the representative under the decided
    // tie-break, the same one a conflict copy of that version is placed for.
    let Some(head) = yadorilink_replica_domain::native_state::resolve_winner(
        heads.iter().filter(|head| head.payload.version == version),
    ) else {
        return Ok(false);
    };
    stable_projection_binding::native_placement_put(
        conn,
        group_id,
        &placement_of(
            physical_path,
            &source,
            &head.dot,
            &head.payload,
            PlacementOrigin::ReconciliationHold,
        ),
    )?;
    Ok(true)
}

/// Native's own local-capture witness for the physical row at
/// `physical_path`, at the moment this is called -- see
/// [`yadorilink_replica_domain::native_state::NativeCaptureWitness`]'s own
/// doc for the exact semantics. Never parses `physical_path` as a
/// conflict-copy name; always resolves it through
/// [`resolve_native_physical_path`] (the binding authority) first.
pub fn capture_native_witness(
    conn: &Connection,
    group_id: &yadorilink_replica_domain::ids::FolderGroupId,
    physical_path: &str,
) -> Result<yadorilink_replica_domain::native_state::NativeCaptureWitness, SyncSqliteError> {
    use yadorilink_replica_domain::native_state::{LiveHead, NativeCaptureWitness};

    if let Some(target) = resolve_native_physical_path(conn, group_id.as_str(), physical_path)? {
        // A copy row: the witness is the exact head the row shows, kept in
        // its placement, so it holds until the row itself is replaced --
        // not only while that head is live. Never the source path's winner.
        let shown_class = live_class(conn, group_id, &target.source_path, &target.payload.version)?;
        return Ok(NativeCaptureWitness {
            physical_path: SyncPath(physical_path.to_string()),
            logical_source_path: target.source_path,
            shown_version: Some(target.payload.version),
            shown_head: Some(LiveHead { dot: target.dot, payload: target.payload }),
            shown_class,
        });
    }

    // Ordinary row: the witness is whatever this path's own current
    // resolution says the winner is (absent if there is none).
    let source_path = SyncPath(physical_path.to_string());
    let heads = crate::native_store::native_heads_at(conn, group_id, &source_path)?;
    let shown_head = match resolve_path(heads.iter().cloned()) {
        PathMaterialization::Present { winner, .. } => heads
            .into_iter()
            .find(|h| h.dot == winner)
            .map(|h| LiveHead { dot: h.dot, payload: h.payload }),
        PathMaterialization::Absent => None,
    };
    // The content the index row displays, and every live head of it: what an
    // edit of this row has to supersede (see `NativeCaptureWitness`).
    let (shown_version, shown_class) =
        match crate::store::read_canonical_current_row(conn, group_id.as_str(), physical_path)? {
            Some(row) if !row.snapshot.deleted => {
                let version = row.version_hash();
                (Some(version), live_class(conn, group_id, &source_path, &version)?)
            }
            _ => (None, Vec::new()),
        };
    Ok(yadorilink_replica_domain::native_state::NativeCaptureWitness {
        physical_path: SyncPath(physical_path.to_string()),
        logical_source_path: source_path,
        shown_head,
        shown_class,
        shown_version,
    })
}

/// Every live head at `source` whose version is `version`, sorted by dot.
fn live_class(
    conn: &Connection,
    group_id: &yadorilink_replica_domain::ids::FolderGroupId,
    source: &SyncPath,
    version: &VersionHash,
) -> Result<Vec<Dot>, SyncSqliteError> {
    let mut class: Vec<Dot> = crate::native_store::native_heads_at(conn, group_id, source)?
        .into_iter()
        .filter(|head| head.payload.version == *version)
        .map(|head| head.dot)
        .collect();
    class.sort();
    Ok(class)
}

/// [`capture_native_witness`] for every physical path native knows in
/// `group_id`, from one read of the group's state: a path with live heads
/// (the winner) or bound as a conflict copy (its bound loser). A path
/// missing from the result has no head and no binding, so its witness is
/// the absent one ([`absent_native_witness`]). Equal, path by path, to what
/// [`capture_native_witness`] returns at the same moment.
pub fn capture_native_witnesses(
    conn: &Connection,
    group_id: &yadorilink_replica_domain::ids::FolderGroupId,
) -> Result<
    std::collections::HashMap<
        String,
        yadorilink_replica_domain::native_state::NativeCaptureWitness,
    >,
    SyncSqliteError,
> {
    use yadorilink_replica_domain::native_state::NativeCaptureWitness;

    let state = crate::native_store::load_state(conn, group_id)?;
    let mut witnesses = std::collections::HashMap::with_capacity(state.heads.len());
    for (path, heads) in &state.heads {
        let live: Vec<LiveHead> = heads
            .iter()
            .map(|(dot, payload)| LiveHead { dot: dot.clone(), payload: payload.clone() })
            .collect();
        let shown_head = match resolve_path(live.iter().cloned()) {
            PathMaterialization::Present { winner, .. } => {
                live.into_iter().find(|h| h.dot == winner)
            }
            PathMaterialization::Absent => None,
        };
        let (shown_version, shown_class) =
            match crate::store::read_canonical_current_row(conn, group_id.as_str(), path.as_str())?
            {
                Some(row) if !row.snapshot.deleted => {
                    let shown = row.version_hash();
                    let mut class: Vec<Dot> = heads
                        .iter()
                        .filter(|(_, payload)| payload.version == shown)
                        .map(|(dot, _)| dot.clone())
                        .collect();
                    class.sort();
                    (Some(shown), class)
                }
                _ => (None, Vec::new()),
            };
        witnesses.insert(
            path.as_str().to_owned(),
            NativeCaptureWitness {
                physical_path: path.clone(),
                logical_source_path: path.clone(),
                shown_head,
                shown_class,
                shown_version,
            },
        );
    }
    for row in stable_projection_binding::native_placements(conn, group_id.as_str())? {
        let identity = identity_of_placement(&row)?;
        if !placement_is_live(conn, group_id.as_str(), &row.physical_path, &identity)? {
            continue;
        }
        let shown_class =
            live_class(conn, group_id, &identity.source_path, &identity.payload.version)?;
        witnesses.insert(
            row.physical_path.clone(),
            NativeCaptureWitness {
                physical_path: SyncPath(row.physical_path),
                logical_source_path: identity.source_path,
                shown_version: Some(identity.payload.version),
                shown_head: Some(LiveHead { dot: identity.dot, payload: identity.payload }),
                shown_class,
            },
        );
    }
    Ok(witnesses)
}

/// The witness of a physical path native has no head and no binding for.
pub fn absent_native_witness(
    physical_path: &str,
) -> yadorilink_replica_domain::native_state::NativeCaptureWitness {
    yadorilink_replica_domain::native_state::NativeCaptureWitness {
        physical_path: SyncPath(physical_path.to_owned()),
        logical_source_path: SyncPath(physical_path.to_owned()),
        shown_head: None,
        shown_class: Vec::new(),
        shown_version: None,
    }
}

/// Why a re-verified [`NativeCaptureWitness`] no longer matches
/// what the row currently shows -- the precondition [`author_local_change`]
/// itself expresses would refuse. Named for the exact thing that changed
/// so a divergence log line is diagnosable without re-deriving state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeStaleCaptureReason {
    /// A different head now lives at the witnessed identity (same path,
    /// different `Dot`/provenance/version than what was captured).
    DifferentHead,
    /// The captured head is no longer live anywhere the witness names --
    /// removed, or (for a conflict-copy witness) its binding no longer
    /// resolves to it.
    HeadGone,
    /// The witness captured an absent row (a create); the row is no
    /// longer absent.
    UnexpectedContentAppeared,
    /// The index row the capture was taken from now displays another
    /// version: something replaced it before the commit.
    RowChanged,
    /// The physical path now resolves to a DIFFERENT logical source path
    /// than the witness named (the stable binding itself relocated).
    BindingRelocated,
}

/// Native's hypothetical verdict on one captured witness, computed
/// entirely read-only -- never refuses anything itself. See this module's
/// own [`verify_native_capture_witness`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeStaleCaptureVerdict {
    /// The physical row still shows exactly the head (or absence) the
    /// witness captured -- native would author.
    Fresh,
    /// Native would refuse with the given reason.
    Stale(NativeStaleCaptureReason),
}

/// Re-verifies `witness` (captured earlier, at prepare time) against
/// CURRENT native state, inside the caller's own transaction/snapshot --
/// a re-read-and-compare of what capture saw, but read-only and
/// non-refusing.
///
/// Compares the EXACT physical row's identity, not "the logical path's
/// current winner": for a conflict-copy witness, a mismatch means the
/// specific bound loser it named is no longer what's there, even if some
/// OTHER head is still a live winner at the shared logical source path.
pub fn verify_native_capture_witness(
    conn: &Connection,
    group_id: &yadorilink_replica_domain::ids::FolderGroupId,
    witness: &yadorilink_replica_domain::native_state::NativeCaptureWitness,
) -> Result<NativeStaleCaptureVerdict, SyncSqliteError> {
    let current = capture_native_witness(conn, group_id, witness.physical_path.as_str())?;
    if current.logical_source_path != witness.logical_source_path {
        return Ok(NativeStaleCaptureVerdict::Stale(NativeStaleCaptureReason::BindingRelocated));
    }
    // What the writer saw is the CONTENT its row displayed, not the
    // head that happened to represent it. A different head of the same content
    // arriving, outranking the captured one, or the captured heads going away
    // does not change what the writer saw: the edit supersedes the heads of
    // that content its capture held (`shown_class`) and leaves every other
    // head concurrent. Only the row itself moving off that content makes the
    // capture stale.
    Ok(match (witness.shown_version, current.shown_version) {
        (None, None) => NativeStaleCaptureVerdict::Fresh,
        // The writer saw no row; one has appeared since.
        (None, Some(_)) => {
            NativeStaleCaptureVerdict::Stale(NativeStaleCaptureReason::UnexpectedContentAppeared)
        }
        (Some(_), None) => NativeStaleCaptureVerdict::Stale(NativeStaleCaptureReason::HeadGone),
        (Some(then), Some(now)) if then == now => NativeStaleCaptureVerdict::Fresh,
        (Some(_), Some(_)) => {
            NativeStaleCaptureVerdict::Stale(NativeStaleCaptureReason::RowChanged)
        }
    })
}

/// Refuses with [`SyncSqliteError::LocalWriteCaptureStale`] when the row a
/// write acts on no longer shows what native captured for it: native's
/// staleness verdict is the authoritative one for local capture. `None`
/// means no earlier observation was taken, so there is nothing to refuse.
pub fn require_fresh_native_capture(
    conn: &Connection,
    group_id: &str,
    row_path: &str,
    witness: Option<&yadorilink_replica_domain::native_state::NativeCaptureWitness>,
) -> Result<(), SyncSqliteError> {
    let Some(witness) = witness else { return Ok(()) };
    if witness.physical_path.as_str() != row_path {
        return Err(SyncSqliteError::InvalidInput(format!(
            "native capture witness is for {:?} but the write acts on {row_path:?}",
            witness.physical_path.as_str()
        )));
    }
    let group = yadorilink_replica_domain::ids::FolderGroupId(group_id.to_owned());
    match verify_native_capture_witness(conn, &group, witness)? {
        NativeStaleCaptureVerdict::Fresh => Ok(()),
        NativeStaleCaptureVerdict::Stale(_) => Err(SyncSqliteError::LocalWriteCaptureStale {
            group_id: group_id.to_string(),
            path: row_path.to_string(),
        }),
    }
}

#[cfg(test)]
mod tests;
