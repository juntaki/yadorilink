//! Native's desired physical tree: what the materializer has to
//! make true on disk, computed from `NativeState`'s live heads, the
//! physical placement authority (`native_physical_placement`)
//! and the version store's record kinds -- and from nothing else.
//!
//! Shapes match [`crate::desired_state`]'s (`DesiredPathState`,
//! `NamespaceProjection`) so the materialization machinery does not change
//! when its source flips.
//!
//! **Fail closed.** A live head whose version's kind is not locally
//! resolvable makes the answer [`SyncSqliteError::NotFound`], never an
//! absent path: without the kind, whether the path is a directory (and
//! what has to be relocated) is undecidable.
//!
//! **Needs a write connection.** Placements for newly seen losers and
//! relocations are assigned on the way (`ensure_native_projection_bindings`),
//! so the caller runs this inside a write transaction.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use rusqlite::Connection;

use yadorilink_replica_domain::file::RecordKind;
use yadorilink_replica_domain::ids::{FolderGroupId, SyncPath, VersionHash};
use yadorilink_replica_domain::native_materialize::{
    self as native, DirectoryNode as NativeDirectory, PhysicalNode as NativeNode,
    Placement as NativePlacement,
};
use yadorilink_replica_domain::native_plan::{
    NativeDesiredNode, NativeLevelPlan, NativeLocatedHead, NativePlannedNode,
};
use yadorilink_replica_domain::native_resolver as resolver;
use yadorilink_replica_domain::native_state::{
    resolve_winner, Dot, HeadPayload, LiveHead, PathHeads,
};
use yadorilink_replica_engine::namespace::{
    DirectoryNode, NamespaceProjection, PhysicalNode, PlacedEntry, Placement,
};

use crate::desired_state::DesiredPathState;
use crate::error::SyncSqliteError;
use crate::native_projection_binding::{
    apply_native_stable_binding_own_node, ensure_native_placements_around,
    ensure_native_projection_bindings, native_placements_around, PlacementWrites,
};
use crate::native_store::{native_has_descendant_head, native_heads_at, native_heads_at_level};

fn unresolvable(version: &VersionHash, path: &str) -> SyncSqliteError {
    SyncSqliteError::NotFound(format!(
        "native live version {} at {path} is not locally resolvable",
        version.to_hex()
    ))
}

/// Kind of every version among `heads`, or [`SyncSqliteError::NotFound`]
/// for the first one that is not in the version store.
fn resolve_kinds<'a>(
    conn: &Connection,
    group_id: &str,
    heads: impl IntoIterator<Item = (&'a SyncPath, &'a PathHeads)>,
) -> Result<HashMap<VersionHash, RecordKind>, SyncSqliteError> {
    let mut kinds = HashMap::new();
    for (path, path_heads) in heads {
        for payload in path_heads.values() {
            if kinds.contains_key(&payload.version) {
                continue;
            }
            let version = crate::dag_store::get_file_version(conn, group_id, &payload.version)?
                .ok_or_else(|| unresolvable(&payload.version, path.as_str()))?;
            kinds.insert(payload.version, version.meta.record_kind);
        }
    }
    Ok(kinds)
}

fn engine_placement(placement: NativePlacement) -> Placement {
    match placement {
        NativePlacement::AtPath => Placement::AtPath,
        NativePlacement::ConflictCopy => Placement::ConflictCopy,
        NativePlacement::Relocated => Placement::Relocated,
    }
}

fn located(source: &SyncPath, dot: &Dot, payload: &HeadPayload) -> NativeLocatedHead {
    NativeLocatedHead {
        source_path: source.clone(),
        head: LiveHead { dot: dot.clone(), payload: payload.clone() },
    }
}

/// The best-ranked Directory head among `heads` -- the one whose metadata
/// an explicit directory carries.
fn best_directory_head(
    path: &SyncPath,
    heads: &PathHeads,
    kinds: &HashMap<VersionHash, RecordKind>,
) -> Option<NativeLocatedHead> {
    let live: Vec<LiveHead> = heads
        .iter()
        .filter(|(_, payload)| kinds.get(&payload.version) == Some(&RecordKind::Directory))
        .map(|(dot, payload)| LiveHead { dot: dot.clone(), payload: payload.clone() })
        .collect();
    resolve_winner(live.iter())
        .map(|head| NativeLocatedHead { source_path: path.clone(), head: head.clone() })
}

/// What `path` is required to be on its own account, with the exact head
/// each requirement stands for: the winner at its own path, unless a
/// placement puts that head elsewhere. Fails closed (`NotFound`) when a
/// live head's version is unresolvable; never turns that into `Absent`.
pub fn native_plan_path(
    conn: &Connection,
    group_id: &str,
    path: &str,
) -> Result<NativeDesiredNode, SyncSqliteError> {
    let group = FolderGroupId(group_id.to_owned());
    let sync = SyncPath(path.to_owned());
    let heads = native_heads_at(conn, &group, &sync)?;
    let path_heads: PathHeads = heads.iter().map(|h| (h.dot.clone(), h.payload.clone())).collect();
    let by_path: BTreeMap<SyncPath, PathHeads> =
        BTreeMap::from([(sync.clone(), path_heads.clone())]);
    let kinds = resolve_kinds(conn, group_id, by_path.iter())?;
    ensure_native_placements_around(conn, group_id, path)?;
    let descendant = native_has_descendant_head(conn, &group, &sync)?;
    let node = native::project_own_node(heads.clone(), descendant, |v| kinds.get(v).copied())
        .map_err(|error| SyncSqliteError::CorruptState(error.to_string()))?;
    let node = apply_native_stable_binding_own_node(conn, group_id, path, &heads, node)?;
    planned_own_node(&sync, &path_heads, &kinds, node)
}

/// The desired node at `sync` for the own-account `node` its heads project to.
fn planned_own_node(
    sync: &SyncPath,
    path_heads: &PathHeads,
    kinds: &HashMap<VersionHash, RecordKind>,
    node: Option<NativeNode>,
) -> Result<NativeDesiredNode, SyncSqliteError> {
    let path = sync.as_str();
    Ok(match node {
        None => NativeDesiredNode::Absent,
        Some(NativeNode::Directory(NativeDirectory::Explicit { .. })) => {
            match best_directory_head(sync, path_heads, kinds) {
                Some(head) => NativeDesiredNode::ExplicitDirectory { head },
                None => {
                    return Err(SyncSqliteError::CorruptState(format!(
                        "explicit directory at {path:?} without a directory head"
                    )))
                }
            }
        }
        Some(NativeNode::Directory(NativeDirectory::Structural)) => {
            NativeDesiredNode::StructuralDirectory
        }
        Some(NativeNode::Entry(entry)) => {
            let payload = path_heads.get(&entry.source_dot).ok_or_else(|| {
                SyncSqliteError::CorruptState(format!("winner of {path:?} is not one of its heads"))
            })?;
            NativeDesiredNode::Entry {
                head: located(sync, &entry.source_dot, payload),
                kind: entry.kind,
            }
        }
    })
}

/// What `path` is required to be given `heads`, the kinds of their versions, and that the path
/// has no live descendant, no placement or stable name recorded for it or its source, and no head
/// at any ancestor: the own-account node its heads project to and nothing the namespace adds.
/// For a caller that holds those facts from the install that wrote the heads; every other caller
/// reads them through [`native_desired_path_state`].
pub(crate) fn desired_path_state_of_unplaced_heads(
    path: &str,
    heads: Vec<LiveHead>,
    kinds: &HashMap<VersionHash, RecordKind>,
) -> Result<DesiredPathState, SyncSqliteError> {
    let sync = SyncPath(path.to_owned());
    let path_heads: PathHeads = heads.iter().map(|h| (h.dot.clone(), h.payload.clone())).collect();
    let node = native::project_own_node(heads, false, |v| kinds.get(v).copied())
        .map_err(|error| SyncSqliteError::CorruptState(error.to_string()))?;
    Ok(desired_of_node(planned_own_node(&sync, &path_heads, kinds, node)?))
}

fn desired_of_node(node: NativeDesiredNode) -> DesiredPathState {
    match node {
        NativeDesiredNode::Absent => DesiredPathState::Absent,
        NativeDesiredNode::StructuralDirectory => DesiredPathState::StructuralDirectory,
        NativeDesiredNode::ExplicitDirectory { head } => {
            DesiredPathState::ExplicitDirectory { version: head.version() }
        }
        NativeDesiredNode::Entry { head, kind } => {
            DesiredPathState::Entry { kind, version: head.version() }
        }
    }
}

/// Gives `path`'s placements their chance to appear, right after a local or
/// admitted event wrote its heads: planning the path records the placement of
/// whatever entry it displaces, so the name chosen now is the one every later
/// plan finds. Best-effort by design: a path that cannot be planned yet is
/// planned again when it is projected, and a failure here never fails the
/// caller's transaction.
pub fn ensure_path_placements(conn: &Connection, group_id: &str, path: &str) {
    let _ = native_plan_path(conn, group_id, path);
}

/// What `path` is required to be on its own account, as the state the
/// materialization proof records. The per-path counterpart of
/// [`native_desired_level_projection`]; the two agree on every path the
/// projection keeps on its own account.
pub fn native_desired_path_state(
    conn: &Connection,
    group_id: &str,
    path: &str,
) -> Result<DesiredPathState, SyncSqliteError> {
    Ok(desired_of_node(native_plan_path(conn, group_id, path)?))
}

/// `resolved_path_state_hash` of [`native_desired_path_state`].
pub fn native_desired_projected_path_state_hash(
    conn: &Connection,
    group_id: &str,
    path: &str,
) -> Result<[u8; 32], SyncSqliteError> {
    Ok(native_desired_path_state(conn, group_id, path)?.resolved_path_state_hash(group_id, path))
}

/// One directory level of the desired tree with every node's exact head:
/// every node whose parent is `parent` (`""` for the root), own-account
/// nodes and the placed (conflict-copy, relocated, held) entries alike.
pub fn native_plan_level(
    conn: &Connection,
    group_id: &str,
    parent: &str,
) -> Result<NativeLevelPlan, SyncSqliteError> {
    let group = FolderGroupId(group_id.to_owned());
    let (children, with_descendant) = native_heads_at_level(conn, &group, parent)?;
    let kinds = resolve_kinds(conn, group_id, children.iter())?;
    let kind_of = |version: &VersionHash| kinds.get(version).copied();

    // Own-account node of every child that has heads or a live descendant.
    let mut raw: BTreeMap<SyncPath, NativeNode> = BTreeMap::new();
    let candidates: BTreeSet<&str> = children
        .keys()
        .map(SyncPath::as_str)
        .chain(with_descendant.iter().map(String::as_str))
        .collect();
    for candidate in candidates {
        let sync = SyncPath(candidate.to_owned());
        let live: Vec<LiveHead> = children
            .get(&sync)
            .into_iter()
            .flat_map(|heads| {
                heads
                    .iter()
                    .map(|(dot, payload)| LiveHead { dot: dot.clone(), payload: payload.clone() })
            })
            .collect();
        let descendant = with_descendant.contains(candidate);
        if let Some(node) = native::project_own_node(live, descendant, kind_of)
            .map_err(|error| SyncSqliteError::CorruptState(error.to_string()))?
        {
            raw.insert(sync, node);
        }
    }

    // Placements for what is new here, then the placed heads move to their
    // physical names.
    if !parent.is_empty() {
        ensure_native_placements_around(conn, group_id, parent)?;
    }
    ensure_native_projection_bindings(conn, group_id, &children, &raw)?;
    // Which logical path each entry at a physical name stands for. A dot
    // does not say: one delta puts under the same dot at several paths.
    let mut level = resolver::AppliedLevel { nodes: raw, sources: BTreeMap::new() };
    let placements = crate::native_projection_binding::placement_records_in_levels(
        conn,
        group_id,
        &BTreeSet::from([parent.to_owned()]),
    )?;
    let kept = crate::native_projection_binding::kept_copies_at(conn, group_id, children.keys())?;
    resolver::apply_placements(parent, &placements, &children, &kinds, &kept, &mut level);
    let resolver::AppliedLevel { nodes: raw, sources } = level;
    planned_level(raw, &sources, &children, &kinds)
}

/// The planned nodes of an applied level: every node with the exact head it stands for.
fn planned_level(
    raw: BTreeMap<SyncPath, NativeNode>,
    sources: &BTreeMap<SyncPath, String>,
    children: &BTreeMap<SyncPath, PathHeads>,
    kinds: &HashMap<VersionHash, RecordKind>,
) -> Result<NativeLevelPlan, SyncSqliteError> {
    let mut plan = NativeLevelPlan::default();
    for (path, node) in raw {
        let planned = match node {
            NativeNode::Directory(NativeDirectory::Structural) => {
                NativePlannedNode::StructuralDirectory
            }
            NativeNode::Directory(NativeDirectory::Explicit { .. }) => {
                let heads = children.get(&path).ok_or_else(|| {
                    SyncSqliteError::CorruptState(format!(
                        "explicit directory at {path:?} has no heads"
                    ))
                })?;
                let head = best_directory_head(&path, heads, kinds).ok_or_else(|| {
                    SyncSqliteError::CorruptState(format!(
                        "explicit directory at {path:?} without a directory head"
                    ))
                })?;
                NativePlannedNode::ExplicitDirectory { head }
            }
            NativeNode::Entry(entry) => {
                let source = SyncPath(
                    sources.get(&path).cloned().unwrap_or_else(|| path.as_str().to_owned()),
                );
                let payload = children
                    .get(&source)
                    .and_then(|heads| heads.get(&entry.source_dot))
                    .ok_or_else(|| {
                        SyncSqliteError::CorruptState(format!(
                            "entry at {path:?} names a head that is not live"
                        ))
                    })?;
                NativePlannedNode::Entry {
                    head: located(&source, &entry.source_dot, payload),
                    kind: entry.kind,
                    placement: entry.placement,
                }
            }
        };
        plan.nodes.insert(path, planned);
    }
    Ok(plan)
}

/// The nodes of `parent`'s level plan that `names` are or stand for, computed from the rows that
/// can influence them and not from the whole level: a node is returned when its physical name or
/// its source path is one of `names`, and it is the node [`native_plan_level`] gives there.
///
/// What a node of a level depends on is its own name's heads and live descendants, and the
/// recorded placements that name it or have it as their source. Applying a placement can displace
/// an entry to a numbered name, which in turn depends on what holds that name; so the set of names
/// the answer rests on starts at `names`, takes in every placement of the level that touches it
/// (a read of the level's placements, never of its siblings' heads) and every name the placements
/// put an entry on, and is applied again until no entry lands on a name outside it. A level with
/// no placement touching `names` resolves each name from its own heads alone.
///
/// Fails closed (`NotFound`) only for a version among the heads of the names it rests on: a
/// sibling the answer does not depend on cannot make it unplannable. Like [`native_plan_level`] it
/// records the placements the names need, so the caller runs it in a write transaction.
pub fn native_plan_nodes(
    conn: &Connection,
    group_id: &str,
    parent: &str,
    names: &BTreeSet<String>,
) -> Result<NativeLevelPlan, SyncSqliteError> {
    match plan_nodes(conn, group_id, parent, names, PlacementWrites::Record)? {
        PlanRead::Planned(plan) => Ok(plan),
        PlanRead::NeedsPlacements => Err(SyncSqliteError::CorruptState(format!(
            "planning {names:?} under {parent:?} left a placement unrecorded"
        ))),
    }
}

/// A plan computed without recording anything: the plan, when every placement
/// it rests on is already recorded, or the finding that one is not.
#[derive(Debug, PartialEq, Eq)]
pub enum PlanRead<T> {
    Planned(T),
    /// A placement is missing. The plan has to be made again where it can
    /// be recorded; nothing read here is an answer.
    NeedsPlacements,
}

/// [`native_plan_nodes`] that writes nothing, for a read transaction. Where it
/// returns a plan, that is the plan [`native_plan_nodes`] gives on the same
/// state, which records nothing there either.
pub fn read_native_plan_nodes(
    conn: &Connection,
    group_id: &str,
    parent: &str,
    names: &BTreeSet<String>,
) -> Result<PlanRead<NativeLevelPlan>, SyncSqliteError> {
    plan_nodes(conn, group_id, parent, names, PlacementWrites::Refuse)
}

fn plan_nodes(
    conn: &Connection,
    group_id: &str,
    parent: &str,
    names: &BTreeSet<String>,
    writes: PlacementWrites,
) -> Result<PlanRead<NativeLevelPlan>, SyncSqliteError> {
    let group = FolderGroupId(group_id.to_owned());
    let on_level = |name: &str| name.rsplit_once('/').map_or("", |(parent, _)| parent) == parent;
    let read_rows = || {
        crate::native_projection_binding::placement_records_in_levels(
            conn,
            group_id,
            &BTreeSet::from([parent.to_owned()]),
        )
    };
    let mut all_rows = read_rows()?;
    // The names whose own placements have been brought up to date. A level plan does so for
    // every child before it applies anything, which retires a placement a name's arrival made
    // stale and names the copies a head's change called for; the names a plan rests on need the
    // same.
    let mut ensured: BTreeSet<String> = BTreeSet::new();
    let mut scope: BTreeSet<String> = names.iter().filter(|name| on_level(name)).cloned().collect();
    // Placements whose name is held by a head of its own: applying one displaces that head to a
    // numbered name, which can be any name nothing holds. Taken in once a name in scope is one
    // nothing holds.
    let mut displacers: Option<BTreeSet<String>> = None;
    loop {
        // The placements that touch the scope, and the names they put heads on.
        let mut rows: Vec<&resolver::PlacementRecord> = Vec::new();
        loop {
            rows.clear();
            let before = scope.len();
            for row in &all_rows {
                let source = row.source_path.as_str();
                if scope.contains(&row.physical_path)
                    || scope.contains(source)
                    || displacers.as_ref().is_some_and(|d| d.contains(row.physical_path.as_str()))
                {
                    rows.push(row);
                    scope.insert(row.physical_path.clone());
                    if on_level(source) {
                        scope.insert(source.to_owned());
                    }
                }
            }
            if scope.len() == before {
                break;
            }
        }
        let fresh: Vec<String> = scope.difference(&ensured).cloned().collect();
        if !fresh.is_empty() {
            for name in fresh {
                if !native_placements_around(conn, group_id, &name, writes)? {
                    return Ok(PlanRead::NeedsPlacements);
                }
                ensured.insert(name);
            }
            all_rows = read_rows()?;
            displacers = None;
            continue;
        }
        let mut children: BTreeMap<SyncPath, PathHeads> = BTreeMap::new();
        let mut with_descendant: BTreeSet<&str> = BTreeSet::new();
        for name in &scope {
            let sync = SyncPath(name.clone());
            let heads = native_heads_at(conn, &group, &sync)?;
            if !heads.is_empty() {
                children
                    .insert(sync.clone(), heads.into_iter().map(|h| (h.dot, h.payload)).collect());
            }
            if native_has_descendant_head(conn, &group, &sync)? {
                with_descendant.insert(name);
            }
        }
        let kinds = resolve_kinds(conn, group_id, children.iter())?;
        let kind_of = |version: &VersionHash| kinds.get(version).copied();
        let mut raw: BTreeMap<SyncPath, NativeNode> = BTreeMap::new();
        for name in &scope {
            let sync = SyncPath(name.clone());
            let live: Vec<LiveHead> = children
                .get(&sync)
                .into_iter()
                .flat_map(|heads| {
                    heads.iter().map(|(dot, payload)| LiveHead {
                        dot: dot.clone(),
                        payload: payload.clone(),
                    })
                })
                .collect();
            let descendant = with_descendant.contains(name.as_str());
            if let Some(node) = native::project_own_node(live, descendant, kind_of)
                .map_err(|error| SyncSqliteError::CorruptState(error.to_string()))?
            {
                raw.insert(sync, node);
            }
        }
        // A name nothing holds is one a displaced entry can land on, so the answer for the scope
        // rests on every placement whose name is held by a head of its own.
        if displacers.is_none()
            && scope.iter().any(|name| !raw.contains_key(&SyncPath(name.clone())))
        {
            displacers = Some(held_placement_names(conn, &group, &all_rows)?);
            continue;
        }
        let kept =
            crate::native_projection_binding::kept_copies_at(conn, group_id, children.keys())?;
        let placements: Vec<resolver::PlacementRecord> = rows.into_iter().cloned().collect();
        let mut level = resolver::AppliedLevel { nodes: raw, sources: BTreeMap::new() };
        resolver::apply_placements(parent, &placements, &children, &kinds, &kept, &mut level);
        // An entry displaced onto a name the scope did not cover was placed without knowing
        // what holds that name: take the name in and apply again.
        let outside: Vec<String> = level
            .nodes
            .keys()
            .map(|path| path.as_str().to_owned())
            .filter(|name| !scope.contains(name))
            .collect();
        if !outside.is_empty() {
            scope.extend(outside);
            continue;
        }
        // The check above runs before the placements are applied, so a name that held an entry
        // then counts as held. Applying can vacate such a name (a kept copy's source goes when
        // its copy is placed, a head goes when a placement takes its name), and a displaced
        // entry of a row outside the scope would then land on it in the level plan. That
        // needs a placement applied without a name of the scope that nothing held (the copy's
        // own name, or the numbered name a displaced entry lands on, is such a name, and
        // brings the displacers in before the apply), so it does not arise; the check is
        // repeated on the applied level so that this equivalence does not rest on that
        // argument alone.
        if displacers.is_none()
            && scope.iter().any(|name| !level.nodes.contains_key(&SyncPath(name.clone())))
        {
            displacers = Some(held_placement_names(conn, &group, &all_rows)?);
            continue;
        }
        let resolver::AppliedLevel { nodes: raw, sources } = level;
        let mut plan = planned_level(raw, &sources, &children, &kinds)?;
        plan.nodes.retain(|physical, node| {
            names.contains(physical.as_str())
                || matches!(node, NativePlannedNode::Entry { head, .. }
                    if names.contains(head.source_path.as_str()))
        });
        return Ok(PlanRead::Planned(plan));
    }
}

/// The physical names of `rows` that a head of the group holds: the placements that displace the
/// entry at their name. One set-based read, not one per placement.
fn held_placement_names(
    conn: &Connection,
    group: &FolderGroupId,
    rows: &[resolver::PlacementRecord],
) -> Result<BTreeSet<String>, SyncSqliteError> {
    let names: Vec<&str> = rows.iter().map(|row| row.physical_path.as_str()).collect();
    crate::native_store::native_paths_with_heads(conn, group, &names)
}

/// The node [`native_plan_level`] of `path`'s parent puts at `path`, or `None` when it puts
/// nothing there, computed without reading the siblings of `path` (see [`native_plan_nodes`]).
pub fn native_plan_node(
    conn: &Connection,
    group_id: &str,
    path: &str,
) -> Result<Option<NativePlannedNode>, SyncSqliteError> {
    let parent = path.rsplit_once('/').map_or("", |(parent, _)| parent);
    let mut plan = native_plan_nodes(conn, group_id, parent, &BTreeSet::from([path.to_owned()]))?;
    Ok(plan.nodes.remove(&SyncPath(path.to_owned())))
}

/// [`native_plan_node`] that writes nothing (see [`read_native_plan_nodes`]).
pub fn read_native_plan_node(
    conn: &Connection,
    group_id: &str,
    path: &str,
) -> Result<PlanRead<Option<NativePlannedNode>>, SyncSqliteError> {
    let parent = path.rsplit_once('/').map_or("", |(parent, _)| parent);
    Ok(match read_native_plan_nodes(conn, group_id, parent, &BTreeSet::from([path.to_owned()]))? {
        PlanRead::Planned(mut plan) => {
            PlanRead::Planned(plan.nodes.remove(&SyncPath(path.to_owned())))
        }
        PlanRead::NeedsPlacements => PlanRead::NeedsPlacements,
    })
}

/// [`native_plan_level`] in the engine's projection shape, which is what
/// the materialization machinery consumes today.
pub fn native_desired_level_projection(
    conn: &Connection,
    group_id: &str,
    parent: &str,
) -> Result<NamespaceProjection, SyncSqliteError> {
    let plan = native_plan_level(conn, group_id, parent)?;
    let mut projection = NamespaceProjection::default();
    for (path, node) in plan.nodes {
        let node = match node {
            NativePlannedNode::StructuralDirectory => {
                PhysicalNode::Directory(DirectoryNode::Structural)
            }
            NativePlannedNode::ExplicitDirectory { head } => {
                PhysicalNode::Directory(DirectoryNode::Explicit { version_hash: head.version().0 })
            }
            NativePlannedNode::Entry { head, kind, placement } => {
                PhysicalNode::Entry(PlacedEntry {
                    kind,
                    version_hash: head.version().0,
                    source: head.source_path.as_str().to_owned(),
                    placement: engine_placement(placement),
                })
            }
        };
        projection.set(path.as_str(), node);
    }
    Ok(projection)
}

/// Arms the projection obligation of every path `delta` touched, once
/// `delta` has been installed into `NativeState`. `local` marks a delta
/// this device authored (its own edit is not a desired state it has yet to
/// place).
pub(crate) fn arm_projection_for_delta(
    conn: &Connection,
    group_id: &str,
    delta: &yadorilink_replica_domain::signed_delta::NativeDelta,
    local: bool,
) -> Result<
    std::collections::BTreeMap<String, crate::projection_obligations::ArmedObligation>,
    SyncSqliteError,
> {
    let paths: BTreeSet<&str> = delta.ops.iter().map(|op| op.path.as_str()).collect();
    let paths: Vec<&str> = paths.into_iter().collect();
    // A delta this device authored is not a desired state it has yet to place: its obligations
    // are written `Local` by the bump itself.
    let origin = if local {
        crate::projection_obligations::ObligationOrigin::Local
    } else {
        crate::projection_obligations::ObligationOrigin::Remote
    };
    let armed = crate::projection_obligations::bump_projection_obligations_with_origin(
        conn,
        group_id,
        &paths,
        crate::dag_store::now_unix_nanos(),
        origin,
    )?;
    // Who lost which name is history: it is recorded with the transition that
    // made it so, before the next delta (a release cascade applies several
    // in a row) can change what the loser lost to. A local edit can also make
    // a contest (a head it never saw stays live beside it). The one thing a
    // local edit does not name is the copy it was made through: that copy
    // follows its row (`follow_write_through_edit`).
    for path in &paths {
        if local
            && crate::native_projection_binding::copy_awaits_write_through(conn, group_id, path)?
        {
            continue;
        }
        ensure_native_placements_around(conn, group_id, path)?;
    }
    Ok(armed)
}

/// A version's metadata just became locally resolvable: every path whose
/// native live head names it was undecidable until now and has to be
/// materialized without waiting for another event. A no-op where the
/// native tables do not exist (a store that never held native state).
pub fn arm_projection_for_arrived_version(
    conn: &Connection,
    group_id: &str,
    version: &VersionHash,
) -> Result<(), SyncSqliteError> {
    let present: i64 = conn
        .prepare_cached(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' \
             AND name IN ('native_heads', 'projection_obligations')",
        )?
        .query_row([], |row| row.get(0))?;
    if present < 2 {
        return Ok(());
    }
    // `DISTINCT path` tempts the planner into walking the group's whole primary
    // key (already in path order) instead of the version index: a scan of every
    // head of the group for each version that arrives.
    let mut stmt = conn.prepare_cached(
        "SELECT DISTINCT path FROM native_heads INDEXED BY idx_native_heads_version \
         WHERE group_id = ?1 AND version = ?2",
    )?;
    let paths: Vec<String> = stmt
        .query_map(rusqlite::params![group_id, &version.0[..]], |row| row.get(0))?
        .collect::<Result<_, _>>()?;
    if paths.is_empty() {
        return Ok(());
    }
    let refs: Vec<&str> = paths.iter().map(String::as_str).collect();
    crate::projection_obligations::bump_projection_obligations_for_touched_paths(
        conn,
        group_id,
        &refs,
        crate::dag_store::now_unix_nanos(),
    )
}

/// [`arm_projection_for_arrived_version`] for several versions that just arrived together: the
/// paths whose heads name any of them are found in a few statements, and each version bumps
/// the paths naming it exactly as arming it alone does (a path naming two of the versions is
/// bumped once per version).
pub fn arm_projection_for_arrived_versions(
    conn: &Connection,
    group_id: &str,
    versions: &[VersionHash],
) -> Result<(), SyncSqliteError> {
    if versions.is_empty() {
        return Ok(());
    }
    let present: i64 = conn
        .prepare_cached(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' \
             AND name IN ('native_heads', 'projection_obligations')",
        )?
        .query_row([], |row| row.get(0))?;
    if present < 2 {
        return Ok(());
    }
    let mut paths_of: std::collections::HashMap<[u8; 32], Vec<String>> =
        std::collections::HashMap::new();
    for chunk in versions.chunks(crate::store::PATHS_PER_QUERY) {
        let marks = vec!["?"; chunk.len()].join(",");
        let mut stmt = conn.prepare_cached(&format!(
            "SELECT DISTINCT version, path FROM native_heads INDEXED BY idx_native_heads_version \
             WHERE group_id = ?1 AND version IN ({marks})"
        ))?;
        let params = std::iter::once(rusqlite::types::Value::from(group_id.to_owned()))
            .chain(chunk.iter().map(|v| rusqlite::types::Value::from(v.0.to_vec())));
        let mut rows = stmt.query(rusqlite::params_from_iter(params))?;
        while let Some(row) = rows.next()? {
            let version: Vec<u8> = row.get(0)?;
            let path: String = row.get(1)?;
            let key: [u8; 32] = version.as_slice().try_into().map_err(|_| {
                SyncSqliteError::CorruptState("a native head names a malformed version".into())
            })?;
            paths_of.entry(key).or_default().push(path);
        }
    }
    let now = crate::dag_store::now_unix_nanos();
    for version in versions {
        let Some(paths) = paths_of.get_mut(&version.0) else { continue };
        paths.sort();
        let refs: Vec<&str> = paths.iter().map(String::as_str).collect();
        crate::projection_obligations::bump_projection_obligations_for_touched_paths(
            conn, group_id, &refs, now,
        )?;
    }
    Ok(())
}

/// Arms every path whose live heads differ between `before` and `after`,
/// for a state installed wholesale (a join with a remote state) rather
/// than as one delta.
pub fn arm_projection_for_state_change(
    conn: &Connection,
    group_id: &str,
    before: &yadorilink_replica_domain::native_state::NativeState,
    after: &yadorilink_replica_domain::native_state::NativeState,
) -> Result<(), SyncSqliteError> {
    let paths: BTreeSet<&SyncPath> = before.heads.keys().chain(after.heads.keys()).collect();
    let changed: Vec<&str> = paths
        .into_iter()
        .filter(|path| before.heads.get(*path) != after.heads.get(*path))
        .map(SyncPath::as_str)
        .collect();
    if changed.is_empty() {
        return Ok(());
    }
    crate::projection_obligations::bump_projection_obligations_for_touched_paths(
        conn,
        group_id,
        &changed,
        crate::dag_store::now_unix_nanos(),
    )?;
    for path in &changed {
        ensure_native_placements_around(conn, group_id, path)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;

/// The source paths whose planned entry has no live row: see
/// `FileIndexRepository::native_plan_gap_paths`.
pub fn native_plan_gap_paths(
    conn: &Connection,
    group_id: &str,
) -> Result<BTreeSet<String>, SyncSqliteError> {
    let mut parents = BTreeSet::new();
    {
        let mut stmt =
            conn.prepare("SELECT DISTINCT path FROM native_heads WHERE group_id = ?1")?;
        let rows = stmt.query_map([group_id], |row| row.get::<_, String>(0))?;
        for path in rows {
            let path = path?;
            parents.insert(
                path.rsplit_once('/').map_or(String::new(), |(parent, _)| parent.to_owned()),
            );
        }
    }
    let mut gaps = BTreeSet::new();
    for parent in parents {
        let plan = native_plan_level(conn, group_id, &parent)?;
        for (physical, node) in &plan.nodes {
            let (NativePlannedNode::Entry { head, .. }
            | NativePlannedNode::ExplicitDirectory { head }) = node
            else {
                continue;
            };
            let row = crate::store::read_canonical_current_row(conn, group_id, physical.as_str())?;
            if row.is_none_or(|row| row.snapshot.deleted) {
                gaps.insert(head.source_path.as_str().to_owned());
            }
        }
    }
    Ok(gaps)
}
