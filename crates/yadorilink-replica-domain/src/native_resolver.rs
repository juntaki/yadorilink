//! Native's physical-placement resolver as a pure function: a snapshot of one
//! directory level (its live heads, the kinds of their versions, the
//! placements and stable names already recorded, and what the index rows at
//! those names show) goes in; the placement changes to record and the
//! desired physical nodes of the level come out. Nothing here reads a
//! database, a clock or the disk, so every invariant can be
//! pinned against it directly and replayed from a seed.
//!
//! Two steps, each usable on its own:
//!
//! * [`plan_placements`] names what is new: a stable copy name for every
//!   version that lost a contested path, a relocation name for a winner whose
//!   own path has to be a directory. It also retires placements that mean
//!   nothing any more. It returns [`PlacementOp`]s, which the caller records
//!   in order.
//! * [`apply_placements`] moves the placed heads of a level to their physical
//!   names inside the own-account nodes.
//!
//! The rules pinned by this module:
//!
//! * A contested path's global winner holds the real name. Its previous copy
//!   placement is retired when it takes the name over; the version it used to
//!   share the path with keeps a copy name.
//! * A winner's deletion does not promote a lone survivor **that a signed
//!   delta declared a kept copy** ([`LevelSnapshot::kept`]): the author who
//!   removed the winner saw that version as a copy, and says so, so every
//!   replica keeps its copy name whatever order it admitted the deltas in. A
//!   lone survivor nobody declared (its contest was concurrent with the
//!   removal) takes the real name everywhere, including on a replica that
//!   lived through the contest.
//! * A copy is a version at a source path. Whichever live head represents the
//!   version stands for it, so the name survives a change of representative.
//! * A name held by a live entry of the level is never handed to another head.
//! * A directory at a name beats a file placed there; a different file is
//!   displaced to a numbered name.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::conflict::native_copy_path;
use crate::file::RecordKind;
use crate::ids::{SyncPath, VersionHash};
use crate::native_materialize::{PhysicalNode, PlacedEntry, Placement};
use crate::native_state::{
    resolve_path, resolve_winner, Dot, HeadPayload, LiveHead, PathHeads, PathMaterialization,
};

/// One native head's stable-name key: `(source path, author device,
/// incarnation, seq)`.
pub type HeadKey = (String, String, [u8; 16], u64);

/// Why a physical path shows a head of another logical path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlacementOrigin {
    /// A loser at its conflict-copy name.
    ConflictCopy,
    /// The winner displaced because its own path has to be a directory.
    TreeRelocation,
    /// Put there by the reconciler for a reason only this device's disk
    /// knows.
    ReconciliationHold,
}

/// What the index row at a physical path shows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlacementRecord {
    pub physical_path: String,
    pub source_path: SyncPath,
    pub dot: Dot,
    pub payload: HeadPayload,
    pub origin: PlacementOrigin,
}

/// What the index holds at a physical path, as far as placements care.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RowFact {
    /// The row is a tombstone.
    pub deleted: bool,
    /// The row is a live File or Symlink (not a directory).
    pub file_like: bool,
    pub version: VersionHash,
}

/// One change to the recorded placement state, replayed in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlacementOp {
    Delete(String),
    Put(PlacementRecord),
    Bind(HeadKey, String),
}

/// The read-only facts a level is resolved from.
pub struct LevelSnapshot<'a> {
    /// Live heads of every path asked about.
    pub heads_by_path: &'a BTreeMap<SyncPath, PathHeads>,
    /// Every placement recorded for the group.
    pub placements: &'a [PlacementRecord],
    /// Every stable name recorded for the group.
    pub bindings: &'a BTreeMap<HeadKey, String>,
    /// The index row at each physical path a placement names; a path with no
    /// entry has no row.
    pub rows: &'a BTreeMap<String, RowFact>,
    /// Kind of each version among the heads, when it is locally resolvable.
    pub kinds: &'a HashMap<VersionHash, RecordKind>,
    /// The paths of `heads_by_path` with a live head below them.
    pub has_descendant: &'a BTreeSet<SyncPath>,
    /// `(source path, version)` pairs some admitted delta declared a kept
    /// copy.
    pub kept: &'a KeptCopies,
}

/// Versions declared kept copies, by source path.
pub type KeptCopies = BTreeSet<(SyncPath, VersionHash)>;

/// The label a native copy name carries where a device would go. A native
/// copy stands for a version at a source path, not for whichever head
/// represents it, so its name cannot depend on that head's device.
pub const NATIVE_COPY_LABEL: &str = "sync";

/// The name a numbered copy of `version` at `path` gets on attempt `attempt`:
/// a function of the source path, the version hash and the attempt alone,
/// so every replica derives the same name for the same loser.
pub fn numbered_copy_name(path: &str, version_hash: [u8; 32], attempt: u32) -> String {
    if attempt <= 1 {
        native_copy_path(path, NATIVE_COPY_LABEL, &version_hash)
    } else {
        native_copy_path(path, &format!("{NATIVE_COPY_LABEL} {attempt}"), &version_hash)
    }
}

/// The name a winner displaced by a directory is relocated to. A relocation
/// names one exact head, so its device does not depend on which head
/// represents a version; the name is the one a base's own relocation gives.
pub fn numbered_relocation_name(
    path: &str,
    device: &str,
    version_hash: [u8; 32],
    attempt: u32,
) -> String {
    if attempt <= 1 {
        native_copy_path(path, device, &version_hash)
    } else {
        native_copy_path(path, &format!("{device} {attempt}"), &version_hash)
    }
}

pub fn head_key(path: &str, dot: &Dot) -> HeadKey {
    (path.to_owned(), dot.author.device.0.clone(), dot.author.incarnation.0, dot.seq.get())
}

fn placement_is_live(snapshot: &LevelSnapshot<'_>, record: &PlacementRecord) -> bool {
    let row = snapshot.rows.get(&record.physical_path).copied();
    if row.is_some_and(|row| !row.deleted && row.file_like && row.version == record.payload.version)
    {
        return true;
    }
    if record.origin != PlacementOrigin::ConflictCopy {
        return false;
    }
    // A live row showing something else means the materializer replaced it.
    if row.is_some_and(|row| !row.deleted) {
        return false;
    }
    // A conflict copy stands for a version at a source path, not for the one
    // head that happened to represent it when it was named: it holds while
    // any head of that version is live.
    snapshot.heads_by_path.get(&record.source_path).is_some_and(|heads| {
        heads.values().any(|payload| payload.version == record.payload.version)
    })
}

/// Whether `existing` was recorded by the reconciler and its row still shows:
/// the truth of what was materialized, which a prediction from native state
/// must not replace.
fn recorded_by_reconciler_and_live(
    snapshot: &LevelSnapshot<'_>,
    existing: Option<&PlacementRecord>,
) -> bool {
    existing.is_some_and(|record| {
        record.origin == PlacementOrigin::ReconciliationHold && placement_is_live(snapshot, record)
    })
}

fn record_of(
    physical_path: &str,
    source: &SyncPath,
    dot: &Dot,
    payload: &HeadPayload,
    origin: PlacementOrigin,
) -> PlacementRecord {
    PlacementRecord {
        physical_path: physical_path.to_owned(),
        source_path: source.clone(),
        dot: dot.clone(),
        payload: payload.clone(),
        origin,
    }
}

/// Replays `ops` over `placements`, as a store would.
pub fn replay_ops(placements: &mut Vec<PlacementRecord>, ops: &[PlacementOp]) {
    for op in ops {
        match op {
            PlacementOp::Delete(path) => placements.retain(|p| p.physical_path != *path),
            PlacementOp::Put(record) => {
                placements.retain(|p| p.physical_path != record.physical_path);
                placements.push(record.clone());
            }
            PlacementOp::Bind(..) => {}
        }
    }
}

/// Whether `name` is in the way of a new name for a copy of `path`: a live
/// entry of the level holds it, or a binding or placement of another source
/// path does (an injective name held for the same source is the same copy).
fn taken(
    chosen: &BTreeSet<String>,
    raw: &dyn Fn(&str) -> bool,
    working: &[PlacementRecord],
    bindings: &BTreeMap<HeadKey, String>,
    path: &SyncPath,
    name: &str,
) -> bool {
    chosen.contains(name)
        || raw(name)
        || bindings.iter().any(|(key, bound)| bound == name && key.0 != path.as_str())
        || working.iter().any(|p| p.physical_path == name && p.source_path != *path)
}

/// Names what is new for the paths of `snapshot.heads_by_path` and retires
/// what means nothing any more. `raw` is the level's nodes as the caller has
/// them, used only to keep a new name off every name a live entry holds.
pub fn plan_placements(snapshot: &LevelSnapshot<'_>, raw: &BTreeSet<String>) -> Vec<PlacementOp> {
    plan_placements_with(snapshot, &|name| raw.contains(name))
}

/// [`plan_placements`] with the level's live names given as a predicate rather
/// than a set, for a caller that can answer "does a live entry hold this
/// name" for the few names a plan actually asks about, and would otherwise
/// have to list the whole level to answer it.
pub fn plan_placements_with(
    snapshot: &LevelSnapshot<'_>,
    raw: &dyn Fn(&str) -> bool,
) -> Vec<PlacementOp> {
    let mut ops = Vec::new();
    // The placements as earlier steps of this very call leave them.
    let mut working: Vec<PlacementRecord> = snapshot.placements.to_vec();
    let bindings = snapshot.bindings;
    // Names a live entry of the level holds. A binding or placement of the
    // same source path holding a candidate name is not in the way: a copy name is a function of the source
    // path, the version and the attempt alone, so whatever recorded that exact
    // name recorded it for this very copy, and reusing it keeps the name the
    // same on a replica that saw an earlier head of the version and one that
    // did not.
    // That is, `raw` plus the names this call chose itself.
    let mut chosen: BTreeSet<String> = BTreeSet::new();

    for (path, path_heads) in snapshot.heads_by_path {
        let live_heads: Vec<LiveHead> = path_heads
            .iter()
            .map(|(dot, payload)| LiveHead { dot: dot.clone(), payload: payload.clone() })
            .collect();
        let PathMaterialization::Present { winner, conflict_copies } = resolve_path(live_heads)
        else {
            continue;
        };
        // When another version contests the path, its global winner holds the
        // real name: a copy placement of the winner's own content is over. With
        // no contest (a loser left alone after the winner was deleted) the
        // stable name stays and nothing is promoted.
        let contested = !conflict_copies.is_empty();
        let winner_version = path_heads.get(&winner).map(|payload| payload.version);

        let of_source: Vec<PlacementRecord> =
            working.iter().filter(|p| p.source_path == *path).cloned().collect();
        for record in of_source {
            let promoted = record.origin == PlacementOrigin::ConflictCopy
                && Some(record.payload.version) == winner_version
                && (contested || !snapshot.kept.contains(&(path.clone(), record.payload.version)));
            // The exact head the placement names is dot AND provenance. A head
            // at that dot with another provenance is not that head (a verified
            // admission never produces one): the placement is stale.
            let names_another_write = path_heads
                .get(&record.dot)
                .is_some_and(|payload| payload.provenance != record.payload.provenance);
            if promoted || names_another_write || !placement_is_live(snapshot, &record) {
                ops.push(PlacementOp::Delete(record.physical_path.clone()));
                working.retain(|p| p.physical_path != record.physical_path);
                // A stable name stays reserved for its head even when the
                // placement showing it is gone, and a name a live entry of the
                // level holds is never freed by forgetting a placement that
                // used to be there.
                if !bindings.values().any(|name| *name == record.physical_path)
                    && !raw(&record.physical_path)
                {
                    chosen.remove(&record.physical_path);
                }
            }
        }

        // A lone survivor a delta declared a kept copy is placed as a copy
        // exactly like a loser, even though this replica may never have seen
        // it lose. The kept set is of (path, version) pairs derived from live
        // kept heads, so while a kept head lives its same-version siblings
        // share its class: a lone unkept sibling shows as a copy until the kept
        // head retires, then is promoted.
        let kept_survivor = (!contested)
            .then_some(&winner)
            .filter(|dot| {
                path_heads
                    .get(*dot)
                    .is_some_and(|payload| snapshot.kept.contains(&(path.clone(), payload.version)))
            })
            .into_iter()
            .cloned();
        let copy_dots: Vec<Dot> = conflict_copies.iter().cloned().chain(kept_survivor).collect();
        for dot in &copy_dots {
            let key = head_key(path.as_str(), dot);
            let Some(payload) = path_heads.get(dot) else { continue };
            // The same content held by another head at this path is the same
            // visible copy: it keeps the name it has, whichever head now
            // represents it. That name outranks a binding an earlier
            // representative kept, or the copy would move back to it.
            let class_name = working
                .iter()
                .filter(|p| {
                    p.source_path == *path
                        && p.origin == PlacementOrigin::ConflictCopy
                        && p.payload.version == payload.version
                })
                .map(|p| p.physical_path.clone())
                .min();
            let name = match (class_name, bindings.get(&key)) {
                (Some(existing), _) => {
                    ops.push(PlacementOp::Bind(key.clone(), existing.clone()));
                    existing
                }
                (None, Some(name)) => name.clone(),
                (None, None) => {
                    let mut attempt = 1u32;
                    let mut name = numbered_copy_name(path.as_str(), payload.version.0, attempt);
                    while taken(&chosen, raw, &working, bindings, path, &name) {
                        attempt += 1;
                        name = numbered_copy_name(path.as_str(), payload.version.0, attempt);
                    }
                    ops.push(PlacementOp::Bind(key.clone(), name.clone()));
                    chosen.insert(name.clone());
                    name
                }
            };
            let record = record_of(&name, path, dot, payload, PlacementOrigin::ConflictCopy);
            let existing = working.iter().find(|p| p.physical_path == name).cloned();
            if existing.as_ref() != Some(&record)
                && !recorded_by_reconciler_and_live(snapshot, existing.as_ref())
            {
                replay_ops(&mut working, &[PlacementOp::Put(record.clone())]);
                ops.push(PlacementOp::Put(record));
            }
        }

        // The winner, when its own path has to be a directory: a live
        // descendant, or a Directory version among the heads, and a directory
        // beats a file whatever its version.
        let Some(winner_payload) = path_heads.get(&winner) else { continue };
        let Some(winner_kind) = snapshot.kinds.get(&winner_payload.version).copied() else {
            continue;
        };
        if !matches!(winner_kind, RecordKind::File | RecordKind::Symlink) {
            continue;
        }
        let needs_directory = snapshot.has_descendant.contains(path)
            || path_heads.values().any(|payload| {
                snapshot.kinds.get(&payload.version).copied() == Some(RecordKind::Directory)
            });
        if !needs_directory {
            continue;
        }
        let existing = working.iter().find(|p| {
            p.source_path == *path && p.origin == PlacementOrigin::TreeRelocation && p.dot == winner
        });
        let name = match existing {
            Some(record) => record.physical_path.clone(),
            None => {
                let device = winner.author.device.0.as_str();
                let mut attempt = 1u32;
                let mut name = numbered_relocation_name(
                    path.as_str(),
                    device,
                    winner_payload.version.0,
                    attempt,
                );
                while taken(&chosen, raw, &working, bindings, path, &name) {
                    attempt += 1;
                    name = numbered_relocation_name(
                        path.as_str(),
                        device,
                        winner_payload.version.0,
                        attempt,
                    );
                }
                chosen.insert(name.clone());
                name
            }
        };
        let existing = working.iter().find(|p| p.physical_path == name).cloned();
        if !recorded_by_reconciler_and_live(snapshot, existing.as_ref()) {
            let record =
                record_of(&name, path, &winner, winner_payload, PlacementOrigin::TreeRelocation);
            replay_ops(&mut working, &[PlacementOp::Put(record.clone())]);
            ops.push(PlacementOp::Put(record));
        }
    }
    ops
}

/// The desired nodes of a level: physical path to node, and the logical
/// source path each placed entry stands for (a dot does not say: one delta
/// puts under the same dot at several paths).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AppliedLevel {
    pub nodes: BTreeMap<SyncPath, PhysicalNode>,
    pub sources: BTreeMap<SyncPath, String>,
}

/// Moves every placed head of the level under `parent` to the physical name
/// its placement gives it.
///
/// * A conflict copy or a reconciler hold stays at its name for as long as
///   its head is live, whatever else has become of the path: a lone survivor
///   declared a kept copy is not promoted (one nobody declared is).
/// * A tree relocation applies only while the source path is a directory;
///   once the directory need is gone the head is at its own path again.
/// * A genuinely different entry already at the name is displaced to a
///   numbered name; a directory there wins and the placed head waits.
pub fn apply_placements(
    parent: &str,
    placements: &[PlacementRecord],
    children: &BTreeMap<SyncPath, PathHeads>,
    kinds: &HashMap<VersionHash, RecordKind>,
    kept: &KeptCopies,
    level: &mut AppliedLevel,
) {
    let mut rows: Vec<&PlacementRecord> =
        placements.iter().filter(|row| parent_of(&row.physical_path) == parent).collect();
    // A stable name outranks a relocation, which is only ever the fallback
    // for a head with no stable name.
    rows.sort_by(|a, b| {
        (a.origin == PlacementOrigin::TreeRelocation, &a.physical_path)
            .cmp(&(b.origin == PlacementOrigin::TreeRelocation, &b.physical_path))
    });
    let raw = &mut level.nodes;
    let sources = &mut level.sources;
    let mut resolved: BTreeMap<SyncPath, (Dot, BTreeSet<Dot>)> = BTreeMap::new();
    let mut placed: BTreeSet<(SyncPath, Dot)> = BTreeSet::new();
    for row in rows {
        let source = row.source_path.clone();
        let Some(path_heads) = children.get(&source) else { continue };
        let (winner, copies) = resolved.entry(source.clone()).or_insert_with(|| {
            let live = path_heads
                .iter()
                .map(|(dot, payload)| LiveHead { dot: dot.clone(), payload: payload.clone() });
            match resolve_path(live) {
                PathMaterialization::Present { winner, conflict_copies } => {
                    (winner, conflict_copies.into_iter().collect())
                }
                PathMaterialization::Absent => {
                    unreachable!("a source with heads resolves to a winner")
                }
            }
        });
        let head = if row.origin == PlacementOrigin::ConflictCopy {
            // A contested path's global winner holds the real name; only a
            // content that is not the winner's, or the sole survivor, stays
            // at a copy name.
            let winners_content = path_heads
                .get(winner)
                .is_some_and(|payload| payload.version == row.payload.version);
            if winners_content
                && (!copies.is_empty() || !kept.contains(&(source.clone(), row.payload.version)))
            {
                continue;
            }
            // A conflict copy is a version at a source path: whichever live
            // head represents that content now (the one with the larger provenance) stands
            // for it, so the copy keeps its name when the representative
            // changes and nothing visible has.
            let class: Vec<LiveHead> = path_heads
                .iter()
                .filter(|(_, payload)| payload.version == row.payload.version)
                .map(|(dot, payload)| LiveHead { dot: dot.clone(), payload: payload.clone() })
                .collect();
            let Some(representative) = resolve_winner(class.iter()) else { continue };
            path_heads.get_key_value(&representative.dot)
        } else {
            // A relocation or a hold names one exact head, and it is only
            // good while that head is the winner or the representative of its
            // content.
            let exact = path_heads.iter().find(|(dot, payload)| {
                **dot == row.dot
                    && payload.version == row.payload.version
                    && payload.provenance == row.payload.provenance
            });
            exact.filter(|(dot, _)| *dot == winner || copies.contains(dot))
        };
        let Some((dot, payload)) = head else { continue };
        // Content that another entry of the same source already shows is one
        // piece of content: it is placed once.
        if !placed.insert((source.clone(), dot.clone())) {
            continue;
        }
        let Some(kind) = kinds.get(&payload.version).copied() else { continue };
        if !matches!(kind, RecordKind::File | RecordKind::Symlink) {
            continue;
        }
        if row.origin == PlacementOrigin::TreeRelocation
            && !matches!(raw.get(&source), Some(PhysicalNode::Directory(_)))
        {
            continue;
        }

        let physical = SyncPath(row.physical_path.clone());
        let entry = PhysicalNode::Entry(PlacedEntry {
            kind,
            version: payload.version,
            source_dot: dot.clone(),
            placement: if row.origin == PlacementOrigin::TreeRelocation {
                Placement::Relocated
            } else {
                Placement::ConflictCopy
            },
        });
        match raw.get(&physical) {
            Some(PhysicalNode::Directory(_)) => continue,
            Some(PhysicalNode::Entry(existing))
                if existing.source_dot == *dot
                    && sources
                        .get(&physical)
                        .map_or(physical == source, |s| s == source.as_str()) => {}
            Some(PhysicalNode::Entry(_)) => {
                let existing = raw.remove(&physical).expect("just matched");
                let existing_source =
                    sources.remove(&physical).unwrap_or_else(|| physical.as_str().to_owned());
                displace(raw, sources, &row.physical_path, existing, existing_source);
            }
            None => {}
        }
        if let Some(PhysicalNode::Entry(entry)) = raw.get(&source) {
            if entry.placement == Placement::AtPath && entry.version == payload.version {
                raw.remove(&source);
            }
        }
        sources.insert(physical.clone(), source.as_str().to_owned());
        raw.insert(physical, entry);
    }
}

/// Puts `existing` (a different entry that lost its name to a placement) at
/// the first free numbered copy name of its own source.
fn displace(
    raw: &mut BTreeMap<SyncPath, PhysicalNode>,
    sources: &mut BTreeMap<SyncPath, String>,
    taken: &str,
    existing: PhysicalNode,
    source: String,
) {
    let PhysicalNode::Entry(entry) = existing else { return };
    let mut attempt = 2u32;
    loop {
        let name = numbered_copy_name(&source, entry.version.0, attempt);
        let key = SyncPath(name.clone());
        if name != taken && !raw.contains_key(&key) {
            sources.insert(key.clone(), source);
            raw.insert(key, PhysicalNode::Entry(entry));
            return;
        }
        attempt += 1;
    }
}

fn parent_of(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(parent, _)| parent)
}

#[cfg(test)]
mod tests;
