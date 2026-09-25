//! DAG-engine conflict resolution built on top of the deterministic
//! conflict-copy naming policy, which now lives entirely in
//! `yadorilink_replica_domain::conflict` -- every caller in this crate and
//! beyond reaches it there directly. `PathHead`/
//! `PathHeadContent`/`ConflictCopy`/`resolve_path_heads`/
//! `dag_conflict_loser_is_a`/`conflict_copy_path_for_losing_change`/
//! `change_touches_path`/`path_head_from_change` stay here: they operate
//! directly on `Change`/`Op` and the DAG's own ancestry-fold semantics, not
//! on the pure identity/naming model the domain crate owns.

use yadorilink_replica_domain::change::PutOrigin;
use yadorilink_replica_domain::conflict::conflict_copy_path;
#[cfg(test)]
use yadorilink_replica_domain::conflict::{
    a_is_loser, conflict_copy_source_path, conflict_copy_stem_was_truncated, is_conflict_copy_of,
    is_conflict_copy_path, resolve_conflict_names, MAX_COMPONENT_BYTES,
    MAX_FUTURE_MTIME_SKEW_NANOS, STEM_TRUNCATION_MARKER,
};

/// Ancestry-grounded conflict resolution for the change-history model:
/// two concurrent changes touching the same path (neither an ancestor of
/// the other) are ordered by the lexicographic pair `(lamport,
/// change_hash)` — the higher pair is the deterministic winner and keeps
/// the real path, the lower pair is the loser and is materialized as a
/// conflict copy. Returns whether `a` is that loser.
///
/// This is the deterministic tie-break the change model calls for: `lamport`
/// is a logical counter carried by the
/// signed change (never wall-clock), and `change_hash` is the change's own
/// content address — neither is a value a peer can adaptively inflate to
/// win a conflict the way an unbounded `mtime_unix_nanos` once could (see
/// this module's trust-boundary doc comment). Every replica holding the
/// same two changes computes the identical winner with no communication,
/// which is what makes the materialized state a pure function of the
/// change set.
///
/// `lamport` leads the ordering so a change that causally *could* have
/// seen more history still tends to win; `change_hash` only ever breaks a
/// genuine lamport tie, and does so identically everywhere because it is
/// the canonical hash both sides already agree on.
pub fn dag_conflict_loser_is_a(
    lamport_a: u64,
    change_hash_a: &[u8],
    lamport_b: u64,
    change_hash_b: &[u8],
) -> bool {
    (lamport_a, change_hash_a) < (lamport_b, change_hash_b)
}

/// Builds the conflict-copy path for the *losing* change of a concurrent
/// pair, as a pure function of that losing change — so every replica
/// independently materializes the identical filename with no
/// communication (the change model's "identical conflict-copy naming on
/// every replica" guarantee).
///
/// Delegates to `conflict_copy_path` with inputs drawn entirely from the
/// losing change and the file version it produced, all of which are
/// fields of the signed, content-addressed change and therefore identical
/// on every replica:
/// - `path`: the losing op's target path,
/// - `losing_device_id`: the change's originating device,
/// - `losing_mtime_unix_nanos`: the `mtime` recorded in the losing file
///   version's metadata (part of the version hash, hence signed and
///   deterministic — not a wall-clock read taken at resolution time), used
///   only to format the human-readable stamp in the filename,
/// - `losing_version_hash`: the losing file version's content address,
///   used as the disambiguator that keeps two different losing contents
///   off one conflict-copy path, exactly as `combined_block_hash` is on
///   the legacy path. Carried whole, never truncated -- see
///   `conflict_copy_path`'s own module doc comment.
///
/// Because the *winner* is chosen by `dag_conflict_loser_is_a`
/// (`(lamport, change_hash)`), not by the mtime embedded here, an
/// implausible mtime can at most make the loser's filename stamp look odd;
/// it can never let a change win the real path by lying about time.
pub fn conflict_copy_path_for_losing_change(
    path: &str,
    losing_device_id: &str,
    losing_mtime_unix_nanos: i64,
    losing_version_hash: &[u8],
) -> String {
    conflict_copy_path(path, losing_mtime_unix_nanos, losing_device_id, losing_version_hash)
}

/// Whether any of a change's ops touches `path`.
pub fn change_touches_path(change: &yadorilink_replica_domain::change::Change, path: &str) -> bool {
    use yadorilink_replica_domain::change::Op;
    change.ops.iter().any(|op| match op {
        Op::Put { path: p, .. } | Op::Delete { path: p } => p.as_str() == path,
        Op::Move { from, to, .. } => from.as_str() == path || to.as_str() == path,
    })
}

/// Builds the head a change contributes to `path` — a content head if it
/// lands content there, a removing head if it deletes/moves it away — or
/// `None` if the change does not touch `path`. A `Move` is a hint desugared
/// to `Delete{from}` + `Put{to, origin: Direct}`: it removes `from` and lands
/// content at `to`, so concurrency resolves per desugared path (no special
/// Move-vs-Move rule — two moves to the same target conflict there like any
/// content; to different targets, both land). The `version_hash` comes
/// straight from the op; `mtime` is a deterministic placeholder (0), since
/// the winner is chosen by `(lamport, change_hash)` and the conflict-copy
/// stamp derived from it is then identical on every replica (the file's real
/// mtime lives in the version metadata resolved on the content path).
///
/// A `Put`'s `origin` (`Direct` vs `ConflictCopy`) does not affect this fold
/// at all: whichever change carries a `Put` op touching `path` is `path`'s
/// head, full stop, regardless of why that `Put` exists. This is
/// deliberate, not an oversight — see `PathHead`'s own doc comment for why
/// causal identity (ancestry/supersession/ordering) on `path` is always the
/// *carrier* change's own hash/lamport/device, never the `losing_change`
/// a `ConflictCopy` origin references for validation purposes.
pub fn path_head_from_change(
    change: &yadorilink_replica_domain::change::Change,
    path: &str,
) -> Option<PathHead> {
    use yadorilink_replica_domain::change::Op;
    let mut touches = false;
    let mut content: Option<[u8; 32]> = None;
    // Defaults to the signing device: for every op except a repair
    // re-assertion, whoever signed the change is whoever wrote the content.
    let mut naming_device_id = change.device_id.as_str().to_string();
    for op in &change.ops {
        match op {
            Op::Put { path: p, version, origin } if p.as_str() == path => {
                touches = true;
                content = Some(version.0);
                // A `ConflictCopy` put deliberately keeps the carrier's id
                // here. Its target path is derived from the losing content's
                // own hash, so two different contents can never contend for
                // that path and its naming identity is never consulted --
                // unlike a re-assertion, which lands at the ordinary shared
                // path where content genuinely does contend.
                if let PutOrigin::Reasserted { naming_device_id: original, .. } = origin {
                    naming_device_id = original.as_str().to_string();
                }
            }
            Op::Delete { path: p } if p.as_str() == path => {
                touches = true;
                content = None;
            }
            Op::Move { to, version, .. } if to.as_str() == path => {
                touches = true;
                content = Some(version.0);
            }
            Op::Move { from, .. } if from.as_str() == path => {
                touches = true;
            }
            _ => {}
        }
    }
    if !touches {
        return None;
    }
    Some(PathHead {
        change_hash: change.change_hash().0,
        lamport: change.lamport,
        device_id: change.device_id.as_str().to_string(),
        naming_device_id,
        content: content.map(|version_hash| PathHeadContent { version_hash, mtime_unix_nanos: 0 }),
    })
}

/// Every path a change touches, each paired with the head that change
/// contributes there — i.e. [`path_head_from_change`] evaluated for every
/// path at once, in a single pass over `ops`.
///
/// This is the *normalization* step that lets a store persist a change's
/// path effects next to the change itself, so answering "what does this
/// change do to path P" later never needs the encoded change decoded and
/// its op list rescanned. `Move` is normalized here exactly as the
/// per-path fold normalizes it: a removing effect at `from` and a content
/// effect at `to`.
///
/// Equivalence with the per-path fold is a hard requirement, not an
/// aspiration: a store that derived a *different* answer here would
/// silently resolve paths differently from every code path that still
/// calls `path_head_from_change`. Three details carry that equivalence
/// and are easy to lose in a rewrite:
///
/// - Within one op, at most one match arm fires per path. A self-move
///   (`from == to`) therefore takes the `to` arm only, and lands content.
/// - Effects accumulate in `ops` order, last write winning for `content`,
///   so a change carrying both a `Put` and a `Delete` for one path
///   resolves the same way the fold resolves it.
/// - `Move { from }` marks the path touched but does *not* clear content
///   an earlier op in the same change put there.
///
/// The returned paths are unique, and ordered by first appearance in
/// `ops`. `yadorilink-replica-engine`'s own test module checks this
/// function against `path_head_from_change` over generated changes.
pub fn path_effects_of_change(
    change: &yadorilink_replica_domain::change::Change,
) -> Vec<(String, PathHead)> {
    use yadorilink_replica_domain::change::Op;

    // `content` carries the same three-state meaning the per-path fold
    // gives it: `None` = this path is removed by the change, `Some` = this
    // path holds that version.
    struct Acc {
        content: Option<[u8; 32]>,
        naming_device_id: String,
    }

    let signing_device_id = change.device_id.as_str();
    let mut order: Vec<String> = Vec::new();
    let mut acc: std::collections::HashMap<String, Acc> = std::collections::HashMap::new();
    let touch =
        |order: &mut Vec<String>, acc: &mut std::collections::HashMap<String, Acc>, path: &str| {
            if !acc.contains_key(path) {
                order.push(path.to_string());
                acc.insert(
                    path.to_string(),
                    Acc { content: None, naming_device_id: signing_device_id.to_string() },
                );
            }
        };

    for op in &change.ops {
        match op {
            Op::Put { path, version, origin } => {
                touch(&mut order, &mut acc, path.as_str());
                let entry = acc.get_mut(path.as_str()).expect("just inserted");
                entry.content = Some(version.0);
                if let PutOrigin::Reasserted { naming_device_id: original, .. } = origin {
                    entry.naming_device_id = original.as_str().to_string();
                }
            }
            Op::Delete { path } => {
                touch(&mut order, &mut acc, path.as_str());
                acc.get_mut(path.as_str()).expect("just inserted").content = None;
            }
            Op::Move { from, to, version } => {
                // The `to` arm precedes the `from` arm in the per-path
                // fold's match, so a self-move takes `to` and only `to`.
                touch(&mut order, &mut acc, to.as_str());
                acc.get_mut(to.as_str()).expect("just inserted").content = Some(version.0);
                if from.as_str() != to.as_str() {
                    // Marks `from` touched without clearing content an
                    // earlier op in this same change may have put there --
                    // the fold's `Move { from, .. }` arm sets `touches`
                    // and nothing else.
                    touch(&mut order, &mut acc, from.as_str());
                }
            }
        }
    }

    let change_hash = change.change_hash().0;
    order
        .into_iter()
        .map(|path| {
            let entry = acc.remove(&path).expect("every ordered path has an accumulator");
            let head = PathHead {
                change_hash,
                lamport: change.lamport,
                device_id: signing_device_id.to_string(),
                naming_device_id: entry.naming_device_id,
                content: entry
                    .content
                    .map(|version_hash| PathHeadContent { version_hash, mtime_unix_nanos: 0 }),
            };
            (path, head)
        })
        .collect()
}

/// One live head competing to own — or to remove — a single path `P`,
/// after the ancestry fold has already dropped every change an applied
/// descendant supersedes. Every field is taken verbatim from the signed,
/// content-addressed change (and the file version it produced), so
/// `resolve_path_heads` below is a pure function of the change set and
/// lands identically on every replica with no communication.
///
/// `change_hash`/`lamport`/`device_id` are always the *carrier* change's own
/// — the change whose own `Op` (of any origin) touches `P` — never a
/// `ConflictCopy` origin's `losing_change`. Ancestry/supersession/ordering on
/// `P` are ordinary DAG path semantics keyed on whoever actually wrote to
/// `P`; `losing_change` is a validation-time reference to the change a
/// `ConflictCopy` Put's content was carried forward from, not a competing
/// identity for `P` itself (see `dag_store::conflict_authoring`'s doc
/// comment for the concrete resurrection bug that conflating the two would
/// cause).
#[derive(Clone, Debug)]
pub struct PathHead {
    pub change_hash: [u8; 32],
    pub lamport: u64,
    pub device_id: String,
    /// The device that actually wrote this head's content, used *only* for
    /// deterministic conflict-copy naming — never for ancestry, supersession,
    /// or ordering, all of which stay on `device_id`.
    ///
    /// Equal to `device_id` for an ordinary put: the device that signed the
    /// change is the device that wrote the content. They diverge exactly
    /// when a head carries content forward on someone else's behalf — a
    /// retroactive-repair re-assertion — where `device_id` is the repairer
    /// and this stays the original author, copied from the op
    /// (`PutOrigin::Reasserted`) rather than looked up in history, so a
    /// path's converged name never depends on what a replica still retains.
    ///
    /// A re-assertion may change a path's carrier identity; it must never
    /// change the naming identity of the content it carries.
    pub naming_device_id: String,
    /// The content this head lands at `P`, or `None` when this head removes
    /// `P` — a tombstone, or the source side of a move away from `P`.
    pub content: Option<PathHeadContent>,
}

#[derive(Clone, Debug)]
pub struct PathHeadContent {
    /// Content address of the file version — doubles as the deterministic
    /// conflict-copy disambiguator, embedded in the copy's name in full.
    pub version_hash: [u8; 32],
    /// The version's recorded mtime, used only to format the human-readable
    /// stamp in a conflict-copy filename. Part of the signed version, not a
    /// wall-clock read taken now, so it is identical on every replica.
    pub mtime_unix_nanos: i64,
}

/// A losing content head materialized as a conflict copy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConflictCopy {
    /// Index into the `heads` slice passed to `resolve_path_heads`.
    pub head: usize,
    /// The conflict-copy path — a pure function of the losing change.
    pub path: String,
}

/// The deterministic outcome of materializing one path from its live heads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PathResolution {
    /// Every live head removed the path (all tombstones / moves-away) — the
    /// path is absent. A stale content head that is an *ancestor* of a
    /// tombstone never reaches here (the fold dropped it as superseded), so
    /// this can never resurrect a deleted file.
    Absent,
    /// The path holds `winner`'s content; each losing content head is
    /// materialized as a conflict copy at the returned path.
    Present { winner: usize, conflict_copies: Vec<ConflictCopy> },
}

/// The deterministic per-path materialization fold, expressed as a pure
/// function so both the reconciliation driver and the property-test
/// reference model resolve concurrency identically:
///
/// - **Content vs. tombstone** keeps the content: a tombstone that is
///   merely *concurrent* with a content head is acknowledged (it already
///   superseded whatever it descended from) but does not remove the
///   concurrent content, so only content heads contest the path.
/// - **Content vs. content** (including move-vs-move landing at the same
///   target) picks the highest `(lamport, change_hash)` as the winner
///   (`dag_conflict_loser_is_a`); every other content head becomes a
///   conflict copy whose name is a pure function of that losing change
///   (`conflict_copy_path_for_losing_change`).
/// - **All-tombstone** → the path is absent.
///
/// `heads` must be the *live* heads for `path` (non-superseded changes
/// whose ops touch `path`, with a move contributing a removing head at its
/// source and a content head at its destination). Order does not matter —
/// the winner is chosen by the total order over `(lamport, change_hash)`,
/// so any permutation of `heads` yields the same resolution, which is the
/// commutativity the SEC suite checks.
pub fn resolve_path_heads(path: &str, heads: &[PathHead]) -> PathResolution {
    let content_heads: Vec<usize> =
        heads.iter().enumerate().filter(|(_, h)| h.content.is_some()).map(|(i, _)| i).collect();
    if content_heads.is_empty() {
        return PathResolution::Absent;
    }
    // Winner = highest `(lamport, change_hash)`. `dag_conflict_loser_is_a`
    // is a strict total order over distinct changes (distinct changes have
    // distinct canonical hashes), so this max is unambiguous and identical
    // on every replica.
    let winner = *content_heads
        .iter()
        .max_by(|&&a, &&b| {
            if dag_conflict_loser_is_a(
                heads[a].lamport,
                &heads[a].change_hash,
                heads[b].lamport,
                &heads[b].change_hash,
            ) {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Greater
            }
        })
        .expect("content_heads is non-empty");
    let winner_version = heads[winner].content.as_ref().expect("content head").version_hash;
    // Identical-content collapse: concurrent content heads that resolve the
    // path to the *same* version hash are one equivalence class — byte-identical
    // content is not a conflict, so they produce no conflict copy between them
    // (this is what stops a per-device initial import of the same tree from
    // materializing a copy storm). A conflict copy is emitted only *between*
    // classes with genuinely different content: one per distinct other version
    // hash, its representative being that class's own `(lamport, change_hash)`
    // max — chosen deterministically so every replica names it identically.
    let mut reps: std::collections::BTreeMap<[u8; 32], usize> = std::collections::BTreeMap::new();
    for &i in &content_heads {
        let vh = heads[i].content.as_ref().expect("content head").version_hash;
        if vh == winner_version {
            continue;
        }
        match reps.get(&vh) {
            None => {
                reps.insert(vh, i);
            }
            Some(&rep) => {
                if dag_conflict_loser_is_a(
                    heads[rep].lamport,
                    &heads[rep].change_hash,
                    heads[i].lamport,
                    &heads[i].change_hash,
                ) {
                    reps.insert(vh, i);
                }
            }
        }
    }
    let conflict_copies = reps
        .values()
        .map(|&i| {
            let content = heads[i].content.as_ref().expect("filtered to content heads");
            ConflictCopy {
                head: i,
                path: conflict_copy_path_for_losing_change(
                    path,
                    // The content's author, not this head's carrier: a
                    // repair re-assertion carries someone else's content
                    // forward, and naming the copy after the carrier
                    // attributes that content to a device that never wrote
                    // it (and erases the device that did).
                    &heads[i].naming_device_id,
                    content.mtime_unix_nanos,
                    &content.version_hash,
                ),
            }
        })
        .collect();
    PathResolution::Present { winner, conflict_copies }
}

/// [`resolve_path_heads`] under DIR-1, for authoring and validating the
/// changes that resolve a fork at `path`.
///
/// An explicit Directory keeps its path whoever wins the rank: when any
/// live content head is a Directory, the best-ranked Directory head is the
/// winner, every File or Symlink content class -- the ranked winner's
/// included -- is owed its copy, and a losing Directory is owed none (an
/// empty directory's copy carries nothing). With no Directory head this is
/// exactly [`resolve_path_heads`].
///
/// This is what the namespace projection already shows (a Directory head
/// makes `path` an explicit directory and relocates a ranked File or
/// Symlink to its copy name); a change that supersedes `path`'s heads has
/// to agree with it, or it re-asserts a File over the Directory, or drops
/// the relocated File, which no copy ever made durable.
///
/// `is_directory` is asked only about content heads.
pub fn resolve_path_heads_keeping_directory(
    path: &str,
    heads: &[PathHead],
    is_directory: impl Fn(&PathHead) -> bool,
) -> PathResolution {
    let PathResolution::Present { winner, conflict_copies } = resolve_path_heads(path, heads)
    else {
        return PathResolution::Absent;
    };
    let best_directory = heads
        .iter()
        .enumerate()
        .filter(|(_, head)| head.content.is_some() && is_directory(head))
        .max_by(|(_, a), (_, b)| {
            if dag_conflict_loser_is_a(a.lamport, &a.change_hash, b.lamport, &b.change_hash) {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Greater
            }
        })
        .map(|(index, _)| index);
    let Some(directory) = best_directory else {
        return PathResolution::Present { winner, conflict_copies };
    };
    let mut copies: Vec<ConflictCopy> =
        conflict_copies.into_iter().filter(|copy| !is_directory(&heads[copy.head])).collect();
    if directory != winner {
        // The ranked winner is a File or Symlink (the best Directory would
        // otherwise be the winner itself), and it represents its whole
        // content class: every head with its version collapsed into it.
        let head = &heads[winner];
        let content = head.content.as_ref().expect("resolve_path_heads selects a content head");
        copies.push(ConflictCopy {
            head: winner,
            path: conflict_copy_path_for_losing_change(
                path,
                &head.naming_device_id,
                content.mtime_unix_nanos,
                &content.version_hash,
            ),
        });
    }
    PathResolution::Present { winner: directory, conflict_copies: copies }
}

#[cfg(test)]
mod tests;
