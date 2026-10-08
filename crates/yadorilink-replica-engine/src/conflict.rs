//! Per-path head conflict resolution built on top of the deterministic
//! conflict-copy naming policy, which now lives entirely in
//! `yadorilink_replica_domain::conflict` -- every caller in this crate and
//! beyond reaches it there directly. `PathHead`/
//! `PathHeadContent`/`ConflictCopy`/`resolve_path_heads`/
//! `dag_conflict_loser_is_a`/`conflict_copy_path_for_losing_change`/
//! `change_touches_path`/`path_head_from_change` stay here: they operate
//! on a path's live head set, not on the pure identity/naming model the
//! domain crate owns.

use yadorilink_replica_domain::conflict::conflict_copy_path;
#[cfg(test)]
use yadorilink_replica_domain::conflict::{
    a_is_loser, conflict_copy_source_path, conflict_copy_stem_was_truncated, is_conflict_copy_of,
    is_conflict_copy_path, resolve_conflict_names, MAX_COMPONENT_BYTES,
    MAX_FUTURE_MTIME_SKEW_NANOS, STEM_TRUNCATION_MARKER,
};

/// The deterministic winner rule between two distinct live content heads
/// of one path: the greater pair `(rank, change_hash)` wins and keeps the
/// real path, the other is the loser and is materialized as a conflict
/// copy. Returns whether `a` is that loser.
///
/// `rank` is the head's display rank. It is display only. Which heads
/// are live is decided by native state alone; this rule only chooses
/// which of them keeps the name, so a writer that inflates its rank can at
/// most have its own concurrent version shown under the name, and no head
/// is kept or removed because of it. The rank leads so that a head that
/// saw more history tends to be the one shown; `change_hash`, the head's
/// content address, breaks a rank tie identically everywhere. Every
/// replica holding the same heads computes the same winner with no
/// communication, which keeps the materialized state a pure function of
/// the heads.
pub fn dag_conflict_loser_is_a(
    rank_a: u64,
    change_hash_a: &[u8],
    rank_b: u64,
    change_hash_b: &[u8],
) -> bool {
    (rank_a, change_hash_a) < (rank_b, change_hash_b)
}

/// Builds the conflict-copy path for the *losing* change of a concurrent
/// pair, as a pure function of that losing change — so every replica
/// independently materializes the identical filename with no
/// communication (identical conflict-copy naming on
/// every replica).
///
/// Delegates to `conflict_copy_path` with inputs drawn entirely from the
/// losing change and the file version it produced, all of which are
/// fields of the signed, content-addressed head and therefore identical
/// on every replica:
/// - `path`: the losing op's target path,
/// - `losing_device_id`: the change's originating device,
/// - `losing_mtime_unix_nanos`: the `mtime` recorded in the losing file
///   version's metadata (part of the version hash, hence signed and
///   deterministic — not a wall-clock read taken at resolution time), used
///   only to format the human-readable stamp in the filename,
/// - `losing_version_hash`: the losing file version's content address,
///   used as the disambiguator that keeps two different losing contents
///   off one conflict-copy path. Carried whole, never truncated -- see
///   `conflict_copy_path`'s own module doc comment.
///
/// Because the *winner* is chosen by `dag_conflict_loser_is_a`
/// (`(rank, change_hash)`), not by the mtime embedded here, an
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

/// One live head competing to own — or to remove — a single path `P`,
/// after every head a later head supersedes has already been dropped. Every field is taken verbatim from the signed,
/// content-addressed change (and the file version it produced), so
/// `resolve_path_heads` below is a pure function of the change set and
/// lands identically on every replica with no communication.
///
/// `change_hash`/`rank`/`device_id` are always the *carrier* head's own
/// — the head whose own `Op` (of any origin) touches `P` — never a
/// `ConflictCopy` origin's `losing_change`. Supersession and ordering on
/// `P` are keyed on whoever actually wrote to `P`; `losing_change` is a
/// validation-time reference to the head a `ConflictCopy` Put's content was
/// carried forward from, not a competing identity for `P` itself (conflating
/// the two would resurrect a deleted path).
#[derive(Clone, Debug)]
pub struct PathHead {
    pub change_hash: [u8; 32],
    /// Display rank: orders which live head keeps the name
    /// ([`dag_conflict_loser_is_a`]) and nothing else.
    pub rank: u64,
    pub device_id: String,
    /// The device that actually wrote this head's content, used *only* for
    /// deterministic conflict-copy naming — never for ancestry, supersession,
    /// or ordering, all of which stay on `device_id`.
    ///
    /// Equal to `device_id` for an ordinary put: the device that signed the
    /// change is the device that wrote the content. They diverge exactly
    /// when a head carries content forward on someone else's behalf — a
    /// retroactive-repair re-assertion — where `device_id` is the repairer
    /// and this stays the original author, copied from the op rather than
    /// looked up in history, so a
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
    /// path is absent. A stale content head that a tombstone supersedes
    /// never reaches here (it was dropped as superseded), so
    /// this can never resurrect a deleted file.
    Absent,
    /// The path holds `winner`'s content; each losing content head is
    /// materialized as a conflict copy at the returned path.
    Present { winner: usize, conflict_copies: Vec<ConflictCopy> },
}

/// The deterministic per-path materialization fold, expressed as a pure
/// function so every caller resolves concurrency identically:
///
/// - **Content vs. tombstone** keeps the content: a tombstone that is
///   merely *concurrent* with a content head is acknowledged (it already
///   superseded whatever it descended from) but does not remove the
///   concurrent content, so only content heads contest the path.
/// - **Content vs. content** (including move-vs-move landing at the same
///   target) picks the highest `(rank, change_hash)` as the winner
///   (`dag_conflict_loser_is_a`); every other content head becomes a
///   conflict copy whose name is a pure function of that losing change
///   (`conflict_copy_path_for_losing_change`).
/// - **All-tombstone** → the path is absent.
///
/// `heads` must be the *live* heads for `path` (non-superseded heads
/// whose ops touch `path`, with a move contributing a removing head at its
/// source and a content head at its destination). Order does not matter —
/// the winner is chosen by the total order over `(rank, change_hash)`,
/// so any permutation of `heads` yields the same resolution, which is the
/// commutativity the SEC suite checks.
pub fn resolve_path_heads(path: &str, heads: &[PathHead]) -> PathResolution {
    let content_heads: Vec<usize> =
        heads.iter().enumerate().filter(|(_, h)| h.content.is_some()).map(|(i, _)| i).collect();
    if content_heads.is_empty() {
        return PathResolution::Absent;
    }
    // Winner = highest `(rank, change_hash)`. `dag_conflict_loser_is_a`
    // is a strict total order over distinct heads (distinct heads have
    // distinct canonical hashes), so this max is unambiguous and identical
    // on every replica.
    let winner = *content_heads
        .iter()
        .max_by(|&&a, &&b| {
            if dag_conflict_loser_is_a(
                heads[a].rank,
                &heads[a].change_hash,
                heads[b].rank,
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
    // hash, its representative being that class's own `(rank, change_hash)`
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
                    heads[rep].rank,
                    &heads[rep].change_hash,
                    heads[i].rank,
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

#[cfg(test)]
mod tests;
