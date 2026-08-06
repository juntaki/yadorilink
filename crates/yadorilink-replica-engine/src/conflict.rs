//! DAG-engine conflict resolution built on top of the deterministic
//! conflict-copy naming policy, which now lives entirely in
//! `yadorilink_replica_domain::conflict` -- every caller in this crate and
//! beyond reaches it there directly (Phase 7D-1). `PathHead`/
//! `PathHeadContent`/`ConflictCopy`/`resolve_path_heads`/
//! `dag_conflict_loser_is_a`/`conflict_copy_path_for_losing_change`/
//! `change_touches_path`/`path_head_from_change` stay here: they operate
//! directly on `Change`/`Op` and the DAG's own ancestry-fold semantics, not
//! on the pure identity/naming model the domain crate owns.

use yadorilink_replica_domain::conflict::conflict_copy_path;
#[cfg(test)]
use yadorilink_replica_domain::conflict::{
    a_is_loser, conflict_copy_source_path, is_conflict_copy_of, is_conflict_copy_path,
    resolve_conflict_names, MAX_FUTURE_MTIME_SKEW_NANOS,
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
///   used as the collision-proof `hash8` disambiguator exactly as
///   `combined_block_hash` is on the legacy path.
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
    for op in &change.ops {
        match op {
            Op::Put { path: p, version, .. } if p.as_str() == path => {
                touches = true;
                content = Some(version.0);
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
        content: content.map(|version_hash| PathHeadContent { version_hash, mtime_unix_nanos: 0 }),
    })
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
    /// The content this head lands at `P`, or `None` when this head removes
    /// `P` — a tombstone, or the source side of a move away from `P`.
    pub content: Option<PathHeadContent>,
}

#[derive(Clone, Debug)]
pub struct PathHeadContent {
    /// Content address of the file version — doubles as the deterministic
    /// conflict-copy disambiguator (`hash8`).
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
                    &heads[i].device_id,
                    content.mtime_unix_nanos,
                    &content.version_hash,
                ),
            }
        })
        .collect();
    PathResolution::Present { winner, conflict_copies }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixed "now" far beyond any of the small epoch-relative mtimes
    /// used throughout this test module, so `MAX_FUTURE_MTIME_SKEW_NANOS`
    /// clamping is a no-op for them — these tests exercise ordinary,
    /// non-adversarial mtime comparisons and must behave exactly as
    /// before the skew bound was added.
    const FAR_FUTURE_NOW: i64 = 2_000_000_000 * 1_000_000_000;

    const HASH_A: &[u8] = b"content-a-loser-bytes";
    const HASH_B: &[u8] = b"content-b-winner-bytes";

    #[test]
    fn conflict_copy_source_path_inverts_generated_names() {
        for original in ["chaos-05.bin", "no-extension", "sub/dir/report.txt"] {
            let copy = conflict_copy_path(original, 1_000, "device-2", &[0xaa, 0xbb, 0xcc, 0xdd]);
            assert_eq!(
                conflict_copy_source_path(&copy),
                original,
                "source reconstruction must invert conflict_copy_path for {original}"
            );
        }
        // A non-copy path maps to itself.
        assert_eq!(conflict_copy_source_path("plain.txt"), "plain.txt");
    }

    #[test]
    fn is_conflict_copy_path_matches_generated_names_and_only_filename_markers() {
        // Whatever `conflict_copy_path` generates must be recognized, with
        // and without an extension, in a subdirectory or not.
        for original in ["chaos-05.bin", "no-extension", "sub/dir/report.txt"] {
            let copy = conflict_copy_path(original, 1_000, "device-2", &[0xaa, 0xbb, 0xcc, 0xdd]);
            assert!(is_conflict_copy_path(&copy), "generated copy path not recognized: {copy}");
            assert!(!is_conflict_copy_path(original), "original misread as a copy: {original}");
        }
        // The marker only counts in the filename stem: a directory
        // component carrying it must not make its ordinary contents read
        // as conflict copies.
        assert!(!is_conflict_copy_path(
            "backups (conflicted copy, 2026-01-01-000000, device-1, aabbccdd)/notes.txt"
        ));
    }

    #[test]
    fn older_mtime_loses() {
        let (winner, loser) = resolve_conflict_names(
            "docs/report.txt",
            1000,
            "device-a",
            HASH_A,
            2000,
            "device-b",
            HASH_B,
            FAR_FUTURE_NOW,
        );
        assert_eq!(winner, "docs/report.txt");
        assert!(loser.contains("device-a")); // device-a had the older mtime
        assert!(loser.starts_with("docs/report (conflicted copy"));
        assert!(loser.ends_with(".txt"));
        assert!(loser.contains(&hex::encode(&HASH_A[..4])), "{loser}");
    }

    #[test]
    fn tie_broken_by_device_id_deterministically() {
        let (_, loser1) = resolve_conflict_names(
            "f.txt",
            5000,
            "device-a",
            HASH_A,
            5000,
            "device-b",
            HASH_B,
            FAR_FUTURE_NOW,
        );
        let (_, loser2) = resolve_conflict_names(
            "f.txt",
            5000,
            "device-b",
            HASH_B,
            5000,
            "device-a",
            HASH_A,
            FAR_FUTURE_NOW,
        );
        // Same inputs regardless of argument order must produce the same
        // result on every peer independently computing this.
        assert_eq!(loser1, loser2);
    }

    #[test]
    fn extensionless_file_has_no_trailing_dot() {
        let name = conflict_copy_path("README", 0, "device-a", HASH_A);
        assert_eq!(
            name,
            format!(
                "README (conflicted copy, 1970-01-01-000000, device-a, {})",
                hex::encode(&HASH_A[..4])
            )
        );
    }

    #[test]
    fn nested_path_preserves_directory() {
        let name = conflict_copy_path("a/b/c.txt", 0, "device-a", HASH_A);
        assert!(name.starts_with("a/b/c (conflicted copy"));
    }

    /// Two different losing contents resolved
    /// within the same second never collide onto one filename: the same
    /// device losing two structurally distinct conflicts for genuinely
    /// different content, with mtimes that truncate to the identical
    /// second, must never produce the same conflict-copy filename — this
    /// is the exact mechanism `monkey_chaos.rs` caught live (see this
    /// module's top-level doc comment).
    #[test]
    fn different_losing_content_in_the_same_second_never_collides() {
        // Both mtimes fall in the same truncated second (999_000_000ns
        // apart, same whole second under `div_euclid(1_000_000_000)`).
        let mtime_1 = 1_700_000_000 * 1_000_000_000i64;
        let mtime_2 = mtime_1 + 999_000_000;
        let (_, loser_1) = resolve_conflict_names(
            "chaos.bin",
            mtime_1,
            "device-loser",
            b"first losing content",
            mtime_1 + 10_000_000_000,
            "device-winner",
            b"winner content unused",
            FAR_FUTURE_NOW,
        );
        let (_, loser_2) = resolve_conflict_names(
            "chaos.bin",
            mtime_2,
            "device-loser",
            b"second losing content, genuinely different",
            mtime_2 + 10_000_000_000,
            "device-winner",
            b"winner content unused",
            FAR_FUTURE_NOW,
        );
        assert_ne!(
            loser_1, loser_2,
            "two different losing contents for the same device/second must not collide: {loser_1} vs {loser_2}"
        );
    }

    /// an already-conflict-suffixed path fed back through
    /// conflict resolution (e.g. the conflict copy itself hits a second,
    /// genuine conflict) must not compound into a doubly-suffixed name.
    #[test]
    fn conflict_copy_naming_does_not_compound_on_an_already_suffixed_path() {
        let already_suffixed = conflict_copy_path("chaos.bin", 0, "device-a", HASH_A);
        let re_resolved = conflict_copy_path(&already_suffixed, 1_000_000_000, "device-b", HASH_B);
        assert_eq!(
            re_resolved.matches("(conflicted copy").count(),
            1,
            "must not compound a second suffix onto an already-suffixed path: {re_resolved}"
        );
        assert!(re_resolved.starts_with("chaos (conflicted copy"), "{re_resolved}");
        assert!(re_resolved.ends_with(".bin"), "{re_resolved}");
    }

    /// extensionless variant: same idempotency guarantee without
    /// an extension in play (exercises the `ext == None` formatting path).
    #[test]
    fn conflict_copy_naming_does_not_compound_without_an_extension() {
        let already_suffixed = conflict_copy_path("README", 0, "device-a", HASH_A);
        let re_resolved = conflict_copy_path(&already_suffixed, 1_000_000_000, "device-b", HASH_B);
        assert_eq!(re_resolved.matches("(conflicted copy").count(), 1, "{re_resolved}");
        assert!(re_resolved.starts_with("README (conflicted copy"), "{re_resolved}");
    }

    /// Adversarial case: a peer advertising
    /// an absurd future `mtime_unix_nanos` (`i64::MAX`) must not
    /// unconditionally win the real filename against a local file with an
    /// ordinary, plausible (near-"now") mtime — the claim gets clamped to
    /// `now + MAX_FUTURE_MTIME_SKEW_NANOS` before comparison, so it can
    /// only win by the bounded skew margin, not by claiming to be
    /// billions of years in the future.
    #[test]
    fn extreme_future_mtime_cannot_unconditionally_win_the_canonical_name() {
        let now = 1_700_000_000 * 1_000_000_000i64; // an ordinary real-world "now"
        let local_mtime = now - 60 * 1_000_000_000; // local edited a minute ago
        let (winner, loser) = resolve_conflict_names(
            "shared.txt",
            local_mtime,
            "device-local",
            HASH_A,
            i64::MAX,
            "device-attacker",
            HASH_B,
            now,
        );
        assert_eq!(winner, "shared.txt");
        // The attacker's file is still the loser (its clamped effective
        // mtime is `now + skew`, later than local's real recent edit) —
        // but the conflict-copy filename embeds the *clamped* timestamp,
        // not the nonsensical far-future date `i64::MAX` would naively
        // format as (year ~292471208677, per `format_timestamp`).
        assert!(loser.contains("device-local"));
        let unclamped_attacker_name =
            conflict_copy_path("shared.txt", i64::MAX, "device-attacker", HASH_B);
        assert_ne!(
            loser, unclamped_attacker_name,
            "conflict-copy filename must not embed the raw unclamped i64::MAX timestamp"
        );
        assert!(!loser.contains("292471208677"), "must not embed i64::MAX's absurd year: {loser}");
    }

    /// Once local's own mtime is *also*
    /// implausibly far in the future relative to "now" (or once the
    /// attacker's clamped value ties with it), the extreme value no
    /// longer wins outright — it degrades to the deterministic device-id
    /// tie-break rather than granting the attacker an unbounded
    /// advantage. This pins down that the bound is a real ceiling, not
    /// just cosmetic: an attacker cannot out-claim a target that is
    /// itself already at (or past) the plausible-future ceiling.
    #[test]
    fn future_skew_bound_caps_the_winning_margin_not_just_the_filename() {
        let now = 1_700_000_000 * 1_000_000_000i64;
        // Local's own mtime is already at the far edge of what's trusted.
        let local_mtime = now + MAX_FUTURE_MTIME_SKEW_NANOS;
        let is_a_loser = a_is_loser(local_mtime, "device-local", i64::MAX, "device-attacker", now);
        // Both sides clamp to the same effective ceiling (`now + skew`),
        // so this degrades to the device-id tie-break, not an automatic
        // attacker win.
        assert_eq!(is_a_loser, "device-local" < "device-attacker");
    }

    /// Legitimate case: an ordinary,
    /// non-adversarial mtime comparison (both well in the past relative
    /// to "now") is completely unaffected by the skew bound — the older,
    /// real mtime loses exactly as it always did.
    #[test]
    fn plausible_past_mtimes_are_unaffected_by_the_skew_bound() {
        let now = 1_700_000_000 * 1_000_000_000i64;
        let older = now - 3600 * 1_000_000_000; // an hour ago
        let newer = now - 60 * 1_000_000_000; // a minute ago
        let (winner, loser) = resolve_conflict_names(
            "notes.md", older, "device-a", HASH_A, newer, "device-b", HASH_B, now,
        );
        assert_eq!(winner, "notes.md");
        assert!(loser.contains("device-a")); // the genuinely older edit loses, as before
    }

    // `is_conflict_copy_of` coverage.

    #[test]
    fn is_conflict_copy_of_matches_a_genuine_sibling() {
        assert!(is_conflict_copy_of(
            "chaos-b (conflicted copy, 2026-07-08-120000, device-a, 6c455bc2).bin",
            "chaos-b.bin",
        ));
    }

    #[test]
    fn is_conflict_copy_of_matches_within_a_subdirectory() {
        assert!(is_conflict_copy_of(
            "docs/report (conflicted copy, 2026-07-08-120000, device-a, aabbccdd).txt",
            "docs/report.txt",
        ));
    }

    #[test]
    fn is_conflict_copy_of_rejects_the_original_path_itself() {
        assert!(!is_conflict_copy_of("chaos-b.bin", "chaos-b.bin"));
    }

    #[test]
    fn is_conflict_copy_of_rejects_an_unrelated_file_with_no_conflict_marker() {
        assert!(!is_conflict_copy_of("chaos-b-backup.bin", "chaos-b.bin"));
    }

    #[test]
    fn is_conflict_copy_of_rejects_a_conflict_copy_of_a_different_stem() {
        assert!(!is_conflict_copy_of(
            "chaos-c (conflicted copy, 2026-07-08-120000, device-a, 6c455bc2).bin",
            "chaos-b.bin",
        ));
    }

    #[test]
    fn is_conflict_copy_of_rejects_a_conflict_copy_with_a_different_extension() {
        assert!(!is_conflict_copy_of(
            "chaos-b (conflicted copy, 2026-07-08-120000, device-a, 6c455bc2).txt",
            "chaos-b.bin",
        ));
    }

    #[test]
    fn is_conflict_copy_of_rejects_a_conflict_copy_in_a_different_directory() {
        assert!(!is_conflict_copy_of(
            "other/chaos-b (conflicted copy, 2026-07-08-120000, device-a, 6c455bc2).bin",
            "chaos-b.bin",
        ));
    }

    // Ancestry-grounded `(lamport, change_hash)` conflict resolution.

    #[test]
    fn higher_lamport_wins_regardless_of_hash() {
        // a has the higher lamport, so a wins and b is the loser, even
        // though b's hash sorts higher.
        assert!(!dag_conflict_loser_is_a(9, b"\x00\x00", 8, b"\xff\xff"));
        assert!(dag_conflict_loser_is_a(8, b"\xff\xff", 9, b"\x00\x00"));
    }

    #[test]
    fn equal_lamport_breaks_on_change_hash() {
        // Same lamport: the lexicographically smaller change hash loses.
        assert!(dag_conflict_loser_is_a(5, b"\x01", 5, b"\x02"));
        assert!(!dag_conflict_loser_is_a(5, b"\x02", 5, b"\x01"));
    }

    #[test]
    fn dag_resolution_is_observer_independent() {
        // Whichever way the pair is presented, the same change is the
        // loser — the property that makes every replica agree without
        // communicating.
        let a = (7u64, &b"aaaa"[..]);
        let b = (7u64, &b"bbbb"[..]);
        let a_loses = dag_conflict_loser_is_a(a.0, a.1, b.0, b.1);
        let b_loses = dag_conflict_loser_is_a(b.0, b.1, a.0, a.1);
        assert_ne!(a_loses, b_loses, "exactly one side must be the loser");
        assert!(a_loses, "the lexicographically smaller change hash loses");
    }

    #[test]
    fn losing_change_name_is_a_pure_function_of_its_fields() {
        // Two replicas independently naming the same losing change from
        // its (path, device, mtime, version-hash) must land on the exact
        // same conflict-copy filename.
        let version_hash = [0xABu8, 0xCD, 0xEF, 0x01, 0x02, 0x03];
        let name_replica_1 = conflict_copy_path_for_losing_change(
            "docs/report.docx",
            "device-c",
            1_700_000_000 * 1_000_000_000,
            &version_hash,
        );
        let name_replica_2 = conflict_copy_path_for_losing_change(
            "docs/report.docx",
            "device-c",
            1_700_000_000 * 1_000_000_000,
            &version_hash,
        );
        assert_eq!(name_replica_1, name_replica_2);
        assert!(name_replica_1.starts_with("docs/report (conflicted copy"));
        assert!(name_replica_1.contains("device-c"));
        assert!(name_replica_1.ends_with(".docx"));
        assert!(name_replica_1.contains(&hex::encode(&version_hash[..4])));
    }

    #[test]
    fn losing_change_name_matches_the_underlying_primitive() {
        // The DAG entry point is exactly the existing naming primitive
        // with the argument order that reads naturally for a change, so
        // the two can never drift apart.
        let vh = [1u8, 2, 3, 4];
        assert_eq!(
            conflict_copy_path_for_losing_change("a/b.txt", "dev-x", 42, &vh),
            conflict_copy_path("a/b.txt", 42, "dev-x", &vh),
        );
    }
}
