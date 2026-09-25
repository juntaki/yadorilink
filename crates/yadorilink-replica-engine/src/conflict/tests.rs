#![cfg(test)]

use super::*;
use yadorilink_replica_domain::test_authoring::create_signed_for_tests;

/// A fixed "now" far beyond any of the small epoch-relative mtimes
/// used throughout this test module, so `MAX_FUTURE_MTIME_SKEW_NANOS`
/// clamping is a no-op for them — these tests exercise ordinary,
/// non-adversarial mtime comparisons and must behave exactly as
/// before the skew bound was added.
const FAR_FUTURE_NOW: i64 = 2_000_000_000 * 1_000_000_000;

const HASH_A: &[u8] = b"content-a-loser-bytes";
const HASH_B: &[u8] = b"content-b-winner-bytes";

/// `path_effects_of_change` is the write-side normalization a store
/// persists so it never has to decode a change and rescan its ops to
/// answer "what does this change do to path P". It is only safe to
/// persist if it agrees, for every path, with the per-path fold
/// (`path_head_from_change`) that every remaining reader still uses --
/// a disagreement would not fail loudly, it would resolve some path
/// differently depending on which of the two answered.
///
/// So this checks the two against each other over generated changes
/// that deliberately include the shapes where a hand-written
/// single-pass rewrite diverges: a self-move, a `Put` and a `Delete`
/// for the same path in one change, a move whose source was also put
/// by the same change, a re-assertion (which moves naming identity
/// off the signer), and a conflict-copy put (which must NOT).
#[test]
fn path_effects_agree_with_the_per_path_fold_for_every_touched_path() {
    use ed25519_dalek::SigningKey;
    use yadorilink_replica_domain::change::{Op, PutOrigin};
    use yadorilink_replica_domain::ids::{
        ChangeHash, DeviceId, FolderGroupId, SyncPath, VersionHash,
    };

    fn p(s: &str) -> SyncPath {
        SyncPath(s.to_string())
    }
    fn v(byte: u8) -> VersionHash {
        VersionHash([byte; 32])
    }

    let key = SigningKey::from_bytes(&[7u8; 32]);
    let device = DeviceId("device-signer".to_string());
    let other = DeviceId("device-original-author".to_string());
    let group = FolderGroupId("group-effects".to_string());

    let op_pool: Vec<Vec<Op>> = vec![
        // A plain put.
        vec![Op::Put { path: p("a.txt"), version: v(1), origin: PutOrigin::Direct }],
        // A plain delete.
        vec![Op::Delete { path: p("a.txt") }],
        // An ordinary move: removing effect at `from`, content at `to`.
        vec![Op::Move { from: p("a.txt"), to: p("b.txt"), version: v(2) }],
        // A self-move: the `to` arm wins, so this lands content.
        vec![Op::Move { from: p("a.txt"), to: p("a.txt"), version: v(3) }],
        // Put and delete for one path in one change.
        vec![
            Op::Put { path: p("a.txt"), version: v(4), origin: PutOrigin::Direct },
            Op::Delete { path: p("a.txt") },
        ],
        // A move whose source this same change also put.
        vec![
            Op::Put { path: p("a.txt"), version: v(5), origin: PutOrigin::Direct },
            Op::Move { from: p("a.txt"), to: p("c.txt"), version: v(6) },
        ],
        // A re-assertion: naming identity moves off the signer.
        vec![Op::Put {
            path: p("a.txt"),
            version: v(7),
            origin: PutOrigin::Reasserted {
                original_change: ChangeHash([9u8; 32]),
                naming_device_id: other.clone(),
            },
        }],
        // A conflict-copy put: naming identity stays on the carrier.
        vec![Op::Put {
            path: p("a.txt"),
            version: v(8),
            origin: PutOrigin::ConflictCopy {
                source_path: p("b.txt"),
                losing_change: ChangeHash([10u8; 32]),
            },
        }],
        // Several unrelated paths at once.
        vec![
            Op::Put { path: p("x/1.txt"), version: v(11), origin: PutOrigin::Direct },
            Op::Delete { path: p("x/2.txt") },
            Op::Move { from: p("x/3.txt"), to: p("x/4.txt"), version: v(12) },
        ],
    ];

    // Every subset-of-two combination as well, so ops from different
    // shapes interleave under the canonical op ordering.
    let mut op_sets: Vec<Vec<Op>> = op_pool.clone();
    for a in &op_pool {
        for b in &op_pool {
            let mut combined = a.clone();
            combined.extend(b.iter().cloned());
            op_sets.push(combined);
        }
    }

    let every_path =
        ["a.txt", "b.txt", "c.txt", "x/1.txt", "x/2.txt", "x/3.txt", "x/4.txt", "absent.txt"];

    for ops in op_sets {
        let change = create_signed_for_tests(vec![], 0, device.clone(), group.clone(), ops, &key);
        let effects = path_effects_of_change(&change);

        // No path appears twice.
        let mut seen = std::collections::HashSet::new();
        for (path, _) in &effects {
            assert!(seen.insert(path.clone()), "path {path} appeared twice in the effects");
        }

        for path in every_path {
            let folded = path_head_from_change(&change, path);
            let normalized = effects.iter().find(|(p, _)| p == path).map(|(_, h)| h);
            match (&folded, normalized) {
                (None, None) => {}
                (Some(f), Some(n)) => {
                    assert_eq!(f.change_hash, n.change_hash, "change_hash for {path}");
                    assert_eq!(f.lamport, n.lamport, "lamport for {path}");
                    assert_eq!(f.device_id, n.device_id, "device_id for {path}");
                    assert_eq!(
                        f.naming_device_id, n.naming_device_id,
                        "naming_device_id for {path}"
                    );
                    assert_eq!(
                        f.content.as_ref().map(|c| c.version_hash),
                        n.content.as_ref().map(|c| c.version_hash),
                        "content for {path}"
                    );
                    assert_eq!(
                        f.content.as_ref().map(|c| c.mtime_unix_nanos),
                        n.content.as_ref().map(|c| c.mtime_unix_nanos),
                        "mtime for {path}"
                    );
                }
                (Some(_), None) => {
                    panic!("the fold found a head at {path} that normalization missed")
                }
                (None, Some(_)) => {
                    panic!("normalization invented a head at {path} the fold does not see")
                }
            }
        }

        // `change_touches_path` is the other read-side twin: the set of
        // normalized paths must be exactly the set it reports touched.
        for path in every_path {
            assert_eq!(
                change_touches_path(&change, path),
                effects.iter().any(|(p, _)| p == path),
                "touch disagreement at {path}"
            );
        }
    }
}

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

/// Pins the limit of that inversion: the naming is injective in the
/// losing *content*, which is what preservation rests on, and is NOT
/// injective in the *source path*.
///
/// The suffix strip runs from the leftmost marker and cannot tell a
/// generated suffix from one a user typed, so a hand-named
/// `a (conflicted copy, x).txt` reduces to the same base as a generated
/// copy of `a.txt`. This is by design: compounding suffixes instead
/// would grow names without bound, and no caller needs the inverse to
/// be injective. It is pinned because a caller that
/// reasons backwards from a copy name to what it replaced -- anything
/// deciding a copy is unjustified, or reconciling copies across a
/// history boundary -- is only correct if it already treats the inverse
/// as evidence rather than proof.
#[test]
fn conflict_copy_naming_is_injective_in_content_but_not_in_the_source_path() {
    // Same source, different losing content: different names. This is
    // the direction preservation depends on.
    let one = conflict_copy_path("a.txt", 1_000, "device-1", &[1u8; 32]);
    let two = conflict_copy_path("a.txt", 1_000, "device-1", &[2u8; 32]);
    assert_ne!(one, two);

    // Different sources, same losing content: the same name, because a
    // user-typed marker is stripped exactly like a generated one.
    let from_plain = conflict_copy_path("a.txt", 1_000, "device-1", &[1u8; 32]);
    let from_marked =
        conflict_copy_path("a (conflicted copy, typed-by-hand).txt", 1_000, "device-1", &[1u8; 32]);
    assert_eq!(
        from_plain, from_marked,
        "the naming is not injective in the source path, and callers must not assume it is"
    );
    assert_eq!(
        conflict_copy_source_path(&from_marked),
        "a.txt",
        "inversion answers with the stripped base, not the hand-typed original"
    );
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
    assert!(loser.contains(&hex::encode(HASH_A)), "{loser}");
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
        format!("README (conflicted copy, 1970-01-01-000000, device-a, {})", hex::encode(HASH_A))
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
    assert!(name_replica_1.contains(&hex::encode(version_hash)));
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

/// The conflict-copy naming invariant conflict preservation rests on,
/// as a property over many generated inputs rather than one example:
///
/// ```text
/// V1 != V2  =>  conflict_copy_path(p, t, d, V1) != conflict_copy_path(p, t, d, V2)
/// ```
///
/// A single example is not enough here. The defect this replaced was a
/// 32-bit truncation of the hash, and a hand-picked pair of hashes
/// almost never collides in 32 bits -- the naming looked correct for
/// every example anyone wrote down, while a whole class of real
/// conflicts silently overwrote each other. So this sweeps a grid of
/// distinct hashes crossed with distinct devices, timestamps and paths
/// and requires the map to be injective over the whole grid, which
/// a truncating implementation cannot be once the grid is wider than
/// the truncation.
///
/// It checks the stronger statement too -- distinct `(path, timestamp,
/// device, hash)` tuples give distinct names, not just distinct hashes
/// -- because that is what the deterministic naming actually has to
/// deliver; the hash-only invariant above is the special case that
/// matters for preservation (two losers at one path from one device
/// differ in nothing else).
#[test]
fn conflict_copy_path_is_injective_over_distinct_hashes_devices_and_timestamps() {
    use std::collections::{HashMap, HashSet};

    // A distinct 32-byte hash per index, generated the way a real
    // version hash arrives: as the digest of something, so the grid
    // exercises full-width, unstructured hashes rather than values that
    // happen to differ in their first bytes.
    fn digest(i: u32) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"conflict-injectivity-property/");
        hasher.update(i.to_le_bytes());
        hasher.finalize().into()
    }

    // The generated hash set: unstructured digests, plus -- crucially --
    // one deliberately adversarial family. Random digests alone would
    // not reliably catch a prefix truncation: 512 random values collide
    // in their first 32 bits only about once in thirty thousand runs,
    // which is exactly why a truncating implementation survived every
    // example test written against it. For each prefix length k, the
    // family adds a hash agreeing with `digest(0)` on its first k bytes
    // and differing immediately after, so ANY implementation that names
    // a copy after a prefix of the hash (of any width short of the whole
    // thing) is caught deterministically, on every run, rather than
    // probabilistically.
    let mut hashes: Vec<[u8; 32]> = (0..512u32).map(digest).collect();
    for k in 1..32usize {
        let mut mutant = digest(0);
        mutant[k] ^= 0xff;
        hashes.push(mutant);
    }
    // Sanity: the family really is distinct (a duplicate would make the
    // property vacuously unsatisfiable rather than test anything).
    assert_eq!(
        hashes.iter().collect::<HashSet<_>>().len(),
        hashes.len(),
        "the generated hashes must themselves be distinct"
    );

    let paths = ["notes.txt", "a/b/c.bin", "README", "dir.with.dots/file.tar.gz"];
    let devices = ["device-a", "device-b", "dev-0123456789abcdef"];
    // Distinct whole seconds: the stamp is formatted to second
    // granularity on purpose (it is a human-readable label, not an
    // identity), so two mtimes inside one second are the case the stamp
    // deliberately cannot separate -- covered on its own below.
    let base = 1_700_000_000 * 1_000_000_000i64;
    let timestamps = [base, base + 1_000_000_000, base + 86_400 * 1_000_000_000];

    let mut seen: HashMap<String, (usize, usize, usize, usize)> = HashMap::new();
    for (pi, path) in paths.iter().enumerate() {
        for (di, device) in devices.iter().enumerate() {
            for (ti, &timestamp) in timestamps.iter().enumerate() {
                for (hi, hash) in hashes.iter().enumerate() {
                    let name = conflict_copy_path(path, timestamp, device, hash);
                    if let Some(prev) = seen.insert(name.clone(), (pi, di, ti, hi)) {
                        panic!(
                            "conflict-copy naming is not injective: {prev:?} and {:?} \
                             both produce {name}",
                            (pi, di, ti, hi)
                        );
                    }
                }
            }
        }
    }

    // The invariant in its load-bearing form: everything else the name
    // can carry held equal, including an mtime inside the SAME truncated
    // second, so the content hash is the only thing left to tell two
    // losers apart. This is the real shape of a concurrent conflict --
    // and for a DAG-resolved conflict the stamp is a fixed placeholder
    // anyway, so the hash is the only disambiguator that exists at all.
    let same_second = base + 999_999_999;
    assert_eq!(
        conflict_copy_path("shared.txt", base, "device-a", &hashes[0]),
        conflict_copy_path("shared.txt", same_second, "device-a", &hashes[0]),
        "the stamp is second-granular: this pair can only differ if the hash does"
    );
    let mut names = HashSet::new();
    for hash in &hashes {
        let name = conflict_copy_path("shared.txt", same_second, "device-a", hash);
        assert!(names.insert(name.clone()), "two distinct hashes share one name: {name}");
    }

    // Injectivity must not have been bought by letting the name grow
    // without bound: a generated filename component has to stay inside
    // the 255-byte floor every target filesystem guarantees for one
    // component. Checked on the widest inputs in the grid.
    let widest =
        conflict_copy_path("dir.with.dots/file.tar.gz", base, "dev-0123456789abcdef", &hashes[0]);
    let component = widest.rsplit_once('/').map_or(widest.as_str(), |(_, name)| name);
    assert!(
        component.len() <= MAX_COMPONENT_BYTES,
        "conflict-copy filename component exceeds the portable 255-byte floor ({}): {component}",
        component.len()
    );
}

/// The length bound, as a property over stems of every length rather
/// than over the one widest name in the grid above.
///
/// The grid's stems are a dozen bytes long, so its length assertion can
/// only ever confirm that short names are short. The bound bites on the
/// other end: the suffix is 105 bytes plus the device id, so a stem in
/// the low hundreds pushes the component past the 255-byte floor, and an
/// over-long component is not cosmetic — the materializer cannot create
/// the file (`ENAMETOOLONG`), so the losing content the copy exists to
/// preserve never reaches the disk at all. That is the same loss class
/// as a colliding name, arriving through length instead.
///
/// So this sweeps stem lengths across the whole region where the bound
/// engages, with and without an extension, in a subdirectory and at the
/// root, and with multi-byte characters (where a byte-wise cut would
/// split a character). Every generated component must fit, and the
/// disambiguating fields must survive intact: the whole hash is still
/// present, so distinct contents are still distinct names.
#[test]
fn a_generated_conflict_copy_component_always_fits_the_portable_limit() {
    let hash = [0x5au8; 32];
    let hash_hex = hex::encode(hash);
    let devices = ["d", "device-a", "dev-0123456789abcdef0123456789abcdef"];
    let stamp = 1_700_000_000 * 1_000_000_000i64;

    for device in devices {
        for len in [0usize, 1, 50, 120, 140, 149, 150, 151, 200, 255, 256, 1_000] {
            // ASCII stems, plus a stem of 3-byte characters at roughly
            // the same byte length, so the cut has to respect character
            // boundaries rather than bytes.
            let ascii = "s".repeat(len);
            let wide = "あ".repeat(len / 3);
            for stem in [ascii.as_str(), wide.as_str()] {
                if stem.is_empty() {
                    continue;
                }
                for path in [format!("{stem}.tar.gz"), stem.to_string(), format!("a/b/{stem}.txt")]
                {
                    let name = conflict_copy_path(&path, stamp, device, &hash);
                    let component = name.rsplit_once('/').map_or(name.as_str(), |(_, n)| n);
                    assert!(
                        component.len() <= MAX_COMPONENT_BYTES,
                        "component is {} bytes for a {}-byte stem and device {device}: {component}",
                        component.len(),
                        stem.len()
                    );
                    assert!(
                        component.contains(&hash_hex),
                        "the whole content hash must survive the length fit: {component}"
                    );
                    assert!(
                        component.contains(device),
                        "the device id must survive the length fit: {component}"
                    );
                    // A cut is marked, and only when there really was
                    // one. The stem the naming works on is the filename
                    // up to its last dot, which for `x.tar.gz` is
                    // `x.tar` -- so the comparison is against that, not
                    // against the loop's `stem`.
                    let filename = path.rsplit_once('/').map_or(path.as_str(), |(_, n)| n);
                    let file_stem = match filename.rsplit_once('.') {
                        Some((s, _)) if !s.is_empty() => s,
                        _ => filename,
                    };
                    let was_cut = conflict_copy_stem_was_truncated(&name);
                    assert_eq!(
                        was_cut,
                        !component.starts_with(file_stem),
                        "truncation marker disagrees with whether the stem survived: {component}"
                    );
                    // Still derived from its source as far as every
                    // caller that asks is concerned.
                    assert!(
                        is_conflict_copy_of(&name, &path),
                        "a length-fitted copy must still be recognized as derived from {path}"
                    );
                    assert!(is_conflict_copy_path(&name));
                }
            }
        }
    }
}

/// Fitting the name to the component limit must not cost injectivity in
/// the content hash: two different losing contents under one long file
/// name must still land on two different paths. This is the same
/// invariant as the grid property above, restated where the stem is long
/// enough that something had to be cut — the case where an
/// implementation that shortened the hash "to make room" would look
/// perfectly reasonable and lose content.
#[test]
fn shortening_a_long_name_never_merges_two_distinct_losing_contents() {
    use std::collections::HashSet;

    let long_stem = "とても長いファイル名".repeat(20);
    let path = format!("deep/dir/{long_stem}.txt");
    let stamp = 1_700_000_000 * 1_000_000_000i64;

    let mut names = HashSet::new();
    for i in 0..256u32 {
        let mut hash = [0u8; 32];
        // Differing only in the LAST byte: a name built from any prefix
        // of the hash collapses this whole family onto one path.
        hash[31] = i as u8;
        hash[30] = (i >> 8) as u8;
        let name = conflict_copy_path(&path, stamp, "device-a", &hash);
        assert!(names.insert(name.clone()), "two distinct contents share one name: {name}");
    }
    assert_eq!(names.len(), 256);
}

/// A shortened name is a prefix of its source, so inverting it gives a
/// marked prefix rather than the original path — and callers that act
/// destructively on that inversion have to be able to tell. This pins
/// both halves: the marker is reported, and the inversion is honest
/// about being partial instead of silently returning a path that looks
/// real.
#[test]
fn a_shortened_conflict_copy_reports_that_its_source_path_is_only_a_prefix() {
    let stem = "x".repeat(300);
    let path = format!("dir/{stem}.txt");
    let name = conflict_copy_path(&path, 0, "device-a", &[0xab; 32]);

    assert!(conflict_copy_stem_was_truncated(&name));
    let inverted = conflict_copy_source_path(&name);
    assert_ne!(inverted, path, "a shortened name cannot reconstruct the whole source path");
    assert!(
        inverted.ends_with(&format!("{STEM_TRUNCATION_MARKER}.txt")),
        "the partial reconstruction must carry the cut marker: {inverted}"
    );

    // A name that fitted is inverted exactly, and is not reported as cut.
    let short = conflict_copy_path("dir/notes.txt", 0, "device-a", &[0xab; 32]);
    assert!(!conflict_copy_stem_was_truncated(&short));
    assert_eq!(conflict_copy_source_path(&short), "dir/notes.txt");
    // Nor is an ordinary file that merely ends in the marker character.
    assert!(!conflict_copy_stem_was_truncated("dir/emacs-backup~.txt"));
}

/// Conflict preservation, stated as a property over an exhaustive
/// enumeration of small concurrent-write sets at one path rather than a
/// handful of examples.
///
/// The guarantee the whole conflict machinery exists to provide is:
///
/// > after resolving one path's concurrent heads, every distinct
/// > concurrent content is still reachable somewhere on disk -- at the
/// > canonical path or at a conflict copy -- and no two distinct contents
/// > are placed at the same path.
///
/// Both halves matter and they fail differently. Dropping a class loses
/// content loudly-ish (the file is simply not there). Two classes sharing
/// one path loses content silently: both are "preserved" as far as the
/// resolution is concerned, one overwrites the other on disk, and every
/// replica agrees on the result, so nothing downstream can tell. That
/// second half is what an injective conflict-copy name buys, and this is
/// where the two halves get checked together.
///
/// The enumeration is exhaustive over every assignment of {three distinct
/// contents, tombstone} x {two lamports} to up to four concurrent heads,
/// with distinct change hashes and alternating devices -- 4096 head sets,
/// covering all-tombstone, single-content, duplicate-content (the
/// identical-content collapse), and every mixed shape.
#[test]
fn every_distinct_concurrent_content_class_survives_resolution_at_a_distinct_path() {
    use std::collections::{BTreeSet, HashMap};

    const PATH: &str = "docs/report.txt";
    // Three distinct contents, generated as digests so they are
    // full-width and unstructured. Classes 1 and 2 deliberately agree on
    // all but their last byte: distinct contents whose hashes are close
    // are exactly the pair a truncating conflict-copy name would place on
    // one path, so the "no two classes share a path" half below is a real
    // check here rather than one that only ever sees easy inputs.
    fn content(class: u8) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"conflict-preservation-property/");
        hasher.update([if class == 2 { 1 } else { class }]);
        let mut out: [u8; 32] = hasher.finalize().into();
        if class == 2 {
            out[31] ^= 0xff;
        }
        out
    }
    // Distinct per head, so no two heads are ever the same change.
    fn change_hash(index: usize) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"conflict-preservation-property/change/");
        hasher.update((index as u32).to_le_bytes());
        hasher.finalize().into()
    }

    // 0..=2 are content classes; 3 is a tombstone (a delete, or the
    // source side of a move away).
    const SLOTS: usize = 4;
    const CHOICES: usize = 4 * 2; // content-or-tombstone x lamport

    for combo in 0..CHOICES.pow(SLOTS as u32) {
        let mut heads: Vec<PathHead> = Vec::new();
        let mut rest = combo;
        for slot in 0..SLOTS {
            let choice = rest % CHOICES;
            rest /= CHOICES;
            let kind = (choice / 2) as u8;
            let lamport = (choice % 2) as u64 + 1;
            let device = format!("device-{}", slot % 2);
            heads.push(PathHead {
                change_hash: change_hash(combo * SLOTS + slot),
                lamport,
                device_id: device.clone(),
                naming_device_id: device,
                content: (kind < 3).then(|| PathHeadContent {
                    version_hash: content(kind),
                    // The placeholder a DAG-resolved head always carries:
                    // the stamp cannot disambiguate anything here, which
                    // is exactly the situation the name has to survive.
                    mtime_unix_nanos: 0,
                }),
            });
        }

        let expected_classes: BTreeSet<[u8; 32]> =
            heads.iter().filter_map(|h| h.content.as_ref().map(|c| c.version_hash)).collect();
        let resolution = resolve_path_heads(PATH, &heads);

        if expected_classes.is_empty() {
            assert_eq!(
                resolution,
                PathResolution::Absent,
                "combo {combo}: all heads remove {PATH}"
            );
            continue;
        }
        let PathResolution::Present { winner, conflict_copies } = resolution else {
            panic!(
                "combo {combo}: {} content classes but the path resolved absent",
                expected_classes.len()
            );
        };

        // Where each surviving class ends up, keyed by the path it lands
        // at -- built the same way materialization would build it.
        let mut placed: Vec<(String, [u8; 32])> = vec![(
            PATH.to_string(),
            heads[winner].content.as_ref().expect("the winner is a content head").version_hash,
        )];
        for copy in &conflict_copies {
            placed.push((
                copy.path.clone(),
                heads[copy.head]
                    .content
                    .as_ref()
                    .expect("a copy names a content head")
                    .version_hash,
            ));
        }

        // Half one: nothing is lost.
        let reachable: BTreeSet<[u8; 32]> = placed.iter().map(|(_, vh)| *vh).collect();
        assert_eq!(
            reachable, expected_classes,
            "combo {combo}: resolution must make every distinct concurrent content reachable"
        );

        // Half two: no two classes are written over each other, and no
        // copy silently takes the canonical path.
        // Two placements at one path are always a failure, but they are
        // two different failures and the message has to say which. Equal
        // contents there means the resolution emitted the same copy
        // twice; different contents there means one silently overwrites
        // the other, which is the loss this half exists to catch. The
        // message used to claim the second unconditionally, so a
        // duplicate-emission bug would have been reported as a naming
        // collision and sent the reader to the wrong module.
        let mut paths: HashMap<String, [u8; 32]> = HashMap::new();
        for (p, vh) in &placed {
            if let Some(existing) = paths.insert(p.clone(), *vh) {
                if existing == *vh {
                    panic!(
                        "combo {combo}: the same content is placed twice at {p} (class {})",
                        hex::encode(vh)
                    );
                }
                panic!(
                    "combo {combo}: two distinct contents share the path {p} \
                     (classes {} and {})",
                    hex::encode(existing),
                    hex::encode(vh)
                );
            }
        }
        assert_eq!(
            paths.len(),
            expected_classes.len(),
            "combo {combo}: one path per surviving class, no more and no fewer"
        );
        for copy in &conflict_copies {
            assert_ne!(
                copy.path, PATH,
                "combo {combo}: a conflict copy must not take the canonical path"
            );
        }
    }
}

/// Two devices that each `mkdir` the same name without having seen the
/// other's change author two concurrent heads for that path. Each device
/// derives its version from its own index row, which holds whatever size
/// and mtime its filesystem reported for the new directory. Those are
/// observations of the directory's children, not directory state, so both
/// heads must name one version and resolve to one directory with no
/// conflict copy, in either arrival order.
#[test]
fn concurrent_identical_mkdir_resolves_without_conflict_copy() {
    use ed25519_dalek::SigningKey;
    use yadorilink_replica_domain::change::{Op, PutOrigin};
    use yadorilink_replica_domain::file::{FileVersion, RecordKind};
    use yadorilink_replica_domain::ids::{DeviceId, FolderGroupId, SyncPath};

    let group = FolderGroupId("group-mkdir".to_string());
    let mkdir = |device: &str, key_byte: u8, observed_size: u64, observed_mtime: i64| {
        let version = FileVersion::from_index_row(
            Vec::new(),
            observed_size,
            observed_mtime,
            RecordKind::Directory,
            Some(0o755),
            None,
            Vec::new(),
        );
        create_signed_for_tests(
            vec![],
            0,
            DeviceId(device.to_string()),
            group.clone(),
            vec![Op::Put {
                path: SyncPath("photos".to_string()),
                version: version.version_hash,
                origin: PutOrigin::Direct,
            }],
            &SigningKey::from_bytes(&[key_byte; 32]),
        )
    };
    let on_mac = mkdir("device-mac", 1, 96, 1_700_000_000_000_000_001);
    let on_linux = mkdir("device-linux", 2, 4096, 1_700_000_123_000_000_000);

    let heads = [
        path_head_from_change(&on_mac, "photos").unwrap(),
        path_head_from_change(&on_linux, "photos").unwrap(),
    ];
    let reversed = [heads[1].clone(), heads[0].clone()];

    let resolved = resolve_path_heads("photos", &heads);
    let PathResolution::Present { winner, conflict_copies } = &resolved else {
        panic!("a concurrently made directory must be present, got {resolved:?}");
    };
    assert!(conflict_copies.is_empty(), "identical mkdirs must not conflict: {conflict_copies:?}");

    let resolved_reversed = resolve_path_heads("photos", &reversed);
    let PathResolution::Present { winner: winner_reversed, conflict_copies } = &resolved_reversed
    else {
        panic!("a concurrently made directory must be present, got {resolved_reversed:?}");
    };
    assert!(conflict_copies.is_empty(), "identical mkdirs must not conflict: {conflict_copies:?}");
    assert_eq!(heads[*winner].change_hash, reversed[*winner_reversed].change_hash);
}
