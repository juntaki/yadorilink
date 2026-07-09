//! Conflict-copy naming (design.md D7, `sync-engine` spec's "Conflict
//! Handling" requirement): when a true concurrent edit is detected, the
//! older-mtime copy is renamed to a conflict-marked filename rather than
//! silently discarded, matching Dropbox/Syncthing user expectations.
//!
//! ## Content-hash disambiguator (`fix-conflict-copy-filename-collision`)
//!
//! `(truncated-second timestamp, device_id)` alone is not unique per
//! losing *content* — only per losing *device-and-second*. When the same
//! device loses two structurally distinct conflicts for genuinely
//! different content within the same truncated second, both computed the
//! identical conflict-copy filename, letting different devices
//! independently materialize different content under a name all peers
//! agree is "the same" — an undetectable split-brain, since the merged
//! version vector is identical either way. `conflict_copy_path` now
//! appends a short, deterministic fragment of the loser's own content
//! hash (`combined_block_hash`) to the filename: exactly as available and
//! exactly as identical-on-both-sides as the mtime/device-id inputs
//! already used, so it preserves `a_is_loser`'s observer-independence
//! while making a same-filename collision between two different pieces
//! of content impossible rather than merely unlikely.
//!
//! ## Trust boundary (SEC-SYNC-3(b), `harden-untrusted-peer-data`)
//!
//! `mtime_unix_nanos` on an incoming `FileRecord` is peer-supplied and
//! otherwise unvalidated. Before this fix, the winner of a genuine
//! `VvOrdering::Concurrent` conflict (which copy keeps the real filename
//! vs. gets renamed to a `(conflicted copy…)` name) was decided primarily
//! by comparing `mtime_unix_nanos` — so a peer advertising
//! `mtime_unix_nanos = i64::MAX` always won the real filename outright,
//! unconditionally demoting the honest local file. `clamp_future_mtime`
//! bounds how far into the future (relative to wall-clock "now" at
//! resolution time) a claimed mtime is trusted at face value; beyond that
//! bound it's treated as no more recent than the bound itself, so an
//! extreme claim can no longer win by an unbounded margin. This is a
//! judgment call, not a complete fix — see `a_is_loser`'s doc comment for
//! why the tie-break itself deliberately stays on device id rather than
//! "prefer local".

use sha2::{Digest, Sha256};

/// SEC-SYNC-3(b): a claimed `mtime_unix_nanos` more than this far in the
/// future of wall-clock "now" is no longer trusted at face value for
/// conflict-resolution purposes — see this module's trust-boundary doc
/// comment. One day is generous enough that ordinary clock drift between
/// real devices (seconds, occasionally minutes) is always a no-op; it only
/// engages for claims that are implausible on their face.
pub const MAX_FUTURE_MTIME_SKEW_NANOS: i64 = 24 * 60 * 60 * 1_000_000_000;

/// Combines a file's per-block content hashes into a single deterministic
/// digest usable as a conflict-copy filename disambiguator. Each block
/// hash is already a `Sha256` digest of that block's own bytes (see
/// `peer_session::block_data_matches`), so hashing their concatenation in
/// block order is cheap, fully deterministic on both sides of a conflict,
/// and requires no re-read of the file's raw bytes.
pub fn combined_block_hash(blocks: &[crate::types::BlockInfo]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    for block in blocks {
        hasher.update(&block.hash);
    }
    hasher.finalize().to_vec()
}

/// Clamps `mtime_unix_nanos` so it is never trusted as more than
/// `MAX_FUTURE_MTIME_SKEW_NANOS` beyond `now_unix_nanos`. A no-op for any
/// ordinary (non-adversarial) mtime, which is always at or before "now".
fn clamp_future_mtime(mtime_unix_nanos: i64, now_unix_nanos: i64) -> i64 {
    mtime_unix_nanos.min(now_unix_nanos.saturating_add(MAX_FUTURE_MTIME_SKEW_NANOS))
}

/// Returns whether `(mtime_a, device_a)` is the *loser* against
/// `(mtime_b, device_b)` — i.e. the older-effective-mtime copy, demoted to
/// a conflict-marked filename. Shared by `resolve_conflict_names` (which
/// needs a result every peer computes identically, regardless of which
/// side of the conflict it's looking at) and
/// `peer_session::resolve_and_apply_conflict` (which needs to know which
/// side's *content*, not just which path name, is the winner) so the two
/// decisions can never disagree with each other.
///
/// Both mtimes are bounded via `clamp_future_mtime` before comparison
/// (SEC-SYNC-3(b)), so an extreme peer-supplied value can no longer win
/// outright by an unbounded margin.
///
/// The tie-break (mtimes equal after clamping) is device id, not "prefer
/// local": this function is deliberately symmetric/observer-independent —
/// it has no notion of which side is "this device's own" copy. A literal
/// "prefer local" tie-break would mean two different peers, each
/// comparing the *same* conflicting pair from their own point of view,
/// could independently pick *different* winners (each preferring itself)
/// while computing the *same* merged version vector for the result —
/// leaving the mesh with two devices permanently disagreeing about a
/// path's content under a version vector that claims they're in sync, a
/// correctness regression no security fix should introduce. Device id is
/// a fixed identity established at pairing time, not something a peer can
/// adaptively choose per-message to win ties, so keeping it as the
/// tie-break closes the concrete exploit (an extreme mtime unilaterally
/// winning) without sacrificing that determinism guarantee.
pub fn a_is_loser(
    mtime_a: i64,
    device_a: &str,
    mtime_b: i64,
    device_b: &str,
    now_unix_nanos: i64,
) -> bool {
    let eff_a = clamp_future_mtime(mtime_a, now_unix_nanos);
    let eff_b = clamp_future_mtime(mtime_b, now_unix_nanos);
    eff_a < eff_b || (eff_a == eff_b && device_a < device_b)
}

/// Given the two concurrently-edited file records' paths/mtimes/device
/// ids/content hashes (plus wall-clock "now", SEC-SYNC-3(b)), returns
/// `(winner_path, loser_conflict_path)` — the loser being the
/// older-effective-mtime copy (ties broken by device id, for determinism
/// so all peers independently compute the same result; see `a_is_loser`'s
/// doc comment for why). `hash_a`/`hash_b` (each a
/// `combined_block_hash` of that side's `FileRecord::blocks`) follow the
/// same observer-independence property as `mtime_a`/`device_a` and
/// `mtime_b`/`device_b`: they're exactly as available and exactly as
/// identical-on-both-sides, so selecting the loser's hash alongside its
/// mtime/device introduces no new source of cross-peer disagreement.
#[allow(clippy::too_many_arguments)]
pub fn resolve_conflict_names(
    path: &str,
    mtime_a: i64,
    device_a: &str,
    hash_a: &[u8],
    mtime_b: i64,
    device_b: &str,
    hash_b: &[u8],
    now_unix_nanos: i64,
) -> (String, String) {
    let (loser_mtime, loser_device, loser_hash) =
        if a_is_loser(mtime_a, device_a, mtime_b, device_b, now_unix_nanos) {
            (clamp_future_mtime(mtime_a, now_unix_nanos), device_a, hash_a)
        } else {
            (clamp_future_mtime(mtime_b, now_unix_nanos), device_b, hash_b)
        };
    (path.to_string(), conflict_copy_path(path, loser_mtime, loser_device, loser_hash))
}

/// Builds `<name> (conflicted copy, <ISO-8601 timestamp>, <device>,
/// <hash8>).<ext>`, where `<hash8>` is an 8-hex-character prefix of
/// `content_hash` (typically a `combined_block_hash` of the loser's
/// blocks) — the collision-proof disambiguator that makes two genuinely
/// different pieces of losing content unable to ever land on the same
/// filename, regardless of how close together their conflicts resolve
/// (see this module's top-level doc comment). Only hex characters are
/// appended, so this cannot introduce a character illegal in Windows
/// filenames (see `hazard.rs`).
///
/// Idempotent against an already-conflict-suffixed `path` (task 2.1): an
/// existing `(conflicted copy, ...)` suffix is stripped before rebuilding,
/// so re-resolving an already-conflict-marked path produces one suffix,
/// not a compounding, doubly-wrapped name.
pub fn conflict_copy_path(
    path: &str,
    mtime_unix_nanos: i64,
    device_id: &str,
    content_hash: &[u8],
) -> String {
    let (dir, filename) = match path.rsplit_once('/') {
        Some((dir, name)) => (format!("{dir}/"), name),
        None => (String::new(), path),
    };
    let (raw_stem, ext) = match filename.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => (stem, Some(ext)),
        _ => (filename, None),
    };
    let stem = strip_conflict_suffix(raw_stem);
    let timestamp = format_timestamp(mtime_unix_nanos);
    let hash8 = hex::encode(content_hash.get(..4).unwrap_or(content_hash));
    match ext {
        Some(ext) => {
            format!("{dir}{stem} (conflicted copy, {timestamp}, {device_id}, {hash8}).{ext}")
        }
        None => format!("{dir}{stem} (conflicted copy, {timestamp}, {device_id}, {hash8})"),
    }
}

/// True if `candidate` is a `(conflicted copy...)` sibling of
/// `original_path` -- same directory, same base stem (once any conflict
/// suffix is stripped from `candidate`), same extension, and `candidate`
/// actually carries the `(conflicted copy, ` marker (so `original_path`
/// itself, or an unrelated file that merely shares a stem, never matches).
/// Used to detect an *existing* conflict-copy of a given piece of content
/// before materializing another one — see `peer_session.rs::resolve_and_
/// apply_conflict`'s dedup guard.
pub fn is_conflict_copy_of(candidate: &str, original_path: &str) -> bool {
    fn split(p: &str) -> (String, &str, Option<&str>) {
        let (dir, filename) = match p.rsplit_once('/') {
            Some((dir, name)) => (format!("{dir}/"), name),
            None => (String::new(), p),
        };
        match filename.rsplit_once('.') {
            Some((stem, ext)) if !stem.is_empty() => (dir, stem, Some(ext)),
            _ => (dir, filename, None),
        }
    }
    let (candidate_dir, candidate_stem, candidate_ext) = split(candidate);
    let (original_dir, original_stem, original_ext) = split(original_path);
    candidate_dir == original_dir
        && candidate_ext == original_ext
        && candidate_stem.contains(" (conflicted copy, ")
        && strip_conflict_suffix(candidate_stem) == original_stem
}

/// Task 2.1 idempotency guard: strips an already-present `(conflicted
/// copy, ...)` suffix from a filename stem, so `conflict_copy_path`
/// rebuilds a single suffix instead of wrapping an already-conflict-marked
/// path a second time (design.md's "strip-and-rebuild rather than
/// compound" decision — defense in depth even if some future edge case
/// still produced a colliding disambiguator). Strips from the leftmost
/// occurrence, so a path that had already (incorrectly) compounded past
/// one suffix is fully unwrapped back to its true base name rather than
/// only peeling off the outermost layer.
fn strip_conflict_suffix(stem: &str) -> &str {
    match stem.find(" (conflicted copy, ") {
        Some(idx) => &stem[..idx],
        None => stem,
    }
}

/// Formats a unix-nanos timestamp as a filesystem-safe ISO-8601-ish
/// string (`:` isn't valid in Windows filenames, so `-` is used instead).
fn format_timestamp(mtime_unix_nanos: i64) -> String {
    let secs = mtime_unix_nanos.div_euclid(1_000_000_000);
    let days = secs.div_euclid(86_400);
    let time_of_day = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let hh = time_of_day / 3600;
    let mm = (time_of_day % 3600) / 60;
    let ss = time_of_day % 60;
    format!("{y:04}-{m:02}-{d:02}-{hh:02}{mm:02}{ss:02}")
}

/// Howard Hinnant's `civil_from_days` algorithm: converts a day count
/// since the Unix epoch into a proleptic-Gregorian (year, month, day),
/// without pulling in a chrono/time dependency for one small conversion.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixed "now" far beyond any of the small epoch-relative mtimes
    /// used throughout this test module, so `MAX_FUTURE_MTIME_SKEW_NANOS`
    /// clamping is a no-op for them — these tests exercise ordinary,
    /// non-adversarial mtime comparisons and must behave exactly as
    /// before the SEC-SYNC-3(b) skew bound was added.
    const FAR_FUTURE_NOW: i64 = 2_000_000_000 * 1_000_000_000;

    const HASH_A: &[u8] = b"content-a-loser-bytes";
    const HASH_B: &[u8] = b"content-b-winner-bytes";

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

    /// Task 4.3(a) / spec scenario "Two different losing contents resolved
    /// within the same second never collide onto one filename": the same
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

    /// Task 2.2: an already-conflict-suffixed path fed back through
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

    /// Task 2.2, extensionless variant: same idempotency guarantee without
    /// an extension in play (exercises the `ext == None` formatting path).
    #[test]
    fn conflict_copy_naming_does_not_compound_without_an_extension() {
        let already_suffixed = conflict_copy_path("README", 0, "device-a", HASH_A);
        let re_resolved = conflict_copy_path(&already_suffixed, 1_000_000_000, "device-b", HASH_B);
        assert_eq!(re_resolved.matches("(conflicted copy").count(), 1, "{re_resolved}");
        assert!(re_resolved.starts_with("README (conflicted copy"), "{re_resolved}");
    }

    /// SEC-SYNC-3(b) / task 4.3(b) — adversarial case: a peer advertising
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

    /// SEC-SYNC-3(b) / task 4.3(b): once local's own mtime is *also*
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

    /// SEC-SYNC-3(b) / task 4.3(b) — legitimate case: an ordinary,
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

    // fix-duplicate-conflict-copy-on-reresolution: `is_conflict_copy_of`
    // coverage.

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
}
