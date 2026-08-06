//! Conflict-copy naming (`sync-engine` spec's "Conflict
//! Handling" requirement): when a true concurrent edit is detected, the
//! older-mtime copy is renamed to a conflict-marked filename rather than
//! silently discarded, matching Dropbox/Syncthing user expectations.
//!
//! ## Content-hash disambiguator
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
//! ## Trust boundary
//!
//! `mtime_unix_nanos` on an incoming `FileRecord` is peer-supplied and
//! otherwise unvalidated. Before this fix, the winner of a genuine
//! concurrent conflict (which copy keeps the real filename vs. gets
//! renamed to a `(conflicted copy…)` name) was decided primarily by
//! comparing `mtime_unix_nanos` — so a peer advertising
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

use crate::file::BlockInfo;

/// A claimed `mtime_unix_nanos` more than this far in the
/// future of wall-clock "now" is no longer trusted at face value for
/// conflict-resolution purposes — see this module's trust-boundary doc
/// comment. One day is generous enough that ordinary clock drift between
/// real devices (seconds, occasionally minutes) is always a no-op; it only
/// engages for claims that are implausible on their face.
pub const MAX_FUTURE_MTIME_SKEW_NANOS: i64 = 24 * 60 * 60 * 1_000_000_000;

/// Combines a file's per-block content hashes into a single deterministic
/// digest usable as a conflict-copy filename disambiguator. Each block
/// hash is already a `Sha256` digest of that block's own bytes, so hashing
/// their concatenation in block order is cheap, fully deterministic on
/// both sides of a conflict, and requires no re-read of the file's raw
/// bytes.
pub fn combined_block_hash(blocks: &[BlockInfo]) -> Vec<u8> {
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
/// Both mtimes are bounded via `clamp_future_mtime` before comparison,
/// so an extreme peer-supplied value can no longer win
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
/// ids/content hashes (plus wall-clock "now"), returns
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
/// filenames.
///
/// Idempotent against an already-conflict-suffixed `path`: an
/// existing `(conflicted copy,...)` suffix is stripped before rebuilding,
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

/// True if `path` is shaped like a conflict-copy output at all: its
/// filename stem carries the `(conflicted copy, ` marker
/// [`conflict_copy_path`] embeds. Unlike [`is_conflict_copy_of`] this needs
/// no original path to compare against — it answers "could this path only
/// have been produced (or deliberately named) as a conflict copy?", not
/// "is it a copy of *that* file?". The marker must be in the *filename*:
/// a directory component carrying it does not make every file inside it a
/// conflict copy.
pub fn is_conflict_copy_path(path: &str) -> bool {
    let filename = path.rsplit_once('/').map_or(path, |(_, name)| name);
    let stem = match filename.rsplit_once('.') {
        Some((stem, _)) if !stem.is_empty() => stem,
        _ => filename,
    };
    stem.contains(" (conflicted copy, ")
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

/// The base path a conflict-copy name derives from: directory and
/// extension preserved, the `(conflicted copy, ...)` suffix stripped from
/// the stem. Inverse of [`conflict_copy_path`] up to the suffix (and like
/// it, collapses a compounded suffix straight back to the true base).
pub fn conflict_copy_source_path(path: &str) -> String {
    let (dir, filename) = match path.rsplit_once('/') {
        Some((dir, name)) => (format!("{dir}/"), name),
        None => (String::new(), path),
    };
    let (stem, ext) = match filename.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => (stem, Some(ext)),
        _ => (filename, None),
    };
    let base_stem = strip_conflict_suffix(stem);
    match ext {
        Some(ext) => format!("{dir}{base_stem}.{ext}"),
        None => format!("{dir}{base_stem}"),
    }
}

/// idempotency guard: strips an already-present `(conflicted
/// copy,...)` suffix from a filename stem, so `conflict_copy_path`
/// rebuilds a single suffix instead of wrapping an already-conflict-marked
/// path a second time (strip-and-rebuild rather than compound — defense
/// in depth even if some future edge case still produced a colliding
/// disambiguator). Strips from the leftmost
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
