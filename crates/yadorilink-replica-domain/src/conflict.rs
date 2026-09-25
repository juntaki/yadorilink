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
//! version vector is identical either way. `conflict_copy_path` therefore
//! appends the loser's own content hash to the filename: exactly as
//! available and exactly as identical-on-both-sides as the mtime/device-id
//! inputs already used, so it preserves `a_is_loser`'s
//! observer-independence.
//!
//! ## The disambiguator is the WHOLE hash, and why it has to be
//!
//! The naming invariant conflict preservation rests on is
//!
//! ```text
//! V1 != V2  =>  conflict_copy_path(p, .., V1) != conflict_copy_path(p, .., V2)
//! ```
//!
//! Without it, two genuinely different losing contents land on one path
//! and one of them overwrites the other: content that resolution promised
//! to preserve is simply gone, with every replica agreeing on the
//! resulting state, so nothing downstream can detect the loss.
//!
//! This used to be an 8-hex-character (32-bit) prefix of the hash, which
//! does not satisfy it: 32 bits collide. Nothing else in the name can
//! absorb that collision — the other fields are held equal exactly when
//! this matters. The rest of the name is `path`, which is the *same* path
//! by construction (both losers contend for it), the losing device, and an
//! mtime stamp that `path_head_from_change` deliberately pins to a
//! constant for DAG-resolved conflicts. So for a pair of concurrent writes
//! from one device the hash field is the only thing that differs at all,
//! and truncating it to 32 bits made a silent overwrite a birthday problem
//! rather than an impossibility.
//!
//! The fix is to encode the hash in full, as lowercase hex:
//!
//! * hex is injective on byte strings (it is a bijection onto even-length
//!   hex strings and `hex::decode` recovers the input exactly), so
//!   distinct hashes give distinct fields;
//! * the field is fixed-width for a fixed-width hash and sits between a
//!   literal `, ` and a literal `)`, so a parser recovers exactly the run
//!   the builder wrote — the encoding cannot bleed into the neighbouring
//!   device-id or extension fields and disguise a difference;
//! * it is single-case, so the case-insensitive filesystems this project
//!   targets (APFS and NTFS in their default configurations) cannot fold
//!   two distinct encodings back together. A case-sensitive encoding such
//!   as base64 would re-open exactly the collision this closes, on exactly
//!   the platforms most users are on.
//!
//! ## Length bound, and which field yields when the name does not fit
//!
//! The generated filename component stays within the 255-byte portable
//! floor for a single path component ([`MAX_COMPONENT_BYTES`]: `NAME_MAX`
//! on Linux, `_PC_NAME_MAX` elsewhere; ext4/APFS/NTFS are all at or above
//! it). The suffix this adds is
//! `" (conflicted copy, " + <17-byte stamp> + ", " + <device id> + ", " +
//! <2 * hash bytes> + ")"` = 105 bytes plus the device id for a 32-byte
//! hash. A file whose own name is long therefore no longer has room for
//! it, and an over-long component is not a cosmetic problem: the
//! materializer gets `ENAMETOOLONG`, the conflict copy is never written,
//! and the losing content is gone — the same loss this module exists to
//! prevent, arriving through the name's length instead of its collisions.
//!
//! So the name is always shortened to fit, and what yields is the
//! **stem**, never the disambiguating fields. `conflict_copy_path` cuts
//! the stem at a UTF-8 character boundary and marks the cut with
//! [`STEM_TRUNCATION_MARKER`]. The hash is never shortened to make a name
//! fit: a truncated disambiguator is precisely the defect above, and
//! silently trading content preservation for a shorter name is never the
//! right trade.
//!
//! Shortening the stem cannot merge two distinct losing contents, which
//! is the property that matters here. Two names can only coincide after a
//! stem cut if they agree on the hash field as well — and the hash field
//! is a function of the content, so agreeing there means the two copies
//! hold the *same bytes*. Distinct content classes still land on distinct
//! paths; what a cut can do is place two long-named files' copies of
//! *identical* content on one path, which stores that content once
//! instead of twice and loses no class.
//!
//! What a cut does cost is exact invertibility: a shortened name no
//! longer spells its source path in full, so
//! [`conflict_copy_source_path`] returns a marked prefix rather than the
//! original. Callers that would *delete* a copy on the strength of that
//! inversion must therefore check [`conflict_copy_stem_was_truncated`]
//! and leave a shortened copy alone — an audit that cannot reconstruct
//! the source path cannot prove the copy unjustified either.
//!
//! ## Injective in the content, NOT injective in the source path
//!
//! The invariant above is about *content*, and it is the only one this
//! module establishes. The naming is deliberately **not** injective in
//! the path it derives from, and anything reasoning about what a
//! conflict copy replaced has to account for that.
//!
//! [`conflict_copy_path`] strips an existing `(conflicted copy, ` suffix
//! from the stem before rebuilding, from the *leftmost* occurrence, so
//! that re-resolving an already-marked path produces one suffix instead
//! of a compounding chain. The stripping cannot distinguish a suffix
//! this module generated from one a user typed. A file the user named
//! `a (conflicted copy, x).txt` by hand therefore reduces to the same
//! base name as a generated copy of `a.txt`, and
//! [`conflict_copy_source_path`] maps both back to `a.txt`.
//!
//! So a copy name determines its content, but a source name does not
//! determine its copy name's preimage: several distinct sources can
//! share one reconstructed source path. That is recorded here rather
//! than fixed. Fixing it would mean either compounding suffixes (which
//! grows names without bound and re-opens the length problem above) or
//! treating a user-typed marker as sacred (which resurrects the
//! compounding chain the strip exists to prevent), and no caller today
//! needs the inverse to be injective. What callers do need is the rule
//! already stated above: the inverse is evidence, not proof, and a
//! caller whose next step is destructive must not act on it alone.
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

/// The portable floor for a single path component, in bytes (`NAME_MAX`
/// on Linux, `_PC_NAME_MAX` elsewhere; ext4, APFS and NTFS are all at or
/// above it). A generated conflict-copy filename is kept at or below this
/// so it can actually be created on every platform this project targets —
/// see this module's length-bound doc comment for why an over-long name
/// is a content-loss bug rather than a cosmetic one.
pub const MAX_COMPONENT_BYTES: usize = 255;

/// Marks the point where [`conflict_copy_path`] cut a stem that was too
/// long for the 255-byte component limit. It is a single ASCII byte that
/// is legal in a filename on every target platform, and its presence at
/// the end of a conflict copy's base stem is what
/// [`conflict_copy_stem_was_truncated`] reports.
pub const STEM_TRUNCATION_MARKER: &str = "~";

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
/// <content hash>).<ext>`, where `<content hash>` is the FULL lowercase
/// hex encoding of `content_hash` (typically a `combined_block_hash` of
/// the loser's blocks, or the losing file version's own hash) — the
/// disambiguator that makes two genuinely different pieces of losing
/// content unable to land on the same filename, regardless of how close
/// together their conflicts resolve. It is deliberately not truncated;
/// see this module's top-level doc comment for the injectivity invariant
/// that depends on that and for the filename-length bound this keeps.
/// Only hex characters are appended, so this cannot introduce a character
/// illegal in Windows filenames.
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
    // The whole hash, never a prefix: this field is the only thing that
    // distinguishes two concurrent losing contents at the same path from
    // the same device, so shortening it silently merges them.
    let content_hex = hex::encode(content_hash);
    let suffix = format!(" (conflicted copy, {timestamp}, {device_id}, {content_hex})");
    // Only the stem may yield to the component limit, and it yields here
    // rather than at materialization time, where the whole copy would
    // fail to be written at all.
    let ext_bytes = ext.map_or(0, |ext| 1 + ext.len());
    let stem = truncate_stem_to_fit(stem, suffix.len() + ext_bytes);
    match ext {
        Some(ext) => format!("{dir}{stem}{suffix}.{ext}"),
        None => format!("{dir}{stem}{suffix}"),
    }
}

/// Shortens `stem` so that `stem.len() + fixed_bytes` fits within
/// [`MAX_COMPONENT_BYTES`], cutting on a UTF-8 character boundary (a cut
/// mid-character would not be a legal `String` at all) and marking the
/// cut with [`STEM_TRUNCATION_MARKER`]. Returns `stem` unchanged whenever
/// it already fits, so ordinary names are untouched and the marker only
/// ever appears on a name that genuinely had to be shortened.
///
/// If `fixed_bytes` alone already fills the budget — only reachable with
/// a device id or extension that is itself hundreds of bytes long — the
/// result is just the marker: the remaining fields are the ones that
/// carry identity, so there is nothing further this may shorten, and an
/// honest over-long name is better than a name that has lost the hash.
fn truncate_stem_to_fit(stem: &str, fixed_bytes: usize) -> String {
    if stem.len() + fixed_bytes <= MAX_COMPONENT_BYTES {
        return stem.to_string();
    }
    let budget = MAX_COMPONENT_BYTES
        .saturating_sub(fixed_bytes)
        .saturating_sub(STEM_TRUNCATION_MARKER.len());
    let mut end = budget.min(stem.len());
    while end > 0 && !stem.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}{STEM_TRUNCATION_MARKER}", &stem[..end])
}

/// Whether `path` is a conflict copy whose stem was shortened to fit the
/// component limit — i.e. whether its embedded source name is a marked
/// prefix rather than the whole original. A caller that acts on
/// [`conflict_copy_source_path`]'s answer *destructively* (retiring or
/// deleting the copy because the reconstructed source no longer justifies
/// it) must treat `true` as "cannot tell" and leave the copy in place:
/// the reconstruction is a prefix, so resolving it would find nothing and
/// look exactly like an unjustified copy.
pub fn conflict_copy_stem_was_truncated(path: &str) -> bool {
    let filename = path.rsplit_once('/').map_or(path, |(_, name)| name);
    let stem = match filename.rsplit_once('.') {
        Some((stem, _)) if !stem.is_empty() => stem,
        _ => filename,
    };
    stem.contains(" (conflicted copy, ")
        && strip_conflict_suffix(stem).ends_with(STEM_TRUNCATION_MARKER)
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
        && base_stem_matches(strip_conflict_suffix(candidate_stem), original_stem)
}

/// Whether a conflict copy's embedded base stem names `original_stem` —
/// either spelled in full, or as the marked prefix
/// [`conflict_copy_path`] writes when the whole name would not fit the
/// component limit. Without the second case a long-named file's conflict
/// copy would stop being recognized as derived from it, which is how a
/// caller ends up treating a still-outstanding copy as settled.
fn base_stem_matches(candidate_base: &str, original_stem: &str) -> bool {
    if candidate_base == original_stem {
        return true;
    }
    match candidate_base.strip_suffix(STEM_TRUNCATION_MARKER) {
        // A prefix strictly shorter than the original: exactly what a cut
        // leaves behind. Equal length would mean nothing was cut.
        Some(prefix) => prefix.len() < original_stem.len() && original_stem.starts_with(prefix),
        None => false,
    }
}

/// The base path a conflict-copy name derives from: directory and
/// extension preserved, the `(conflicted copy, ...)` suffix stripped from
/// the stem. Inverse of [`conflict_copy_path`] up to the suffix (and like
/// it, collapses a compounded suffix straight back to the true base).
///
/// Not an inverse when the stem had to be shortened to fit the component
/// limit: the answer is then a marked prefix of the true source name.
/// [`conflict_copy_stem_was_truncated`] reports that case, and any caller
/// whose next step is destructive must check it.
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
