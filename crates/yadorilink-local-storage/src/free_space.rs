//! Free-space classification shared by every disk-pressure decision in the
//! system — the local-storage block-store preflight (`FsBlockStore::put`),
//! the sync-core hydration/materialization preflight
//! (`yadorilink_local_storage::check_disk_headroom`, called directly by
//! `yadorilink-sync-core::materialization`), the
//! disk-pressure eviction trigger, and `yadorilink status`'s per-volume
//! reporting all call through this one module, so a single computed
//! classification always backs both the preflight decision and what's
//! reported — never two independently-computed answers that could
//! disagree.

use std::path::Path;

/// Minimum headroom floor when no explicit override is configured:
/// `max(1 GiB, 5% of the hosting volume)`.
pub const DEFAULT_MIN_HEADROOM_BYTES: u64 = 1024 * 1024 * 1024;
/// The percentage half of the same default formula.
pub const DEFAULT_HEADROOM_PERCENT: f64 = 0.05;

/// A volume's free-space state relative to its effective headroom.
/// Ordered from healthiest to worst so a caller that only cares about
/// "is this at least as bad as X" can compare with `>=`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FreeSpaceState {
    /// Comfortably above headroom (more than double it free).
    Ok,
    /// Above headroom, but only modestly so (at or below double headroom).
    Low,
    /// At or below headroom.
    Critical,
}

impl FreeSpaceState {
    pub fn as_str(self) -> &'static str {
        match self {
            FreeSpaceState::Ok => "ok",
            FreeSpaceState::Low => "low",
            FreeSpaceState::Critical => "critical",
        }
    }
}

/// A volume's free-space snapshot plus its effective headroom — the single
/// source of truth both the preflight rejection decision and status
/// reporting read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VolumeFreeSpace {
    pub available_bytes: u64,
    pub total_bytes: u64,
    pub headroom_bytes: u64,
}

impl VolumeFreeSpace {
    /// `critical` at or below headroom, `low` up to double
    /// headroom, `ok` beyond that.
    pub fn classify(&self) -> FreeSpaceState {
        if self.available_bytes <= self.headroom_bytes {
            FreeSpaceState::Critical
        } else if self.available_bytes <= self.headroom_bytes.saturating_mul(2) {
            FreeSpaceState::Low
        } else {
            FreeSpaceState::Ok
        }
    }

    /// Would writing `additional_bytes` more bring available space to at or
    /// below the configured headroom? (The preflight predicate —
    /// deliberately the same `<=` boundary `classify`'s `Critical` uses, so
    /// "would breach" and "would become critical" are the same condition.)
    pub fn would_breach(&self, additional_bytes: u64) -> bool {
        self.available_bytes.saturating_sub(additional_bytes) <= self.headroom_bytes
    }
}

/// The effective headroom for a volume of `total_bytes`: the explicit
/// `configured_override` if set, else `max(1 GiB, 5%)` of the volume.
pub fn effective_headroom_bytes(total_bytes: u64, configured_override: Option<u64>) -> u64 {
    configured_override.unwrap_or_else(|| {
        let percent = (total_bytes as f64 * DEFAULT_HEADROOM_PERCENT) as u64;
        percent.max(DEFAULT_MIN_HEADROOM_BYTES)
    })
}

/// Queries the OS for free/total space on the volume hosting `path`
/// (`path` must currently exist) and classifies it against the effective
/// headroom.
///
/// Explicitly stats `path` itself first rather than leaving that to
/// `fs2::available_space`/`total_space` — the two platforms resolve a
/// missing `path` completely differently underneath those calls. On Unix,
/// `fs2` shells out to `statvfs(2)` directly on `path`, which requires the
/// exact directory to exist and fails with `NotFound` otherwise. On
/// Windows, `fs2` first calls `GetVolumePathNameW(path, ..)` to find the
/// containing volume/drive root, then queries THAT root with
/// `GetDiskFreeSpaceW` — a purely syntactic walk up the path that never
/// requires `path` (or any of its ancestors short of the drive itself) to
/// actually exist on disk. A directory tree that was deleted out from
/// under this call — e.g. a faulted or unmounted block-store root, which
/// every caller of this function relies on being surfaced as a `NotFound`
/// (see `is_source_path_vanished_error`'s doc comment in
/// `yadorilink-local-capture`) — is therefore silently invisible on
/// Windows without this guard: `fs2` would happily report the whole
/// volume's free space instead of erroring, and every headroom preflight
/// built on top of "stat the target root" would wrongly proceed as if
/// nothing were wrong. Stating `path` ourselves first makes both platforms
/// fail on the same input the same way.
pub fn classify_volume(
    path: &Path,
    configured_override: Option<u64>,
) -> std::io::Result<VolumeFreeSpace> {
    std::fs::metadata(path)?;
    let available_bytes = fs2::available_space(path)?;
    let total_bytes = fs2::total_space(path)?;
    let headroom_bytes = effective_headroom_bytes(total_bytes, configured_override);
    Ok(VolumeFreeSpace { available_bytes, total_bytes, headroom_bytes })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// config defaults when unset — the 1 GiB floor wins on a
    /// small volume, the 5% figure wins on a large one.
    #[test]
    fn default_headroom_is_max_of_1gib_and_5_percent() {
        let small_volume = 10 * 1024 * 1024 * 1024u64; // 10 GiB: 5% = 512 MiB < 1 GiB floor
        assert_eq!(effective_headroom_bytes(small_volume, None), DEFAULT_MIN_HEADROOM_BYTES);

        let large_volume = 100 * 1024 * 1024 * 1024u64; // 100 GiB: 5% = 5 GiB > 1 GiB floor
        let expected = (large_volume as f64 * DEFAULT_HEADROOM_PERCENT) as u64;
        assert!(expected > DEFAULT_MIN_HEADROOM_BYTES);
        assert_eq!(effective_headroom_bytes(large_volume, None), expected);
    }

    /// config round-trip after an explicit override — the
    /// override always wins over the formula, regardless of volume size.
    #[test]
    fn explicit_override_wins_regardless_of_volume_size() {
        assert_eq!(effective_headroom_bytes(1_000_000_000_000, Some(42)), 42);
        assert_eq!(effective_headroom_bytes(0, Some(0)), 0);
    }

    /// classification boundary behavior at the ok/low/critical
    /// thresholds — exercised directly against constructed `VolumeFreeSpace`
    /// values (not real disk state) so the boundaries themselves are
    /// deterministic.
    #[test]
    fn classification_boundaries() {
        let mk = |available_bytes| VolumeFreeSpace {
            available_bytes,
            total_bytes: 1_000_000,
            headroom_bytes: 1000,
        };
        assert_eq!(mk(1000).classify(), FreeSpaceState::Critical); // at headroom
        assert_eq!(mk(999).classify(), FreeSpaceState::Critical); // below headroom
        assert_eq!(mk(1001).classify(), FreeSpaceState::Low); // just above headroom
        assert_eq!(mk(2000).classify(), FreeSpaceState::Low); // exactly 2x headroom
        assert_eq!(mk(2001).classify(), FreeSpaceState::Ok); // just above 2x headroom
    }

    #[test]
    fn would_breach_matches_the_critical_boundary() {
        let space =
            VolumeFreeSpace { available_bytes: 1500, total_bytes: 1_000_000, headroom_bytes: 1000 };
        // Writing 400 more leaves 1100 available, still above the 1000 headroom.
        assert!(!space.would_breach(400));
        // Writing 600 more leaves 900 available, below the 1000 headroom.
        assert!(space.would_breach(600));
        // Writing exactly down to the headroom boundary itself breaches
        // (available must stay strictly above headroom, matching `classify`'s
        // `<=` -> critical boundary).
        assert!(space.would_breach(500));
    }

    /// A real, existing directory resolves via the OS without error — this
    /// doesn't assert particular numbers (real disk state), just that the
    /// query itself succeeds and returns internally-consistent values.
    #[test]
    fn classify_volume_queries_a_real_existing_path() {
        let dir = tempfile::tempdir().unwrap();
        let space = classify_volume(dir.path(), None).unwrap();
        assert!(space.total_bytes > 0);
        assert!(space.headroom_bytes > 0);
    }

    /// A missing `path` must fail this query outright, never silently fall
    /// back to reporting free space for whatever volume/drive happens to
    /// contain it. Every caller of `classify_volume` relies on exactly
    /// this to detect a vanished/unmounted block-store root as a real
    /// fault (see `FsBlockStore::check_headroom`'s doc comment and
    /// `is_source_path_vanished_error` in `yadorilink-local-capture`) --
    /// without this guard, `fs2`'s underlying OS call is only path-exact
    /// on Unix (`statvfs(2)` needs the exact directory) and is actually
    /// volume-relative on Windows (`GetVolumePathNameW` +
    /// `GetDiskFreeSpaceW` resolve up to the containing drive root
    /// regardless of whether `path` itself exists), so a platform-specific
    /// regression here would go undetected by every OTHER test in this
    /// module, which only ever exercises a real, existing directory.
    #[test]
    fn classify_volume_on_a_missing_path_fails_rather_than_reporting_the_containing_volume() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("never-created");
        assert_eq!(
            classify_volume(&missing, None).unwrap_err().kind(),
            std::io::ErrorKind::NotFound,
            "a path that was never created (or was removed out from under this call, e.g. a \
             faulted block-store root) must surface as NotFound, not as a successful query of \
             its containing volume"
        );
    }
}
