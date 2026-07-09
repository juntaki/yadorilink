//! Free-space classification shared by every disk-pressure decision in the
//! system — the local-storage block-store preflight (`FsBlockStore::put`),
//! the sync-core hydration/materialization preflight
//! (`yadorilink_sync_core::materialization::check_disk_headroom`), the
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

/// A volume's free-space state relative to its effective headroom (task
/// 1.3). Ordered from healthiest to worst so a caller that only cares about
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
    /// below the configured headroom? (task 3.1/3.2's preflight predicate —
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
pub fn classify_volume(
    path: &Path,
    configured_override: Option<u64>,
) -> std::io::Result<VolumeFreeSpace> {
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
}
