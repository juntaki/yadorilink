//! A bounded, in-memory, in-process-only history of reporting-safe sync
//! errors — the "Recent-error ring buffer" — surfaced by `yadorilink
//! status` so a stuck or failing sync is diagnosable without reading
//! logs.
//!
//! Deliberately mirrors `connection_trace::ConnectionTraceLog` field for
//! field (bounded `VecDeque`, oldest dropped once the cap is reached, never
//! durably persisted, a restart starts empty) rather than this crate's
//! disk-persisted `reporting::error_candidates::ErrorCandidateStore` — that
//! store exists for a different job (user-reviewable, exportable/submittable
//! severe-error snapshots the user explicitly decides what to do with);
//! this one is a lightweight, always-on diagnostic feed with no user action
//! involved, so it gets the same "purely in-memory" treatment as
//! `ConnectionTraceLog` and `daemon_state`'s `degraded_links`.
//!
//! Every record is `{category, timestamp, coarse_context}` only:
//! `category` is one of `SyncError::category`'s stable slugs (or a handful
//! of daemon-observed categories with no dedicated `SyncError` variant, e.g.
//! `"block_integrity"`), and `coarse_context` is a short, fixed subsystem
//! tag (e.g. `"hydration"`) — never a raw path, key, token, or peer IP.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// Bounded ring buffer size — last N entries, e.g. 64.
pub const MAX_RECENT_ERRORS: usize = 64;

fn now_unix() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// One recorded error — see this module's doc comment for the exact field
/// contract. `#[derive(Debug, Clone, PartialEq, Eq)]` matches
/// `connection_trace::ConnectionAttemptTrace`'s own derives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecentErrorRecord {
    pub category: &'static str,
    pub timestamp_unix: i64,
    pub coarse_context: String,
}

struct Inner {
    entries: Mutex<VecDeque<RecentErrorRecord>>,
    /// Monotonic per-category counts, never shrinking even as old entries
    /// roll off `entries` — the `/metrics` endpoint's
    /// `yadorilink_sync_errors_total{category}` counter must never
    /// decrease just because the bounded ring buffer above evicted an
    /// old entry, mirroring `reporting::counters`'s own
    /// `error_category_counts` "counts, never rewritten down" contract.
    category_counts: Mutex<HashMap<&'static str, u64>>,
}

/// Cheap-to-clone handle (same `Arc`-backed shape as
/// `crate::transfer_progress::TransferProgressTracker`), so it can be
/// passed into `hydration.rs`'s spawned per-lane worker tasks directly.
#[derive(Clone)]
pub struct RecentErrorLog(Arc<Inner>);

impl Default for RecentErrorLog {
    fn default() -> Self {
        Self::new()
    }
}

impl RecentErrorLog {
    pub fn new() -> Self {
        Self(Arc::new(Inner {
            entries: Mutex::new(VecDeque::new()),
            category_counts: Mutex::new(HashMap::new()),
        }))
    }

    /// Records one error. `coarse_context` must already be a short, fixed
    /// subsystem tag (e.g. `"hydration"`) — callers must never pass a raw
    /// path/key/token/IP here.
    pub fn record(&self, category: &'static str, coarse_context: impl Into<String>) {
        let record = RecentErrorRecord {
            category,
            timestamp_unix: now_unix(),
            coarse_context: coarse_context.into(),
        };
        let mut entries = self.0.entries.lock().unwrap_or_else(|p| p.into_inner());
        entries.push_back(record);
        while entries.len() > MAX_RECENT_ERRORS {
            entries.pop_front();
        }
        drop(entries);
        *self
            .0
            .category_counts
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .entry(category)
            .or_insert(0) += 1;
    }

    /// Most recent errors first, matching
    /// `ConnectionTraceLog::recent`'s ordering convention.
    pub fn recent(&self) -> Vec<RecentErrorRecord> {
        self.0.entries.lock().unwrap_or_else(|p| p.into_inner()).iter().rev().cloned().collect()
    }

    /// A snapshot of the monotonic per-category totals, for `/metrics`'
    /// `yadorilink_sync_errors_total{category}` counter family.
    pub fn category_counts(&self) -> Vec<(&'static str, u64)> {
        self.0
            .category_counts
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .map(|(k, v)| (*k, *v))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ring buffer is bounded — recording past `MAX_RECENT_ERRORS`
    /// drops the oldest, not the newest.
    #[test]
    fn ring_buffer_is_bounded_and_drops_oldest_first() {
        let log = RecentErrorLog::new();
        for i in 0..(MAX_RECENT_ERRORS + 10) {
            log.record("disk_pressure", format!("sweep-{i}"));
        }
        let recent = log.recent();
        assert_eq!(recent.len(), MAX_RECENT_ERRORS);
        // Newest first.
        assert_eq!(recent[0].coarse_context, format!("sweep-{}", MAX_RECENT_ERRORS + 9));
    }

    /// The recent-error buffer is redacted — every field is a stable
    /// category, a timestamp, or whatever fixed context string the
    /// caller passed; this test exists as a structural guard (an
    /// exhaustive match with named bindings) so a future field addition
    /// can't quietly smuggle in a raw path/key/token/IP without updating
    /// this note.
    #[test]
    fn record_shape_never_carries_more_than_category_timestamp_and_context() {
        let record = RecentErrorRecord {
            category: "disk_pressure",
            timestamp_unix: 0,
            coarse_context: "hydration".to_string(),
        };
        let RecentErrorRecord { category: _, timestamp_unix: _, coarse_context: _ } = record;
    }

    /// Per-category counts are monotonic even once the bounded ring
    /// buffer starts evicting old entries.
    #[test]
    fn category_counts_stay_monotonic_across_ring_buffer_eviction() {
        let log = RecentErrorLog::new();
        for i in 0..(MAX_RECENT_ERRORS + 5) {
            log.record("peer_unreachable", format!("attempt-{i}"));
        }
        let counts = log.category_counts();
        let (_, count) = counts.iter().find(|(c, _)| *c == "peer_unreachable").unwrap();
        assert_eq!(*count, (MAX_RECENT_ERRORS + 5) as u64);
        // The bounded ring buffer itself did evict older entries.
        assert_eq!(log.recent().len(), MAX_RECENT_ERRORS);
    }

    #[test]
    fn different_categories_are_counted_independently() {
        let log = RecentErrorLog::new();
        log.record("disk_pressure", "sweep");
        log.record("disk_pressure", "sweep");
        log.record("peer_unreachable", "hydration");

        let counts: HashMap<_, _> = log.category_counts().into_iter().collect();
        assert_eq!(counts.get("disk_pressure"), Some(&2));
        assert_eq!(counts.get("peer_unreachable"), Some(&1));
    }
}
