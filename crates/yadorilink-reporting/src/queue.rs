//! Metadata for a locally-queued, not-yet-submitted report (design.md
//! D4/D7). Like `consent.rs`, this module defines the shape only —
//! actual on-disk storage/retention enforcement lives in
//! `yadorilink-daemon` (section 2), outside any linked folder.

use serde::{Deserialize, Serialize};

use crate::schema::ReportType;

/// What a successful HTTPS submission (design.md D6) hands back. Defined
/// here rather than in a future submission-client module since it's
/// part of the shared local record of "this report was sent" — the
/// queue needs to be able to mark an entry submitted and show the user
/// the receipt without any HTTPS-specific code being involved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmissionReceipt {
    pub report_id: String,
    /// Opaque, endpoint-assigned — never fed back into sync/auth
    /// behavior, per D6's "avoid feeding any response back into sync
    /// behavior."
    pub receipt_id: String,
    pub submitted_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueuedReportMetadata {
    /// Locally generated, not derived from any account/device identity —
    /// stable only for as long as this queue entry exists.
    pub report_id: String,
    pub report_type: ReportType,
    /// RFC 3339 timestamp, caller-supplied (see `ReportEnvelope::generated_at`
    /// for why this crate doesn't stamp time itself).
    pub queued_at: String,
    pub size_bytes: usize,
    pub submit_attempts: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetentionPolicy {
    pub max_entries: usize,
    pub max_age_seconds: u64,
    pub max_entry_bytes: usize,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        RetentionPolicy {
            max_entries: 50,
            // 30 days.
            max_age_seconds: 30 * 24 * 60 * 60,
            max_entry_bytes: crate::schema::MAX_REPORT_BYTES,
        }
    }
}

impl RetentionPolicy {
    /// Given the current queue and "now" (caller-supplied, same
    /// no-internal-clock reasoning as elsewhere in this crate), returns
    /// the `report_id`s that violate this policy and should be deleted:
    /// entries older than `max_age_seconds`, oversized entries, and (if
    /// still over `max_entries` after those) the oldest excess entries.
    pub fn entries_to_evict(
        &self,
        queue: &[QueuedReportMetadata],
        now_unix_seconds: u64,
        queued_at_unix_seconds: impl Fn(&QueuedReportMetadata) -> u64,
    ) -> Vec<String> {
        let mut evict = Vec::new();
        let mut survivors: Vec<&QueuedReportMetadata> = Vec::new();
        for entry in queue {
            let age = now_unix_seconds.saturating_sub(queued_at_unix_seconds(entry));
            if age > self.max_age_seconds || entry.size_bytes > self.max_entry_bytes {
                evict.push(entry.report_id.clone());
            } else {
                survivors.push(entry);
            }
        }
        if survivors.len() > self.max_entries {
            survivors.sort_by_key(|e| queued_at_unix_seconds(e));
            let excess = survivors.len() - self.max_entries;
            evict.extend(survivors.into_iter().take(excess).map(|e| e.report_id.clone()));
        }
        evict
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: &str, size_bytes: usize) -> QueuedReportMetadata {
        QueuedReportMetadata {
            report_id: id.to_string(),
            report_type: ReportType::Usage,
            queued_at: "2026-01-01T00:00:00Z".into(),
            size_bytes,
            submit_attempts: 0,
        }
    }

    #[test]
    fn evicts_entries_older_than_max_age() {
        let policy = RetentionPolicy { max_age_seconds: 100, ..Default::default() };
        let queue = vec![entry("old", 10), entry("fresh", 10)];
        let ages = |id: &str| if id == "old" { 500 } else { 5 };
        let evicted = policy.entries_to_evict(&queue, 1000, |e| 1000 - ages(&e.report_id));
        assert_eq!(evicted, vec!["old".to_string()]);
    }

    #[test]
    fn evicts_entries_over_the_max_entry_byte_cap() {
        let policy = RetentionPolicy { max_entry_bytes: 1000, ..Default::default() };
        let queue = vec![entry("huge", 5000), entry("normal", 100)];
        let evicted = policy.entries_to_evict(&queue, 0, |_| 0);
        assert_eq!(evicted, vec!["huge".to_string()]);
    }

    #[test]
    fn evicts_oldest_excess_entries_once_over_max_count() {
        let policy =
            RetentionPolicy { max_entries: 2, max_age_seconds: u64::MAX, ..Default::default() };
        let queue = vec![entry("a", 10), entry("b", 10), entry("c", 10)];
        // "a" queued first (oldest), "c" queued last (newest).
        let queued_order = |id: &str| match id {
            "a" => 0,
            "b" => 1,
            "c" => 2,
            _ => unreachable!(),
        };
        let evicted = policy.entries_to_evict(&queue, 0, |e| queued_order(&e.report_id));
        assert_eq!(evicted, vec!["a".to_string()]);
    }

    #[test]
    fn empty_queue_evicts_nothing() {
        let policy = RetentionPolicy::default();
        assert!(policy.entries_to_evict(&[], 0, |_| 0).is_empty());
    }
}
