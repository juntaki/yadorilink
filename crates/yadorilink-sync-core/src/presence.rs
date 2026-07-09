//! Edit-presence detection (`edit-presence-awareness` capability, task
//! 9.1): recognizing Office's own `~$<name>.<ext>` temporary lock-file
//! naming convention — the same mechanism that lets a second person
//! opening a document in Word see "this file is locked for editing by
//! ..." with no server involved at all. The local folder watcher already
//! sees every filesystem event, so detecting this needs no new OS
//! integration, just a pattern match on events it already receives.

/// Returns the original file's name (e.g. `"report.docx"`) if `filename`
/// matches Office's `~$<name>.<ext>` lock-file convention, `None`
/// otherwise. A lock file with no name after the prefix (just `"~$"`) is
/// deliberately not matched — Office never produces that.
pub fn office_lock_file_target(filename: &str) -> Option<&str> {
    filename.strip_prefix("~$").filter(|rest| !rest.is_empty())
}

/// Default TTL (seconds) a presence signal is valid for on the receiving
/// side absent a refresh (design D7's open question, resolved with a
/// concrete default here: refresh well within the TTL so a couple of
/// missed sends don't flap the "open elsewhere" badge).
pub const PRESENCE_TTL_SECS: u32 = 90;
/// How often the sender re-sends a presence signal for a file it's still
/// editing — comfortably under `PRESENCE_TTL_SECS` so normal network
/// jitter never causes a spurious expiry.
pub const PRESENCE_REFRESH_INTERVAL_SECS: u64 = 30;

/// A received or locally-originated edit-presence event — the daemon-level
/// representation `PeerSyncSession` forwards incoming `PresenceSignal`
/// wire messages as (mirroring `forward_tx`'s `FileRecord` forwarding
/// pattern), and what `link_manager` constructs from a local
/// `LocalChangeOutcome::PresenceChanged` to broadcast to peers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresenceEvent {
    pub group_id: String,
    pub path: String,
    pub device_id: String,
    pub editing: bool,
    pub ttl_seconds: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_office_lock_files() {
        assert_eq!(office_lock_file_target("~$report.docx"), Some("report.docx"));
        assert_eq!(office_lock_file_target("~$Budget 2026.xlsx"), Some("Budget 2026.xlsx"));
    }

    #[test]
    fn does_not_match_ordinary_files() {
        assert_eq!(office_lock_file_target("report.docx"), None);
        assert_eq!(office_lock_file_target("~notes.txt"), None);
        assert_eq!(office_lock_file_target("$report.docx"), None);
    }

    #[test]
    fn does_not_match_a_bare_prefix_with_no_name() {
        assert_eq!(office_lock_file_target("~$"), None);
    }
}
