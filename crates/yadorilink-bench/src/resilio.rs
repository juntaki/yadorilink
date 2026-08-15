//! Resilio Sync comparison -- interface stub. Not installed on this
//! machine (checked at development time via `which resilio-sync rslsync
//! Resilio\ Sync`, all absent), so there is nothing to shell out to yet.
//! Kept as an explicit, documented seam rather than silently absent so a
//! machine that DOES have Resilio installed gets a real "not implemented"
//! signal instead of a benchmark that quietly only ever measures
//! YadoriLink.

use std::process::Command;

/// Common binary names across Resilio Sync's Linux/macOS packaging
/// (`rslsync` is the historical BitTorrent Sync/Resilio CLI daemon name;
/// `resilio-sync` is the newer package's name).
const CANDIDATE_BINARIES: &[&str] = &["resilio-sync", "rslsync"];

pub struct ResilioAvailability {
    pub binary_path: Option<String>,
}

impl ResilioAvailability {
    pub fn detect() -> Self {
        for name in CANDIDATE_BINARIES {
            if let Ok(output) = Command::new("which").arg(name).output() {
                if output.status.success() {
                    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
                    if !path.is_empty() {
                        return Self { binary_path: Some(path) };
                    }
                }
            }
        }
        Self { binary_path: None }
    }

    pub fn describe(&self) -> String {
        match &self.binary_path {
            Some(path) => format!(
                "Resilio Sync found at {path} -- comparison runner not implemented yet (TODO: \
                 drive it as a real, separate OS process pointed at its own sync folder over the \
                 same scenario, per DESIGN.md's \"Resilio comparison\" section)"
            ),
            None => "Resilio Sync not installed on this machine (checked: resilio-sync, rslsync \
                     on $PATH) -- comparison skipped"
                .to_string(),
        }
    }
}
