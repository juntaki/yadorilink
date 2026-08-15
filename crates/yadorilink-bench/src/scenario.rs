//! The scenario extension point: every one of the 10 M6 scenarios (L1/L2/
//! S1/S2/W1/W2/D1/M1/O1/O2) implements this trait. Only L1 is implemented
//! in this first slice -- see DESIGN.md for the remaining 9's shape.

use crate::metrics::ScenarioReport;

pub struct RunOptions {
    /// Primary file size in bytes -- what "10GB" means for L1/L2/D1/O1/O2.
    /// Not meaningful for the file-count scenarios (S1/S2), which will read
    /// their own count/size options once implemented.
    pub file_size_bytes: u64,
}

#[async_trait::async_trait]
pub trait Scenario: Send + Sync {
    /// The scenario id exactly as named in the M6 task's list (`"L1"`, …).
    fn id(&self) -> &'static str;

    async fn run(&self, opts: &RunOptions) -> anyhow::Result<ScenarioReport>;
}

/// Every scenario id the M6 milestone specifies, in the task's own order --
/// the fixed roster `list` and CLI dispatch iterate over. Kept as a plain
/// list (not an enum with a `Scenario` per variant) because 9 of these have
/// no runner yet; adding one is "implement `Scenario` and add a match arm
/// in `main.rs`", not a change to this list itself.
pub const ALL_SCENARIO_IDS: &[&str] = &["L1", "L2", "S1", "S2", "W1", "W2", "D1", "M1", "O1", "O2"];
