use super::*;

#[test]
fn compaction_scheduling_remains_explicitly_gated_off() {
    const { assert!(!COMPACTION_SCHEDULING_READY) };
}
