#![cfg(test)]

use super::*;
use yadorilink_replica_domain::ids::VersionHash;

fn plan_of(entries: Vec<RewindPathEntry>) -> RewindPlan {
    RewindPlan {
        group_id: "g".to_string(),
        target_unix_nanos: 100,
        entries,
        rename_candidates: Vec::new(),
    }
}

fn entry(path: &str, action: RewindPathAction) -> RewindPathEntry {
    RewindPathEntry { path: path.to_string(), action }
}

/// The default response omits `unchanged` entries but must still report
/// them -- a summary that undercounted the paths a rewind would leave
/// alone would misdescribe the plan.
#[test]
fn omitting_unchanged_entries_never_changes_the_counts() {
    let plan = plan_of(vec![
        entry("a", RewindPathAction::Unchanged),
        entry("b", RewindPathAction::Delete),
        entry("c", RewindPathAction::Unchanged),
    ]);

    let trimmed = trim_for_wire(plan.clone(), false);
    assert_eq!(trimmed.counts.unchanged, 2);
    assert_eq!(trimmed.counts.delete, 1);
    assert_eq!(trimmed.total_entry_count, 3);
    assert_eq!(trimmed.entries.len(), 1, "only the non-unchanged path is listed");
    assert_eq!(trimmed.entries[0].path, "b");
    assert!(!trimmed.listing_truncated, "a filter is not a truncation");

    let verbose = trim_for_wire(plan, true);
    assert_eq!(verbose.counts, trimmed.counts, "the tallies do not depend on the listing");
    assert_eq!(verbose.entries.len(), 3);
}

/// The filter alone is not a bound: a target older than the whole
/// folder classifies every path as something other than `unchanged`.
/// The byte budget is what actually guarantees a deliverable response,
/// and it must say when it cut something.
#[test]
fn the_listing_is_capped_even_when_nothing_is_unchanged() {
    let entries = (0..200_000)
        .map(|i| {
            entry(&format!("deep/nested/directory/path/file-{i:06}.bin"), RewindPathAction::Delete)
        })
        .collect();
    let trimmed = trim_for_wire(plan_of(entries), false);

    assert_eq!(trimmed.total_entry_count, 200_000, "the whole plan is still reported");
    assert_eq!(trimmed.counts.delete, 200_000);
    assert!(trimmed.listing_truncated, "a cut listing must be flagged as cut");
    assert!(
        trimmed.entries.len() < 200_000,
        "the listing must actually be capped, not merely flagged"
    );
}

/// The advisory rename list gets its own, much smaller budget so it
/// cannot crowd out the authoritative per-path entries.
#[test]
fn the_rename_list_has_its_own_budget() {
    let mut plan = plan_of(vec![entry("a", RewindPathAction::Delete)]);
    plan.rename_candidates = (0..100_000)
        .map(|i| RewindRenameCandidate {
            from_path: format!("from/long/enough/to/matter/{i:06}"),
            to_path: format!("to/long/enough/to/matter/{i:06}"),
            version_hash: VersionHash([0u8; 32]),
        })
        .collect();

    let trimmed = trim_for_wire(plan, false);
    assert_eq!(trimmed.total_rename_candidate_count, 100_000);
    assert!(trimmed.rename_candidates.len() < 100_000);
    assert!(trimmed.listing_truncated);
    assert_eq!(
        trimmed.entries.len(),
        1,
        "the per-path entry must survive a flood of rename candidates"
    );
}
