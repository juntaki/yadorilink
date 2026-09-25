#![cfg(test)]

use super::*;

#[test]
fn action_counts_tallies_every_variant_separately() {
    let plan = RewindPlan {
        group_id: "g".into(),
        target_unix_nanos: 100,
        entries: vec![
            RewindPathEntry {
                path: "a".into(),
                action: RewindPathAction::Create {
                    version_seq: 1,
                    version_hash: VersionHash([1u8; 32]),
                },
            },
            RewindPathEntry { path: "b".into(), action: RewindPathAction::Delete },
            RewindPathEntry {
                path: "c".into(),
                action: RewindPathAction::Replace {
                    from_version_seq: 3,
                    to_version_seq: 1,
                    to_version_hash: VersionHash([2u8; 32]),
                },
            },
            RewindPathEntry { path: "d".into(), action: RewindPathAction::Unchanged },
            RewindPathEntry {
                path: "e".into(),
                action: RewindPathAction::Unavailable { reason: "gone".into() },
            },
            RewindPathEntry { path: "f".into(), action: RewindPathAction::Unchanged },
        ],
        rename_candidates: Vec::new(),
    };
    assert_eq!(
        plan.action_counts(),
        RewindActionCounts { create: 1, delete: 1, replace: 1, unchanged: 2, unavailable: 1 }
    );
}

/// An `Unavailable` path must never be counted as, or collapse into,
/// `Unchanged`: the whole point of the variant is that "no answer
/// exists" is reported as itself.
#[test]
fn unavailable_is_never_tallied_as_unchanged() {
    let plan = RewindPlan {
        group_id: "g".into(),
        target_unix_nanos: 0,
        entries: vec![RewindPathEntry {
            path: "a".into(),
            action: RewindPathAction::Unavailable { reason: "no history".into() },
        }],
        rename_candidates: Vec::new(),
    };
    let counts = plan.action_counts();
    assert_eq!(counts.unavailable, 1);
    assert_eq!(counts.unchanged, 0);
}
