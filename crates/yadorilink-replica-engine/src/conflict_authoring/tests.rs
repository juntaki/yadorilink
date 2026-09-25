#![cfg(test)]

use super::*;
use crate::conflict::PathHeadContent;

fn head(change_hash: u8, lamport: u64, device_id: &str, content_hash: Option<u8>) -> PathHead {
    PathHead {
        change_hash: [change_hash; 32],
        lamport,
        device_id: device_id.to_string(),
        // The ordinary case these tests cover: the signer wrote the
        // content, so carrier and naming identity coincide.
        naming_device_id: device_id.to_string(),
        content: content_hash
            .map(|c| PathHeadContent { version_hash: [c; 32], mtime_unix_nanos: 0 }),
    }
}

#[test]
fn collect_touched_paths_covers_put_delete_and_both_sides_of_a_move() {
    let ops = vec![
        Op::Put {
            path: SyncPath("a.txt".into()),
            version: VersionHash([1; 32]),
            origin: PutOrigin::Direct,
        },
        Op::Delete { path: SyncPath("b.txt".into()) },
        Op::Move {
            from: SyncPath("c.txt".into()),
            to: SyncPath("d.txt".into()),
            version: VersionHash([2; 32]),
        },
    ];
    let touched = collect_touched_paths(&ops);
    assert_eq!(
        touched,
        BTreeSet::from([
            "a.txt".to_string(),
            "b.txt".to_string(),
            "c.txt".to_string(),
            "d.txt".to_string(),
        ])
    );
}

#[test]
fn conflict_copy_candidates_is_empty_when_the_path_resolves_absent() {
    let heads = vec![head(1, 1, "device-a", None)];
    assert!(conflict_copy_candidates("p.txt", &heads, |_| false).is_empty());
}

#[test]
fn conflict_copy_candidates_names_the_loser_for_two_concurrent_content_heads() {
    let heads = vec![head(1, 1, "device-a", Some(0xAA)), head(2, 2, "device-b", Some(0xBB))];
    let candidates = conflict_copy_candidates("p.txt", &heads, |_| false);
    assert_eq!(candidates.len(), 1, "exactly one loser between two concurrent content heads");
    assert_eq!(candidates[0].losing_change.0, [1; 32], "lower lamport is the loser");
    assert_eq!(candidates[0].losing_content.version_hash, [0xAA; 32]);
}

#[test]
fn content_already_preserved_at_target_matches_only_on_version_hash() {
    let target_heads = vec![head(9, 1, "device-x", Some(0xCC))];
    assert!(content_already_preserved_at_target(&target_heads, &[0xCC; 32]));
    assert!(!content_already_preserved_at_target(&target_heads, &[0xDD; 32]));
}

#[test]
fn validate_claimed_matches_required_rejects_a_missing_claim() {
    let required = vec![Op::Put {
        path: SyncPath("copy.txt".into()),
        version: VersionHash([1; 32]),
        origin: PutOrigin::ConflictCopy {
            source_path: SyncPath("src.txt".into()),
            losing_change: ChangeHash([2; 32]),
        },
    }];
    let claimed = BTreeSet::new();
    assert!(matches!(
        validate_claimed_matches_required(&required, &claimed),
        Err(ConflictCopyClaimSetError::Missing { .. })
    ));
}

#[test]
fn validate_claimed_matches_required_rejects_an_unrequired_claim() {
    let claimed = BTreeSet::from([("src.txt".to_string(), ChangeHash([2; 32]))]);
    assert!(matches!(
        validate_claimed_matches_required(&[], &claimed),
        Err(ConflictCopyClaimSetError::Unrequired { .. })
    ));
}

#[test]
fn validate_claimed_matches_required_accepts_an_exact_match() {
    let required = vec![Op::Put {
        path: SyncPath("copy.txt".into()),
        version: VersionHash([1; 32]),
        origin: PutOrigin::ConflictCopy {
            source_path: SyncPath("src.txt".into()),
            losing_change: ChangeHash([2; 32]),
        },
    }];
    let claimed = BTreeSet::from([("src.txt".to_string(), ChangeHash([2; 32]))]);
    assert!(validate_claimed_matches_required(&required, &claimed).is_ok());
}

#[test]
fn validate_retroactive_repair_claims_is_a_no_op_for_ordinary_changes() {
    assert!(validate_retroactive_repair_claims(&ChangePurpose::Ordinary, &[], &BTreeSet::new(),)
        .is_ok());
}

#[test]
fn validate_retroactive_repair_claims_rejects_an_undeclared_reassertion() {
    use yadorilink_replica_domain::change::RepairObligation;
    let purpose = ChangePurpose::RetroactiveRepair {
        obligations: vec![RepairObligation {
            source_path: SyncPath("declared.txt".into()),
            losing_change: ChangeHash([2; 32]),
        }],
    };
    let claimed = BTreeSet::from([("declared.txt".to_string(), ChangeHash([2; 32]))]);
    let direct_ops = vec![Op::Put {
        path: SyncPath("undeclared.txt".into()),
        version: VersionHash([3; 32]),
        origin: PutOrigin::Reasserted {
            original_change: ChangeHash([4; 32]),
            naming_device_id: yadorilink_replica_domain::ids::DeviceId("device-a".into()),
        },
    }];
    assert!(matches!(
        validate_retroactive_repair_claims(&purpose, &direct_ops, &claimed),
        Err(RetroactiveRepairClaimError::UndeclaredReassertion(_))
    ));
}

/// A repair carrier's own re-assertion must say whose content it carries.
/// A bare `Direct` put asserts the repairer wrote the content, which is
/// exactly the misattribution `PutOrigin::Reasserted` exists to prevent
/// -- so it is rejected rather than accepted as an equivalent encoding.
#[test]
fn validate_retroactive_repair_claims_rejects_a_bare_direct_reassertion() {
    use yadorilink_replica_domain::change::RepairObligation;
    let purpose = ChangePurpose::RetroactiveRepair {
        obligations: vec![RepairObligation {
            source_path: SyncPath("declared.txt".into()),
            losing_change: ChangeHash([2; 32]),
        }],
    };
    let claimed = BTreeSet::from([("declared.txt".to_string(), ChangeHash([2; 32]))]);
    let direct_ops = vec![Op::Put {
        path: SyncPath("declared.txt".into()),
        version: VersionHash([3; 32]),
        origin: PutOrigin::Direct,
    }];
    assert!(matches!(
        validate_retroactive_repair_claims(&purpose, &direct_ops, &claimed),
        Err(RetroactiveRepairClaimError::NonReassertionDirectOp)
    ));
}

/// A repair re-assertion carries someone else's content forward, so the
/// head's carrier and its naming identity differ -- and the copy is named
/// after the content's author, because naming it after the carrier would
/// attribute the content to a device that never wrote it.
///
/// Validation has to derive the expected name from the same field
/// `resolve_path_heads` names it with. Deriving it from the carrier made
/// the two disagree for exactly these heads, and then the only copy
/// anyone could author was the one validation rejected by name.
#[test]
fn a_reasserted_losers_copy_is_named_after_its_author_not_its_carrier() {
    let mut winner = head(1, 2, "device-w", Some(9));
    winner.naming_device_id = "device-w".to_string();
    // Carried forward by device-3 on device-1's behalf.
    let mut loser = head(2, 1, "device-3", Some(4));
    loser.naming_device_id = "device-1".to_string();
    let heads = vec![winner, loser];

    let PathResolution::Present { conflict_copies, .. } =
        crate::conflict::resolve_path_heads("shared.bin", &heads)
    else {
        panic!("both heads carry content, so the path is present");
    };
    let copy = conflict_copies.first().expect("the losing head produces one copy");
    assert!(
        copy.path.contains("device-1"),
        "the copy must be named after the content's author: {}",
        copy.path
    );

    validate_conflict_copy_claim(
        &heads,
        &copy.path,
        &VersionHash([4; 32]),
        "shared.bin",
        &ChangeHash([2; 32]),
        |_| false,
    )
    .expect("the name resolve_path_heads asks for is the name validation must accept");
}

/// DIR-1: a Directory head (content 0xD0 here) keeps the path whoever wins
/// the rank. Every File content class is a candidate, the ranked winner's
/// included, and a losing Directory is none.
#[test]
fn a_directory_keeps_the_path_and_every_leaf_class_is_a_candidate() {
    let is_directory = |h: &PathHead| h.content.as_ref().is_some_and(|c| c.version_hash[0] >= 0xD0);
    // File 0xAA wins the rank (lamport 9); a second File 0xBB; the ranked
    // File's content again under a lower head; two Directories.
    let heads = vec![
        head(1, 9, "device-a", Some(0xAA)),
        head(2, 1, "device-b", Some(0xBB)),
        head(3, 2, "device-c", Some(0xAA)),
        head(4, 3, "device-d", Some(0xD0)),
        head(5, 4, "device-e", Some(0xD1)),
    ];
    let PathResolution::Present { winner, .. } =
        crate::conflict::resolve_path_heads_keeping_directory("a", &heads, is_directory)
    else {
        panic!("present");
    };
    assert_eq!(heads[winner].change_hash, [5; 32], "the best-ranked Directory keeps the path");
    let mut losers: Vec<u8> = conflict_copy_candidates("a", &heads, is_directory)
        .iter()
        .map(|c| c.losing_change.0[0])
        .collect();
    losers.sort();
    assert_eq!(losers, vec![1, 2], "one copy per leaf class, the ranked winner's included");
    let without_directories = conflict_copy_candidates("a", &heads[..3], is_directory);
    assert_eq!(
        without_directories.iter().map(|c| c.losing_change.0[0]).collect::<Vec<_>>(),
        vec![2],
        "with no Directory head the ordinary rank decides"
    );
}
