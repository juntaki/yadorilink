use ed25519_dalek::SigningKey;

use super::*;
use crate::change::{Change, ChangePurpose, Op, PutOrigin};
use crate::ids::{AuthorSeq, DeviceId, FolderGroupId, SyncPath, VersionHash};
use crate::rebootstrap::HistoryEpoch;

fn key() -> SigningKey {
    SigningKey::from_bytes(&[11u8; 32])
}

fn delete(path: &str) -> Op {
    Op::Delete { path: SyncPath(path.into()) }
}

fn put(path: &str) -> Op {
    Op::Put {
        path: SyncPath(path.into()),
        version: VersionHash([3u8; 32]),
        origin: PutOrigin::Direct,
    }
}

fn rm_tree(root: &str, part_index: u32, part_count: u32, effects: &[Op]) -> RecursiveOperation {
    RecursiveOperation {
        operation_id: RecursiveOperationId([0x5A; 16]),
        kind: RecursiveOperationKind::RmTree { root: SyncPath(root.into()) },
        part_index,
        part_count,
        effect_set_hash: EffectSetHash::of_effects(effects),
    }
}

fn part(operation: RecursiveOperation, ops: Vec<Op>) -> Change {
    Change::create_recursive_part_signed(
        vec![],
        0,
        DeviceId("dev".into()),
        AuthorSeq::FIRST,
        None,
        FolderGroupId("g".into()),
        HistoryEpoch::Genesis,
        operation,
        ops,
        &key(),
    )
}

fn validate(change: &Change) -> Result<(), ChangeError> {
    change.validate_structure(&change.compute_hash())
}

fn assert_malformed(change: &Change, why: &str) {
    match validate(change) {
        Err(ChangeError::Malformed(_)) => {}
        other => panic!("{why}: expected Malformed, got {other:?}"),
    }
}

/// The grouping is part of the signed bytes: it survives the wire, and a
/// part that differs only in its descriptor is a different change.
#[test]
fn recursive_part_descriptor_round_trips_and_is_part_of_the_change_identity() {
    let effects = vec![delete("a"), delete("a/x"), delete("a/y")];
    let first = part(rm_tree("a", 0, 2, &effects), vec![delete("a/x"), delete("a/y")]);
    validate(&first).expect("a well-formed part validates");

    let decoded = Change::from_wire_bytes(&first.to_wire_bytes()).expect("round trip");
    assert_eq!(decoded, first);
    assert_eq!(decoded.recursive_operation, Some(rm_tree("a", 0, 2, &effects)));

    let other_index = part(rm_tree("a", 1, 2, &effects), vec![delete("a/x"), delete("a/y")]);
    assert_ne!(first.compute_hash(), other_index.compute_hash());

    let ungrouped = Change::create_signed(
        vec![],
        0,
        DeviceId("dev".into()),
        AuthorSeq::FIRST,
        None,
        FolderGroupId("g".into()),
        HistoryEpoch::Genesis,
        vec![delete("a/x"), delete("a/y")],
        &key(),
    );
    assert_eq!(ungrouped.recursive_operation, None);
    assert_ne!(first.compute_hash(), ungrouped.compute_hash());
}

/// A compacted part keeps only its header; the header must still say which
/// operation the part belonged to.
#[test]
fn authenticated_header_carries_the_recursive_operation() {
    let effects = vec![delete("a/x")];
    let grouped = part(rm_tree("a", 0, 1, &effects), effects.clone());
    let other = part(
        RecursiveOperation {
            operation_id: RecursiveOperationId([0x77; 16]),
            ..rm_tree("a", 0, 1, &effects)
        },
        effects.clone(),
    );
    assert_ne!(grouped.authenticated_header_encoding(), other.authenticated_header_encoding());
}

#[test]
fn reserved_all_zero_operation_id_is_malformed() {
    let effects = vec![delete("a/x")];
    let op = RecursiveOperation {
        operation_id: RecursiveOperationId([0; 16]),
        ..rm_tree("a", 0, 1, &effects)
    };
    assert_malformed(&part(op, effects), "an all-zero id is the unset value");
}

#[test]
fn part_index_must_be_below_a_bounded_nonzero_part_count() {
    let effects = vec![delete("a/x")];
    assert_malformed(&part(rm_tree("a", 1, 1, &effects), effects.clone()), "index == count");
    assert_malformed(&part(rm_tree("a", 0, 0, &effects), effects.clone()), "count == 0");
    assert_malformed(
        &part(rm_tree("a", 0, MAX_RECURSIVE_OPERATION_PARTS + 1, &effects), effects.clone()),
        "count above the bound",
    );
    validate(&part(
        rm_tree("a", MAX_RECURSIVE_OPERATION_PARTS - 1, MAX_RECURSIVE_OPERATION_PARTS, &effects),
        effects,
    ))
    .expect("the last index of the largest count is well-formed");
}

/// `root` is an ancestor-or-self of every op path, by path segment and not
/// by string prefix.
#[test]
fn rm_tree_part_may_only_act_at_or_under_its_root() {
    let at_root = vec![delete("a")];
    validate(&part(rm_tree("a", 0, 1, &at_root), at_root)).expect("the root itself is in scope");

    let sibling_prefix = vec![delete("a/x"), delete("ab")];
    assert_malformed(
        &part(rm_tree("a", 0, 1, &sibling_prefix), sibling_prefix),
        "`ab` shares a string prefix with `a` but is not under it",
    );

    let moved_out = vec![Op::Move {
        from: SyncPath("a/x".into()),
        to: SyncPath("elsewhere".into()),
        version: VersionHash([1; 32]),
    }];
    assert_malformed(&part(rm_tree("a", 0, 1, &moved_out), moved_out), "both ends of a move count");
}

#[test]
fn rm_tree_root_must_be_a_clean_path() {
    let effects = vec![delete("a/x")];
    assert_malformed(&part(rm_tree("", 0, 1, &effects), effects.clone()), "empty root");
    assert_malformed(&part(rm_tree("a/../a", 0, 1, &effects), effects), "dot-dot root");
}

fn rename_tree(from: &str, to: &str, effects: &[Op]) -> RecursiveOperation {
    RecursiveOperation {
        operation_id: RecursiveOperationId([0x6B; 16]),
        kind: RecursiveOperationKind::RenameTree {
            from: SyncPath(from.into()),
            to: SyncPath(to.into()),
        },
        part_index: 0,
        part_count: 1,
        effect_set_hash: EffectSetHash::of_effects(effects),
    }
}

#[test]
fn rename_tree_part_acts_only_in_its_old_or_new_namespace() {
    let effects = vec![delete("a/x"), put("b/x")];
    validate(&part(rename_tree("a", "b", &effects), effects)).expect("old and new namespaces");

    let stray = vec![delete("a/x"), put("c/x")];
    assert_malformed(&part(rename_tree("a", "b", &stray), stray), "a path in neither namespace");
}

#[test]
fn rename_tree_source_and_destination_may_not_nest() {
    let effects = vec![delete("a/x")];
    assert_malformed(&part(rename_tree("a", "a", &effects), effects.clone()), "same path");
    assert_malformed(
        &part(rename_tree("a", "a/sub", &effects), effects.clone()),
        "into own subtree",
    );
    assert_malformed(&part(rename_tree("a/sub", "a", &effects), effects), "onto own ancestor");
}

#[test]
fn a_part_with_no_operations_is_malformed() {
    assert_malformed(&part(rm_tree("a", 0, 1, &[]), vec![]), "an empty part");
}

#[test]
fn a_repair_carrier_cannot_claim_to_be_a_recursive_part() {
    let effects = vec![delete("a/x")];
    let mut change = part(rm_tree("a", 0, 1, &effects), effects);
    change.purpose = ChangePurpose::RetroactiveRepair {
        obligations: vec![crate::change::RepairObligation {
            source_path: SyncPath("a/x".into()),
            losing_change: crate::ids::ChangeHash([9; 32]),
        }],
    };
    change.sign(&key());
    assert_malformed(&change, "a repair carrier is not a user's recursive mutation");
}

/// The digest names the observed set, not the way it was cut into parts.
#[test]
fn effect_set_hash_is_independent_of_order_and_split() {
    let a = [delete("t/1"), delete("t/2"), delete("t")];
    let b = [delete("t"), delete("t/2"), delete("t/1")];
    assert_eq!(EffectSetHash::of_effects(&a), EffectSetHash::of_effects(&b));
    let fewer = [delete("t"), delete("t/2")];
    assert_ne!(EffectSetHash::of_effects(&a), EffectSetHash::of_effects(&fewer));
}

#[test]
fn descriptor_bytes_round_trip() {
    let descriptor = rename_tree("a", "b", &[delete("a/x")]).descriptor();
    assert_eq!(RecursiveOperationDescriptor::from_bytes(&descriptor.to_bytes()), Ok(descriptor));
}

/// A conflict copy derived while closing a fork on the root is named as the
/// root's sibling. It is not one of the operation's effects: it neither
/// breaks the scope rule nor enters the effect set.
#[test]
fn a_derived_conflict_copy_is_not_an_effect_of_the_operation() {
    let effects = vec![delete("a"), delete("a/x")];
    let copy = Op::Put {
        path: SyncPath("a (conflict from dev)".into()),
        version: VersionHash([4; 32]),
        origin: PutOrigin::ConflictCopy {
            source_path: SyncPath("a".into()),
            losing_change: crate::ids::ChangeHash([8; 32]),
        },
    };
    let mut ops = effects.clone();
    ops.push(copy.clone());
    validate(&part(rm_tree("a", 0, 1, &effects), ops.clone()))
        .expect("a derived conflict copy outside the root is allowed");
    assert_eq!(EffectSetHash::of_effects(&ops), EffectSetHash::of_effects(&effects));
    assert_malformed(
        &part(rm_tree("a", 0, 1, &[]), vec![copy]),
        "a part must carry at least one effect of its own",
    );
}
