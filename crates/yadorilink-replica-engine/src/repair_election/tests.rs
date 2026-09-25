#![cfg(test)]

use super::*;

fn writer(device_id: &str, fingerprint_byte: u8) -> AuthorizedWriter {
    AuthorizedWriter {
        device_id: device_id.to_string(),
        signing_key_fingerprint: [fingerprint_byte; 32],
    }
}

fn group(name: &str) -> FolderGroupId {
    FolderGroupId(name.to_string())
}

fn path(name: &str) -> SyncPath {
    SyncPath(name.to_string())
}

#[test]
fn obligation_id_is_stable_and_distinguishes_its_inputs() {
    let losing_a = ChangeHash([1u8; 32]);
    let losing_b = ChangeHash([2u8; 32]);
    let id = RepairObligationId::compute(&group("group"), &path("path.bin"), &losing_a);
    assert_eq!(id, RepairObligationId::compute(&group("group"), &path("path.bin"), &losing_a));
    assert_ne!(
        id,
        RepairObligationId::compute(&group("other-group"), &path("path.bin"), &losing_a)
    );
    assert_ne!(id, RepairObligationId::compute(&group("group"), &path("other.bin"), &losing_a));
    assert_ne!(id, RepairObligationId::compute(&group("group"), &path("path.bin"), &losing_b));
}

#[test]
fn ranking_is_a_permutation_of_the_input_writers() {
    let policy_head = [7u8; 32];
    let obligation =
        RepairObligationId::compute(&group("group"), &path("path.bin"), &ChangeHash([9u8; 32]));
    let writers = vec![writer("device-a", 1), writer("device-b", 2), writer("device-c", 3)];
    let ranked = rank_writers_for_obligation(&policy_head, obligation, &writers);
    assert_eq!(ranked.len(), writers.len());
    for w in &writers {
        assert!(ranked.contains(w));
    }
}

#[test]
fn ranking_is_deterministic_across_independent_calls_and_input_order() {
    let policy_head = [7u8; 32];
    let obligation =
        RepairObligationId::compute(&group("group"), &path("path.bin"), &ChangeHash([9u8; 32]));
    let writers = vec![writer("device-a", 1), writer("device-b", 2), writer("device-c", 3)];
    let mut shuffled = writers.clone();
    shuffled.reverse();

    let ranked_1 = rank_writers_for_obligation(&policy_head, obligation, &writers);
    let ranked_2 = rank_writers_for_obligation(&policy_head, obligation, &shuffled);
    assert_eq!(ranked_1, ranked_2, "ranking must not depend on the caller's input order");
}

/// Pins the actual ranking `rank_writers_for_obligation` produces for a
/// fixed set of inputs, rather than asserting a property (like "changes
/// with policy_head") rendezvous hashing does not actually guarantee for
/// an arbitrary pair of inputs. If this ever fails after a genuinely
/// intended algorithm change, recompute and update the expected order
/// deliberately -- do not "fix" it by loosening the assertion.
#[test]
fn ranking_matches_a_fixed_reference_vector() {
    let policy_head = [0x11u8; 32];
    let obligation = RepairObligationId::compute(
        &group("group-ref"),
        &path("ref/path.bin"),
        &ChangeHash([0x22u8; 32]),
    );
    let writers =
        vec![writer("device-a", 0xAA), writer("device-b", 0xBB), writer("device-c", 0xCC)];
    let ranked = rank_writers_for_obligation(&policy_head, obligation, &writers);
    let ranked_ids: Vec<&str> = ranked.iter().map(|w| w.device_id.as_str()).collect();
    assert_eq!(ranked_ids, vec!["device-b", "device-a", "device-c"]);
}

#[test]
fn score_is_bound_to_policy_head() {
    let obligation =
        RepairObligationId::compute(&group("group"), &path("path.bin"), &ChangeHash([9u8; 32]));
    let w = writer("device-a", 1);
    assert_ne!(
        election_score(&[1u8; 32], obligation, &w),
        election_score(&[2u8; 32], obligation, &w)
    );
}

#[test]
fn score_is_bound_to_obligation() {
    let policy_head = [7u8; 32];
    let obligation_1 =
        RepairObligationId::compute(&group("group"), &path("path-1.bin"), &ChangeHash([9u8; 32]));
    let obligation_2 =
        RepairObligationId::compute(&group("group"), &path("path-2.bin"), &ChangeHash([9u8; 32]));
    let w = writer("device-a", 1);
    assert_ne!(
        election_score(&policy_head, obligation_1, &w),
        election_score(&policy_head, obligation_2, &w)
    );
}

#[test]
fn score_is_bound_to_writer_identity_and_fingerprint() {
    let policy_head = [7u8; 32];
    let obligation =
        RepairObligationId::compute(&group("group"), &path("path.bin"), &ChangeHash([9u8; 32]));
    let a = writer("device-a", 1);
    let b = writer("device-b", 1);
    let a_other_key = writer("device-a", 2);
    assert_ne!(
        election_score(&policy_head, obligation, &a),
        election_score(&policy_head, obligation, &b),
        "score must depend on device_id"
    );
    assert_ne!(
        election_score(&policy_head, obligation, &a),
        election_score(&policy_head, obligation, &a_other_key),
        "score must depend on the bound signing-key fingerprint, not just device_id"
    );
}

fn obligation_fixture() -> RepairObligationId {
    RepairObligationId::compute(&group("group"), &path("path.bin"), &ChangeHash([9u8; 32]))
}

#[test]
fn context_new_rejects_a_duplicate_device_id() {
    let writers = vec![writer("device-a", 1), writer("device-a", 2)];
    let result = RepairElectionContext::new(
        [0u8; 32],
        obligation_fixture(),
        writers,
        "device-a".to_string(),
        [1u8; 32],
    );
    assert_eq!(
        result.unwrap_err(),
        RepairElectionError::DuplicateWriter { device_id: "device-a".to_string() }
    );
}

#[test]
fn context_ranks_writers_against_expected_policy_head() {
    let policy_head = [7u8; 32];
    let writers = vec![writer("device-a", 1), writer("device-b", 2), writer("device-c", 3)];
    let context = RepairElectionContext::new(
        policy_head,
        obligation_fixture(),
        writers.clone(),
        "device-a".to_string(),
        [1u8; 32],
    )
    .unwrap();
    assert_eq!(
        context.ranked_writers(),
        rank_writers_for_obligation(&policy_head, obligation_fixture(), &writers)
    );
    assert_eq!(context.expected_policy_head(), policy_head);
}

#[test]
fn local_rank_finds_self_among_ranked_writers() {
    let writers = vec![writer("device-b", 2), writer("device-a", 1), writer("device-c", 3)];
    let context = RepairElectionContext::new(
        [0u8; 32],
        obligation_fixture(),
        writers,
        "device-a".to_string(),
        [1u8; 32],
    )
    .unwrap();
    assert_eq!(context.ranked_writers()[context.local_rank().unwrap()].device_id, "device-a");
}

#[test]
fn local_rank_is_none_when_not_an_authorized_writer() {
    let context = RepairElectionContext::new(
        [0u8; 32],
        obligation_fixture(),
        vec![writer("device-a", 1)],
        "device-z".to_string(),
        [1u8; 32],
    )
    .unwrap();
    assert_eq!(context.local_rank(), None);
}

/// The liveness gap this whole module exists to close would reopen if a
/// process presenting the right device_id but the WRONG signing key
/// could still see itself as rank 0 and keep re-attempting a repair it
/// isn't actually authorized for.
#[test]
fn local_rank_is_none_when_device_id_matches_but_fingerprint_differs() {
    let context = RepairElectionContext::new(
        [0u8; 32],
        obligation_fixture(),
        vec![writer("device-a", 1)],
        "device-a".to_string(),
        [0xFFu8; 32],
    )
    .unwrap();
    assert_eq!(context.local_rank(), None);
}
