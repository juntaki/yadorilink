//! Seeded property-style coverage for the repair-election contract.
//!
//! The small unit tests in `repair_election.rs` pin individual inputs and one
//! reference vector. This integration matrix exercises the combinations the
//! daemon depends on in production: independently ordered writer snapshots,
//! the rank bijection that failover is derived from, revocation, key rotation,
//! grants, and malformed duplicate snapshots. Every failure reports its seed so
//! the exact case is reproducible with a single filtered test run.
//!
//! Failover *behaviour* itself lives in `retroactive_repair_seed_matrix.rs`.

use std::collections::BTreeSet;

use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use yadorilink_replica_domain::change::ChangeAuth;
use yadorilink_replica_domain::ids::{ChangeHash, FolderGroupId, SyncPath};
use yadorilink_replica_engine::repair_election::{
    rank_writers_for_obligation, AuthorizedWriter, RepairElectionContext, RepairElectionError,
    RepairObligationId,
};

const SEEDS: u64 = 128;
const MAX_WRITERS: usize = 8;
const PERMUTATIONS_PER_SEED: usize = 8;

fn random_bytes(rng: &mut StdRng) -> [u8; 32] {
    let mut out = [0u8; 32];
    for byte in &mut out {
        *byte = rng.random_range(0..=u8::MAX);
    }
    out
}

fn writer_set(rng: &mut StdRng, count: usize) -> Vec<AuthorizedWriter> {
    (0..count)
        .map(|index| {
            let mut fingerprint = random_bytes(rng);
            // Keep fingerprints distinct even in the astronomically unlikely
            // event that two generated arrays happen to match.
            fingerprint[0] ^= index as u8;
            fingerprint[31] = fingerprint[31].wrapping_add(index as u8).wrapping_add(1);
            AuthorizedWriter {
                device_id: format!("device-{index:02}"),
                signing_key_fingerprint: fingerprint,
            }
        })
        .collect()
}

fn shuffle<T>(rng: &mut StdRng, values: &mut [T]) {
    for index in (1..values.len()).rev() {
        values.swap(index, rng.random_range(0..=index));
    }
}

fn obligation(seed: u64, rng: &mut StdRng) -> RepairObligationId {
    RepairObligationId::compute(
        &FolderGroupId(format!("matrix-group-{seed}")),
        &SyncPath(format!("nested/{seed}/shared-{}.bin", rng.random_range(0..16))),
        &ChangeHash(random_bytes(rng)),
    )
}

fn auth(seed: u64, policy_head_hash: [u8; 32]) -> ChangeAuth {
    ChangeAuth { auth_seq: seed + 1, auth_epoch: seed % 7, policy_head_hash }
}

fn context(
    auth: ChangeAuth,
    obligation: RepairObligationId,
    writers: Vec<AuthorizedWriter>,
    local: &AuthorizedWriter,
) -> RepairElectionContext {
    RepairElectionContext::new(
        auth,
        obligation,
        writers,
        local.device_id.clone(),
        local.signing_key_fingerprint,
    )
    .unwrap()
}

#[test]
fn seeded_input_order_and_failover_matrix_is_stable() {
    for seed in 0..SEEDS {
        let mut rng = StdRng::seed_from_u64(seed ^ 0xA11C_E5E1_5EED_0001);
        let writer_count = rng.random_range(1..=MAX_WRITERS);
        let writers = writer_set(&mut rng, writer_count);
        let policy_head = random_bytes(&mut rng);
        let obligation = obligation(seed, &mut rng);
        let auth = auth(seed, policy_head);
        let baseline = rank_writers_for_obligation(&policy_head, obligation, &writers);

        assert_eq!(baseline.len(), writer_count, "seed {seed}");
        assert_eq!(
            baseline.iter().cloned().collect::<BTreeSet<_>>(),
            writers.iter().cloned().collect::<BTreeSet<_>>(),
            "seed {seed}: ranking must be a permutation of the writer snapshot"
        );

        for permutation in 0..PERMUTATIONS_PER_SEED {
            let mut shuffled = writers.clone();
            shuffle(&mut rng, &mut shuffled);
            let ranked = rank_writers_for_obligation(&policy_head, obligation, &shuffled);
            assert_eq!(
                ranked, baseline,
                "seed {seed} permutation {permutation}: replicas with the same signed writer set must not depend on input order"
            );

            for (expected_rank, local) in baseline.iter().enumerate() {
                let local_context = context(auth, obligation, shuffled.clone(), local);
                assert_eq!(
                    local_context.ranked_writers(),
                    baseline.as_slice(),
                    "seed {seed} permutation {permutation}: context ranking drifted"
                );
                assert_eq!(
                    local_context.local_rank(),
                    Some(expected_rank),
                    "seed {seed} permutation {permutation}: {} must observe its canonical rank",
                    local.device_id
                );

                let mut wrong_fingerprint = local.signing_key_fingerprint;
                wrong_fingerprint[0] ^= 0x80;
                let wrong_key_context = RepairElectionContext::new(
                    auth,
                    obligation,
                    shuffled.clone(),
                    local.device_id.clone(),
                    wrong_fingerprint,
                )
                .unwrap();
                assert_eq!(
                    wrong_key_context.local_rank(),
                    None,
                    "seed {seed} permutation {permutation}: a matching device id with the wrong key must never become eligible"
                );
            }
        }

        // The loop above only ever feeds shuffled snapshots into the context.
        // Repeat it once on the snapshot in its original order so the ranking is
        // pinned against the un-permuted input as well, and check that the ranks
        // form a bijection onto 0..writer_count: no two writers may claim the
        // same failover slot, and no slot may be left unclaimed.
        //
        // Actual failover *behaviour* (a rank-1 writer waiting out the primary's
        // stable-frontier window and then repairing) is covered end-to-end by
        // `retroactive_repair_seed_matrix.rs`; this test only pins the ranking
        // contract that failover is derived from.
        let mut claimed = BTreeSet::new();
        for (expected_rank, fallback) in baseline.iter().enumerate() {
            let fallback_context = context(auth, obligation, writers.clone(), fallback);
            assert_eq!(
                fallback_context.local_rank(),
                Some(expected_rank),
                "seed {seed}: writer {} lost its canonical rank when the snapshot was passed in its original order",
                fallback.device_id
            );
            assert!(
                claimed.insert(expected_rank),
                "seed {seed}: rank {expected_rank} was claimed twice"
            );
        }
        assert_eq!(claimed.len(), writer_count, "seed {seed}: ranks are not a bijection");
    }
}

#[test]
fn seeded_membership_churn_and_key_rotation_fail_closed() {
    for seed in 0..SEEDS {
        let mut rng = StdRng::seed_from_u64(seed ^ 0xC0DE_CAFE_5EED_0002);
        let writer_count = rng.random_range(2..=MAX_WRITERS);
        let writers = writer_set(&mut rng, writer_count);
        let obligation = obligation(seed, &mut rng);
        let victim_index = rng.random_range(0..writer_count);
        let victim = writers[victim_index].clone();

        let old_auth = auth(seed, random_bytes(&mut rng));
        let old_ranking =
            rank_writers_for_obligation(&old_auth.policy_head_hash, obligation, &writers);
        assert!(old_ranking.contains(&victim), "seed {seed}");

        // Revoke: the old device/key identity must disappear completely.
        let mut revoked = writers.clone();
        revoked.retain(|writer| writer.device_id != victim.device_id);
        let revoked_auth = auth(seed + SEEDS, random_bytes(&mut rng));
        let revoked_ranking =
            rank_writers_for_obligation(&revoked_auth.policy_head_hash, obligation, &revoked);
        assert!(!revoked_ranking.contains(&victim), "seed {seed}: revoked writer survived");
        let revoked_context = RepairElectionContext::new(
            revoked_auth,
            obligation,
            revoked.clone(),
            victim.device_id.clone(),
            victim.signing_key_fingerprint,
        )
        .unwrap();
        assert_eq!(
            revoked_context.local_rank(),
            None,
            "seed {seed}: a revoked writer must not obtain a failover rank"
        );

        // Key rotation represented by a later Grant for the same device id:
        // old key loses eligibility and the newly bound key gains one rank.
        let mut rotated = writers.clone();
        let mut new_fingerprint = random_bytes(&mut rng);
        if new_fingerprint == victim.signing_key_fingerprint {
            new_fingerprint[0] ^= 1;
        }
        rotated[victim_index].signing_key_fingerprint = new_fingerprint;
        let rotated_auth = auth(seed + 2 * SEEDS, random_bytes(&mut rng));
        let old_key_context = RepairElectionContext::new(
            rotated_auth,
            obligation,
            rotated.clone(),
            victim.device_id.clone(),
            victim.signing_key_fingerprint,
        )
        .unwrap();
        assert_eq!(
            old_key_context.local_rank(),
            None,
            "seed {seed}: rotated-out key remained eligible"
        );

        let new_identity = rotated[victim_index].clone();
        assert!(
            context(rotated_auth, obligation, rotated.clone(), &new_identity)
                .local_rank()
                .is_some(),
            "seed {seed}: newly bound key did not receive a rank"
        );

        // Grant: a new writer appears exactly once and independently ordered
        // snapshots still converge on one ranking.
        let mut granted = rotated;
        let mut newcomer_fingerprint = random_bytes(&mut rng);
        newcomer_fingerprint[0] ^= 0x5A;
        let newcomer = AuthorizedWriter {
            device_id: format!("new-device-{seed}"),
            signing_key_fingerprint: newcomer_fingerprint,
        };
        granted.push(newcomer.clone());
        let granted_auth = auth(seed + 3 * SEEDS, random_bytes(&mut rng));
        let expected =
            rank_writers_for_obligation(&granted_auth.policy_head_hash, obligation, &granted);
        assert_eq!(expected.iter().filter(|writer| **writer == newcomer).count(), 1, "seed {seed}");
        for permutation in 0..PERMUTATIONS_PER_SEED {
            let mut shuffled = granted.clone();
            shuffle(&mut rng, &mut shuffled);
            assert_eq!(
                rank_writers_for_obligation(
                    &granted_auth.policy_head_hash,
                    obligation,
                    &shuffled,
                ),
                expected,
                "seed {seed} permutation {permutation}: membership churn exposed input-order dependence"
            );
        }
    }
}

#[test]
fn duplicate_writer_matrix_is_rejected_at_every_position() {
    for seed in 0..64u64 {
        let mut rng = StdRng::seed_from_u64(seed ^ 0xD00D_1E55_5EED_0003);
        let writer_count = rng.random_range(1..=MAX_WRITERS);
        let writers = writer_set(&mut rng, writer_count);
        let duplicate_source = writers[rng.random_range(0..writer_count)].clone();
        let auth = auth(seed, random_bytes(&mut rng));
        let obligation = obligation(seed, &mut rng);

        for insertion_index in 0..=writers.len() {
            let mut malformed = writers.clone();
            let mut duplicate = duplicate_source.clone();
            // Cover both exact duplicate rows and the more dangerous shape in
            // which one device id is paired with two different keys.
            if insertion_index % 2 == 1 {
                duplicate.signing_key_fingerprint[0] ^= 0xFF;
            }
            malformed.insert(insertion_index, duplicate);

            let error = RepairElectionContext::new(
                auth,
                obligation,
                malformed,
                duplicate_source.device_id.clone(),
                duplicate_source.signing_key_fingerprint,
            )
            .unwrap_err();
            assert_eq!(
                error,
                RepairElectionError::DuplicateWriter {
                    device_id: duplicate_source.device_id.clone(),
                },
                "seed {seed} insertion {insertion_index}"
            );
        }
    }
}

#[test]
fn seeded_obligation_distribution_does_not_collapse_to_one_primary() {
    let writers = (0..5)
        .map(|index| AuthorizedWriter {
            device_id: format!("distribution-device-{index}"),
            signing_key_fingerprint: [index as u8 + 1; 32],
        })
        .collect::<Vec<_>>();
    let policy_head = [0xA5; 32];
    let mut primary_counts = vec![0usize; writers.len()];

    for seed in 0..512u64 {
        let mut rng = StdRng::seed_from_u64(seed ^ 0xFA17_0E12_5EED_0004);
        let obligation = obligation(seed, &mut rng);
        let ranking = rank_writers_for_obligation(&policy_head, obligation, &writers);
        let primary_index = writers
            .iter()
            .position(|writer| writer == &ranking[0])
            .expect("ranked primary must come from the writer set");
        primary_counts[primary_index] += 1;
    }

    assert!(
        primary_counts.iter().all(|count| *count > 0),
        "obligation hashing collapsed primary selection: {primary_counts:?}"
    );
}
