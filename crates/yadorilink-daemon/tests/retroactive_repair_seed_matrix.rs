//! Seeded delivery-order and failover matrix for retroactive conflict repair.
//!
//! Each seed builds the same logical fork on independent author states, then
//! admits the resulting signed change SET into fresh replicas in several
//! permutations. Rank 0 is deliberately unavailable; rank 1 must first wait,
//! then publish one byte-identical repair carrier once its failover window is
//! eligible. This combines the orphan-buffer/order path, deterministic winner
//! resolution, election, signed repair obligations, and idempotent re-planning
//! without networking or wall-clock timing.

use std::collections::HashMap;
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_replica_domain::change::{Change, ChangeAuth, ChangePurpose, Op, PutOrigin};
use yadorilink_replica_domain::file::RecordKind;
use yadorilink_replica_domain::file::{FileMeta, FileVersion};
use yadorilink_replica_domain::ids::{ChangeHash, SyncPath, VersionHash};
use yadorilink_replica_domain::session_state::RetroactiveRepairOutcome;
use yadorilink_replica_engine::repair_election::{AuthorizedWriter, RepairElectionContext};
use yadorilink_sync_sqlite::dag_store::ChangeEmitter;

const GROUP: &str = "retroactive-seed-matrix";
const SEEDS: u64 = 32;
const PERMUTATIONS_PER_SEED: usize = 8;

const PATH_SHAPES: [&str; 4] =
    ["shared.bin", "nested/shared.bin", "space dir/shared file.bin", "deep/a/b/c/shared.bin"];

type VersionTable = HashMap<[u8; 32], FileVersion>;

fn key(byte: u8) -> SigningKey {
    SigningKey::from_bytes(&[byte; 32])
}

fn state() -> ReplicaCoordinator {
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    state.set_local_change_auth_provider(Arc::new(|_| Ok(ChangeAuth::PLACEHOLDER)));
    state
}

fn version(mtime: i64) -> FileVersion {
    FileVersion::new(
        vec![],
        0,
        FileMeta {
            mtime_unix_nanos: mtime,
            unix_mode: None,
            symlink_target: None,
            record_kind: RecordKind::File,
            xattrs: Vec::new(),
        },
    )
}

fn remember(versions: &mut VersionTable, value: &FileVersion) {
    versions.insert(value.version_hash.0, value.clone());
}

fn versions_for(change: &Change, versions: &VersionTable) -> Vec<FileVersion> {
    change
        .ops
        .iter()
        .filter_map(|op| match op {
            Op::Put { version, .. } | Op::Move { version, .. } => {
                Some(versions[&version.0].clone())
            }
            Op::Delete { .. } => None,
        })
        .collect()
}

fn emit_put(
    state: &ReplicaCoordinator,
    emitter: &ChangeEmitter,
    path: &str,
    value: &FileVersion,
) -> Change {
    state
        .append_history_backfill(
            GROUP,
            vec![Op::Put {
                path: SyncPath(path.to_string()),
                version: value.version_hash,
                origin: PutOrigin::Direct,
            }],
            std::slice::from_ref(value),
            emitter,
        )
        .unwrap();
    let heads = state.sqlite().dag_group_heads(GROUP).unwrap();
    assert_eq!(heads.len(), 1, "linear author fixture must retain one head");
    state.sqlite().dag_get_change(&heads[0]).unwrap().unwrap()
}

fn admit(state: &ReplicaCoordinator, change: &Change, versions: &VersionTable) {
    let needed = versions_for(change, versions);
    state
        .change_history_repository()
        .dag_admit_change_with_versions(change, &needed, false)
        .unwrap();
}

fn shuffle<T>(rng: &mut StdRng, values: &mut [T]) {
    for index in (1..values.len()).rev() {
        values.swap(index, rng.random_range(0..=index));
    }
}

struct Scenario {
    path: String,
    changes: Vec<Change>,
    versions: VersionTable,
    winner_version: VersionHash,
    loser_version: VersionHash,
    loser_change: ChangeHash,
}

fn build_scenario(seed: u64) -> Scenario {
    let path = format!("{}-{seed}", PATH_SHAPES[(seed as usize) % PATH_SHAPES.len()]);
    let mut versions = VersionTable::new();
    let base = (seed as i64) * 10;
    let root_version = version(base + 1);
    let first_winner_version = version(base + 2);
    let loser_version = version(base + 3);
    let final_winner_version = version(base + 4);
    for value in [&root_version, &first_winner_version, &loser_version, &final_winner_version] {
        remember(&mut versions, value);
    }

    let root_author = state();
    let root_emitter = ChangeEmitter::new("root-author", key(10));
    let root = emit_put(&root_author, &root_emitter, &path, &root_version);

    let winner_author = state();
    admit(&winner_author, &root, &versions);
    let first_winner_emitter = ChangeEmitter::new("winner-a", key(20));
    let first_winner =
        emit_put(&winner_author, &first_winner_emitter, &path, &first_winner_version);
    let final_winner_emitter = ChangeEmitter::new("winner-descendant", key(30));
    let final_winner =
        emit_put(&winner_author, &final_winner_emitter, &path, &final_winner_version);

    // The late loser knows only the root, so its edit is genuinely concurrent
    // with the winner branch and cannot have been carried by the already-signed
    // winner descendant.
    let loser_author = state();
    admit(&loser_author, &root, &versions);
    let loser_emitter = ChangeEmitter::new("late-loser", key(40));
    let loser = emit_put(&loser_author, &loser_emitter, &path, &loser_version);

    Scenario {
        path,
        changes: vec![root, first_winner, final_winner, loser.clone()],
        versions,
        winner_version: final_winner_version.version_hash,
        loser_version: loser_version.version_hash,
        loser_change: loser.compute_hash(),
    }
}

fn install_rank_one_repairer(state: &ReplicaCoordinator, emitter: &ChangeEmitter) {
    let local_fingerprint = emitter.signing_key_fingerprint();
    state.set_repair_election_provider(Arc::new(move |_group, obligation| {
        // Search a deterministic offline-primary fingerprint that places the
        // local repairer at rank 1 for this exact obligation. This avoids
        // pinning a fragile hash reference vector while guaranteeing that the
        // failover branch is exercised for every seed.
        for byte in 1..=u8::MAX {
            let context = RepairElectionContext::new(
                ChangeAuth::PLACEHOLDER,
                obligation,
                vec![
                    AuthorizedWriter {
                        device_id: "offline-primary".to_string(),
                        signing_key_fingerprint: [byte; 32],
                    },
                    AuthorizedWriter {
                        device_id: "repairer".to_string(),
                        signing_key_fingerprint: local_fingerprint,
                    },
                ],
                "repairer".to_string(),
                local_fingerprint,
            )
            .unwrap();
            if context.local_rank() == Some(1) {
                return Ok(context);
            }
        }
        panic!("could not construct a rank-one repair fixture");
    }));
}

#[test]
fn seeded_delivery_order_and_rank_failover_converge_on_one_carrier() {
    for seed in 0..SEEDS {
        let scenario = build_scenario(seed);
        let mut rng = StdRng::seed_from_u64(seed ^ 0x7E70_AC71_5EED_0001);
        let mut reference_carrier: Option<ChangeHash> = None;

        for permutation in 0..PERMUTATIONS_PER_SEED {
            let replica = state();
            let mut delivery = scenario.changes.clone();
            if permutation > 0 {
                shuffle(&mut rng, &mut delivery);
            }
            for change in &delivery {
                admit(&replica, change, &scenario.versions);
            }

            let diagnostics =
                replica.change_history_repository().dag_group_diagnostics(GROUP).unwrap();
            assert_eq!(
                diagnostics.orphan_total, 0,
                "seed {seed} permutation {permutation}: full change set left buffered orphans"
            );
            assert_eq!(
                diagnostics.admitted_total as usize,
                scenario.changes.len(),
                "seed {seed} permutation {permutation}: not every change admitted"
            );

            let repairer = ChangeEmitter::new("repairer", key(99));
            install_rank_one_repairer(&replica, &repairer);
            let before = replica.sqlite().dag_group_heads(GROUP).unwrap();

            let waiting =
                replica.repair_retroactive_conflict_copy_obligations(GROUP, &repairer, 0).unwrap();
            assert!(
                matches!(
                    waiting,
                    RetroactiveRepairOutcome::AwaitingFailover { local_rank: Some(1), .. }
                ),
                "seed {seed} permutation {permutation}: rank-one writer did not wait for failover"
            );
            assert_eq!(
                replica.sqlite().dag_group_heads(GROUP).unwrap(),
                before,
                "seed {seed} permutation {permutation}: ineligible writer mutated the DAG"
            );

            let repaired =
                replica.repair_retroactive_conflict_copy_obligations(GROUP, &repairer, 1).unwrap();
            assert!(
                matches!(
                    repaired,
                    RetroactiveRepairOutcome::Repaired { ref repaired_paths, .. }
                        if repaired_paths == &vec![scenario.path.clone()]
                ),
                "seed {seed} permutation {permutation}: eligible fallback did not repair the path"
            );

            let heads = replica.sqlite().dag_group_heads(GROUP).unwrap();
            assert_eq!(heads.len(), 1, "seed {seed} permutation {permutation}");
            let carrier = replica.sqlite().dag_get_change(&heads[0]).unwrap().unwrap();
            assert_eq!(carrier.device_id.as_str(), "repairer");
            let ChangePurpose::RetroactiveRepair { obligations } = &carrier.purpose else {
                panic!("seed {seed} permutation {permutation}: head is not a repair carrier");
            };
            assert_eq!(obligations.len(), 1, "seed {seed} permutation {permutation}");
            assert_eq!(obligations[0].source_path.as_str(), scenario.path);
            assert_eq!(obligations[0].losing_change, scenario.loser_change);

            let mut saw_winner_reassertion = false;
            let mut saw_loser_copy = false;
            for op in &carrier.ops {
                match op {
                    Op::Put { path, version, origin: PutOrigin::Direct }
                        if path.as_str() == scenario.path
                            && *version == scenario.winner_version =>
                    {
                        saw_winner_reassertion = true;
                    }
                    Op::Put {
                        version,
                        origin: PutOrigin::ConflictCopy { source_path, losing_change },
                        ..
                    } if source_path.as_str() == scenario.path
                        && *losing_change == scenario.loser_change
                        && *version == scenario.loser_version =>
                    {
                        saw_loser_copy = true;
                    }
                    _ => {}
                }
            }
            assert!(
                saw_winner_reassertion,
                "seed {seed} permutation {permutation}: carrier did not reassert the deterministic winner"
            );
            assert!(
                saw_loser_copy,
                "seed {seed} permutation {permutation}: carrier did not preserve the late loser"
            );

            let carrier_hash = carrier.compute_hash();
            match reference_carrier {
                None => reference_carrier = Some(carrier_hash),
                Some(reference) => assert_eq!(
                    carrier_hash, reference,
                    "seed {seed} permutation {permutation}: repair carrier depends on delivery order"
                ),
            }

            let no_op =
                replica.repair_retroactive_conflict_copy_obligations(GROUP, &repairer, 1).unwrap();
            assert!(
                matches!(no_op, RetroactiveRepairOutcome::NothingToDo { .. }),
                "seed {seed} permutation {permutation}: repaired frontier authored again"
            );
            assert_eq!(replica.sqlite().dag_group_heads(GROUP).unwrap(), vec![carrier_hash]);
        }
    }
}
