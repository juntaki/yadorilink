//! Admission-order-invariance fuzz for the change-DAG store — no network,
//! no madsim, no filesystem watchers: the smallest possible configuration
//! in which the order-dependence class of bug can exist at all.
//!
//! Three "authors" (each its own `SyncState`) interleave honest local
//! emissions (via `append_history_backfill`, which parents on the author's
//! current heads and derives any required conflict-copy ops exactly like
//! real authoring) with random pairwise syncs (admitting another author's
//! changes, in shuffled order, so the orphan buffer's out-of-order path is
//! exercised during construction too). The resulting union of signed
//! changes is then admitted into several FRESH states, each in a different
//! random permutation.
//!
//! The invariant: the final DAG state must be a pure function of the SET of
//! changes, never of their delivery order. Concretely, for every
//! permutation: every change admits (no stuck orphans, no provably-missing
//! frontier), the admitted count equals the union size, and the head set is
//! identical to every other permutation's. This is precisely the class the
//! orphan-chain re-request bug and the promotion self-heal bugs lived in —
//! kept as a permanent, cheap (seconds, deterministic per seed) sweep so a
//! regression in admission/promotion order-independence fails a plain
//! `cargo test` instead of waiting for a contended-host chaos run.

use std::collections::HashMap;
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_replica_domain::change::{Change, ChangeAuth, Op};
use yadorilink_replica_domain::file::RecordKind;
use yadorilink_replica_domain::file::{FileMeta, FileVersion};
use yadorilink_replica_domain::ids::SyncPath;
use yadorilink_sync_sqlite::dag_store::ChangeEmitter;

const GROUP_PREFIX: &str = "order-fuzz-group";
const PATHS: [&str; 3] = ["p0.bin", "p1.bin", "sub/p2.bin"];
const SEEDS: u64 = 120;
const OPS_PER_SEED: usize = 14;
const PERMUTATIONS_PER_SEED: usize = 3;

fn author_state() -> ReplicaCoordinator {
    let state = ReplicaCoordinator::open_in_memory().unwrap();
    state.set_local_change_auth_provider(Arc::new(|_| {
        Ok(ChangeAuth { auth_seq: 1, auth_epoch: 1, policy_head_hash: [0; 32] })
    }));
    state
}

fn emitter(idx: usize) -> ChangeEmitter {
    ChangeEmitter::new(format!("device-{idx}"), SigningKey::from_bytes(&[idx as u8 + 1; 32]))
}

/// A unique empty-content version per call — distinct mtime is enough for a
/// distinct version hash, and empty block lists keep admission free of any
/// block-store dependency.
fn fresh_version(counter: &mut i64) -> FileVersion {
    *counter += 1;
    FileVersion::new(
        vec![],
        0,
        FileMeta {
            mtime_unix_nanos: *counter,
            unix_mode: None,
            symlink_target: None,
            record_kind: RecordKind::File,
            xattrs: Vec::new(),
        },
    )
}

/// Admits every change of `from` that `to` lacks, in shuffled order, so the
/// orphan buffer's out-of-order admission path runs during construction too.
fn sync_authors(
    group: &str,
    rng: &mut StdRng,
    to: &ReplicaCoordinator,
    from: &ReplicaCoordinator,
    versions: &VersionTable,
) {
    let mut changes = from.change_history_repository().dag_list_group_changes(group).unwrap();
    for i in (1..changes.len()).rev() {
        changes.swap(i, rng.random_range(0..=i));
    }
    for change in changes {
        let hash = change.compute_hash();
        if to.change_history_repository().dag_has_change_or_buffered_orphan(&hash).unwrap() {
            continue;
        }
        let needed = versions_for(&change, versions);
        to.change_history_repository()
            .dag_admit_change_with_versions(&change, &needed, false)
            .unwrap();
    }
}

type VersionTable = HashMap<[u8; 32], FileVersion>;

fn versions_for(change: &Change, versions: &VersionTable) -> Vec<FileVersion> {
    change
        .ops
        .iter()
        .filter_map(|op| match op {
            Op::Put { version, .. } => Some(versions[&version.0].clone()),
            Op::Move { version, .. } => Some(versions[&version.0].clone()),
            Op::Delete { .. } => None,
        })
        .collect()
}

fn run_seed(
    seed: u64,
    authors: &[ReplicaCoordinator],
    emitters: &[ChangeEmitter],
    fresh_states: &[ReplicaCoordinator],
) {
    let group = format!("{GROUP_PREFIX}-{seed}");
    let mut rng = StdRng::seed_from_u64(seed);
    let mut versions: VersionTable = HashMap::new();
    let mut version_counter: i64 = 0;

    for _ in 0..OPS_PER_SEED {
        let author = rng.random_range(0..authors.len());
        // Occasionally pull another author's history first, so emissions
        // genuinely branch and merge rather than forming three isolated
        // chains.
        if rng.random_bool(0.5) {
            let from = (author + 1 + rng.random_range(0..2)) % 3;
            sync_authors(&group, &mut rng, &authors[author], &authors[from], &versions);
        }
        let path = PATHS[rng.random_range(0..PATHS.len())];
        let op = if rng.random_bool(0.2) {
            Op::Delete { path: SyncPath(path.to_string()) }
        } else {
            let version = fresh_version(&mut version_counter);
            let hash = version.version_hash.0;
            versions.insert(hash, version.clone());
            Op::Put {
                path: SyncPath(path.to_string()),
                version: version.version_hash,
                origin: yadorilink_replica_domain::change::PutOrigin::Direct,
            }
        };
        authors[author]
            .append_history_backfill(
                &group,
                vec![op],
                &versions_for_ops(&versions),
                &emitters[author],
            )
            .unwrap();
    }

    // The union of every change any author produced or holds.
    let mut union: HashMap<[u8; 32], Change> = HashMap::new();
    for state in authors {
        for change in state.change_history_repository().dag_list_group_changes(&group).unwrap() {
            union.insert(change.compute_hash().0, change);
        }
    }
    let mut all_changes: Vec<Change> = union.into_values().collect();
    all_changes.sort_by_key(|c| (c.lamport, c.compute_hash().0));

    let mut reference_heads: Option<Vec<String>> = None;
    for (perm, fresh) in fresh_states.iter().enumerate().take(PERMUTATIONS_PER_SEED) {
        let mut order = all_changes.clone();
        for i in (1..order.len()).rev() {
            order.swap(i, rng.random_range(0..=i));
        }
        for change in &order {
            let needed = versions_for(change, &versions);
            fresh
                .change_history_repository()
                .dag_admit_change_with_versions(change, &needed, false)
                .unwrap();
        }
        let diag = fresh.change_history_repository().dag_group_diagnostics(&group).unwrap();
        assert_eq!(
            diag.orphan_total, 0,
            "seed {seed} perm {perm}: {} change(s) stuck in the orphan buffer after every \
             change in the union was delivered",
            diag.orphan_total
        );
        assert!(
            diag.orphan_missing_frontier.is_empty(),
            "seed {seed} perm {perm}: admission reports a provably-missing frontier \
             {:?} although the full union was delivered",
            diag.orphan_missing_frontier
        );
        assert_eq!(
            diag.admitted_total as usize,
            all_changes.len(),
            "seed {seed} perm {perm}: admitted count diverged from the union size"
        );
        let mut heads: Vec<String> =
            fresh.sqlite().dag_group_heads(&group).unwrap().iter().map(|h| h.to_hex()).collect();
        heads.sort();
        match &reference_heads {
            None => reference_heads = Some(heads),
            Some(reference) => assert_eq!(
                &heads, reference,
                "seed {seed} perm {perm}: final head set depends on delivery order"
            ),
        }
    }
}

/// `append_history_backfill` needs the referenced versions passed alongside
/// the ops; handing it the full table is harmless (only referenced ones are
/// read) and keeps the emission call simple.
fn versions_for_ops(versions: &VersionTable) -> Vec<FileVersion> {
    versions.values().cloned().collect()
}

#[test]
fn admission_order_never_changes_the_final_dag() {
    // Reuse a fixed number of independent databases across seeds. Each
    // seed has a unique group id, so its DAG remains isolated without
    // repeatedly constructing r2d2 maintenance thread pools (which can
    // temporarily exhaust macOS's per-process thread limit before dropped
    // pools finish shutting down).
    let authors: Vec<ReplicaCoordinator> = (0..3).map(|_| author_state()).collect();
    let emitters: Vec<ChangeEmitter> = (0..3).map(emitter).collect();
    let fresh_states: Vec<ReplicaCoordinator> =
        (0..PERMUTATIONS_PER_SEED).map(|_| author_state()).collect();
    for seed in 0..SEEDS {
        run_seed(seed, &authors, &emitters, &fresh_states);
    }
}
