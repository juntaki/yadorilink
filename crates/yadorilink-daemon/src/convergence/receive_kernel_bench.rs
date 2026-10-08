#![cfg(test)]

//! Kernel benchmarks for the receive path's two serial costs, with no
//! network and no block fetch. All `#[ignore]`: they measure whatever disk
//! runs them and assert only that the kernel did what it claims to measure.
//!
//! - **Finalization** (`kernel_finalization_batch_size`): the receive path's
//!   two per-file SQLite transactions, run through the same statement helpers
//!   the lane uses against a file-backed database (WAL, `synchronous = FULL`),
//!   one file per transaction versus 8, 32, 128 and 512 files per
//!   transaction. The batched shape exists only here; no production path
//!   batches.
//! - **Durability** (`kernel_durability_coalescing`): `fsync(file) -> rename
//!   -> fsync(parent)` per file versus all file fsyncs, then all renames,
//!   then one fsync per distinct parent, over 1, 10, 100 and 1000 directories.
//! - **Planning scale** (`kernel_planning_by_population`): the same 500
//!   paths planned, claimed and finalized while the database holds 1k, 10k
//!   and 100k rows, to expose queries that grow with the population.
//!
//! Run, for example:
//! `cargo test -p yadorilink-daemon --lib receive_kernel_bench -- --ignored --nocapture --test-threads=1`

use std::time::{Duration, Instant};

use yadorilink_replica_domain::file::{FileMeta, FileVersion, RecordKind};
use yadorilink_sync_sqlite::exact_materialized_commit::{
    commit_internal_materialized_state_closing_obligation, ExactMaterializedState,
    ExpectedAuthoring, InternalMaterializedCommit,
};
use yadorilink_sync_sqlite::projection_obligations::ClaimedObligation;

use super::receive_cost_tests::{fixture, Fixture, GROUP};
use crate::local_convergence::types::file_record_from_version;
use crate::test_support::remote_admission_fixture::{admit_remote, put};

fn now_nanos() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

/// An empty file's version, distinct per `seed` through its mtime. Content is
/// irrelevant to the database kernels; blocks would only add store writes.
fn version_for(seed: i64) -> FileVersion {
    FileVersion::new(
        Vec::new(),
        0,
        FileMeta {
            mtime_unix_nanos: seed + 1,
            unix_mode: None,
            symlink_target: None,
            record_kind: RecordKind::File,
            xattrs: Vec::new(),
        },
    )
}

/// Admits one put per name, a thousand to a delta, as a peer's delivery would.
fn admit_paths(f: &Fixture, names: &[String], first_seed: i64) -> Vec<(String, FileVersion)> {
    let mut admitted = Vec::with_capacity(names.len());
    for (chunk_index, chunk) in names.chunks(1000).enumerate() {
        let versions: Vec<FileVersion> = chunk
            .iter()
            .enumerate()
            .map(|(i, _)| version_for(first_seed + (chunk_index * 1000 + i) as i64))
            .collect();
        let ops = chunk
            .iter()
            .zip(&versions)
            .map(|(name, version)| put(name, version.version_hash, vec![]))
            .collect();
        admit_remote(&f.state.replica_coordinator, GROUP, "device-peer", ops, &versions);
        admitted.extend(chunk.iter().cloned().zip(versions));
    }
    admitted
}

/// The obligation claim the engine would hold for each of `paths`.
fn claims_for(
    f: &Fixture,
    paths: &[String],
) -> std::collections::HashMap<String, ClaimedObligation> {
    let wanted: std::collections::HashSet<&String> = paths.iter().collect();
    f.state
        .replica_coordinator
        .sqlite()
        .dag_claim_runnable_obligations(now_nanos(), u32::MAX, u32::MAX)
        .expect("claim")
        .into_iter()
        .filter(|c| wanted.contains(&c.path))
        .map(|c| (c.path.clone(), c))
        .collect()
}

/// The statements of `open_content_write`, for one path, inside `tx`.
fn open_in_tx(
    tx: &rusqlite::Transaction<'_>,
    path: &str,
    version: &FileVersion,
    now: i64,
) -> Result<i64, yadorilink_sync_sqlite::SyncSqliteError> {
    let record = file_record_from_version(path, version);
    let target = yadorilink_local_storage::intent_target_hash(&record.blocks);
    yadorilink_sync_sqlite::MaterializationIntentRepository::begin_materialization_intent_in_tx(
        tx, GROUP, path, &target, now,
    )?;
    yadorilink_sync_sqlite::file_index::FileIndexRepository::upsert_file_with_origin_and_authoring_in_tx(
        tx,
        GROUP,
        &record,
        "device-peer",
        None,
    )?;
    yadorilink_sync_sqlite::MaterializationStateRepository::set_materialization_state_in_tx(
        tx,
        GROUP,
        path,
        yadorilink_peer_session::ports::MATERIALIZATION_IN_FLIGHT_STATE,
    )?;
    yadorilink_sync_sqlite::MaterializationStateRepository::clear_held_in_tx(tx, GROUP, path)?;
    yadorilink_sync_sqlite::materialized_generation::bump_mutation_fence(
        tx,
        GROUP,
        path,
        "eager_content_write",
        now,
    )
}

/// The statements of `close_content_write` for a claimed path, inside `tx`.
/// Returns whether the proof published and the obligation closed.
fn close_in_tx(
    tx: &rusqlite::Transaction<'_>,
    path: &str,
    version: &FileVersion,
    generation: i64,
    claim: &ClaimedObligation,
    now: i64,
) -> Result<(bool, bool), yadorilink_sync_sqlite::SyncSqliteError> {
    let (commit, closed) = commit_internal_materialized_state_closing_obligation(
        tx,
        GROUP,
        path,
        &ExactMaterializedState::Object {
            kind: RecordKind::File,
            version: version.version_hash,
            identity: Box::new(None),
        },
        generation,
        Some(ExpectedAuthoring {
            state: yadorilink_peer_session::ports::MATERIALIZATION_IN_FLIGHT_STATE,
            expected_version: Some(&version.version_hash),
        }),
        claim.token(),
        now,
    )?;
    Ok((matches!(commit, InternalMaterializedCommit::Published(_)), closed))
}

struct Finalized {
    open: Duration,
    close: Duration,
    published: usize,
    closed: usize,
}

/// Runs open then close for every file, `batch` files per transaction.
fn finalize(
    f: &Fixture,
    files: &[(String, FileVersion)],
    claims: &std::collections::HashMap<String, ClaimedObligation>,
    batch: usize,
) -> Finalized {
    let database = f.state.replica_coordinator.database();
    let mut generations = Vec::with_capacity(files.len());
    let started = Instant::now();
    for chunk in files.chunks(batch) {
        let now = now_nanos();
        let chunk_generations: Vec<i64> = database
            .write_immediate::<_, yadorilink_sync_sqlite::SyncSqliteError>(|tx| {
                chunk
                    .iter()
                    .map(|(path, version)| open_in_tx(tx, path, version, now))
                    .collect::<Result<Vec<_>, _>>()
            })
            .expect("open transaction");
        generations.extend(chunk_generations);
    }
    let open = started.elapsed();

    let (mut published, mut closed) = (0, 0);
    let started = Instant::now();
    for (chunk, gens) in files.chunks(batch).zip(generations.chunks(batch)) {
        let now = now_nanos();
        let outcomes = database
            .write_immediate::<_, yadorilink_sync_sqlite::SyncSqliteError>(|tx| {
                chunk
                    .iter()
                    .zip(gens)
                    .map(|((path, version), generation)| {
                        close_in_tx(tx, path, version, *generation, &claims[path], now)
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .expect("close transaction");
        for (p, c) in outcomes {
            published += usize::from(p);
            closed += usize::from(c);
        }
    }
    let close = started.elapsed();
    Finalized { open, close, published, closed }
}

fn per_file_ms(d: Duration, files: usize) -> f64 {
    d.as_secs_f64() * 1000.0 / files as f64
}

fn paths(prefix: &str, n: usize) -> Vec<String> {
    (0..n).map(|i| format!("{prefix}/f{i:06}.bin")).collect()
}

/// K1: per-file finalization at batch 1 versus batched in one transaction.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "measurement; run explicitly"]
async fn kernel_finalization_batch_size() {
    const FILES: usize = 1000;
    for batch in [1usize, 8, 32, 128, 512] {
        // A fresh database per batch size, so every shape starts from the
        // same state: FILES admitted paths, each with a claimable obligation.
        let f = fixture(true).await;
        let names = paths("k1", FILES);
        let files = admit_paths(&f, &names, 0);
        let claims = claims_for(&f, &names);
        assert_eq!(claims.len(), FILES, "every admitted path has a claimable obligation");
        let r = finalize(&f, &files, &claims, batch);
        assert_eq!(r.published, FILES, "every proof published");
        assert_eq!(r.closed, FILES, "every obligation closed in its proof's transaction");
        println!(
            "K1 batch={batch:>3}: open {:.3} ms/file, close {:.3} ms/file, total {:.3} ms/file",
            per_file_ms(r.open, FILES),
            per_file_ms(r.close, FILES),
            per_file_ms(r.open + r.close, FILES),
        );
    }
}

/// K2: durability syscalls per file versus coalesced, by directory spread.
#[test]
#[ignore = "measurement; run explicitly"]
fn kernel_durability_coalescing() {
    use std::io::Write as _;
    const FILES: usize = 1000;
    for dirs in [1usize, 10, 100, 1000] {
        let mut results = Vec::new();
        for coalesced in [false, true] {
            let root = tempfile::tempdir().expect("tempdir");
            let dir_paths: Vec<_> = (0..dirs)
                .map(|d| {
                    let p = root.path().join(format!("d{d:04}"));
                    std::fs::create_dir(&p).unwrap();
                    p
                })
                .collect();
            // Pre-created, written and closed, not yet synced.
            let temps: Vec<(std::fs::File, std::path::PathBuf, std::path::PathBuf)> = (0..FILES)
                .map(|i| {
                    let dir = &dir_paths[i % dirs];
                    let tmp = dir.join(format!(".tmp-{i}"));
                    let mut file = std::fs::File::create(&tmp).unwrap();
                    file.write_all(&[i as u8; 4096]).unwrap();
                    (file, tmp, dir.join(format!("final-{i}")))
                })
                .collect();
            let started = Instant::now();
            if coalesced {
                for (file, _, _) in &temps {
                    file.sync_all().unwrap();
                }
                for (_, tmp, dst) in &temps {
                    std::fs::rename(tmp, dst).unwrap();
                }
                for dir in &dir_paths {
                    std::fs::File::open(dir).unwrap().sync_all().unwrap();
                }
            } else {
                for (file, tmp, dst) in &temps {
                    file.sync_all().unwrap();
                    std::fs::rename(tmp, dst).unwrap();
                    std::fs::File::open(dst.parent().unwrap()).unwrap().sync_all().unwrap();
                }
            }
            results.push(started.elapsed());
        }
        println!(
            "K2 dirs={dirs:>4}: per-file {:.3} ms/file, coalesced {:.3} ms/file ({:.2}x)",
            per_file_ms(results[0], FILES),
            per_file_ms(results[1], FILES),
            results[0].as_secs_f64() / results[1].as_secs_f64(),
        );
    }
}

/// K3: the same 500 paths, planned and finalized against growing databases.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "measurement; run explicitly"]
async fn kernel_planning_by_population() {
    const MEASURED: usize = 500;
    for population in [1_000usize, 10_000, 100_000] {
        let f = fixture(true).await;
        let measured = paths("k3", MEASURED);
        let filler = paths("pop", population - MEASURED);
        let files = admit_paths(&f, &measured, 0);
        admit_paths(&f, &filler, MEASURED as i64);

        // Claim: the engine's read of what to do. Time the call that returns
        // the measured paths' claims among the whole runnable population.
        let started = Instant::now();
        let claims = claims_for(&f, &measured);
        let claim_ms = started.elapsed().as_secs_f64() * 1000.0;
        assert_eq!(claims.len(), MEASURED);

        // The zero-work pre-check, per path, as the engine runs it.
        let executor = f.state.local_convergence();
        let started = Instant::now();
        for path in &measured {
            let _ = executor.zero_work_settlement_for_path(GROUP, path).expect("pre-check");
        }
        let precheck = started.elapsed();

        // The engine's real claim: one call, 128 per group (256 total).
        let started = Instant::now();
        let tick = f
            .state
            .replica_coordinator
            .sqlite()
            .dag_claim_runnable_obligations(now_nanos(), 128, 256)
            .expect("claim");
        let tick_claim_ms = started.elapsed().as_secs_f64() * 1000.0;
        assert!(!tick.is_empty());

        // The claim by window at this population: it should follow the
        // window, not the table.
        let mut by_window = String::new();
        for window in [1u32, 8, 32, 128] {
            let started = Instant::now();
            let got = f
                .state
                .replica_coordinator
                .sqlite()
                .dag_claim_runnable_obligations(now_nanos(), window, window)
                .expect("claim");
            assert_eq!(got.len(), window as usize);
            by_window.push_str(&format!(
                " w{window}={:.3} ms",
                started.elapsed().as_secs_f64() * 1000.0
            ));
        }

        // The conflict-copy retirement pass, woken per completion: with no
        // copies to retire it is the group read alone.
        let started = Instant::now();
        let retired = executor
            .retire_unjustified_ephemeral_conflict_copies(GROUP, 0)
            .await
            .map(|(attempt, _)| format!("{attempt:?}"))
            .unwrap_or_else(|e| format!("err {e}"));
        let retire_ms = started.elapsed().as_secs_f64() * 1000.0;

        // Native planning for the window's paths, eight at a time, as the
        // per-path loop plans them.
        let windows: Vec<std::collections::BTreeSet<String>> =
            measured.chunks(8).map(|c| c.iter().cloned().collect()).collect();
        let started = Instant::now();
        for window in &windows {
            f.state
                .replica_coordinator
                .native_plan_for_names(GROUP, "k3", window)
                .expect("a planned level");
        }
        let plan = started.elapsed();

        let r = finalize(&f, &files, &claims, 1);
        assert_eq!((r.published, r.closed), (MEASURED, MEASURED));
        println!(
            "K3 rows={population:>6}: claim(128/256 as the engine) {tick_claim_ms:.1} ms, claim(unbounded) {claim_ms:.1} ms, claim by window{by_window}, retire pass {retire_ms:.1} ms ({retired}), pre-check {:.3} ms/path, \
             plan {:.3} ms/path (windows of 8), finalize batch=1 {:.3} ms/file (open {:.3}, close {:.3})",
            per_file_ms(precheck, MEASURED),
            per_file_ms(plan, MEASURED),
            per_file_ms(r.open + r.close, MEASURED),
            per_file_ms(r.open, MEASURED),
            per_file_ms(r.close, MEASURED),
        );
    }
}

/// K4: the receive path's per-file name-hazard check on a volume that folds
/// case and normalization, against one database grown through 1k, 10k, 100k
/// and 1M rows. One path is checked repeatedly, as a hit (a case variant of
/// an indexed name) and as a miss.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "measurement; run explicitly"]
async fn kernel_hazard_by_population() {
    use crate::local_convergence::types::{hazard_reason_for_volume, VolumeFolding};
    const CALLS: usize = 200;
    let volume = VolumeFolding { case_insensitive: true, normalization_insensitive: true };
    let f = fixture(true).await;
    let realistic = |i: usize| format!("dir{:03}/sub{:03}/file{i:07}.txt", i % 997, i % 89);
    let mut have = 0usize;
    let mut seed = 0i64;
    // A few deliberate collisions: a case variant and a decomposed variant.
    let known = vec!["Docs/Report.TXT".to_string(), "Docs/caf\u{e9}.txt".to_string()];
    let populate = |names: &[String], first_seed: i64| {
        for chunk in names.chunks(5000) {
            let records: Vec<_> = chunk
                .iter()
                .enumerate()
                .map(|(i, n)| file_record_from_version(n, &version_for(first_seed + i as i64)))
                .collect();
            f.state
                .replica_coordinator
                .file_index_repository()
                .upsert_files_batch(
                    GROUP,
                    &records,
                    "device-peer",
                    &[],
                    &[],
                    &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
                )
                .expect("populate files rows");
        }
    };
    populate(&known, 0);
    seed += 2;
    for target in [1_000usize, 10_000, 100_000, 1_000_000] {
        let names: Vec<String> = (have..target).map(realistic).collect();
        populate(&names, seed);
        seed += names.len() as i64;
        have = target;
        let probes: [(&str, String); 3] = [
            ("hit-case", "docs/report.txt".to_string()),
            ("hit-nfd", "Docs/cafe\u{301}.txt".to_string()),
            ("miss", "Docs/absent-name.txt".to_string()),
        ];
        for (label, path) in probes {
            let record = file_record_from_version(&path, &version_for(0));
            let started = Instant::now();
            let mut last = None;
            for _ in 0..CALLS {
                last =
                    hazard_reason_for_volume(&f.state.replica_coordinator, GROUP, &record, volume)
                        .expect("hazard check");
            }
            let per_call = started.elapsed().as_secs_f64() * 1e6 / CALLS as f64;
            assert_eq!(last.is_some(), label != "miss", "{label} decision");
            println!("K4 rows={target:>8} {label:<8}: {per_call:>10.1} us/call");
        }
    }
}

/// K5: one conflict-copy retirement pass against a group whose `files` and
/// native-heads tables both hold the whole population. The pass is woken per
/// completed obligation, and it first reads every row of the group, so the
/// per-pass cost is what decides the receive's share. 1% of the rows are
/// conflict-copy-shaped and carried by a change (justified by history); the
/// last measurement adds a few that no change carries.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "measurement; run explicitly"]
async fn kernel_retirement_pass_by_population() {
    for population in [1_000usize, 10_000, 100_000] {
        let f = fixture(true).await;
        let copies = population / 100;
        let ordinary: Vec<String> = paths("pop", population - copies);
        let carried: Vec<String> = (0..copies)
            .map(|i| format!("pop/c{i:06} (conflicted copy, 2026-01-01, device-peer, ab12).bin"))
            .collect();
        let mut all = ordinary.clone();
        all.extend(carried.iter().cloned());
        admit_paths(&f, &all, 0);
        let populate = |names: &[String], first_seed: i64| {
            for chunk in names.chunks(5000) {
                let records: Vec<_> = chunk
                    .iter()
                    .enumerate()
                    .map(|(i, n)| file_record_from_version(n, &version_for(first_seed + i as i64)))
                    .collect();
                f.state
                    .replica_coordinator
                    .file_index_repository()
                    .upsert_files_batch(
                        GROUP,
                        &records,
                        "device-peer",
                        &[],
                        &[],
                        &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
                    )
                    .expect("populate files rows");
            }
        };
        populate(&all, 0);

        let executor = f.state.local_convergence();
        let state = &f.state;
        let ms = |d: Duration| d.as_secs_f64() * 1000.0;
        const REPS: u32 = 5;

        let started = Instant::now();
        for _ in 0..REPS {
            let rows = state.replica_coordinator.list_files(GROUP).expect("list_files");
            assert_eq!(rows.len(), population);
        }
        let list_ms = ms(started.elapsed()) / f64::from(REPS);
        let started = Instant::now();
        for _ in 0..REPS {
            let heads =
                state.replica_coordinator.native_head_paths(GROUP).expect("native_head_paths");
            assert!(heads.len() >= population - copies);
        }
        let heads_ms = ms(started.elapsed()) / f64::from(REPS);
        let started = Instant::now();
        for _ in 0..REPS {
            let (attempt, retired) = executor
                .retire_unjustified_ephemeral_conflict_copies(GROUP, 0)
                .await
                .expect("retirement pass");
            assert!(retired.is_empty(), "{attempt:?}");
        }
        let pass_ms = ms(started.elapsed()) / f64::from(REPS);

        // The same pass with a handful of unjustified copies: each costs a
        // plan, a flush and a delete, and only the first pass has any.
        let unjustified: Vec<String> = (0..5)
            .map(|i| format!("pop/u{i:02} (conflicted copy, 2026-01-01, device-peer, cd34).bin"))
            .collect();
        populate(&unjustified, 9_000_000);
        let started = Instant::now();
        let (attempt, retired) = executor
            .retire_unjustified_ephemeral_conflict_copies(GROUP, 0)
            .await
            .expect("retirement pass with copies");
        let with_ms = ms(started.elapsed());
        println!(
            "K5 rows={population:>6}: list_files {list_ms:.2} ms, native_head_paths {heads_ms:.2} ms, \
             pass (no retirable copy) {pass_ms:.2} ms, pass retiring 5 {with_ms:.2} ms ({attempt:?}, {} retired)",
            retired.len()
        );
    }
}

/// K6: one retirement pass against a fixed population as the number of
/// conflict-copy candidates grows (all carried by a change, so none retires),
/// with the fixed cost around the pass reported separately. Release profile
/// for meaningful absolute numbers:
/// `cargo test --release -p yadorilink-daemon --lib kernel_retirement_candidates_sweep -- --ignored --nocapture`
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "measurement; run explicitly"]
async fn kernel_retirement_candidates_sweep() {
    const REPS: u32 = 30;
    for population in [10_000usize, 100_000] {
        let f = fixture(true).await;
        let ordinary = paths("pop", population);
        admit_paths(&f, &ordinary, 0);
        let populate = |names: &[String], first_seed: i64| {
            for chunk in names.chunks(5000) {
                let records: Vec<_> = chunk
                    .iter()
                    .enumerate()
                    .map(|(i, n)| file_record_from_version(n, &version_for(first_seed + i as i64)))
                    .collect();
                f.state
                    .replica_coordinator
                    .file_index_repository()
                    .upsert_files_batch(
                        GROUP,
                        &records,
                        "device-peer",
                        &[],
                        &[],
                        &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
                    )
                    .expect("populate files rows");
            }
        };
        populate(&ordinary, 0);
        if population == 100_000 {
            let plans: Vec<(&str, String)> = vec![
                (
                    "candidate read",
                    yadorilink_sync_sqlite::file_index::CONFLICT_COPY_CANDIDATES_SQL.to_string(),
                ),
                (
                    "heads at path",
                    "SELECT author, incarnation, seq, version, provenance FROM native_heads \
                     WHERE group_id = ?1 AND path = ?2"
                        .to_string(),
                ),
                (
                    "frontier",
                    "SELECT author, incarnation, seq, tip FROM native_author_frontier \
                     WHERE group_id = ?1"
                        .to_string(),
                ),
            ];
            for (label, sql) in plans {
                let plan = f
                    .state
                    .replica_coordinator
                    .database()
                    .read::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
                        explain_plan(conn, &sql)
                    })
                    .expect("plan");
                println!("K6 plan {label}: {plan}");
            }
        }
        let executor = f.state.local_convergence();
        let ms = |d: Duration| d.as_secs_f64() * 1000.0;
        let mut have = 0usize;
        for candidates in [0usize, 1, 10, 100, 1000] {
            let more: Vec<String> = (have..candidates)
                .map(|i| {
                    format!("pop/c{i:06} (conflicted copy, 2026-01-01, device-peer, ab12).bin")
                })
                .collect();
            admit_paths(&f, &more, 5_000_000 + have as i64);
            populate(&more, 5_000_000 + have as i64);
            have = candidates;

            let started = Instant::now();
            for _ in 0..REPS {
                executor
                    .retire_unjustified_ephemeral_conflict_copies(GROUP, 0)
                    .await
                    .expect("inner pass");
            }
            let inner = ms(started.elapsed()) / f64::from(REPS);
            let started = Instant::now();
            for _ in 0..REPS {
                executor.retire_conflict_copies_only(GROUP).await.expect("wrapped pass");
            }
            let wrapped = ms(started.elapsed()) / f64::from(REPS);
            let started = Instant::now();
            for _ in 0..REPS {
                f.state.replica_coordinator.native_author_frontier(GROUP).expect("frontier");
            }
            let frontier = ms(started.elapsed()) / f64::from(REPS);
            let started = Instant::now();
            for _ in 0..REPS {
                f.state
                    .replica_coordinator
                    .list_live_conflict_copy_candidates(GROUP)
                    .expect("candidates");
            }
            let read = ms(started.elapsed()) / f64::from(REPS);
            let started = Instant::now();
            for _ in 0..REPS {
                f.state.replica_coordinator.link_gate_for_group(GROUP).expect("gate");
            }
            let gate = ms(started.elapsed()) / f64::from(REPS);
            // The loop around the pass: a mark, the pending read, the completion.
            let wake = f.state.replica_coordinator.retirement_wake();
            let started = Instant::now();
            for _ in 0..1000 {
                wake.mark_dirty(GROUP);
                let pending = wake.pending();
                wake.complete(GROUP, pending[GROUP]);
            }
            let wake_us = started.elapsed().as_secs_f64() * 1e6 / 1000.0;
            println!(
                "K6 rows={population:>6} candidates={candidates:>4}: inner pass {inner:.3} ms, \
                 whole pass (gate, guard, 2 frontiers, lease, publish) {wrapped:.3} ms; \
                 parts: frontier read {frontier:.3} ms, candidate read {read:.3} ms, link gate {gate:.3} ms, \
                 wake mark+pending+complete {wake_us:.1} us"
            );
        }
    }
}

/// The `EXPLAIN QUERY PLAN` of `sql` (every placeholder bound to a dummy), one line.
fn explain_plan(
    conn: &rusqlite::Connection,
    sql: &str,
) -> Result<String, yadorilink_sync_sqlite::SyncSqliteError> {
    let mut stmt = conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}"))?;
    let n = stmt.column_count();
    let mut rows =
        stmt.query(rusqlite::params_from_iter(std::iter::repeat_n("x", sql.matches('?').count())))?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(row.get::<_, String>(n - 1)?);
    }
    Ok(out.join(" | "))
}
