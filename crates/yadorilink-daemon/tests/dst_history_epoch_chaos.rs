//! History-epoch chaos: seals, epoch resets and foreign-base merges while
//! devices are partitioned, over the real stack, with directory operations
//! on the side.
//!
//! The store-level reference-model differential
//! (`history_epoch_reference_model_differential` in `yadorilink-sync-sqlite`)
//! compares one store with a model step by step; this scenario asks the
//! question a store alone cannot: when three real devices -- each a
//! `DaemonState`, a `SyncStack` on a simulated iroh carrier, a reconciliation
//! driver and a watched folder with the production capture pipeline behind
//! it -- write, delete, `rm -rf` and rename directories, seal their history
//! while a peer cannot hear them, and merge each other's bases when they meet
//! again, does every device end up holding the same tree, and did any byte a
//! user wrote go missing on the way?
//!
//! # What drives what
//!
//! The filesystem ops are performed on disk and reported to the device's
//! watcher, exactly as `dst_turmoil_stack_case` does; nothing stages a
//! Change for the scenario. Seals and merges are driven by the harness,
//! because `COMPACTION_SCHEDULING_READY` is false and nothing in production
//! schedules either -- the hook is the store's own entry point
//! (`seal_group`, `commit_foreign_merge`), called on the device's own
//! database. A merge happens only between devices that can reach each other
//! (the carrier is not cut between them), which is what "on reconnect"
//! means here, and it follows the foreign-merge trust model: the returning base is
//! believed on its manifest signature and a `BaseSignerAuthority` that
//! trusts the signer, and the merged base's provenance is not re-verified.
//! The base itself crosses in-process rather than over the snapshot lane --
//! a fidelity gap, named: this scenario does not test the snapshot fetch.
//!
//! What that leaves untested, named too: the authority callback answers
//! yes to every signer and the manifest carries no witnesses, and
//! `verify_returning_base` feeds `commit_foreign_merge` directly. So the
//! `BaseSignerAuthority` policy, the rebootstrap handler's frontier and
//! witness checks, and `verify_foreign_base` never run here, and a device
//! trusting an installed base's authors as verified authoring identities
//! (hydration's `is_verified_authoring_change`) is exercised only on bases
//! nothing checked at install. A base those checks would refuse is out of
//! this scenario's reach.
//!
//! After an install the harness runs the materialization repair pass the
//! daemon's maintenance job would run, which is what reconciles the paths
//! the install held. Nothing else in the fixture runs it.
//!
//! # Oracles
//!
//! Checked once every partition is healed and every device has merged onto
//! one base, and again after a final seal:
//!
//! * **Convergence**: one history base, one `Gamma` (the head set of every
//!   path), and one physical tree (directories, kinds and bytes) on every
//!   device.
//! * **Projection**: the tree on disk is `project(Gamma)` -- every projected
//!   node present with its kind, every projected file holding the bytes of
//!   the version placed there, and no file the projection does not place --
//!   and the projection passes the namespace oracles (`NeedsDirectory`
//!   closure, explicit vs structural, no data lost to a shape conflict).
//! * **No content loss**: every byte string a device wrote survives on every
//!   device -- at its path, as a conflict copy or relocated beside it, or
//!   wherever a directory rename carried it -- unless a device overwrote or
//!   removed that exact file *while it could see it*: a write supersedes
//!   only what its author observed, including on top of an installed base. The harness
//!   records what each op observed from the device's own disk, after the
//!   device has settled, so the rule is checked against observation and not
//!   against what the product decided to supersede.
//! * **No corruption**: nothing on disk holds bytes no device wrote.
//! * **Bounded metadata, no stuck holds**: after the final seal, no retained
//!   change, orphan or pruned row, a single stored base snapshot, no
//!   snapshot-install hold and no projection obligation, on every device.
//! * **No stuck seal**: a seal the store keeps refusing on a settled device.
//!
//! # Replay
//!
//! A run is recorded as a `Case`: filesystem ops per device in the round
//! they ran, partitions and heals in `fault_schedule` at `round *
//! ROUND_NANOS` (applied at that round's boundary, not on a timer -- this
//! scenario's rounds are sequential steps, and every step waits for the
//! device to settle), and seals and merges in `history_steps`. Only what
//! actually ran is recorded: a generated op the device's disk made
//! impossible is skipped and left out, and a write-through is recorded as
//! the concrete delete or edit of the copy it resolved to.
//!
//! # Cost
//!
//! Real time. An established QUIC connection stops turmoil's clock from
//! auto-advancing (`turmoil_clock_limits.rs`), so every settle below is paid
//! in wall-clock seconds. The defaults are sized for that: a handful of
//! seeds per run, and `DST_OPS_BUDGET` / `DST_VARIATIONS` to widen it.

#![cfg(turmoil)]

mod dst_support;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use iroh::test_utils::test_transport::TestNetwork;
use rand::rngs::StdRng;
use rand::{RngExt, SeedableRng};
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::sync_adapter::{ReconciliationDriver, SyncStack};
use yadorilink_daemon::test_support::sync_stack_fixture::{
    authority_key, device, endpoint_of, init_staging_schema, pin, watch_folder,
    FixtureAuthenticator, FixtureCheckpointSource, WatchedFolder, GROUP,
};
use yadorilink_filesystem_sync::watcher::FsChangeKind;
use yadorilink_lane_ports::sim_fault::SimFaultController;
use yadorilink_replica_domain::file::{FileVersion, RecordKind};
use yadorilink_replica_domain::ids::DeviceId;
use yadorilink_replica_engine::conflict::{PathHead, PathHeadContent};
use yadorilink_replica_engine::namespace::{PhysicalNode, Placement};
use yadorilink_replica_engine::rebootstrap::SnapshotManifest;
use yadorilink_sync_sqlite::rebootstrap_store::{
    build_group_history_summary, history_base, seal_group, verify_current_base,
    verify_returning_base, GroupHistorySummary, SealRefusal,
};
use yadorilink_sync_sqlite::SyncSqliteError;
use yadorilink_sync_substrate::NetworkConfig;

use dst_support::case_ir::{
    Case, ContentTable, DeviceTimeline, Fault, FaultPlan, HistoryStep, LinkTopology, NetFault, Op,
    Topology,
};
use dst_support::clock::HarnessClock;
use dst_support::device_network::DeviceNetworkFaults;
use dst_support::fault_carrier::CarrierFaults;
use dst_support::fs_events::{decompose, FsOp};
use dst_support::namespace_oracle::{
    check_disk_against_projection, check_projection, check_trees_converge, disk_tree, sha256_hex,
    DiskNode, DiskTree, ExpectedLeaf, ExplicitHeads, ProjectedTree,
};
use dst_support::op_applier::{apply_op, AppliedEffect};

const DEVICES: usize = 3;
const HOSTS: [&str; DEVICES] = ["device-alice", "device-bob", "device-carol"];
const KEYS: [u8; DEVICES] = [11, 22, 33];

/// What one round is worth in `Case::fault_schedule`'s nanoseconds. A
/// partition recorded at `round * ROUND_NANOS` is applied at the start of
/// that round, before its step runs.
const ROUND_NANOS: u64 = 1_000_000_000;

/// Long enough for the debouncer to close a quiet period and the executor
/// to publish (see `dst_turmoil_stack_case`'s `FLUSH_SETTLE`).
const FLUSH_SETTLE: Duration = Duration::from_millis(1500);

/// A device is settled when it owes no projection and holds no install.
const SETTLE_BUDGET: Duration = Duration::from_secs(45);

/// How long a seal may keep being refused on a settled device before the
/// scenario calls it stuck.
const SEAL_BUDGET: Duration = Duration::from_secs(45);

/// How long a write-through waits for its device to show a copy.
const COPY_BUDGET: Duration = Duration::from_secs(15);

/// How long devices that can all reach each other, on one base, get to agree
/// on a tree.
const CONVERGE_BUDGET: Duration = Duration::from_secs(120);

/// Merge rounds the final phase may spend bringing every device onto one
/// base before it reports that they never got there.
const FINAL_MERGE_ROUNDS: usize = 6;

const DEFAULT_STEPS: usize = 18;
const DEFAULT_VARIATIONS: u64 = 3;
const DEFAULT_BASE_SEED: u64 = 0x9B_0000;

/// Files the generator writes, edits and deletes. `f0` against `f0/g` and
/// `d1` against `d1/f4` are the shape conflicts: a device that
/// cannot see its peer can make a path a file while the peer makes it a
/// directory.
const FILES: [&str; 7] = ["f0", "f1", "d0/f2", "d0/e/f3", "d1/f4", "f0/g", "d1"];
/// Directories the generator makes, removes (`rm -rf`) and renames.
const DIRS: [&str; 4] = ["d0", "d0/e", "d1", "f0"];

// ---------------------------------------------------------------------------
// Steps
// ---------------------------------------------------------------------------

/// One step of a run, as the generator draws it. `WriteThrough` is the only
/// one that is not concrete: which copy it deletes or edits is resolved
/// against the device's projection when the step runs, and the run records
/// the concrete op it became.
#[derive(Debug, Clone)]
enum Step {
    Fs { device: usize, op: Op },
    WriteThrough { device: usize, delete: bool, content_id: u64 },
    Net(NetFault),
    History(HistoryStep),
}

fn content_bytes(seed: u64, id: u64) -> Vec<u8> {
    let mut bytes = format!("seed {seed} content {id}\n").into_bytes();
    while bytes.len() < 512 {
        bytes.extend_from_slice(format!("{id:016x}").as_bytes());
    }
    bytes
}

/// The warm-up every run starts with: one file per device, so each device
/// has written history of its own before anything is cut, sealed or merged.
const WARMUP_STEPS: usize = DEVICES;

fn generate(seed: u64, steps: usize) -> (ContentTable, Vec<Step>) {
    let mut rng = StdRng::seed_from_u64(seed ^ 0x9B9B_9B9B);
    let mut contents = ContentTable::default();
    let mut next_id = 1u64;
    let mut fresh = |contents: &mut ContentTable| {
        let id = next_id;
        next_id += 1;
        contents.insert(id, content_bytes(seed, id));
        id
    };
    let mut out = Vec::new();
    for device in 0..DEVICES {
        let content_id = fresh(&mut contents);
        out.push(Step::Fs { device, op: Op::Write { path: format!("w{device}"), content_id } });
    }
    let mut cut: BTreeSet<(usize, usize)> = BTreeSet::new();
    let mut renames = 0usize;
    for _ in 0..steps {
        let device = rng.random_range(0..DEVICES);
        fn pick(rng: &mut StdRng, pool: &[&'static str]) -> &'static str {
            pool[rng.random_range(0..pool.len())]
        }
        let roll = rng.random_range(0..100u32);
        let step = match roll {
            0..=27 => {
                let content_id = fresh(&mut contents);
                Step::Fs {
                    device,
                    op: Op::Write { path: pick(&mut rng, &FILES).into(), content_id },
                }
            }
            28..=35 => {
                let content_id = fresh(&mut contents);
                Step::Fs {
                    device,
                    op: Op::Edit { path: pick(&mut rng, &FILES).into(), content_id },
                }
            }
            36..=42 => Step::Fs { device, op: Op::Delete { path: pick(&mut rng, &FILES).into() } },
            43..=46 => Step::Fs { device, op: Op::Mkdir { path: pick(&mut rng, &DIRS).into() } },
            47..=52 => Step::Fs { device, op: Op::RmTree { path: pick(&mut rng, &DIRS).into() } },
            53..=56 => {
                renames += 1;
                Step::Fs {
                    device,
                    op: Op::RenameTree {
                        from: pick(&mut rng, &DIRS).into(),
                        to: format!("mv{renames}"),
                    },
                }
            }
            57..=61 => {
                let content_id = fresh(&mut contents);
                Step::WriteThrough { device, delete: rng.random_bool(0.5), content_id }
            }
            62..=72 => {
                let other = (device + rng.random_range(1..DEVICES)) % DEVICES;
                let pair = (device.min(other), device.max(other));
                if cut.contains(&pair) || (cut.len() >= 2 && rng.random_bool(0.6)) {
                    let pair = if cut.contains(&pair) {
                        pair
                    } else {
                        *cut.iter().next().expect("two pairs are cut")
                    };
                    cut.remove(&pair);
                    Step::Net(NetFault::Heal { device_a: pair.0, device_b: pair.1 })
                } else {
                    cut.insert(pair);
                    Step::Net(NetFault::Partition { device_a: pair.0, device_b: pair.1 })
                }
            }
            73..=85 => Step::History(HistoryStep::Seal { device }),
            _ => {
                let from = (device + rng.random_range(1..DEVICES)) % DEVICES;
                Step::History(HistoryStep::Merge { into: device, from })
            }
        };
        out.push(step);
    }
    (contents, out)
}

/// What a run actually performed, round by round, as a `Case`.
fn to_case(seed: u64, contents: &ContentTable, executed: &[(u64, Step)]) -> Case {
    let mut workload: Vec<DeviceTimeline> =
        (0..DEVICES).map(|device_index| DeviceTimeline { device_index, ops: Vec::new() }).collect();
    let mut fault_schedule = Vec::new();
    let mut history_steps = Vec::new();
    for (round, step) in executed {
        match step {
            Step::Fs { device, op } => workload[*device].ops.push((*round, op.clone())),
            Step::Net(fault) => {
                fault_schedule.push((round * ROUND_NANOS, Fault::Net(fault.clone())))
            }
            Step::History(history) => history_steps.push((*round, history.clone())),
            Step::WriteThrough { .. } => {
                unreachable!("a write-through is recorded as the op it became")
            }
        }
    }
    Case {
        seed,
        topology: Topology {
            device_count: DEVICES,
            links: (0..DEVICES)
                .map(|_| LinkTopology { group_id: GROUP.into(), initial_online: true })
                .collect(),
        },
        workload,
        fault_schedule,
        content_table: contents.clone(),
        fault_plan: FaultPlan::default(),
        history_steps,
    }
}

/// A recorded `Case` back into the steps it ran, in round order.
fn from_case(case: &Case) -> Result<Vec<Step>, String> {
    if case.topology.device_count != DEVICES {
        return Err(format!(
            "case {} has {} devices, not {DEVICES}",
            case.seed, case.topology.device_count
        ));
    }
    let mut by_round: BTreeMap<u64, Step> = BTreeMap::new();
    let mut put = |round: u64, step: Step| match by_round.insert(round, step) {
        None => Ok(()),
        Some(_) => Err(format!("case {} runs two steps in round {round}", case.seed)),
    };
    for timeline in &case.workload {
        for (round, op) in &timeline.ops {
            put(*round, Step::Fs { device: timeline.device_index, op: op.clone() })?;
        }
    }
    for (at, fault) in &case.fault_schedule {
        let Fault::Net(net) = fault else {
            return Err(format!("case {} schedules a non-network fault {fault:?}", case.seed));
        };
        put(at / ROUND_NANOS, Step::Net(net.clone()))?;
    }
    for (round, history) in &case.history_steps {
        put(*round, Step::History(history.clone()))?;
    }
    Ok(by_round.into_values().collect())
}

// ---------------------------------------------------------------------------
// Devices
// ---------------------------------------------------------------------------

struct Dev {
    index: usize,
    state: Arc<DaemonState>,
    stack: Arc<SyncStack>,
    driver: Arc<ReconciliationDriver>,
    folder: Arc<WatchedFolder>,
    /// Publishes what this device authored outside its watched folder's
    /// executor -- a conflict copy the projection wrote, a directory the
    /// namespace closure captured -- as `broadcast_change` would. The
    /// fixture has no coordination plane, so without it such a change
    /// stays Pending: unservable to peers, and a seal refuses it.
    publisher: FixtureCheckpointSource,
}

impl Dev {
    fn root(&self) -> &Path {
        self.folder.path()
    }

    fn read<T>(
        &self,
        f: impl FnMut(&rusqlite::Connection) -> Result<T, SyncSqliteError>,
    ) -> Result<T, SyncSqliteError> {
        self.state.replica_coordinator.database().read::<_, SyncSqliteError>(f)
    }

    fn count(&self, sql: &str) -> i64 {
        self.read(|conn| Ok(conn.query_row(sql, [GROUP], |row| row.get(0))?)).unwrap_or(-1)
    }

    fn pending_obligations(&self) -> u64 {
        self.state
            .replica_coordinator
            .sqlite()
            .dag_count_pending_projection_obligations(GROUP)
            .unwrap_or(u64::MAX)
    }

    fn holds(&self) -> usize {
        self.state
            .replica_coordinator
            .snapshot_install_hold_repository()
            .held_paths(GROUP)
            .map(|paths| paths.len())
            .unwrap_or(usize::MAX)
    }

    /// What the device still owes, path by path: the obligation, the
    /// heads `Gamma` holds there, the current index row and the disk.
    fn describe_pending(&self) -> String {
        let rows: Vec<(String, i64, i64, String)> = self
            .read(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT path, attempt_count, next_attempt_at, origin FROM projection_obligations \
                     WHERE group_id = ?1 AND state = 'pending' ORDER BY path",
                )?;
                let rows = stmt.query_map([GROUP], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
                })?;
                Ok(rows.collect::<Result<Vec<_>, _>>()?)
            })
            .unwrap_or_default();
        let gamma = self.gamma().ok();
        let tree = self.tree();
        let mut out = format!(
            "base {:?} retained {}",
            self.base().map(|b| hex::encode(&b[..4])),
            self.retained()
        );
        for (path, attempts, next, origin) in rows {
            let heads: Vec<String> = gamma
                .iter()
                .flat_map(|g| g.path_heads.iter())
                .filter(|h| h.path == path)
                .map(|h| {
                    format!("{}@{}:{}", h.device_id, h.lamport, hex::encode(&h.version_hash.0[..4]))
                })
                .collect();
            let row: Option<(String, i64, i64)> = self
                .read(|conn| {
                    use rusqlite::OptionalExtension;
                    Ok(conn
                        .query_row(
                            "SELECT record_kind, deleted, size FROM files WHERE group_id = ?1 \
                             AND path = ?2 AND state = 'current'",
                            [GROUP, path.as_str()],
                            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                        )
                        .optional()?)
                })
                .ok()
                .flatten();
            out.push_str(&format!(
                "\n    {path}: attempts {attempts} next {next} origin {origin} heads {heads:?} row {row:?} disk {:?}",
                tree.get(&path)
            ));
        }
        out
    }

    fn retained(&self) -> i64 {
        self.count("SELECT COUNT(*) FROM changes WHERE group_id = ?1")
    }

    fn base(&self) -> Option<[u8; 32]> {
        self.read(|conn| history_base(conn, GROUP)).ok().flatten().map(|base| base.0)
    }

    fn gamma(&self) -> Result<GroupHistorySummary, SyncSqliteError> {
        self.read(|conn| build_group_history_summary(conn, GROUP))
    }

    /// Every version this device stores, by kind.
    fn kinds(&self) -> HashMap<[u8; 32], RecordKind> {
        self.read(|conn| {
            let mut stmt = conn.prepare("SELECT encoded FROM file_versions WHERE group_id = ?1")?;
            let rows = stmt.query_map([GROUP], |row| row.get::<_, Vec<u8>>(0))?;
            let mut out = HashMap::new();
            for encoded in rows {
                if let Ok(version) = FileVersion::from_canonical_encoding(&encoded?) {
                    out.insert(version.version_hash.0, version.meta.record_kind);
                }
            }
            Ok(out)
        })
        .unwrap_or_default()
    }

    /// The bytes every single-block File version this device stores
    /// stands for, as the SHA-256 the disk tree records: a version's one
    /// block is its whole content, and the block's hash is the content's
    /// SHA-256. Versions of more than one block (none in this scenario:
    /// every content is 512 bytes) are left out and checked by kind only.
    fn leaf_shas(&self) -> HashMap<[u8; 32], String> {
        self.read(|conn| {
            let mut stmt = conn.prepare("SELECT encoded FROM file_versions WHERE group_id = ?1")?;
            let rows = stmt.query_map([GROUP], |row| row.get::<_, Vec<u8>>(0))?;
            let mut out = HashMap::new();
            for encoded in rows {
                let Ok(version) = FileVersion::from_canonical_encoding(&encoded?) else {
                    continue;
                };
                if let (RecordKind::File, [only]) =
                    (version.meta.record_kind, version.blocks.as_slice())
                {
                    out.insert(version.version_hash.0, hex::encode(&only.hash.0));
                }
            }
            Ok(out)
        })
        .unwrap_or_default()
    }

    /// Directories this device's engine is answerable for: ones it made
    /// for descendants, ones it is holding to remove once empty, and ones
    /// it replicates as entries (live or deleted). Anything else on disk is
    /// the user's, and the engine never removes it.
    fn engine_owned_directories(&self) -> BTreeSet<String> {
        self.read(|conn| {
            let mut out = BTreeSet::new();
            for sql in [
                "SELECT path FROM structural_directory_origins WHERE group_id = ?1",
                "SELECT path FROM retained_directories WHERE group_id = ?1 \
                 AND filesystem_identity IS NOT NULL",
                "SELECT DISTINCT path FROM files WHERE group_id = ?1 AND record_kind = 'directory'",
            ] {
                let mut stmt = conn.prepare(sql)?;
                for path in stmt.query_map([GROUP], |row| row.get::<_, String>(0))? {
                    out.insert(path?);
                }
            }
            Ok(out)
        })
        .unwrap_or_default()
    }

    fn tree(&self) -> DiskTree {
        disk_tree(self.root())
    }

    /// The daemon's materialization repair pass, which reconciles every
    /// path a snapshot install holds before anything else. The fixture runs
    /// no maintenance job, so the harness runs it where the daemon would.
    fn repair(&self) -> Result<(), String> {
        let store = yadorilink_daemon::adapters::block_store_ports::BlockStorePortsAdapter::new(
            self.state.block_store.clone(),
        );
        let report =
            yadorilink_filesystem_sync::materialization_repair::repair_interrupted_materializations(
                self.state.replica_coordinator.as_ref(),
                &store,
                self.root(),
                GROUP,
                yadorilink_filesystem_sync::materialization_repair::RepairMode::Live,
                &yadorilink_root_authority::root_commit::RootCommitPermit::for_tests(),
            )
            .map_err(|error| format!("repair on {}: {error}", HOSTS[self.index]))?;
        // What the reconcile moved aside is a new file to the watcher, as it
        // would be to the OS's.
        let moved: Vec<String> =
            report.quarantined_dirty.iter().map(|(_, to)| to.clone()).collect();
        for to in moved {
            let path = if Path::new(&to).is_absolute() { to.into() } else { self.root().join(to) };
            self.folder_notify_blocking(path, FsChangeKind::CreatedOrModified);
        }
        Ok(())
    }

    /// Publishes this device's Pending changes. Racing the folder's own
    /// executor on one batch is harmless here: whichever attaches its
    /// evidence first wins, and the other's attach is refused and ignored.
    async fn publish_pending(&self) {
        use yadorilink_daemon::checkpoint_source::{flush_pending_checkpoint, FlushOutcome};
        use yadorilink_replica_domain::authorization_checkpoint::fingerprint_signing_key;
        let signing = self.state.device_signing_key().expect("the device has a signing key");
        let authority = authority_key().verifying_key();
        let expected = fingerprint_signing_key(&authority);
        let flushed = flush_pending_checkpoint(
            &self.state.replica_coordinator.database(),
            &self.publisher,
            GROUP,
            &self.state.device_id,
            &signing.verifying_key(),
            &move |key_id: &[u8; 32], _: &[u8; 32]| (*key_id == expected).then_some(authority),
        )
        .await;
        if matches!(flushed, Ok(FlushOutcome::Flushed { .. })) {
            self.driver
                .note_local_change(&yadorilink_replica_domain::ids::FolderGroupId(GROUP.into()));
        }
    }

    /// The part of the daemon's periodic maintenance the fixture does not
    /// run: the repair pass, and the audit that retires a conflict copy
    /// nothing justifies any more. The fixture has neither job, so the
    /// harness runs them where the daemon's maintenance tick would.
    async fn maintain(&self) {
        let _ = self.repair();
        let _ = self.state.local_convergence().retire_conflict_copies_only(GROUP).await;
    }

    fn folder_notify_blocking(&self, path: std::path::PathBuf, kind: FsChangeKind) {
        let folder = self.folder.clone();
        tokio::spawn(async move { folder.notify(path, kind).await });
    }
}

// ---------------------------------------------------------------------------
// Observation: what a device's disk shows, and who wrote it
// ---------------------------------------------------------------------------

/// Every content a device wrote, and which of them a later op overwrote or
/// removed while its device could see it.
#[derive(Default)]
struct Ledger {
    by_sha: HashMap<String, u64>,
    written: BTreeMap<u64, (usize, String)>,
    superseded: BTreeSet<u64>,
}

impl Ledger {
    fn new(contents: &ContentTable) -> Self {
        let by_sha = contents.iter().map(|(id, bytes)| (sha256_hex(bytes), *id)).collect();
        Self { by_sha, ..Default::default() }
    }

    fn content_at(&self, tree: &DiskTree, path: &str) -> Option<u64> {
        match tree.get(path) {
            Some(DiskNode::File { sha256 }) => self.by_sha.get(sha256).copied(),
            _ => None,
        }
    }

    /// What a device shows at `path`: the bytes on disk when they are a
    /// known content, and otherwise -- a placeholder not hydrated yet --
    /// the content of the row the device materialized there. A user who
    /// overwrites a placeholder overwrites the file it stands for.
    fn shown_at(&self, dev: &Dev, tree: &DiskTree, path: &str) -> Option<u64> {
        if !matches!(tree.get(path), Some(DiskNode::File { .. })) {
            return None;
        }
        self.content_at(tree, path).or_else(|| {
            let row = dev.state.replica_coordinator.get_file(GROUP, path).ok().flatten()?;
            match row.blocks.as_slice() {
                [only] if !row.deleted => self.by_sha.get(&hex::encode(&only.hash)).copied(),
                _ => None,
            }
        })
    }

    fn supersede_at(&mut self, dev: &Dev, tree: &DiskTree, path: &str) {
        if let Some(id) = self.shown_at(dev, tree, path) {
            self.superseded.insert(id);
        }
    }

    fn supersede_under(&mut self, dev: &Dev, tree: &DiskTree, dir: &str) {
        let prefix = format!("{dir}/");
        let ids: Vec<u64> = tree
            .keys()
            .filter(|path| path.starts_with(&prefix))
            .filter_map(|path| self.shown_at(dev, tree, path))
            .collect();
        self.superseded.extend(ids);
    }
}

fn is_dir(tree: &DiskTree, path: &str) -> bool {
    matches!(tree.get(path), Some(DiskNode::Directory { .. }))
}

fn ancestors(path: &str) -> Vec<String> {
    let parts: Vec<&str> = path.split('/').collect();
    (1..parts.len()).map(|n| parts[..n].join("/")).collect()
}

/// Whether `op` can run on this disk at all: a write under a file, a file
/// over a directory, a rename onto something, are not operations a user
/// can perform.
fn runnable(tree: &DiskTree, op: &Op) -> bool {
    let parents_ok =
        |path: &str| ancestors(path).iter().all(|a| tree.get(a).is_none_or(DiskNode::is_directory));
    match op {
        Op::Write { path, .. } | Op::Edit { path, .. } => !is_dir(tree, path) && parents_ok(path),
        Op::Delete { path } => matches!(tree.get(path), Some(DiskNode::File { .. })),
        Op::Mkdir { path } => tree.get(path).is_none() && parents_ok(path),
        Op::RmTree { path } => is_dir(tree, path),
        Op::RenameTree { from, to } => {
            is_dir(tree, from) && tree.get(to).is_none() && parents_ok(to)
        }
        _ => false,
    }
}

fn heads_by_path(summary: &GroupHistorySummary) -> ExplicitHeads {
    let mut out: ExplicitHeads = BTreeMap::new();
    for head in &summary.path_heads {
        out.entry(head.path.clone()).or_default().push(PathHead {
            change_hash: head.change_hash.0,
            lamport: head.lamport,
            device_id: head.device_id.clone(),
            naming_device_id: head.naming_device_id.clone(),
            content: Some(PathHeadContent {
                version_hash: head.version_hash.0,
                mtime_unix_nanos: 0,
            }),
        });
    }
    out
}

/// `Gamma` as a comparable set: which change put which version at which
/// path.
fn gamma_key(summary: &GroupHistorySummary) -> BTreeSet<(String, [u8; 32], [u8; 32])> {
    summary
        .path_heads
        .iter()
        .map(|head| (head.path.clone(), head.change_hash.0, head.version_hash.0))
        .collect()
}

// ---------------------------------------------------------------------------
// The run
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct Reached {
    fs_ops: usize,
    skipped: usize,
    write_throughs: usize,
    /// Write-throughs drawn while the device showed no copy to write
    /// through, even after waiting `COPY_BUDGET` for one.
    write_throughs_without_copy: usize,
    partitions: usize,
    seals: usize,
    reseals: usize,
    merges: BTreeMap<String, usize>,
    merge_claimed: usize,
    installs: usize,
    merges_skipped_cut: usize,
    merges_deferred: usize,
    nothing_to_seal: usize,
    seals_deferred: usize,
    seals_awaiting_user: usize,
    user_resolutions: usize,
    unsettled: usize,
}

struct Violation {
    kind: &'static str,
    detail: String,
}

struct Run<'a> {
    devs: &'a [Arc<Dev>],
    faults: &'a DeviceNetworkFaults,
    controller: &'a SimFaultController,
    endpoints: &'a [iroh::EndpointId],
    clock: HarnessClock,
    contents: ContentTable,
    ledger: Ledger,
    violations: Vec<Violation>,
    reached: Reached,
    /// Set while converging: the harness then acts as the user, resolving
    /// the conflicts a seal waits on.
    resolving: bool,
}

async fn within(budget: Duration, mut check: impl FnMut() -> bool) -> bool {
    let deadline = tokio::time::Instant::now() + budget;
    while tokio::time::Instant::now() < deadline {
        if check() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    check()
}

impl Run<'_> {
    fn violation(&mut self, kind: &'static str, detail: String) {
        eprintln!("[history-epoch] VIOLATION {kind}: {detail}");
        self.violations.push(Violation { kind, detail });
    }

    fn cut(&self, a: usize, b: usize) -> bool {
        self.controller.is_partitioned(self.endpoints[a], self.endpoints[b])
    }

    /// Waits for `dev` to owe no projection and hold no install. Not
    /// settling is not by itself a failure: a device that needs content only
    /// a peer it cannot reach -- or a peer on another base -- holds is
    /// correctly waiting. The final convergence check is what fails a run
    /// in which a device never settles.
    async fn settle(&mut self, dev: usize) -> bool {
        let d = self.devs[dev].clone();
        d.publish_pending().await;
        d.maintain().await;
        let settled = within(SETTLE_BUDGET, || {
            if d.holds() > 0 {
                let _ = d.repair();
            }
            d.pending_obligations() == 0 && d.holds() == 0
        })
        .await;
        if !settled {
            self.reached.unsettled += 1;
        }
        settled
    }

    /// Performs one filesystem op on `dev`'s folder and reports it to the
    /// watcher the way the OS would. Returns whether it ran.
    async fn fs(&mut self, dev: usize, op: &Op) -> bool {
        let d = self.devs[dev].clone();
        let tree = d.tree();
        if !runnable(&tree, op) {
            self.reached.skipped += 1;
            return false;
        }
        // What the op overwrites or removes, as the device sees it now.
        match op {
            Op::Write { path, content_id } | Op::Edit { path, content_id } => {
                self.ledger.supersede_at(&d, &tree, path);
                self.ledger.written.insert(*content_id, (dev, path.clone()));
            }
            Op::Delete { path } => self.ledger.supersede_at(&d, &tree, path),
            Op::RmTree { path } => self.ledger.supersede_under(&d, &tree, path),
            _ => {}
        }
        let created: Vec<String> = match op {
            Op::Write { path, .. } | Op::Edit { path, .. } => ancestors(path),
            Op::Mkdir { path } => {
                let mut all = ancestors(path);
                all.push(path.clone());
                all
            }
            _ => Vec::new(),
        }
        .into_iter()
        .filter(|dir| !tree.contains_key(dir))
        .collect();
        let effect = match apply_op(&self.clock, d.root(), op, &self.contents) {
            Ok(effect) => effect,
            Err(error) => {
                self.violation("HarnessOp", format!("{op:?} on {}: {error}", HOSTS[dev]));
                return false;
            }
        };
        let mut events: Vec<(String, FsChangeKind)> =
            created.into_iter().map(|dir| (dir, FsChangeKind::CreatedOrModified)).collect();
        match effect {
            AppliedEffect::Wrote { path, .. } => {
                events.push((path, FsChangeKind::CreatedOrModified))
            }
            AppliedEffect::Removed { path } => events.push((path, FsChangeKind::Removed)),
            AppliedEffect::DirCreated { .. } => {}
            AppliedEffect::TreeRemoved { observed, .. } => {
                let mut observed = observed;
                observed.sort();
                observed.reverse();
                events.extend(observed.into_iter().map(|path| (path, FsChangeKind::Removed)));
            }
            AppliedEffect::TreeRenamed { from, to, observed } => {
                let prefix = format!("{from}/");
                let children = observed
                    .iter()
                    .filter_map(|path| path.strip_prefix(&prefix).map(str::to_owned))
                    .collect();
                events.extend(
                    decompose(&FsOp::DirRename { from_dir: from, to_dir: to, children })
                        .into_iter()
                        .map(|event| (event.path, event.kind)),
                );
            }
            other => {
                self.violation("HarnessOp", format!("unexpected effect {other:?}"));
                return false;
            }
        }
        for (path, kind) in events {
            d.folder.notify(d.root().join(path), kind).await;
        }
        tokio::time::sleep(FLUSH_SETTLE).await;
        self.reached.fs_ops += 1;
        true
    }

    /// `path` as `dev` holds it: `Gamma`'s heads there, every node its
    /// projection places from it, and what its disk has at each.
    fn describe_path(&self, dev: usize, path: &str) -> String {
        let d = &self.devs[dev];
        let Ok(summary) = d.gamma() else { return "no summary".into() };
        let kinds = d.kinds();
        let heads: Vec<String> = summary
            .path_heads
            .iter()
            .filter(|head| head.path == path)
            .map(|head| {
                format!(
                    "{}#{}@{}:{}",
                    head.device_id,
                    head.author_seq.get(),
                    head.lamport,
                    hex::encode(&head.version_hash.0[..4])
                )
            })
            .collect();
        let tree = d.tree();
        let nodes: Vec<String> = summary
            .project(|v| kinds.get(v).copied())
            .map(|projection| {
                projection
                    .nodes()
                    .iter()
                    .filter_map(|(name, node)| match node {
                        PhysicalNode::Entry(entry) if entry.source == path => Some(format!(
                            "{name} {:?} {} disk {:?}",
                            entry.placement,
                            hex::encode(&entry.version_hash[..4]),
                            tree.get(name)
                        )),
                        _ => None,
                    })
                    .collect()
            })
            .unwrap_or_default();
        format!("heads {heads:?} placed {nodes:?}")
    }

    /// The copies `dev`'s projection places beside `source` for heads
    /// `author` wrote, as files on its disk: a losing head's conflict copy,
    /// or a leaf relocated for a directory. Only `author`'s: the seal
    /// refuses over two heads of one author, and resolving that is deleting
    /// the copy of that author's stranded head -- a copy of another
    /// author's concurrent write beside it is not part of the conflict the
    /// seal waits on, and deleting it would mark its bytes superseded and
    /// take them out of the content-loss oracle.
    fn copies_of(&self, dev: usize, source: &str, author: &str) -> Vec<String> {
        let d = &self.devs[dev];
        let (Ok(summary), kinds) = (d.gamma(), d.kinds()) else { return Vec::new() };
        let Ok(projection) = summary.project(|v| kinds.get(v).copied()) else { return Vec::new() };
        let authored: BTreeSet<[u8; 32]> = summary
            .path_heads
            .iter()
            .filter(|head| head.path == source && head.device_id == author)
            .map(|head| head.version_hash.0)
            .collect();
        let tree = d.tree();
        projection
            .nodes()
            .iter()
            .filter_map(|(name, node)| match node {
                PhysicalNode::Entry(entry)
                    if entry.source == source
                        && entry.placement != Placement::AtPath
                        && authored.contains(&entry.version_hash)
                        && matches!(tree.get(name), Some(DiskNode::File { .. })) =>
                {
                    Some(name.clone())
                }
                _ => None,
            })
            .collect()
    }

    /// Resolves a write-through against `dev`'s projection: the copy a
    /// conflict or a shape conflict placed beside its source, deleted or
    /// edited by the user. `None` when the device shows no such copy.
    fn resolve_write_through(&self, dev: usize, delete: bool, content_id: u64) -> Option<Op> {
        let d = &self.devs[dev];
        let summary = d.gamma().ok()?;
        let kinds = d.kinds();
        let projection = summary.project(|v| kinds.get(v).copied()).ok()?;
        let tree = d.tree();
        let copies: Vec<String> = projection
            .nodes()
            .iter()
            .filter_map(|(name, node)| match node {
                PhysicalNode::Entry(entry)
                    if entry.placement != Placement::AtPath
                        && matches!(tree.get(name), Some(DiskNode::File { .. })) =>
                {
                    Some(name.clone())
                }
                _ => None,
            })
            .collect();
        let name = copies.get(content_id as usize % copies.len().max(1))?.clone();
        Some(if delete { Op::Delete { path: name } } else { Op::Edit { path: name, content_id } })
    }

    /// [`Self::resolve_write_through`] once `dev` has settled, waiting up
    /// to `COPY_BUDGET` for a copy to show: a conflict a heal just exposed
    /// reaches the disk only once the peer's change has arrived and been
    /// projected, and a write-through drawn a moment too early would
    /// otherwise almost never find one.
    async fn await_write_through(
        &mut self,
        dev: usize,
        delete: bool,
        content_id: u64,
    ) -> Option<Op> {
        self.settle(dev).await;
        let deadline = tokio::time::Instant::now() + COPY_BUDGET;
        loop {
            if let Some(op) = self.resolve_write_through(dev, delete, content_id) {
                return Some(op);
            }
            if tokio::time::Instant::now() >= deadline {
                return None;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
            self.devs[dev].maintain().await;
        }
    }

    fn net(&mut self, fault: &NetFault) {
        let outcome = self.faults.apply(&Fault::Net(fault.clone()));
        if !outcome.fully_applied() {
            self.violation("HarnessNet", format!("{fault:?} was not applied: {outcome:?}"));
        }
        if matches!(fault, NetFault::Partition { .. }) {
            self.reached.partitions += 1;
        }
    }

    /// Seals `dev`'s history, retrying while the store refuses a device that
    /// is still catching up. Returns whether the device now stands on a base
    /// that holds everything it had.
    async fn seal(&mut self, dev: usize) -> bool {
        let d = self.devs[dev].clone();
        if d.retained() == 0 {
            self.reached.nothing_to_seal += 1;
            return true;
        }
        if !self.settle(dev).await {
            // The store refuses to seal over a pending projection, and it
            // is right to: the seal waits, as a scheduled one would.
            self.reached.seals_deferred += 1;
            return false;
        }
        let reseal = d.base().is_some();
        let deadline = tokio::time::Instant::now() + SEAL_BUDGET;
        let mut last: Option<String>;
        loop {
            let attempt = d
                .state
                .replica_coordinator
                .database()
                .write_immediate::<_, SyncSqliteError>(|tx| seal_group(tx, GROUP));
            match attempt {
                Ok(_) => {
                    self.reached.seals += 1;
                    self.reached.reseals += usize::from(reseal);
                    return true;
                }
                Err(SyncSqliteError::SealRefused {
                    refusal: SealRefusal::NothingToSeal, ..
                }) => {
                    self.reached.nothing_to_seal += 1;
                    return true;
                }
                // One author holds two live heads of a path: its write left
                // its own earlier head standing because it never showed it.
                // By design the seal fails closed until the user resolves
                // the conflict -- deleting or editing the copy of the head
                // left standing -- and sync goes on meanwhile. While steps
                // run the seal just waits; converging, the harness is the
                // user, keeps the visible winner, and deletes the copies of
                // that author's heads (and only those: see `copies_of`).
                Err(SyncSqliteError::SealRefused {
                    refusal: SealRefusal::TwoHeadsFromOneAuthor { path, device_id },
                    ..
                }) => {
                    if !self.resolving {
                        self.reached.seals_awaiting_user += 1;
                        return false;
                    }
                    let copies = self.copies_of(dev, &path, &device_id);
                    if copies.is_empty() {
                        last = Some(format!(
                            "two live heads of {path} by one author, no copy shown: {}",
                            self.describe_path(dev, &path)
                        ));
                    } else {
                        for copy in copies {
                            self.fs(dev, &Op::Delete { path: copy }).await;
                        }
                        self.reached.user_resolutions += 1;
                        self.settle(dev).await;
                        continue;
                    }
                }
                Err(error) => last = Some(error.to_string()),
            }
            if tokio::time::Instant::now() >= deadline {
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
            d.publish_pending().await;
            if d.holds() > 0 {
                let _ = d.repair();
            }
        }
        self.violation(
            "SealStuck",
            format!(
                "{} could not seal for {SEAL_BUDGET:?} on a settled device: {}",
                HOSTS[dev],
                last.unwrap_or_default()
            ),
        );
        false
    }

    /// `into` merges the base `from` stands on, as it would on meeting it.
    /// Returns `None` when the step could not run (the two cannot reach each
    /// other, or there is nothing to merge), else whether it succeeded.
    async fn merge(&mut self, into: usize, from: usize) -> Option<bool> {
        if self.cut(into, from) {
            self.reached.merges_skipped_cut += 1;
            return None;
        }
        for side in [into, from] {
            if !self.seal(side).await {
                self.reached.merges_deferred += 1;
                return None;
            }
        }
        let (a, b) = (self.devs[into].clone(), self.devs[from].clone());
        let (Some(into_base), Some(from_base)) = (a.base(), b.base()) else {
            return None;
        };
        if into_base == from_base {
            return None;
        }
        let claimed = a
            .stack
            .foreign_bases()
            .merge_required(
                &yadorilink_replica_domain::ids::FolderGroupId(GROUP.into()),
                yadorilink_replica_engine::rebootstrap::HistoryEpoch::Base(
                    yadorilink_replica_engine::rebootstrap::HistoryBase(into_base),
                ),
            )
            .iter()
            .any(|claim| claim.peer_device == HOSTS[from]);
        self.reached.merge_claimed += usize::from(claimed);

        let side = match b.read(|conn| Ok(verify_current_base(conn, GROUP))) {
            Ok(Ok(side)) => side,
            Ok(Err(error)) => {
                self.violation(
                    "MergeRefused",
                    format!("{} cannot offer its base: {error}", HOSTS[from]),
                );
                return Some(false);
            }
            Err(error) => {
                self.violation(
                    "MergeRefused",
                    format!("{} cannot offer its base: {error}", HOSTS[from]),
                );
                return Some(false);
            }
        };
        let key = SigningKey::from_bytes(&[KEYS[from]; 32]);
        let manifest = SnapshotManifest::new_signed(
            side.checkpoint().clone(),
            Vec::new(),
            None,
            DeviceId(HOSTS[from].into()),
            &key,
        )
        .expect("the manifest signs");
        let signer = key.verifying_key().to_bytes();
        let trust = |device: &str| (device == HOSTS[from]).then_some(signer);
        let authority = |_: &str, _: &str, _: &[u8; 32]| true;
        let returning = match verify_returning_base(
            GROUP,
            &manifest,
            &side.snapshot().canonical_encoding(),
            &trust,
            &authority,
        ) {
            Ok(returning) => returning,
            Err(error) => {
                self.violation(
                    "MergeRefused",
                    format!("{}'s base does not verify: {error}", HOSTS[from]),
                );
                return Some(false);
            }
        };
        match a.state.replica_coordinator.commit_foreign_merge(&returning) {
            Ok(committed) => {
                *self.reached.merges.entry(format!("{:?}", committed.order)).or_default() += 1;
                if committed.installed.is_some() {
                    self.reached.installs += 1;
                    if let Err(error) = a.repair() {
                        self.violation("Repair", error);
                    }
                }
                Some(true)
            }
            Err(error) => {
                self.violation(
                    "MergeRefused",
                    format!("{} refused {}'s base: {error}", HOSTS[into], HOSTS[from]),
                );
                Some(false)
            }
        }
    }

    /// Every device on one base, holding one `Gamma` and one tree.
    fn agreed(&self) -> bool {
        let bases: BTreeSet<_> = self.devs.iter().map(|d| d.base()).collect();
        if bases.len() != 1 {
            return false;
        }
        let gammas: Vec<_> =
            self.devs.iter().map(|d| d.gamma().ok().map(|g| gamma_key(&g))).collect();
        if gammas.iter().any(Option::is_none) || gammas.windows(2).any(|w| w[0] != w[1]) {
            return false;
        }
        let trees: Vec<_> = self.devs.iter().map(|d| d.tree()).collect();
        trees.windows(2).all(|w| w[0] == w[1])
            && self.devs.iter().all(|d| d.pending_obligations() == 0 && d.holds() == 0)
    }

    async fn wait_agreed(&self, budget: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + budget;
        loop {
            for d in self.devs {
                d.publish_pending().await;
                d.maintain().await;
            }
            if self.agreed() {
                return true;
            }
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    /// Heals everything, then merges until every device stands on one base
    /// and agrees on the tree.
    async fn converge(&mut self) -> bool {
        self.resolving = true;
        for a in 0..DEVICES {
            for b in a + 1..DEVICES {
                if self.cut(a, b) {
                    self.net(&NetFault::Heal { device_a: a, device_b: b });
                }
            }
        }
        for _ in 0..FINAL_MERGE_ROUNDS {
            let bases: BTreeSet<_> = self.devs.iter().map(|d| d.base()).collect();
            if bases.len() == 1 && self.wait_agreed(CONVERGE_BUDGET).await {
                return true;
            }
            for other in 1..DEVICES {
                self.merge(0, other).await;
            }
            for other in 1..DEVICES {
                self.merge(other, 0).await;
            }
        }
        false
    }

    /// The end-state oracles, over what every device holds now.
    fn check(&mut self, label: &str) {
        let trees: Vec<(usize, DiskTree)> = self.devs.iter().map(|d| (d.index, d.tree())).collect();
        for v in check_trees_converge(&trees) {
            self.violation("TreeDivergence", format!("{label}: {v:?}"));
        }
        let bases: BTreeSet<_> = self.devs.iter().map(|d| d.base()).collect();
        if bases.len() != 1 {
            self.violation(
                "BaseDivergence",
                format!("{label}: devices stand on {} bases", bases.len()),
            );
        }
        let mut gammas = Vec::new();
        for d in self.devs.iter() {
            let summary = match d.gamma() {
                Ok(summary) => summary,
                Err(error) => {
                    self.violation(
                        "Gamma",
                        format!("{label}: {} cannot summarize: {error}", HOSTS[d.index]),
                    );
                    continue;
                }
            };
            gammas.push(gamma_key(&summary));
            let kinds = d.kinds();
            let kind_of = |v: &[u8; 32]| kinds.get(v).copied();
            let heads = heads_by_path(&summary);
            let projection = match summary.project(kind_of) {
                Ok(projection) => projection,
                Err(error) => {
                    self.violation(
                        "ProjectionFailed",
                        format!("{label}: {}: {error}", HOSTS[d.index]),
                    );
                    continue;
                }
            };
            let nodes: ProjectedTree = projection.nodes().clone();
            for v in check_projection(&heads, &kind_of, &nodes) {
                self.violation("Projection", format!("{label}: {}: {v:?}", HOSTS[d.index]));
            }
            let tree = d.tree();
            // Every projected file holds the bytes of the version placed
            // there: two paths with their contents swapped, or a stale
            // version left at a path, keep every byte string somewhere in
            // the tree and would pass the content oracles below.
            let shas = d.leaf_shas();
            let sha_of = |entry: &yadorilink_replica_engine::namespace::PlacedEntry| {
                (entry.kind == RecordKind::File)
                    .then(|| shas.get(&entry.version_hash))
                    .flatten()
                    .map(|sha| ExpectedLeaf::FileSha256(sha.clone()))
            };
            // A projected file version the device does not store cannot be
            // checked byte for byte, and is itself a failure.
            let mut unknown_versions = BTreeSet::new();
            for (name, node) in &nodes {
                if let PhysicalNode::Entry(entry) = node {
                    if entry.kind == RecordKind::File && !shas.contains_key(&entry.version_hash) {
                        unknown_versions.insert(name.clone());
                    }
                }
            }
            if !unknown_versions.is_empty() {
                self.violation(
                    "DiskVsProjection",
                    format!(
                        "{label}: {} projects file versions it does not store at {unknown_versions:?}",
                        HOSTS[d.index]
                    ),
                );
            }
            // A file on disk the projection does not place: a stale copy,
            // or a version left behind at a name nothing places any more.
            // Every file a device holds here was written by a generated op
            // and captured, so none is the user's untracked content.
            let untracked: Vec<&String> = tree
                .iter()
                .filter(|(path, node)| !node.is_directory() && !nodes.contains_key(*path))
                .map(|(path, _)| path)
                .collect();
            if !untracked.is_empty() {
                self.violation(
                    "DiskVsProjection",
                    format!(
                        "{label}: {} holds files the projection does not place: {untracked:?}",
                        HOSTS[d.index]
                    ),
                );
            }
            let owned = d.engine_owned_directories();
            let (found, _) = check_disk_against_projection(
                d.index,
                &tree,
                &nodes,
                &|path: &str| owned.contains(path),
                sha_of,
            );
            for v in found {
                self.violation("DiskVsProjection", format!("{label}: {v:?}"));
            }
        }
        if gammas.windows(2).any(|w| w[0] != w[1]) {
            self.violation("GammaDivergence", format!("{label}: devices hold different heads"));
        }
        // Content: nothing lost, nothing invented. Only once the devices
        // agree: before that, a device missing a write it has not been able
        // to receive yet is the convergence failure already reported, not a
        // loss.
        if label == "unconverged" {
            return;
        }
        for (index, tree) in &trees {
            let present: BTreeSet<&String> = tree
                .values()
                .filter_map(|node| match node {
                    DiskNode::File { sha256 } => Some(sha256),
                    _ => None,
                })
                .collect();
            for sha in &present {
                if !self.ledger.by_sha.contains_key(*sha) {
                    self.violation(
                        "Corruption",
                        format!("{label}: {} holds bytes {sha} nobody wrote", HOSTS[*index]),
                    );
                }
            }
            let lost: Vec<String> = self
                .ledger
                .written
                .iter()
                .filter(|(id, _)| !self.ledger.superseded.contains(id))
                .filter(|(id, _)| {
                    let sha = sha256_hex(self.contents.get(**id).expect("a written content"));
                    !present.contains(&sha)
                })
                .map(|(id, (writer, path))| {
                    format!("content {id} ({} wrote {path})", HOSTS[*writer])
                })
                .collect();
            for what in lost {
                self.violation(
                    "ContentLoss",
                    format!(
                        "{label}: {} lost {what}, which no device overwrote or removed",
                        HOSTS[*index]
                    ),
                );
            }
        }
    }

    /// Bounded metadata and no stuck state, after a final seal.
    fn check_settled_metadata(&mut self) {
        for d in self.devs.iter() {
            for (what, sql) in [
                ("retained changes", "SELECT COUNT(*) FROM changes WHERE group_id = ?1"),
                ("orphan changes", "SELECT COUNT(*) FROM orphan_changes WHERE group_id = ?1"),
                ("pruned changes", "SELECT COUNT(*) FROM pruned_changes WHERE group_id = ?1"),
                (
                    "stored base snapshots beyond the installed one",
                    "SELECT COUNT(*) - 1 FROM change_checkpoint_snapshots WHERE group_id = ?1",
                ),
            ] {
                let n = d.count(sql);
                if n != 0 {
                    self.violation(
                        "UnboundedMetadata",
                        format!("{} holds {n} {what}", HOSTS[d.index]),
                    );
                }
            }
            if d.holds() != 0 || d.pending_obligations() != 0 {
                self.violation(
                    "StuckHold",
                    format!(
                        "{} ends with {} install hold(s) and {} projection obligation(s)",
                        HOSTS[d.index],
                        d.holds(),
                        d.pending_obligations()
                    ),
                );
            }
        }
    }
}

/// The outcome of one run: what was reached, what went wrong, and the case
/// that reproduces it.
struct Outcome {
    case: Case,
    reached: Reached,
    violations: Vec<Violation>,
}

fn carrier_config(
    faults: &SimFaultController,
    network: &TestNetwork,
    endpoint: iroh::EndpointId,
) -> NetworkConfig {
    NetworkConfig::over_custom_transport(
        faults.transport_for(network, endpoint).expect("a unique endpoint id"),
    )
    .with_address_lookup_override(Arc::new(network.address_lookup()))
}

async fn start_device(
    index: usize,
    faults: &SimFaultController,
    network: &TestNetwork,
) -> (Arc<Dev>, impl Sized) {
    let (state, dir) = device(HOSTS[index], KEYS[index]);
    init_staging_schema(&state);
    for peer in 0..DEVICES {
        if peer != index {
            pin(&state, HOSTS[peer], KEYS[peer]);
        }
    }
    let stack = Arc::new(
        SyncStack::spawn(
            state.clone(),
            Arc::new(FixtureAuthenticator),
            carrier_config(faults, network, endpoint_of(KEYS[index])),
        )
        .await
        .expect("the stack starts"),
    );
    let driver = ReconciliationDriver::start(state.clone(), stack.clone());
    state.install_reconciliation_driver(driver.clone());
    let folder = Arc::new(watch_folder(&state, &driver));
    let publisher = FixtureCheckpointSource::for_device(&state);
    (Arc::new(Dev { index, state, stack, driver, folder, publisher }), dir)
}

/// Runs `steps` (generated from `seed`, or replayed from a case) through one
/// simulation.
fn run_one(seed: u64, contents: ContentTable, steps: Vec<Step>) -> Outcome {
    // `DST_LOG=<env-filter>` routes the product's own tracing to stderr, for
    // reading one failing seed; off by default because logging overhead
    // changes the interleavings a sweep explores.
    if let Ok(filter) = std::env::var("DST_LOG") {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::new(filter))
            .with_writer(std::io::stderr)
            .try_init();
    }
    yadorilink_transport::sim_rand::seed_this_thread(seed);
    let mut sim = turmoil::Builder::new()
        .rng_seed(seed)
        .enable_random_order()
        .enable_tokio_io()
        .tick_duration(Duration::from_millis(10))
        .simulation_duration(Duration::from_secs(3600))
        .build();

    let network = TestNetwork::new();
    let faults = SimFaultController::new();
    let endpoints: Vec<iroh::EndpointId> = KEYS.iter().map(|key| endpoint_of(*key)).collect();

    let published: Arc<Mutex<Vec<Option<Arc<Dev>>>>> = Arc::new(Mutex::new(vec![None; DEVICES]));
    for (index, host) in HOSTS.iter().enumerate().skip(1) {
        let (network, faults, published) = (network.clone(), faults.clone(), published.clone());
        sim.host(*host, move || {
            let (network, faults, published) = (network.clone(), faults.clone(), published.clone());
            async move {
                let (dev, _dir) = start_device(index, &faults, &network).await;
                published.lock().expect("devices lock")[index] = Some(dev);
                std::future::pending::<()>().await;
                Ok(())
            }
        });
    }

    let outcome: Arc<Mutex<Option<Outcome>>> = Arc::new(Mutex::new(None));
    let outcome_out = outcome.clone();
    let done = Arc::new(AtomicBool::new(false));
    let done_in = done.clone();
    sim.client(HOSTS[0], async move {
        let (alice, _alice_dir) = start_device(0, &faults, &network).await;
        let devs: Vec<Arc<Dev>> = loop {
            {
                let mut slots = published.lock().expect("devices lock");
                slots[0] = Some(alice.clone());
                if slots.iter().all(Option::is_some) {
                    break slots.iter().map(|d| d.clone().expect("published")).collect();
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        };
        for a in 0..DEVICES {
            for b in a + 1..DEVICES {
                SyncStack::teach_each_other_for_tests(&devs[a].stack, &devs[b].stack);
            }
        }
        let injectors = DeviceNetworkFaults::substrate_only(CarrierFaults::new(
            faults.clone(),
            endpoints.clone(),
        ));
        let mut run = Run {
            devs: &devs,
            faults: &injectors,
            controller: &faults,
            endpoints: &endpoints,
            clock: HarnessClock::from_seed(seed),
            ledger: Ledger::new(&contents),
            contents: contents.clone(),
            violations: Vec::new(),
            reached: Reached::default(),
            resolving: false,
        };

        let mut executed: Vec<(u64, Step)> = Vec::new();
        for (round, step) in steps.into_iter().enumerate() {
            let round = round as u64;
            if !run.violations.is_empty() {
                break;
            }
            eprintln!("[history-epoch seed {seed} round {round}] {step:?}");
            if round == WARMUP_STEPS as u64 && !run.wait_agreed(CONVERGE_BUDGET).await {
                run.violation(
                    "WarmupConvergence",
                    "the devices never agreed before any fault".into(),
                );
                break;
            }
            match step {
                Step::Fs { device, op } => {
                    if run.fs(device, &op).await {
                        executed.push((round, Step::Fs { device, op }));
                    }
                }
                Step::WriteThrough { device, delete, content_id } => {
                    match run.await_write_through(device, delete, content_id).await {
                        Some(op) => {
                            if run.fs(device, &op).await {
                                run.reached.write_throughs += 1;
                                executed.push((round, Step::Fs { device, op }));
                            }
                        }
                        None => run.reached.write_throughs_without_copy += 1,
                    }
                }
                Step::Net(fault) => {
                    run.net(&fault);
                    executed.push((round, Step::Net(fault)));
                }
                Step::History(HistoryStep::Seal { device }) => {
                    run.seal(device).await;
                    executed.push((round, Step::History(HistoryStep::Seal { device })));
                }
                Step::History(HistoryStep::Merge { into, from }) => {
                    if run.merge(into, from).await.is_some() {
                        executed.push((round, Step::History(HistoryStep::Merge { into, from })));
                    }
                }
            }
        }

        if run.violations.is_empty() {
            if run.converge().await {
                run.check("converged");
                // A final seal on one device, adopted by the rest: sealing
                // must not change what anyone holds, and must leave nothing
                // behind.
                let before: Vec<DiskTree> = devs.iter().map(|d| d.tree()).collect();
                if run.seal(0).await {
                    // The others adopt it the way they met every base before:
                    // merging until one base stands.
                    if !run.converge().await {
                        run.violation(
                            "FinalSealConvergence",
                            "devices disagree after the final seal".into(),
                        );
                    }
                    let after: Vec<DiskTree> = devs.iter().map(|d| d.tree()).collect();
                    if before != after {
                        run.violation(
                            "SealObservable",
                            "the final seal and its adoption changed a device's tree".into(),
                        );
                    }
                    run.check("after the final seal");
                    run.check_settled_metadata();
                } else if run.violations.is_empty() {
                    run.violation(
                        "StuckSettle",
                        format!(
                            "a converged device could not be sealed: {}",
                            devs[0].describe_pending()
                        ),
                    );
                }
            } else {
                let states: Vec<String> = devs
                    .iter()
                    .map(|d| format!("{}: {}", HOSTS[d.index], d.describe_pending()))
                    .collect();
                run.violation(
                    "Convergence",
                    format!(
                        "the devices never agreed after every heal and merge:\n  {}",
                        states.join("\n  ")
                    ),
                );
                run.check("unconverged");
            }
        }

        let case = to_case(seed, &contents, &executed);
        *outcome_out.lock().expect("outcome lock") = Some(Outcome {
            case,
            reached: std::mem::take(&mut run.reached),
            violations: std::mem::take(&mut run.violations),
        });
        done_in.store(true, Ordering::Release);
        Ok(())
    });

    if let Err(error) = sim.run() {
        if !done.load(Ordering::Acquire) {
            panic!("seed {seed}: the simulation failed before the run finished: {error}");
        }
    }
    let recorded = outcome.lock().expect("outcome lock").take();
    recorded.expect("the run recorded its outcome")
}

fn steps_budget() -> usize {
    std::env::var("DST_OPS_BUDGET").ok().and_then(|v| v.parse().ok()).unwrap_or(DEFAULT_STEPS)
}

fn corpus_path() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/dst_corpus/history_epoch_chaos_cases.jsonl")
}

/// Writes a failing run's case where `cargo dst-targeted --case` can find
/// it. Curated entries -- with a note on what they turned out to be -- go
/// to the corpus by hand.
fn persist_failure(outcome: &Outcome) -> Option<std::path::PathBuf> {
    let dir = std::env::var("CARGO_TARGET_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target"))
        .join("dst-failures");
    std::fs::create_dir_all(&dir).ok()?;
    let path = dir.join(format!("dst_history_epoch_chaos-{}.json", outcome.case.seed));
    let entry = serde_json::json!({
        "scenario": "dst_history_epoch_chaos",
        "seed": outcome.case.seed,
        "case": outcome.case,
        "violations": outcome.violations.iter().map(|v| format!("{}: {}", v.kind, v.detail)).collect::<Vec<_>>(),
    });
    std::fs::write(&path, serde_json::to_string_pretty(&entry).ok()?).ok()?;
    Some(path)
}

fn report(label: &str, outcome: &Outcome) -> Result<(), String> {
    eprintln!("{label}: seed {} reached {:?}", outcome.case.seed, outcome.reached);
    if outcome.violations.is_empty() {
        return Ok(());
    }
    let saved = persist_failure(outcome);
    Err(format!(
        "{label}: seed {} failed ({} violation(s), case at {saved:?}):\n{}",
        outcome.case.seed,
        outcome.violations.len(),
        outcome
            .violations
            .iter()
            .map(|v| format!("  {}: {}", v.kind, v.detail))
            .collect::<Vec<_>>()
            .join("\n")
    ))
}

/// Every recorded case, replayed.
///
/// Fresh seeds are not part of the default run: open findings (see
/// [`fresh_seeds_converge_without_loss`]) still fail a known share of them,
/// and `xtask`'s DST lanes run this binary's default tests, so a fresh sweep
/// here would turn those lanes red on every run until the findings are fixed.
#[test]
fn seals_merges_and_directory_ops_under_partition_converge_without_loss() {
    let mut failures = Vec::new();
    if !dst_support::corpus::should_skip_replay() {
        for entry in dst_support::corpus::load_corpus(&corpus_path()) {
            let steps = match from_case(&entry.case) {
                Ok(steps) => steps,
                Err(error) => {
                    failures.push(error);
                    continue;
                }
            };
            let outcome = run_one(entry.case.seed, entry.case.content_table.clone(), steps);
            if let Err(error) = report("corpus", &outcome) {
                failures.push(error);
            }
        }
    }
    assert!(failures.is_empty(), "{} run(s) failed:\n{}", failures.len(), failures.join("\n"));
}

/// `DST_VARIATIONS` fresh seeds from `DST_BASE_SEED`.
///
/// Ignored because it is known red: the P9-B findings recorded in
/// `docs/design/history-base-epoch-compaction-plan.md` (copy rows with no
/// head in `Gamma` keep their obligations pending, an empty directory left
/// after `rm -rf` or a directory rename, and one author's two identical
/// heads at a conflict-copy name that no user can see to resolve -- seed
/// 41) fail a share of fresh seeds.
/// Run it by hand to sweep; un-ignore it once those are fixed.
#[test]
#[ignore = "known red on the open P9-B findings; a sweep, run by hand"]
fn fresh_seeds_converge_without_loss() {
    let base: u64 = std::env::var("DST_BASE_SEED")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_BASE_SEED);
    let variations: u64 = std::env::var("DST_VARIATIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_VARIATIONS);
    let mut failures = Vec::new();
    for seed in base..base + variations {
        let (contents, steps) = generate(seed, steps_budget());
        let outcome = run_one(seed, contents, steps);
        if let Err(error) = report("fresh", &outcome) {
            failures.push(error);
        }
    }
    assert!(failures.is_empty(), "{} run(s) failed:\n{}", failures.len(), failures.join("\n"));
}

/// D7 write-through, reached for certain: while two devices are cut
/// apart, one writes `f0` and `d1` as files and the other writes files
/// below both names. Healed, each path has to be a directory, and the
/// projection relocates each file beside it under a copy name that no
/// change authored -- the copy a write-through acts on. (A conflict copy of
/// a losing concurrent write is no such copy: the first device to see the
/// fork authors it durably, and an edit of it is an ordinary write at its
/// own name.) The user deletes one relocated file before any seal, while
/// the heads it writes through are the frontier's, and edits the other on
/// the second device after it installed the sealed base, where they are
/// the base's.
///
/// The generator draws write-throughs too, but a fresh run reaches one only
/// when such a copy happens to be on disk at that step, and a sweep of 60
/// seeds once reached none; this is what keeps the coverage from being
/// vacuous.
#[test]
fn a_write_through_on_a_relocated_copy_before_and_after_a_seal_loses_nothing() {
    const SEED: u64 = 0xD7;
    let mut contents = ContentTable::default();
    for id in 1..=9 {
        contents.insert(id, content_bytes(SEED, id));
    }
    let write = |device: usize, path: &str, content_id: u64| Step::Fs {
        device,
        op: Op::Write { path: path.into(), content_id },
    };
    let steps = vec![
        write(0, "w0", 1),
        write(1, "w1", 2),
        write(2, "w2", 3),
        Step::Net(NetFault::Partition { device_a: 0, device_b: 1 }),
        Step::Net(NetFault::Partition { device_a: 1, device_b: 2 }),
        write(0, "f0", 4),
        write(1, "f0/g", 5),
        write(0, "d1", 6),
        write(1, "d1/f4", 7),
        Step::Net(NetFault::Heal { device_a: 0, device_b: 1 }),
        Step::Net(NetFault::Heal { device_a: 1, device_b: 2 }),
        Step::WriteThrough { device: 0, delete: true, content_id: 8 },
        Step::History(HistoryStep::Seal { device: 0 }),
        Step::History(HistoryStep::Merge { into: 1, from: 0 }),
        Step::WriteThrough { device: 1, delete: false, content_id: 9 },
    ];
    let outcome = run_one(SEED, contents, steps);
    report("write-through", &outcome).unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(
        outcome.reached.write_throughs, 2,
        "both write-throughs must run on a copy the device showed, or D7 went untested: {:?}",
        outcome.reached
    );
}

/// One seed, for `cargo dst-replay`: `DST_SEED`, fresh from the generator.
#[test]
fn single_seed() {
    let Some(seed) = std::env::var("DST_SEED").ok().and_then(|v| v.parse().ok()) else {
        return;
    };
    let (contents, steps) = generate(seed, steps_budget());
    let outcome = run_one(seed, contents, steps);
    report("single", &outcome).unwrap_or_else(|error| panic!("{error}"));
}

/// Cheap and simulator-free: the generator emits every kind of step, and a
/// recorded case replays as the steps that produced it. Emitting a
/// write-through is not reaching one -- that takes a copy on disk when it
/// runs; `a_write_through_on_a_relocated_copy_...` is what asserts one runs.
#[test]
fn the_generator_reaches_every_step_and_a_case_round_trips() {
    let mut kinds = BTreeSet::new();
    for seed in 0..64u64 {
        let (contents, steps) = generate(seed, DEFAULT_STEPS);
        for step in &steps {
            kinds.insert(match step {
                Step::Fs { op, .. } => {
                    format!("{op:?}").split_whitespace().next().unwrap_or("").to_owned()
                }
                Step::WriteThrough { .. } => "WriteThrough".into(),
                Step::Net(NetFault::Partition { .. }) => "Partition".into(),
                Step::Net(NetFault::Heal { .. }) => "Heal".into(),
                Step::Net(other) => format!("{other:?}"),
                Step::History(HistoryStep::Seal { .. }) => "Seal".into(),
                Step::History(HistoryStep::Merge { .. }) => "Merge".into(),
            });
        }
        let concrete: Vec<(u64, Step)> = steps
            .iter()
            .enumerate()
            .filter(|(_, s)| !matches!(s, Step::WriteThrough { .. }))
            .map(|(i, s)| (i as u64, s.clone()))
            .collect();
        let case = to_case(seed, &contents, &concrete);
        let json = serde_json::to_string(&case).expect("a case serializes");
        let back: Case = serde_json::from_str(&json).expect("and deserializes");
        let replayed = from_case(&back).expect("a recorded case replays");
        assert_eq!(
            format!("{:?}", replayed),
            format!("{:?}", concrete.iter().map(|(_, s)| s.clone()).collect::<Vec<_>>()),
            "seed {seed}: the case does not replay as the steps it recorded"
        );
    }
    for kind in [
        "Write",
        "Edit",
        "Delete",
        "Mkdir",
        "RmTree",
        "RenameTree",
        "WriteThrough",
        "Partition",
        "Heal",
        "Seal",
        "Merge",
    ] {
        assert!(kinds.contains(kind), "the generator never emits {kind}: {kinds:?}");
    }
}

/// Every recorded case loads, and replays as steps this scenario can run:
/// a line the loader skipped, or one naming a topology or fault this
/// scenario does not have, would otherwise be silently not replayed.
#[test]
fn every_recorded_case_loads_and_replays_as_steps() {
    let text = std::fs::read_to_string(corpus_path()).unwrap_or_default();
    let lines = text.lines().filter(|line| !line.trim().is_empty()).count();
    let entries = dst_support::corpus::load_corpus(&corpus_path());
    assert_eq!(entries.len(), lines, "a corpus line did not load");
    for entry in &entries {
        let steps = from_case(&entry.case).unwrap_or_else(|error| panic!("{error}"));
        assert!(!steps.is_empty(), "case {} replays nothing", entry.case.seed);
        assert!(entry.note.is_some(), "case {} carries no note", entry.case.seed);
    }
}
