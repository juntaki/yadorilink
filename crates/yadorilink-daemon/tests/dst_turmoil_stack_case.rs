//! A `Case`'s fault schedule against the shipped propagation path.
//!
//! The two halves that were built separately, joined:
//!
//! ```text
//! Case::fault_schedule        (nanosecond offsets)
//!   ↓  run_schedule_from       -- when each fault fires
//!   ↓  DeviceNetworkFaults     -- one owner, every plane
//!   ├─ CarrierFaults → SimFaultController → iroh's custom carrier
//!   └─ ControlPlaneHosts      → turmoil::partition
//!          ↓
//!   two Turmoil hosts
//!          ↓
//!   DaemonState + SyncStack + ReconciliationDriver
//!          ↓
//!   Lane::Reconciliation, RBSR
//!          ↓
//!   the peer possesses the Change, or does not
//! ```
//!
//! `dst_turmoil_substrate_case.rs` drives the same schedule against a raw
//! block lane: cheaper, lower, and it answers "did the carrier stop the
//! bytes". This one answers "did the product stop syncing", which is a
//! different question with a different failure mode -- a carrier that cuts
//! correctly and a stack that syncs anyway would pass there and fail here.
//!
//! # The scenario writes files, and nothing else
//!
//! A `Case`'s `Op::Write` is a filesystem operation, so a scenario that also
//! had to stage a Change, publish a checkpoint or raise a commit would be
//! running a workload the `Case` does not describe. `watch_folder` puts the
//! production pipeline behind the folder -- `SimulatedFolderWatchSource`, the
//! real debouncer, `LocalChangeProcessor` with the device's own signing key,
//! `flush_pending_checkpoint`, then `note_local_change` in the order
//! `broadcast_change` uses -- so the scenario body writes a file and waits.
//!
//! No call to `sync_with` anywhere, and after the heal nothing is written and
//! nothing is nudged: the device has to notice by itself, through the driver,
//! or the last phase fails. A scenario that called `sync_with` after the heal
//! would prove reconciliation works when asked, which is covered elsewhere,
//! and would say nothing about whether a device recovers on its own.
//!
//! `sync_adapter::local_capture_tests` covers that pipeline on its own, with
//! the control this scenario cannot carry: that a file written with no
//! watcher event does *not* propagate. Without that control somewhere, every
//! convergence assertion here would also be satisfied by a background scan.
//!
//! # What "converge" means here, and what it does not
//!
//! **Changes, not files.** Every assertion below reads
//! `verified_change_store::servable_change_hashes` -- what a device can serve
//! over RBSR. Whether the bytes reach the peer's disk is a further question,
//! and this scenario does not ask it: its devices' folders exist to be
//! written *into*, so a `Case`'s ops have somewhere to happen.
//!
//! That is not a claim that projection is broken. `local_capture_tests`
//! measures the whole path layer by layer on fully linked devices, and the
//! retirement ledger records where it currently stops. The distinction
//! matters here only so a reader does not take "converged" to mean "both
//! devices have the file" -- and so that when the DST oracle suite
//! (`dst_support::oracle`), which compares on-disk state, is eventually
//! pointed at this runner, it is clear which layer had been covered before.
//!
//! # Why `Partition` cuts both planes
//!
//! Because that is what the `Case` means by it. A Change travels the
//! substrate, so cutting the substrate is what stops sync -- but two devices
//! whose control channel still carries traffic are degraded, not
//! partitioned. `DeviceNetworkFaults` owns both so a scenario cannot cut one
//! and report the other. The `sync partition` / `whole-device partition`
//! distinction itself is pinned in
//! `sync_adapter::turmoil_partition_tests`, which can name a substrate-only
//! cut; the `Case` IR deliberately cannot.

#![cfg(turmoil)]

mod dst_support;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use iroh::test_utils::test_transport::TestNetwork;
use yadorilink_daemon::daemon_state::DaemonState;
use yadorilink_daemon::sync_adapter::{ReconciliationDriver, SyncStack};
use yadorilink_daemon::test_support::sim_control_plane::ControlPlane;
use yadorilink_daemon::test_support::sync_stack_fixture::{
    device, endpoint_of, init_staging_schema, pin, possessed, watch_folder, FixtureAuthenticator,
    WatchedFolder, GROUP,
};
use yadorilink_lane_ports::sim_fault::SimFaultController;
use yadorilink_replica_domain::ids::{ChangeHash, FolderGroupId};
use yadorilink_sync_substrate::NetworkConfig;

use dst_support::case_ir::{ContentTable, Fault, NetFault, Op};
use dst_support::clock::HarnessClock;
use dst_support::device_network::{ControlPlaneHosts, DeviceNetworkFaults};
use dst_support::fault_carrier::CarrierFaults;
use dst_support::fault_schedule::{run_schedule_from, Activation, ScheduledInjectors};
use dst_support::op_applier::{apply_op, AppliedEffect};

/// Fixed per device index rather than per seed.
///
/// A `Case` names devices by index and its schedule may cut a link at offset
/// zero, so the index-to-endpoint mapping has to exist before either device
/// starts. `endpoint_of` derives the endpoint from the same key byte the
/// device is built with, which is what makes that possible. The seed varies
/// host ordering and message latency, not who anyone is.
const ALICE_KEY: u8 = 11;
const BOB_KEY: u8 = 22;
const ALICE_HOST: &str = "device-alice";
const BOB_HOST: &str = "device-bob";
const CONTROL_PORT: u16 = 9300;

/// The `Case`'s own schedule, in the nanoseconds `Case::fault_schedule`
/// carries. The cut is a constant; the heal is computed.
///
/// Computed because guessing it broke twice. The heal has to land after the
/// entire cut phase: if it fires inside, the phase's own assertions start
/// reporting a healed link, and the failure names whichever check ran first
/// -- "control traffic crossed a cut link" -- rather than the scheduling
/// mistake that caused it. Adding one op to the workload is enough to cross
/// that line, and it did.
///
/// So the offset is the sum of what the cut phase actually spends, plus
/// margin. A phase that grows moves the heal with it, and the class of bug
/// stops being representable.
///
/// The margin is paid in real seconds, not simulated ones: a partition does
/// not close the connections it cuts, and while an established QUIC
/// connection exists turmoil's paused clock stops auto-advancing
/// (`turmoil_clock_limits.rs` bisects exactly where).
const PARTITION_AT_NANOS: u64 = 1_000_000_000;

/// Everything the cut phase spends before it is allowed to see a heal.
const CUT_PHASE_BUDGET: Duration = Duration::from_nanos(
    SETTLE_AFTER_CUT.as_nanos() as u64
        + 4 * FLUSH_SETTLE.as_nanos() as u64
        + MUST_NOT_ARRIVE_WINDOW.as_nanos() as u64
        + CONTROL_CUT_BUDGET.as_nanos() as u64,
);

/// Enough that ordinary scheduling jitter cannot push a phase past the heal.
const CUT_PHASE_MARGIN: Duration = Duration::from_secs(10);

const HEAL_AT_NANOS: u64 =
    PARTITION_AT_NANOS + CUT_PHASE_BUDGET.as_nanos() as u64 + CUT_PHASE_MARGIN.as_nanos() as u64;

/// Past `PARTITION_AT_NANOS` however the healthy phase is scheduled.
const SETTLE_AFTER_CUT: Duration = Duration::from_secs(2);

/// How long a Change is given to reach the peer before the scenario concludes
/// it did not. Simulated, and only spent in full when nothing arrives.
const CONVERGE_BUDGET: Duration = Duration::from_secs(60);

/// How long the peer is watched, while cut, for a Change that must not
/// arrive. Long enough that "it had simply not arrived yet" is not an
/// available explanation, and short enough to finish before the heal.
const MUST_NOT_ARRIVE_WINDOW: Duration = Duration::from_secs(20);

/// After the heal the device has to notice by itself, which it does on the
/// driver's own backstop rather than on anything this scenario does.
const CATCH_UP_BUDGET: Duration = Duration::from_secs(120);

/// A control probe is a datagram and a reply, and while it is outstanding
/// the clock is Turmoil's -- a budget measured in simulated seconds can
/// elapse before the answering host has been scheduled at all. These are
/// caps, not waits: a healthy link answers on the first probe, and the
/// budget is only ever spent in full when the answer is "no".
const CONTROL_HEALTHY_BUDGET: Duration = Duration::from_secs(10);
const CONTROL_CUT_BUDGET: Duration = Duration::from_secs(4);

async fn within(budget: Duration, mut check: impl FnMut() -> bool) -> bool {
    let deadline = tokio::time::Instant::now() + budget;
    while tokio::time::Instant::now() < deadline {
        if check() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    check()
}

/// Performs one of a `Case`'s ops on a device's folder and reports it.
///
/// `op_applier::apply_op` is the same function every other `Case` consumer
/// uses to turn an `Op` into disk state, so nothing here interprets the
/// `Case` a second way. All this adds is the watcher event the OS would have
/// produced, which is the one thing a simulated folder has no other source
/// for.
///
/// The scenario does not stage a Change, publish a checkpoint or raise a
/// commit: `watch_folder` put the production pipeline behind this folder, so
/// what a `Case` describes is exactly what a scenario performs.
async fn apply_case_op(
    folder: &WatchedFolder,
    clock: &HarnessClock,
    contents: &ContentTable,
    op: &Op,
) {
    use yadorilink_filesystem_sync::watcher::FsChangeKind;

    let effect = apply_op(clock, folder.path(), op, contents).expect("apply the Case's op");
    let (relative, kind) = match &effect {
        AppliedEffect::Wrote { path, .. } => (path.clone(), FsChangeKind::CreatedOrModified),
        AppliedEffect::Removed { path } => (path.clone(), FsChangeKind::Removed),
        other => panic!("this scenario's Case uses only Write/Edit/Delete, got {other:?}"),
    };
    folder.notify(folder.path().join(relative), kind).await;
}

/// Long enough for the debouncer to close a quiet period and flush.
///
/// Ops are spaced by this on purpose. The debouncer coalesces, which is what
/// it is for: a Write and an Edit of one path inside a single quiet period
/// reach the peer as ONE Change carrying the edited content, and a Write
/// followed by a Delete inside one period reaches it as nothing at all.
/// Correct, and it makes "how many Changes should have arrived" a question
/// about event spacing rather than about the product.
///
/// A `Case` does carry spacing -- `DeviceTimeline`'s `virtual_ts` -- but that
/// is a round counter that drives no scheduling, and mapping it onto
/// simulated time is the open question `Case::fault_schedule`'s own doc
/// records. Until that is settled, this scenario spaces its own ops and says
/// so, rather than reading a number that does not mean what it looks like.
const FLUSH_SETTLE: Duration = Duration::from_secs(2);

/// A small pool of shared paths, as the chaos scenarios use.
///
/// Shared on purpose: paths that no two devices ever both touch cannot
/// produce the concurrent pair this scenario is about.
const PATH_POOL: [&str; 4] = ["alpha.bin", "beta.bin", "gamma.bin", "delta.bin"];

/// This scenario's `Case` workload, derived from the seed.
///
/// The seed picks which paths each device owns, which path they contest, and
/// whether each device edits or deletes its own file while cut. A fixed
/// workload would make every seed explore the same ops under a different host
/// ordering, which is half a sweep.
///
/// What the seed does NOT vary is the *shape*: one write per device, then one
/// mutation each plus a contested pair. The scenario's assertions depend on
/// that shape -- two devices must hold different sets before converging, and
/// the contested writes must be a genuine concurrent pair -- so a generator
/// free to emit any op sequence would need the assertions rewritten as an
/// oracle rather than as phases. That is what
/// `dst_support::generator` + the oracle suite are for, and the step after
/// this one.
///
/// Write, Edit and Delete only. `apply_case_op` refuses the rest by name
/// rather than silently skipping, so widening the pool is a visible change.
fn workload(seed: u64) -> (ContentTable, Vec<Op>, Vec<Op>) {
    use rand::rngs::StdRng;
    use rand::{RngExt, SeedableRng};

    let mut rng = StdRng::seed_from_u64(seed);
    let mut paths: Vec<&str> = PATH_POOL.to_vec();
    // A seeded shuffle, so which path each device owns and which is contested
    // differs per seed while all three stay distinct.
    for index in (1..paths.len()).rev() {
        paths.swap(index, rng.random_range(0..=index));
    }
    let (alice_path, bob_path, contested) = (paths[0], paths[1], paths[2]);

    let mut contents = ContentTable::default();
    for (id, byte) in [(1u64, 0x11u8), (2, 0x22), (3, 0x33), (4, 0x44)] {
        contents.insert(id, vec![byte; 4096]);
    }

    // Each device either edits its own file or deletes it while cut. Both
    // are "a durably observed local change", and they reach the peer as
    // different things -- superseding content, and a tombstone.
    let mutate = |path: &str, delete: bool, content_id: u64| {
        if delete {
            Op::Delete { path: path.to_string() }
        } else {
            Op::Edit { path: path.to_string(), content_id }
        }
    };
    let (alice_deletes, bob_deletes) = (rng.random_bool(0.5), rng.random_bool(0.5));

    (
        contents,
        // Healthy: one file per device, on its own path.
        vec![
            Op::Write { path: alice_path.to_string(), content_id: 1 },
            Op::Write { path: bob_path.to_string(), content_id: 1 },
        ],
        // Cut: each device mutates its own file, and both write the contested
        // path with different content. That last pair is the one that
        // matters: two writes to one path with neither causally after the
        // other is the shape a durable local write gets silently discarded
        // in, and it is the property `dst_two_device_chaos` exists for.
        vec![
            mutate(alice_path, alice_deletes, 2),
            mutate(bob_path, bob_deletes, 2),
            Op::Write { path: contested.to_string(), content_id: 3 },
            Op::Write { path: contested.to_string(), content_id: 4 },
        ],
    )
}

/// What a device can serve, as a set.
///
/// Sorted rather than compared as the `Vec` the store returns: two devices'
/// rows arriving in the same order is a property of how they were inserted,
/// not of convergence, and a scenario that compared raw `Vec`s would pass or
/// fail on that.
fn servable(state: &Arc<DaemonState>, group: &FolderGroupId) -> Vec<ChangeHash> {
    let mut hashes = possessed(state, group);
    hashes.sort();
    hashes
}

/// Applies one op and waits for the debouncer to flush it, so each op reaches
/// the peer as its own Change rather than coalescing with its neighbour.
async fn apply_and_settle(
    folder: &WatchedFolder,
    clock: &HarnessClock,
    contents: &ContentTable,
    op: &Op,
) {
    apply_case_op(folder, clock, contents, op).await;
    tokio::time::sleep(FLUSH_SETTLE).await;
}

/// The simulated substrate for one device: the carrier a `Case` can cut, and
/// the address lookup that carrier's network answers with.
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

/// One simulation: two hosts, two stacks, one `Case` schedule, three phases.
fn run_one(seed: u64) -> turmoil::Result {
    // The transport's backoff jitter is application randomness; turmoil's rng
    // does not reach it, and unseeded it would read the wall clock.
    yadorilink_transport::sim_rand::seed_this_thread(seed);
    let mut sim = turmoil::Builder::new()
        .rng_seed(seed)
        // Distinct seeds must reach distinct host orderings, or running
        // several proves nothing beyond running one several times.
        .enable_random_order()
        // iroh's endpoint watches network interfaces through netlink, which
        // panics outright on a runtime with the I/O driver off.
        .enable_tokio_io()
        .tick_duration(Duration::from_millis(10))
        .simulation_duration(Duration::from_secs(900))
        .build();

    // Everything shared is fixed before either host starts, so the `Case`'s
    // device indices resolve to endpoints that exist from offset zero.
    let network = TestNetwork::new();
    let faults = SimFaultController::new();
    let (alice_endpoint, bob_endpoint) = (endpoint_of(ALICE_KEY), endpoint_of(BOB_KEY));

    // Bob publishes his stack, state and watched folder so the scenario can
    // pin the pair together and drive ops on either device, and flags himself
    // ready once he exists on both planes.
    //
    // The folder is published rather than built by the scenario because the
    // capture pipeline behind it has to run on Bob's own host: its debouncer
    // and its executor are tasks, and a task belongs to the host that spawned
    // it. What crosses is the handle, and what it carries is a filesystem
    // write plus a channel send -- neither of which is host-bound.
    let bob_stack_out: Arc<Mutex<Option<Arc<SyncStack>>>> = Arc::new(Mutex::new(None));
    let bob_state_out: Arc<Mutex<Option<Arc<DaemonState>>>> = Arc::new(Mutex::new(None));
    let bob_folder_out: Arc<Mutex<Option<Arc<WatchedFolder>>>> = Arc::new(Mutex::new(None));
    let ready = Arc::new(AtomicBool::new(false));

    let (bn, bf, bstack, bstate, bfolder, bready) = (
        network.clone(),
        faults.clone(),
        bob_stack_out.clone(),
        bob_state_out.clone(),
        bob_folder_out.clone(),
        ready.clone(),
    );
    sim.host(BOB_HOST, move || {
        let (network, faults, stack_out, state_out, folder_out, ready) = (
            bn.clone(),
            bf.clone(),
            bstack.clone(),
            bstate.clone(),
            bfolder.clone(),
            bready.clone(),
        );
        async move {
            let (bob, _bob_dir) = device(BOB_HOST, BOB_KEY);
            init_staging_schema(&bob);
            pin(&bob, ALICE_HOST, ALICE_KEY);

            let stack = Arc::new(
                SyncStack::spawn(
                    bob.clone(),
                    Arc::new(FixtureAuthenticator),
                    carrier_config(&faults, &network, bob_endpoint),
                )
                .await
                .expect("bob's stack starts"),
            );
            let bob_driver = ReconciliationDriver::start(bob.clone(), stack.clone());
            bob.install_reconciliation_driver(bob_driver.clone());
            let folder = Arc::new(watch_folder(&bob, &bob_driver));

            let control = ControlPlane::bind(CONTROL_PORT).await;
            control.answer_probes();

            *stack_out.lock().expect("bob stack lock") = Some(stack);
            *state_out.lock().expect("bob state lock") = Some(bob);
            *folder_out.lock().expect("bob folder lock") = Some(folder);
            ready.store(true, Ordering::Release);
            // The device stays up for the rest of the run, and `_bob_dir` has
            // to outlive the stack that stores into it.
            std::future::pending::<()>().await;
            Ok(())
        }
    });

    sim.client(ALICE_HOST, async move {
        let group = FolderGroupId(GROUP.into());
        let (alice, _alice_dir) = device(ALICE_HOST, ALICE_KEY);
        init_staging_schema(&alice);
        pin(&alice, BOB_HOST, BOB_KEY);

        let alice_stack = Arc::new(
            SyncStack::spawn(
                alice.clone(),
                Arc::new(FixtureAuthenticator),
                carrier_config(&faults, &network, alice_endpoint),
            )
            .await
            .expect("alice's stack starts"),
        );

        let control = ControlPlane::bind(CONTROL_PORT).await;
        let bob_control_addr = std::net::SocketAddr::new(turmoil::lookup(BOB_HOST), CONTROL_PORT);

        // Both devices exist on both planes before anything is measured.
        // Taking the fault epoch after this is deliberate: measuring a
        // `Case`'s offsets from "the scenario started" would fold endpoint
        // startup into the `Case`'s own timing, differently on every run.
        while !ready.load(Ordering::Acquire) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let bob_stack = bob_stack_out.lock().expect("bob stack lock").clone().expect("bob's stack");
        let bob = bob_state_out.lock().expect("bob state lock").clone().expect("bob");
        let bob_folder =
            bob_folder_out.lock().expect("bob folder lock").clone().expect("bob's folder");
        SyncStack::teach_each_other_for_tests(&alice_stack, &bob_stack);

        let alice_driver = ReconciliationDriver::start(alice.clone(), alice_stack);
        alice.install_reconciliation_driver(alice_driver.clone());

        // One owner, both planes. The substrate knows devices by
        // `EndpointId`, the control plane by Turmoil host name, and the
        // `Case`'s index is what joins them.
        let injectors =
            ScheduledInjectors::new().with_carrier(DeviceNetworkFaults::with_control_plane(
                CarrierFaults::new(faults.clone(), vec![alice_endpoint, bob_endpoint]),
                ControlPlaneHosts::new(vec![ALICE_HOST.to_string(), BOB_HOST.to_string()]),
            ));
        let schedule = vec![
            (PARTITION_AT_NANOS, Fault::Net(NetFault::Partition { device_a: 0, device_b: 1 })),
            (HEAL_AT_NANOS, Fault::Net(NetFault::Heal { device_a: 0, device_b: 1 })),
        ];

        // Phase 1: healthy. Without this the rest says nothing -- a pair that
        // never synced would stop syncing just as convincingly.
        let folder = watch_folder(&alice, &alice_driver);
        let clock = HarnessClock::from_seed(seed);
        let (contents, healthy_ops, cut_ops) = workload(seed);

        // Both devices author, because sync is not one-directional and a
        // scenario in which only one device ever writes would let a
        // receive-only peer pass as a converged one.
        apply_and_settle(&folder, &clock, &contents, &healthy_ops[0]).await;
        let alice_authored = servable(&alice, &group);
        apply_and_settle(&bob_folder, &clock, &contents, &healthy_ops[1]).await;
        let bob_authored = servable(&bob, &group);
        assert!(
            !alice_authored.is_empty() && !bob_authored.is_empty(),
            "seed {seed}: a device authored nothing from its own filesystem ({} and {}), so \
             nothing below is about the network",
            alice_authored.len(),
            bob_authored.len()
        );
        // What makes the convergence below a merge rather than a formality:
        // each device put something into it that the other did not have.
        //
        // Stated as Bob's own contribution rather than as "the two sets
        // differ", which is what this used to be. That version read both
        // sets after both had settled, and `apply_and_settle` waits for the
        // debouncer -- so sync had a window to run inside that wait, and
        // when it did, the sets matched and the precondition failed on the
        // devices having worked. It survived only because the window was
        // small; G3-G6 deleted the legacy dial, the iroh session keeper
        // connects sooner, and the window closed. This says the same thing
        // and does not depend on sync being slow.
        let bobs_own: Vec<_> =
            bob_authored.iter().filter(|hash| !alice_authored.contains(hash)).collect();
        assert!(
            !bobs_own.is_empty(),
            "seed {seed}: the second device added nothing of its own -- it holds {bob_authored:?} \
             and the first had already authored all of it, so converging on that set would say \
             nothing about sync being two-directional"
        );
        let authored: Vec<_> = {
            let mut union = alice_authored.clone();
            union.extend(bob_authored.iter().copied());
            union.sort();
            union.dedup();
            union
        };
        assert!(
            within(CONVERGE_BUDGET, || servable(&alice, &group) == authored
                && servable(&bob, &group) == authored)
            .await,
            "seed {seed}: the two devices did not converge on what both had written before \
             the Case cut anything"
        );
        assert!(
            control.can_reach(bob_control_addr, CONTROL_HEALTHY_BUDGET).await,
            "seed {seed}: the devices could not reach each other before the Case cut anything"
        );

        // The Case's clock starts HERE, not at the top of the scenario.
        //
        // Reaching a first convergence costs about 36 seconds of simulated
        // time -- two stacks starting, exchanging addresses and running a
        // first RBSR round -- and how much simulated time that consumes
        // depends on how often the hosts are scheduled, which depends on the
        // machine. An earlier version took the epoch before phase 1 and the
        // whole schedule elapsed inside it: by phase 2 the partition had
        // fired AND been healed, so `!is_partitioned` at the end of phase 1
        // passed for the wrong reason and phase 2 failed with "the partition
        // never reached the carrier".
        //
        // That is not a tuning problem to be fixed by moving the offsets out.
        // A `Case`'s offsets mean "this long after the system is up and
        // working", and startup is not part of what the `Case` describes.
        // Folding it in would make every offset depend on machine load, which
        // is the one thing a deterministic harness must not do.
        assert!(
            !faults.is_partitioned(alice_endpoint, bob_endpoint),
            "seed {seed}: the link was cut before the Case's clock even started"
        );
        let fault_epoch = tokio::time::Instant::now();
        let scheduler = {
            let injectors = injectors.clone();
            tokio::spawn(async move { run_schedule_from(fault_epoch, schedule, injectors).await })
        };

        // Phase 2: the Case's partition stops sync and isolates the devices.
        //
        // One fidelity gap worth naming rather than discovering. The device
        // publishes its checkpoint through `FixtureCheckpointSource`, which is
        // in-process and always answers -- so a write authored here reaches
        // Published while the device is partitioned. A real device asks a
        // coordination plane over the network, and a partitioned one may get
        // no answer, leaving the Change Pending and unservable until it does.
        //
        // That does not weaken what this scenario asserts, because the
        // question here is whether a *published* Change crosses a cut link,
        // and answering it needs a published Change to exist. But a scenario
        // whose subject is "what happens to a write authored during an
        // outage" would need the coordination plane to be cuttable too, and
        // it is not yet: `Case`'s `Partition` reaches the substrate and
        // Turmoil's own network, and the checkpoint issuer sits on neither.
        tokio::time::sleep(SETTLE_AFTER_CUT).await;
        assert!(
            faults.is_partitioned(alice_endpoint, bob_endpoint),
            "seed {seed}: the Case's partition never reached the carrier"
        );
        let dropped_before = faults.dropped_datagrams();

        apply_and_settle(&folder, &clock, &contents, &cut_ops[0]).await;
        apply_and_settle(&bob_folder, &clock, &contents, &cut_ops[1]).await;
        // The contested path. Both devices write it while neither can see the
        // other, so neither write is causally after the other -- which is the
        // only way to author a genuine concurrent pair.
        let alice_before_contest = servable(&alice, &group);
        let bob_before_contest = servable(&bob, &group);
        apply_and_settle(&folder, &clock, &contents, &cut_ops[2]).await;
        apply_and_settle(&bob_folder, &clock, &contents, &cut_ops[3]).await;
        let alice_contested: Vec<_> = servable(&alice, &group)
            .into_iter()
            .filter(|hash| !alice_before_contest.contains(hash))
            .collect();
        let bob_contested: Vec<_> = servable(&bob, &group)
            .into_iter()
            .filter(|hash| !bob_before_contest.contains(hash))
            .collect();
        assert_eq!(
            (alice_contested.len(), bob_contested.len()),
            (1, 1),
            "seed {seed}: the contested write did not produce exactly one Change on each \
             device, so what converges below is not a concurrent pair"
        );
        assert_ne!(
            alice_contested, bob_contested,
            "seed {seed}: both devices produced the SAME Change for the contested path, so \
             there is no concurrency here to lose"
        );

        let after_cut: Vec<_> = {
            let mut union = servable(&alice, &group);
            union.extend(servable(&bob, &group).iter().copied());
            union.sort();
            union.dedup();
            union
        };
        assert!(
            after_cut.len() > authored.len(),
            "seed {seed}: the ops applied while cut produced no new Change, so the peer has \
             nothing to be missing and this phase asserts nothing"
        );
        assert!(
            !within(MUST_NOT_ARRIVE_WINDOW, || servable(&alice, &group) == after_cut
                || servable(&bob, &group) == after_cut)
            .await,
            "seed {seed}: a Change crossed a link the Case had cut"
        );
        assert!(
            faults.dropped_datagrams() > dropped_before,
            "seed {seed}: the link is cut but nothing was discarded, so the attempts never \
             reached the carrier and this phase would pass with the fault removed"
        );
        assert!(
            !control.can_reach(bob_control_addr, CONTROL_CUT_BUDGET).await,
            "seed {seed}: control traffic crossed a link the Case had cut, so these devices \
             were not partitioned -- only their substrate was"
        );
        assert!(
            faults.is_partitioned(alice_endpoint, bob_endpoint),
            "seed {seed}: the heal fired while the cut phase was still running, so the \
             non-arrival above may just be a window that expired"
        );

        // Phase 3: the Case's heal, and nothing else. Nothing is authored and
        // nothing is driven -- the device notices by itself or this fails.
        scheduler
            .await
            .expect("the scheduler task")
            .expect("the schedule must not name a device this run does not have");
        assert!(
            !faults.is_partitioned(alice_endpoint, bob_endpoint),
            "seed {seed}: the Case's heal never reached the carrier"
        );
        assert!(
            within(CATCH_UP_BUDGET, || servable(&alice, &group) == after_cut
                && servable(&bob, &group) == after_cut)
            .await,
            "seed {seed}: the peer never caught up on the Change authored while partitioned"
        );
        let healed = servable(&bob, &group);
        assert!(
            authored.iter().all(|hash| healed.contains(hash)),
            "seed {seed}: catching up lost a Change the peer already had, which is worse than \
             not catching up"
        );
        // The property `dst_two_device_chaos` exists for: a durably observed
        // local write is never silently discarded except by a causally-later
        // one. These two are concurrent, so neither supersedes the other and
        // BOTH have to survive on both devices. A merge that picked a winner
        // and dropped the loser would converge perfectly and lose a write.
        for (owner, contested) in [("alice", &alice_contested), ("bob", &bob_contested)] {
            for hash in contested {
                assert!(
                    servable(&alice, &group).contains(hash)
                        && servable(&bob, &group).contains(hash),
                    "seed {seed}: {owner}'s concurrent write to the contested path did not \
                     survive on both devices -- a write was discarded by one that was not \
                     causally after it"
                );
            }
        }

        // Both planes took both faults, and the fault plan took neither --
        // one owner per variant.
        let trace = injectors.trace();
        assert!(
            matches!(
                trace.as_slice(),
                [
                    Activation::Carried { outcome: cut, .. },
                    Activation::Carried { outcome: healed, .. }
                ] if cut.fully_applied() && healed.fully_applied()
            ),
            "seed {seed}: the schedule's network faults did not all go to the carrier: {trace:?}"
        );
        assert!(
            injectors.net_plan().partition_windows.is_empty(),
            "seed {seed}: the fault plan opened a partition window too, so this link had two \
             owners"
        );
        for activation in &trace {
            if let Activation::Carried { outcome, at_nanos } = activation {
                assert!(
                    outcome.control.is_some(),
                    "seed {seed}: the fault at {at_nanos}ns reached no control plane, so this \
                     scenario cut only the substrate"
                );
            }
        }

        Ok(())
    });

    sim.run()
}

/// Several seeds, because `enable_random_order` gives each a different host
/// ordering, and catch-up after a heal is exactly the kind of property that
/// holds for one ordering of two hosts and not another.
#[test]
fn a_cases_partition_stops_sync_and_its_heal_lets_the_device_catch_up() {
    for seed in dst_support::seeds(4) {
        run_one(seed).unwrap_or_else(|e| panic!("seed {seed} failed: {e}"));
    }
}

/// Distinct seeds must produce distinct workloads.
///
/// The control for calling this workload seed-derived. Without it, a shuffle
/// that happened to be a no-op -- or a seed that never reached the RNG --
/// would leave every seed exploring the same ops under a different host
/// ordering, which is half a sweep wearing the name of a whole one. Costs
/// nothing: no simulation, no devices, no network.
#[test]
fn distinct_seeds_produce_distinct_workloads() {
    let rendered = |seed: u64| {
        let (_, healthy, cut) = workload(seed);
        format!("{healthy:?}|{cut:?}")
    };

    let seeds: Vec<String> = (0..8u64).map(rendered).collect();
    let distinct: std::collections::BTreeSet<&String> = seeds.iter().collect();
    assert!(
        distinct.len() > 1,
        "every seed produced the same workload, so the sweep varies only host ordering: {}",
        seeds[0]
    );

    // And the same seed twice is the same workload, or a failing seed could
    // not be replayed -- which is the whole reason the harness is seeded.
    assert_eq!(rendered(3), rendered(3), "the same seed produced two different workloads");
}

/// Whatever the seed picks, the shape the scenario's assertions depend on
/// holds: three distinct paths, and a contested pair with different content.
///
/// A seeded shuffle that let two of the three collide would make the devices
/// share a path in the healthy phase, and "the two devices hold different
/// sets before converging" would fail for a reason that has nothing to do
/// with the product.
#[test]
fn every_seed_keeps_the_shape_the_assertions_rely_on() {
    for seed in 0..32u64 {
        let (_, healthy, cut) = workload(seed);

        let path_of = |op: &Op| match op {
            Op::Write { path, .. } | Op::Edit { path, .. } | Op::Delete { path } => path.clone(),
            other => panic!("seed {seed}: unexpected op {other:?}"),
        };

        let (alice_path, bob_path) = (path_of(&healthy[0]), path_of(&healthy[1]));
        let contested = path_of(&cut[2]);
        assert_ne!(alice_path, bob_path, "seed {seed}: both devices were given the same path");
        assert_ne!(contested, alice_path, "seed {seed}: the contested path is Alice's own");
        assert_ne!(contested, bob_path, "seed {seed}: the contested path is Bob's own");

        assert_eq!(path_of(&cut[3]), contested, "seed {seed}: the contested pair split paths");
        match (&cut[2], &cut[3]) {
            (Op::Write { content_id: a, .. }, Op::Write { content_id: b, .. }) => assert_ne!(
                a, b,
                "seed {seed}: both devices wrote the SAME content to the contested path, so \
                 there is no concurrency to lose"
            ),
            other => panic!("seed {seed}: the contested pair is not two writes: {other:?}"),
        }

        assert_eq!(path_of(&cut[0]), alice_path, "seed {seed}: Alice mutated someone else's file");
        assert_eq!(path_of(&cut[1]), bob_path, "seed {seed}: Bob mutated someone else's file");
    }
}
