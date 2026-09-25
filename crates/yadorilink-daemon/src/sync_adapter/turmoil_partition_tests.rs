//! Cutting the substrate stops sync while the devices can still reach each
//! other.
//!
//! This file holds exactly one property, and it is here rather than in the
//! `Case`-driven runner because **the `Case` IR cannot express it**. A
//! `Case`'s `NetFault::Partition` means "these two devices cannot reach each
//! other", and `DeviceNetworkFaults` therefore cuts every plane at once --
//! deliberately, so a scenario cannot cut one plane and report a device
//! partition it never had. There is no way to write "substrate only" as a
//! `Case`, and there should not be.
//!
//! So the division of labour is:
//!
//! * `tests/dst_turmoil_stack_case.rs` -- whole-device partition, heal, and
//!   automatic catch-up, driven from a `Case`'s fault schedule, swept over
//!   seeds. That is where robustness across host orderings is proven.
//! * here -- a substrate-only cut, one scenario, one seed. Not a robustness
//!   sweep: a statement that the two cuts are different cuts, which is the
//!   thing no amount of seeds on the Case runner can say.
//!
//! `driver_tests` pins that one device's own local-commit event moves a
//! Change to the other through the assembled stack. This takes that
//! arrangement unchanged -- same devices, same netmap pinning, same
//! `SyncStack::spawn`, same `ReconciliationDriver`, same single
//! `note_local_change` -- and changes two things: the devices run on separate
//! Turmoil hosts, and their substrate runs on a carrier a test can cut.
//!
//! Nothing here calls `sync_with`. A test that drove reconciliation by hand
//! would show that reconciliation works when asked, which is covered
//! elsewhere, and would say nothing about whether a device notices it has
//! work to do.
//!
//! # What carries a Change, and what does not
//!
//! Worth stating because a scenario that assumes otherwise fails in a way
//! that looks like a simulation bug. A local commit propagates like this:
//!
//! ```text
//! DaemonState::note_local_commit_for_group
//!   -> ReconciliationDriver::note_local_change   (a Wake::Group, nothing more)
//!   -> SyncStack::sync_with(peer, group)
//!   -> SyncRuntime::sync_once
//!   -> opens Lane::Reconciliation on the SUBSTRATE and runs RBSR over it
//! ```
//!
//! Nothing else carries a Change. A pair of `PeerSyncSession`s wired
//! together without a `SyncStack` and a driver syncs whatever existed at
//! startup and nothing afterwards: nothing is missing from the sessions, the
//! layer above them is simply absent. That is why this file builds the stack
//! rather than the sessions.
//!
//! The control plane this file also builds carries no Change and is not a
//! transport under test. It exists to answer one question -- can these two
//! hosts reach each other at all -- and it is a bare datagram echo on
//! Turmoil's own network, cut by `turmoil::partition` and by nothing the
//! substrate's faults do. See `test_support::sim_control_plane`.
//!
//! # Two partitions, not one
//!
//! Since a Change travels the substrate, cutting the substrate is what stops
//! sync. It is not what isolates a device: two devices whose control channel
//! still carries traffic are degraded, not partitioned, and calling that a
//! partition would report an isolation the run never had.
//!
//! * **Sync partition** -- the substrate only. Sync stops; the devices can
//!   still reach each other. Proven here.
//! * **Whole-device partition** -- every plane. Nothing reaches anything.
//!   Proven by the `Case` runner.
//!
//! The reachability assertion is what separates them, and it is asserted
//! rather than assumed: a test that checked only that sync had stopped could
//! not tell a substrate cut from an isolation it never produced.

#![cfg(turmoil)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::daemon_state::DaemonState;
use yadorilink_lane_ports::sim_fault::SimFaultController;
use yadorilink_replica_domain::ids::{ChangeHash, FolderGroupId};
use yadorilink_sync_sqlite::verified_change_store;
use yadorilink_sync_substrate::NetworkConfig;

use super::driver::ReconciliationDriver;
use super::sync_stack::SyncStack;
use crate::test_support::sim_control_plane::ControlPlane;
use crate::test_support::sync_stack_fixture::{
    change_putting, device, file_version, honest_bundle_carrying, init_staging_schema, pin,
    possessed, FixtureAuthenticator, GROUP,
};

const ALICE_KEY: u8 = 11;
const BOB_KEY: u8 = 22;
const ALICE_HOST: &str = "device-alice";
const BOB_HOST: &str = "device-bob";
const CONTROL_PORT: u16 = 9200;

/// The endpoint identity a device with this signing key will have.
///
/// `SyncStack::spawn` hands the device signing key straight to
/// `SubstrateNode::spawn_as_device`, so knowing the key is knowing the
/// endpoint -- which is what lets a partition be declared against a device
/// that has not started yet.
fn endpoint_of(key_byte: u8) -> iroh::EndpointId {
    iroh::SecretKey::from_bytes(&[key_byte; 32]).public()
}

/// The one plane this file cuts, and the endpoints it cuts between.
///
/// It holds the substrate and nothing else, which is the whole point: the
/// control plane stays up, so what the cut produces is a sync partition and
/// not an isolation.
///
/// `dst_support::device_network::DeviceNetworkFaults` is the same job driven
/// from a `Case`'s device indices rather than from a test's own names, and it
/// is what `tests/dst_turmoil_stack_case.rs` uses for the whole-device cut.
/// They are deliberately not shared, and the asymmetry is the reason: that
/// one cuts every plane at once so a `Case` cannot report a partition it
/// never had, and this one names a single plane precisely so that it can
/// leave the other alone -- which is what the Case IR refuses to let a
/// scenario do.
struct DeviceLink {
    substrate: SimFaultController,
    endpoints: (iroh::EndpointId, iroh::EndpointId),
}

impl DeviceLink {
    /// Stops sync without isolating the devices: the substrate carries the
    /// reconciliation lane, and the control plane is left untouched.
    fn cut_sync(&self) {
        self.substrate.partition(self.endpoints.0, self.endpoints.1);
    }

    fn heal_sync(&self) {
        self.substrate.heal(self.endpoints.0, self.endpoints.1);
    }
}

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

/// Stages a Change on `state` and raises the one event a local commit raises.
fn author(
    state: &Arc<DaemonState>,
    driver: &Arc<ReconciliationDriver>,
    group: &FolderGroupId,
    path: &str,
    fill: u8,
    seq: i64,
) -> ChangeHash {
    let version = file_version(4096, fill);
    let change = change_putting(path, &version);
    state
        .replica_coordinator
        .database()
        .write_immediate::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            verified_change_store::stage_verified_bundles(
                conn,
                std::slice::from_ref(&honest_bundle_carrying(
                    change.clone(),
                    vec![version.clone()],
                )),
                seq,
            )
        })
        .unwrap();
    driver.note_local_change(group);
    change.compute_hash()
}

/// The scenario body: two hosts, two stacks, two drivers, a control channel,
/// and a `DeviceLink` that cuts the substrate.
///
/// This was once parameterised over which planes to cut, so that a
/// substrate-only run and a whole-device run could be the same code and the
/// difference in outcome attributable to that alone. The whole-device half
/// has moved to `tests/dst_turmoil_stack_case.rs`, where the `Case` runner
/// already builds the same stack and asserts the same unreachability across
/// seeds, so running it twice bought nothing and cost a minute. What holds
/// the comparison together now is that both sides assert reachability
/// explicitly -- here that it survives, there that it does not -- rather than
/// either side leaving it unmeasured.
///
/// `seed` varies what the simulation is free to vary: which host runs next
/// and how long each message takes. Not the devices' identities, which stay
/// fixed -- a partition is declared against an endpoint before that endpoint
/// starts, so it has to be knowable from the key.
fn run_partition_scenario(seed: u64) {
    // The transport's jitter is the application's own randomness, and
    // turmoil's rng does not reach it.
    yadorilink_transport::sim_rand::seed_this_thread(seed);
    let mut sim = turmoil::Builder::new()
        .rng_seed(seed)
        // Without this a seed only redraws link latencies, and the two hosts
        // always run in the same order -- which is most of what a second seed
        // is for here.
        .enable_random_order()
        // iroh watches network interfaces through netlink, which panics
        // outright on a runtime with the I/O driver off.
        .enable_tokio_io()
        .simulation_duration(Duration::from_secs(900))
        .build();

    let network = iroh::test_utils::test_transport::TestNetwork::new();
    let faults = SimFaultController::new();
    let (alice_endpoint, bob_endpoint) = (endpoint_of(ALICE_KEY), endpoint_of(BOB_KEY));

    let bob_stack_out: Arc<std::sync::Mutex<Option<Arc<SyncStack>>>> =
        Arc::new(std::sync::Mutex::new(None));
    let bob_state_out: Arc<std::sync::Mutex<Option<Arc<DaemonState>>>> =
        Arc::new(std::sync::Mutex::new(None));
    let ready = Arc::new(AtomicBool::new(false));

    let (bn, bf, bstack, bstate, bready) = (
        network.clone(),
        faults.clone(),
        bob_stack_out.clone(),
        bob_state_out.clone(),
        ready.clone(),
    );
    sim.host(BOB_HOST, move || {
        let (network, faults, stack_out, state_out, ready) =
            (bn.clone(), bf.clone(), bstack.clone(), bstate.clone(), bready.clone());
        async move {
            let (bob, _bob_dir) = device(BOB_HOST, BOB_KEY);
            init_staging_schema(&bob);
            pin(&bob, ALICE_HOST, ALICE_KEY);

            let config = NetworkConfig::over_custom_transport(
                faults.transport_for(&network, bob_endpoint).expect("a unique endpoint id"),
            )
            .with_address_lookup_override(Arc::new(network.address_lookup()));
            let stack = Arc::new(
                SyncStack::spawn(bob.clone(), Arc::new(FixtureAuthenticator), config)
                    .await
                    .expect("bob's stack starts"),
            );
            bob.install_reconciliation_driver(ReconciliationDriver::start(
                bob.clone(),
                stack.clone(),
            ));

            let control = ControlPlane::bind(CONTROL_PORT).await;
            control.answer_probes();

            *stack_out.lock().expect("bob stack lock") = Some(stack);
            *state_out.lock().expect("bob state lock") = Some(bob);
            ready.store(true, Ordering::Release);
            // The device stays up for the rest of the run; its `_bob_dir`
            // has to outlive the stack that stores into it.
            std::future::pending::<()>().await;
            Ok(())
        }
    });

    sim.client(ALICE_HOST, async move {
        let group = FolderGroupId(GROUP.into());
        let (alice, _alice_dir) = device(ALICE_HOST, ALICE_KEY);
        init_staging_schema(&alice);
        pin(&alice, BOB_HOST, BOB_KEY);

        let config = NetworkConfig::over_custom_transport(
            faults.transport_for(&network, alice_endpoint).expect("a unique endpoint id"),
        )
        .with_address_lookup_override(Arc::new(network.address_lookup()));
        let alice_stack = Arc::new(
            SyncStack::spawn(alice.clone(), Arc::new(FixtureAuthenticator), config)
                .await
                .expect("alice's stack starts"),
        );

        let control = ControlPlane::bind(CONTROL_PORT).await;

        // Both devices exist on both planes before anything is measured.
        while !ready.load(Ordering::Acquire) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let bob_stack = bob_stack_out.lock().expect("bob stack lock").clone().expect("bob's stack");
        let bob = bob_state_out.lock().expect("bob state lock").clone().expect("bob");
        SyncStack::teach_each_other_for_tests(&alice_stack, &bob_stack);

        let alice_driver = ReconciliationDriver::start(alice.clone(), alice_stack);
        alice.install_reconciliation_driver(alice_driver.clone());

        let bob_control_addr = std::net::SocketAddr::new(turmoil::lookup(BOB_HOST), CONTROL_PORT);
        let link =
            DeviceLink { substrate: faults.clone(), endpoints: (alice_endpoint, bob_endpoint) };

        // Phase 1: healthy. Without this the rest says nothing -- a pair
        // that never synced would stop syncing just as convincingly.
        let first = author(&alice, &alice_driver, &group, "before.bin", 0x11, 1);
        assert!(
            within(Duration::from_secs(60), || possessed(&bob, &group).contains(&first)).await,
            "seed {seed}: a Change did not reach the peer before anything was cut"
        );
        assert!(
            control.can_reach(bob_control_addr, Duration::from_secs(20)).await,
            "seed {seed}: the devices could not reach each other before anything was cut"
        );

        // Phase 2: cut, by whichever of the two this scenario is about.
        link.cut_sync();
        let second = author(&alice, &alice_driver, &group, "during.bin", 0x22, 2);
        assert!(
            !within(Duration::from_secs(25), || possessed(&bob, &group).contains(&second)).await,
            "seed {seed}: a Change crossed a cut substrate"
        );
        assert!(
            faults.dropped_datagrams() > 0,
            "seed {seed}: the substrate is cut but nothing was discarded, so the attempts \
             never reached the carrier and this would pass with the fault removed"
        );
        // The whole point of the file. Without this the scenario would be
        // indistinguishable from the Case runner's whole-device partition,
        // and there would be no reason for it to exist.
        assert!(
            control.can_reach(bob_control_addr, Duration::from_secs(10)).await,
            "seed {seed}: the devices could not reach each other with only their substrate \
             cut, so this ran a whole-device partition and proved nothing the Case runner \
             does not already prove"
        );

        // Phase 3: healed. Nothing authored, nothing driven -- the device
        // has to notice on its own.
        link.heal_sync();
        assert!(
            within(Duration::from_secs(120), || possessed(&bob, &group).contains(&second)).await,
            "seed {seed}: the peer never caught up after the link healed"
        );
        assert!(
            possessed(&bob, &group).contains(&first),
            "seed {seed}: catching up lost a Change the peer already had"
        );

        Ok(())
    });

    sim.run().expect("the simulation must complete");
}

/// One scenario, one seed.
///
/// Not a robustness sweep, on purpose. What this file asserts is that a
/// substrate-only cut is a *different* cut from a whole-device one, and that
/// is a statement about which planes were touched, not about host ordering.
/// Robustness across orderings is the `Case` runner's job, which sweeps
/// seeds against the same stack -- paying for a second multi-seed sweep here
/// would buy nothing and cost a minute of every run.
#[test]
fn cutting_only_the_substrate_stops_sync_while_the_devices_still_reach_each_other() {
    run_partition_scenario(1);
}
