//! The deterministic fault-schedule scheduler: the runtime piece that fires
//! a `Case`'s `fault_schedule` against the simulated clock.
//!
//! The three fault injectors (`fault::FaultingChannel` for the network,
//! `fault_disk::FaultingBlockStore` for the block store, and
//! `fault_sqlite::FaultingSyncState` for the index database) each replay a
//! *pure* plan (`FaultPlan` / `DiskFaultPlan` / `SqliteFaultPlan`). Until now
//! a scenario constructed each injector with one fixed plan up front and had
//! no way to turn a fault window on or off partway through a run: the
//! `Case::fault_schedule` (a `Vec<(virtual_ts, Fault)>`) had no runtime that
//! activated/cleared those windows at the scheduled simulated-clock points.
//!
//! This module is that runtime. It owns each injector's *active plan* behind
//! interior mutability (`Arc<Mutex<..Plan>>`), so a plan a scheduled entry
//! mutates is picked up by whatever consults the shared handle -- an injector
//! built to read the current plan sees the window open or close the instant
//! the scheduler flips it, with no change to the existing (plan-by-value)
//! decorators. `run_schedule` is the async task that sleeps to each entry's
//! offset on `tokio::time` (the simulated clock under `--cfg turmoil`) and
//! applies it, fully deterministically: the same schedule replays an
//! identical activation timeline, entry for entry, from a seed alone.
//!
//! Binding to each injector:
//!   * `Fault::Net(_)`  -> the network `FaultPlan` handle. `Partition`/`Heal`
//!     open/close a partition window; `Drop`/`Duplicate`/`Delay`/`Reorder`
//!     engage the matching every-Nth class.
//!   * `Fault::Disk(_)` -> the block-store `DiskFaultPlan` handle, except the
//!     two index-database members of `DiskFault` (`SqliteBusy`/`SqliteLocked`,
//!     which the block-store decorator itself documents as out of its scope)
//!     route to the SQLite `SqliteFaultPlan` handle instead.
//!   * `Fault::ClockSkew`/`ClockJump` and `Fault::Crash`/`Restart` are
//!     out of scope at this layer (there is no clock-injector or
//!     device-lifecycle seam here to drive); they are recorded in the trace
//!     as `Deferred` so the timeline still accounts for every entry, but no
//!     plan is mutated. `DiskFault::FsyncFail` is `Deferred` for the same
//!     reason the disk decorator gives: the `BlockStore` trait exposes no
//!     separate durability/flush step to fail.
//!
//! Consuming the live plans: the existing decorators take a plan *by value*
//! at construction, so the intended binding is to snapshot the current active
//! plan from the handle at each decision point and run the injector's own pure
//! decision engine against it -- e.g.
//! `FaultingChannel::new(injectors.net_plan()).decide(now)`. Because
//! `net_plan()` returns whatever the scheduler has installed *now*, a decision
//! taken before a window opens and one taken after it observe different plans
//! with no interior-mutability retrofit to `FaultingChannel` itself. The unit
//! tests below exercise exactly that against the real `FaultingChannel`.
//!
//! Gated on the simulation cfgs like every DST scenario file.

#![cfg(turmoil)]
#![allow(dead_code)] // not every scenario drives every injector/accessor yet

use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::case_ir::{DiskFault, Fault, FaultPlan, NetFault};
#[cfg(turmoil)]
use super::device_network::PlaneOutcomes;
use super::fault_disk::DiskFaultPlan;
use super::fault_sqlite::{ScheduledFault, SqliteFaultKind, SqliteFaultPlan, SqliteOp};

/// The simulated delay a `NetFault::Reorder` entry installs. Reorder
/// manifests as a heterogeneous delay (a delayed message lands after later,
/// undelayed ones), matching `FaultPlan`'s own reorder-via-delay model; the
/// class is engaged on every 2nd message so some messages overtake others.
const REORDER_DELAY_NANOS: i64 = 1_000_000;

/// A large-but-finite run length for an engaged SQLite fault window: "fault
/// this op from its next call until the window is cleared". Finite so the
/// per-op sequence arithmetic in `ScheduledFault::covers` never has to reason
/// about an unbounded run.
const SQLITE_ENGAGED_RUN_LEN: u64 = u64::MAX;

/// Which injector a scheduled entry acted on. Used only in the activation
/// trace, so a replay-determinism check compares *which* injector each entry
/// touched, not just the resulting plan state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InjectorKind {
    Net,
    Disk,
    Sqlite,
}

/// One applied schedule entry, in the order the scheduler applied it. The
/// full sequence of these is the deterministic "activation trace" a replay
/// must reproduce byte for byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Activation {
    /// A fault window opened on `injector` at simulated offset `at_nanos`.
    Engaged { at_nanos: u64, injector: InjectorKind },
    /// A fault window closed on `injector` (e.g. a `Heal`) at `at_nanos`.
    Cleared { at_nanos: u64, injector: InjectorKind },
    /// An entry recognized but not applied at this layer (a clock/lifecycle
    /// fault, or `FsyncFail`), recorded so the timeline still accounts for it.
    Deferred { at_nanos: u64 },
    /// Handed to the simulated substrate's datagram carrier rather than to
    /// an injector here.
    ///
    /// Distinct from `Engaged`/`Cleared` on purpose: those say a plan in
    /// this process changed, and a reader of the trace should be able to
    /// tell "the fault plan now says partitioned" from "the carrier now
    /// drops these datagrams". They are different mechanisms with different
    /// blast radii, and collapsing them would make a scenario that thought
    /// it had both look identical to one that had either.
    #[cfg(turmoil)]
    Carried { at_nanos: u64, outcome: PlaneOutcomes },
}

/// Shared, interior-mutable handles to the three injectors' *active* fault
/// plans, plus the activation trace the scheduler appends to. Cheap to clone
/// (every field is an `Arc`), so the same set of handles is shared by the
/// scheduler task, the code consulting the injectors, and a test that wants
/// to observe activations as they happen.
#[derive(Clone)]
pub struct ScheduledInjectors {
    net: Arc<Mutex<FaultPlan>>,
    disk: Arc<Mutex<DiskFaultPlan>>,
    sqlite: Arc<Mutex<SqliteFaultPlan>>,
    trace: Arc<Mutex<Vec<Activation>>>,
    /// Who owns `Partition`/`Heal` for this run.
    ///
    /// `None` -- the historical arrangement -- leaves them to the `FaultPlan`
    /// below, where a partition is a window the in-process channel decorator
    /// consults. `Some` hands them to the simulated substrate's carrier
    /// instead, where a partition discards real datagrams.
    ///
    /// Ownership per variant, not per injector, and exactly one owner each:
    /// a scenario that drove both would cut the link twice and heal it once,
    /// or heal a `FaultPlan` partition that was never opened. The remaining
    /// `NetFault` variants (`Drop`, `Delay`, `Reorder`, `Duplicate`) stay
    /// with the `FaultPlan` in either arrangement, because the carrier
    /// cannot express them yet.
    #[cfg(turmoil)]
    carrier: Option<super::device_network::DeviceNetworkFaults>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl ScheduledInjectors {
    /// All three injectors start with their default (empty) plan -- i.e. no
    /// injected faults until the schedule opens a window.
    pub fn new() -> Self {
        Self {
            net: Arc::new(Mutex::new(FaultPlan::default())),
            disk: Arc::new(Mutex::new(DiskFaultPlan::default())),
            sqlite: Arc::new(Mutex::new(SqliteFaultPlan::default())),
            trace: Arc::new(Mutex::new(Vec::new())),
            #[cfg(turmoil)]
            carrier: None,
        }
    }

    /// Hands `Partition`/`Heal` to the simulated substrate's carrier for the
    /// rest of this run.
    ///
    /// Takes ownership of those two variants away from the `FaultPlan`
    /// rather than adding to it. A scenario running on the real substrate
    /// wants a partition that discards datagrams, not a window an in-process
    /// channel decorator consults -- and certainly not both, which would cut
    /// the link twice and heal it once.
    #[cfg(turmoil)]
    pub fn with_carrier(mut self, carrier: super::device_network::DeviceNetworkFaults) -> Self {
        self.carrier = Some(carrier);
        self
    }

    /// A snapshot of the network injector's current active plan. Build a
    /// `FaultingChannel` from this at a decision point to apply whatever
    /// window the schedule has open *now*.
    pub fn net_plan(&self) -> FaultPlan {
        lock(&self.net).clone()
    }

    /// A snapshot of the block-store injector's current active plan.
    pub fn disk_plan(&self) -> DiskFaultPlan {
        lock(&self.disk).clone()
    }

    /// A snapshot of the index-database injector's current active plan.
    pub fn sqlite_plan(&self) -> SqliteFaultPlan {
        lock(&self.sqlite).clone()
    }

    /// True once any network fault window is open (the plan differs from the
    /// inert default).
    pub fn net_active(&self) -> bool {
        *lock(&self.net) != FaultPlan::default()
    }

    /// True once any block-store fault window is open.
    pub fn disk_active(&self) -> bool {
        *lock(&self.disk) != DiskFaultPlan::default()
    }

    /// True once any index-database fault window is open.
    pub fn sqlite_active(&self) -> bool {
        !lock(&self.sqlite).faults.is_empty()
    }

    /// The activation trace so far, in application order.
    pub fn trace(&self) -> Vec<Activation> {
        lock(&self.trace).clone()
    }

    /// Clears every injector back to its inert default and records nothing --
    /// a scenario teardown convenience (the IR has no disk/index "heal"
    /// variant, so a scenario that wants to close a disk/index window between
    /// phases resets here rather than through a schedule entry).
    pub fn clear_all(&self) {
        *lock(&self.net) = FaultPlan::default();
        *lock(&self.disk) = DiskFaultPlan::default();
        *lock(&self.sqlite) = SqliteFaultPlan::default();
    }

    /// Applies one schedule entry at simulated offset `at_nanos`, mutating the
    /// target injector's active plan and appending to the trace. Pure w.r.t.
    /// the wall clock: the effect depends only on `(at_nanos, fault)`, never
    /// on real time, so replaying the same entries yields the same trace.
    fn apply(&self, at_nanos: u64, fault: &Fault) -> Result<(), ScheduleError> {
        match fault {
            Fault::Net(net_fault) => return self.apply_net(at_nanos, net_fault),
            Fault::Disk(disk_fault) => self.apply_disk(at_nanos, disk_fault),
            // No clock-injector or device-lifecycle seam exists at this layer;
            // recorded so the timeline is complete, not applied.
            Fault::ClockSkew { .. }
            | Fault::ClockJump { .. }
            | Fault::Crash { .. }
            | Fault::Restart { .. } => self.record(Activation::Deferred { at_nanos }),
        }
        Ok(())
    }

    fn apply_net(&self, at_nanos: u64, net_fault: &NetFault) -> Result<(), ScheduleError> {
        // `Partition`/`Heal` belong to the carrier when there is one, and to
        // the plan below when there is not. Never to both: see `carrier`'s
        // own comment.
        #[cfg(turmoil)]
        if matches!(net_fault, NetFault::Partition { .. } | NetFault::Heal { .. }) {
            if let Some(carrier) = &self.carrier {
                let outcome = carrier.apply(&Fault::Net(net_fault.clone()));
                self.record(Activation::Carried { at_nanos, outcome });
                if let Some(device) = outcome.unknown_device() {
                    return Err(ScheduleError::UnknownDevice { at_nanos, device });
                }
                return Ok(());
            }
        }
        let mut plan = lock(&self.net);
        let activation = match net_fault {
            NetFault::Partition { .. } => {
                // An open-ended cut from now on; a later `Heal` closes it.
                plan.partition_windows = vec![(0, i64::MAX)];
                Activation::Engaged { at_nanos, injector: InjectorKind::Net }
            }
            NetFault::Heal { .. } => {
                // Only the partition. This reset the whole plan, which meant
                // a `Heal` also switched off steady packet loss, added
                // latency and reordering -- and `dst_network_fault_chaos`
                // engages all three at offset zero before it partitions, so
                // its heal quietly returned the network to perfect health.
                // The scenario went on believing it was testing recovery
                // under a lossy link.
                plan.partition_windows.clear();
                Activation::Cleared { at_nanos, injector: InjectorKind::Net }
            }
            NetFault::Drop => {
                plan.drop_every = 1;
                Activation::Engaged { at_nanos, injector: InjectorKind::Net }
            }
            NetFault::Duplicate => {
                plan.duplicate_every = 1;
                Activation::Engaged { at_nanos, injector: InjectorKind::Net }
            }
            NetFault::Delay { millis } => {
                plan.delay_every = 1;
                plan.delay_nanos = millis_to_nanos(*millis);
                Activation::Engaged { at_nanos, injector: InjectorKind::Net }
            }
            NetFault::Reorder => {
                plan.delay_every = 2;
                plan.delay_nanos = REORDER_DELAY_NANOS;
                Activation::Engaged { at_nanos, injector: InjectorKind::Net }
            }
        };
        drop(plan);
        self.record(activation);
        Ok(())
    }

    fn apply_disk(&self, at_nanos: u64, disk_fault: &DiskFault) {
        // The two index-database members of `DiskFault` drive the SQLite
        // injector, not the block store (the block-store decorator documents
        // them as out of its scope).
        match disk_fault {
            DiskFault::SqliteBusy => {
                self.engage_sqlite(SqliteFaultKind::Busy);
                self.record(Activation::Engaged { at_nanos, injector: InjectorKind::Sqlite });
                return;
            }
            DiskFault::SqliteLocked => {
                self.engage_sqlite(SqliteFaultKind::Locked);
                self.record(Activation::Engaged { at_nanos, injector: InjectorKind::Sqlite });
                return;
            }
            // No fsync/flush seam on the `BlockStore` trait to fail here.
            DiskFault::FsyncFail => {
                self.record(Activation::Deferred { at_nanos });
                return;
            }
            _ => {}
        }
        let mut plan = lock(&self.disk);
        match disk_fault {
            DiskFault::Enospc => plan.enospc_every = 1,
            DiskFault::Eio => plan.eio_every = 1,
            DiskFault::TornWrite => plan.torn_write_every = 1,
            DiskFault::SlowIo { millis } => {
                plan.slow_io_every = 1;
                plan.slow_io_nanos = millis_to_nanos(*millis);
            }
            // Handled above.
            DiskFault::FsyncFail | DiskFault::SqliteBusy | DiskFault::SqliteLocked => {
                unreachable!()
            }
        }
        drop(plan);
        self.record(Activation::Engaged { at_nanos, injector: InjectorKind::Disk });
    }

    fn engage_sqlite(&self, kind: SqliteFaultKind) {
        lock(&self.sqlite).faults.push(ScheduledFault {
            op: SqliteOp::UpsertFile,
            first_seq: 1,
            run_len: SQLITE_ENGAGED_RUN_LEN,
            kind,
        });
    }

    fn record(&self, activation: Activation) {
        lock(&self.trace).push(activation);
    }
}

impl Default for ScheduledInjectors {
    fn default() -> Self {
        Self::new()
    }
}

fn millis_to_nanos(millis: u64) -> i64 {
    (millis as i64).saturating_mul(1_000_000)
}

/// Fires `schedule` against the simulated clock: for each `(virtual_ts,
/// Fault)` entry (in nondecreasing `virtual_ts` order, ties applied in input
/// order), sleeps until `virtual_ts` nanoseconds past the moment this task
/// started, then flips the matching injector's active plan on/off.
///
/// Deterministic by construction: the sleeps run on `tokio::time` (the
/// simulated clock under `--cfg turmoil`), the schedule is stable-sorted so
/// equal timestamps keep input order, and `apply` depends only on
/// `(offset, fault)`. The same schedule therefore produces an identical
/// activation trace on every replay.
///
/// Takes owned values so the task is `'static` (spawnable): a scenario clones
/// the `ScheduledInjectors` handle (cheap -- all `Arc`s) to keep its own copy
/// for the injectors it built from the same handles.
/// Why a schedule stopped early.
///
/// The only way it can. Everything else a fault entry may turn out to be --
/// deferred, unimplemented, meant for another injector -- is recorded and
/// stepped past, because those are things a schedule is entitled to contain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScheduleError {
    /// A `Case` named a device this run has no endpoint for.
    ///
    /// Fail-closed, and this is the whole reason the outcome is carried out
    /// of the adapter at all. A corpus entry generated for a three-device
    /// topology, replayed against two, would otherwise partition nothing and
    /// let the run finish green while its report claimed a fault it never
    /// injected. A scenario that cannot inject what it was asked to inject
    /// has not run, and should say so rather than pass.
    #[cfg(turmoil)]
    UnknownDevice { at_nanos: u64, device: usize },
}

impl std::fmt::Display for ScheduleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(turmoil)]
            ScheduleError::UnknownDevice { at_nanos, device } => write!(
                f,
                "the schedule names device {device} at {at_nanos}ns, and this run has no \
                 endpoint for it -- the Case's topology and the run's do not match"
            ),
            #[cfg(not(turmoil))]
            _ => unreachable!("ScheduleError has no variants outside a turmoil build"),
        }
    }
}

impl std::error::Error for ScheduleError {}

/// [`run_schedule_from`] with the epoch taken at the call.
///
/// For a scenario whose schedule starts when the scheduler does. Anything
/// with setup worth excluding should name its epoch instead.
pub async fn run_schedule(
    schedule: Vec<(u64, Fault)>,
    injectors: ScheduledInjectors,
) -> Result<(), ScheduleError> {
    run_schedule_from(tokio::time::Instant::now(), schedule, injectors).await
}

/// Fires each entry at `epoch + offset`, where the offsets are the
/// nanoseconds `Case::fault_schedule` carries.
///
/// The epoch is a parameter because it was previously "whenever this task
/// happened to be spawned", which is not a property of the `Case` and not
/// something a scenario controls. A scenario that builds two devices,
/// completes a handshake and then spawns the scheduler had already spent an
/// unknown part of its own schedule before the first entry could fire, and
/// two runs of the same `Case` differed by however long setup took. Naming
/// the epoch lets a scenario say "faults are measured from the moment both
/// devices were ready", which is the thing the `Case` actually means.
///
/// # "Ready" means synced, not started
///
/// Take the epoch **after** the healthy phase, not before it. Bringing two
/// stacks up and reaching a first convergence costs tens of seconds of
/// *simulated* time, and how much depends on how often the hosts happen to be
/// scheduled -- which depends on the machine. Fold that into the `Case`'s own
/// timing and its offsets become load-dependent, which is the one thing a
/// deterministic harness must not allow.
///
/// The failure this produces is quiet, which is why it is written down here.
/// `dst_turmoil_stack_case.rs` took the epoch before its healthy phase, and a
/// 1s partition and a 30s heal both fired inside a 36s convergence. Its
/// end-of-phase-1 "nothing is cut yet" assertion then passed -- because the
/// link had been cut *and healed again* -- and the run failed two phases
/// later claiming the partition never reached the carrier. The offsets were
/// right; the epoch was wrong. It had also passed a four-seed sweep on a less
/// loaded machine, so a green run is not evidence against this.
pub async fn run_schedule_from(
    epoch: tokio::time::Instant,
    mut schedule: Vec<(u64, Fault)>,
    injectors: ScheduledInjectors,
) -> Result<(), ScheduleError> {
    // Defensive stable sort: the IR states `fault_schedule` is already sorted
    // by `virtual_ts`, but sorting here makes the scheduler correct for an
    // out-of-order input too, and `sort_by_key` is stable so same-timestamp
    // entries stay in input order (the deterministic tie-break).
    schedule.sort_by_key(|(ts, _)| *ts);

    for (ts, fault) in &schedule {
        let target = epoch + Duration::from_nanos(*ts);
        let now = tokio::time::Instant::now();
        if target > now {
            tokio::time::sleep(target - now).await;
        }
        injectors.apply(*ts, fault)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::fault::{FaultDecision, FaultingChannel};
    use super::*;

    /// Every test below needs virtual time -- a window scheduled at 1ms and
    /// a budget measured in seconds must both resolve instantly -- and none
    /// needs a verdict carried back out. `sim::block_on` is that.
    fn sim_block_on<F: std::future::Future<Output = ()> + 'static>(
        f: impl FnOnce() -> F + 'static,
    ) {
        super::super::sim::block_on(1, f);
    }

    /// With a carrier installed, `Partition` is the carrier's and the
    /// `FaultPlan` must not also open a window for it.
    ///
    /// Both driving the same fault is the failure this ownership split
    /// exists to prevent: the link would be cut in two places and healed in
    /// one, so a scenario would carry a partition past the heal that was
    /// supposed to end it and never find out why.
    #[cfg(turmoil)]
    #[test]
    fn a_carrier_owns_partition_and_the_plan_does_not() {
        use super::super::device_network::DeviceNetworkFaults;
        use super::super::fault_carrier::CarrierFaults;
        use yadorilink_lane_ports::sim_fault::SimFaultController;

        let controller = SimFaultController::new();
        let a = iroh::SecretKey::from_bytes(&[1; 32]).public();
        let b = iroh::SecretKey::from_bytes(&[2; 32]).public();
        let injectors = ScheduledInjectors::new().with_carrier(
            DeviceNetworkFaults::substrate_only(CarrierFaults::new(controller.clone(), vec![a, b])),
        );

        injectors
            .apply(0, &Fault::Net(NetFault::Partition { device_a: 0, device_b: 1 }))
            .expect("a known device");

        assert!(controller.is_partitioned(a, b), "the carrier was not told to cut the link");
        assert!(
            injectors.net_plan().partition_windows.is_empty(),
            "the fault plan opened a partition window as well, so this link is cut twice and \
             one heal will not close it"
        );
        assert!(matches!(
            injectors.trace().as_slice(),
            [Activation::Carried { outcome, .. }] if outcome.fully_applied()
        ));

        injectors
            .apply(1, &Fault::Net(NetFault::Heal { device_a: 0, device_b: 1 }))
            .expect("a known device");
        assert!(!controller.is_partitioned(a, b), "the carrier was not told to heal the link");
    }

    /// The variants the carrier cannot express stay with the plan even when
    /// a carrier is installed. Ownership is per variant, not per injector.
    #[cfg(turmoil)]
    #[test]
    fn a_carrier_does_not_take_the_faults_it_cannot_express() {
        use super::super::device_network::DeviceNetworkFaults;
        use super::super::fault_carrier::CarrierFaults;
        use yadorilink_lane_ports::sim_fault::SimFaultController;

        let a = iroh::SecretKey::from_bytes(&[1; 32]).public();
        let b = iroh::SecretKey::from_bytes(&[2; 32]).public();
        let injectors =
            ScheduledInjectors::new().with_carrier(DeviceNetworkFaults::substrate_only(
                CarrierFaults::new(SimFaultController::new(), vec![a, b]),
            ));

        injectors.apply(0, &Fault::Net(NetFault::Drop)).expect("a known device");

        assert_eq!(
            injectors.net_plan().drop_every,
            1,
            "a Drop went to the carrier, which cannot express it, so it was injected nowhere"
        );
    }

    /// Without a carrier, nothing changes. The historical arrangement is
    /// still the one every existing scenario runs.
    #[test]
    fn without_a_carrier_partition_stays_with_the_plan() {
        let injectors = ScheduledInjectors::new();

        injectors
            .apply(0, &Fault::Net(NetFault::Partition { device_a: 0, device_b: 1 }))
            .expect("a known device");

        assert!(
            !injectors.net_plan().partition_windows.is_empty(),
            "a scenario with no carrier lost its partition entirely"
        );
    }

    /// A `Heal` closes the partition and leaves everything else alone.
    ///
    /// It used to reset the whole plan, so a heal also switched off steady
    /// packet loss, latency and reordering. `dst_network_fault_chaos`
    /// engages all three at offset zero and then partitions and heals, so
    /// its healed phase ran on a perfect network while the scenario went on
    /// believing it was testing recovery under a lossy one.
    #[test]
    fn a_heal_closes_the_partition_and_nothing_else() {
        let injectors = ScheduledInjectors::new();

        injectors.apply(0, &Fault::Net(NetFault::Drop)).expect("a known device");
        injectors.apply(0, &Fault::Net(NetFault::Delay { millis: 5 })).expect("a known device");
        injectors
            .apply(0, &Fault::Net(NetFault::Partition { device_a: 0, device_b: 1 }))
            .expect("a known device");
        injectors
            .apply(1, &Fault::Net(NetFault::Heal { device_a: 0, device_b: 1 }))
            .expect("a known device");

        let plan = injectors.net_plan();
        assert!(plan.partition_windows.is_empty(), "the heal did not close the partition");
        assert_eq!(plan.drop_every, 1, "the heal switched off packet loss it was not asked about");
        assert!(plan.delay_nanos > 0, "the heal switched off latency it was not asked about");
    }

    /// A schedule naming a device this run does not have stops the run.
    ///
    /// Recording it and carrying on was the earlier behaviour, and it is the
    /// worst of both: the run finishes green while its own trace says a
    /// fault was never injected. A scenario that could not inject what it
    /// was asked to inject has not run.
    #[cfg(turmoil)]
    #[test]
    fn a_schedule_naming_an_unknown_device_fails_the_run() {
        use super::super::device_network::DeviceNetworkFaults;
        use super::super::fault_carrier::CarrierFaults;
        use yadorilink_lane_ports::sim_fault::SimFaultController;

        let a = iroh::SecretKey::from_bytes(&[1; 32]).public();
        let b = iroh::SecretKey::from_bytes(&[2; 32]).public();
        let injectors =
            ScheduledInjectors::new().with_carrier(DeviceNetworkFaults::substrate_only(
                CarrierFaults::new(SimFaultController::new(), vec![a, b]),
            ));

        let outcome =
            injectors.apply(7, &Fault::Net(NetFault::Partition { device_a: 0, device_b: 4 }));

        assert_eq!(
            outcome,
            Err(ScheduleError::UnknownDevice { at_nanos: 7, device: 4 }),
            "a Case naming a device this run does not have was absorbed instead of refused"
        );
    }

    /// The schedule measures from the epoch it is given, not from whenever
    /// its task happened to start.
    ///
    /// A scenario that builds devices and completes a handshake before
    /// spawning the scheduler had already spent part of its own schedule,
    /// and two runs of one `Case` differed by however long setup took. With
    /// an epoch in the past, an entry whose offset has already elapsed fires
    /// at once rather than a full offset later.
    #[test]
    fn a_schedule_measures_from_the_epoch_it_is_given() {
        sim_block_on(|| async {
            let injectors = ScheduledInjectors::new();
            let epoch = tokio::time::Instant::now();

            // Setup happens, and takes time the Case knows nothing about.
            tokio::time::sleep(Duration::from_millis(30)).await;

            let started_at = tokio::time::Instant::now();
            run_schedule_from(
                epoch,
                vec![(20_000_000u64, Fault::Net(NetFault::Drop))],
                injectors.clone(),
            )
            .await
            .expect("a known device");

            assert!(
                started_at.elapsed() < Duration::from_millis(5),
                "an entry 20ms after an epoch 30ms ago waited anyway, so the schedule is \
                 measuring from its own start rather than from the epoch"
            );
            assert_eq!(injectors.net_plan().drop_every, 1, "the entry never fired");
        });
    }

    /// The schedule's offsets are nanoseconds, and this is the only place
    /// that is enforced rather than assumed.
    ///
    /// It was assumed, and wrongly, by every producer: one scenario wrote
    /// milliseconds and the generator wrote round indices, so a partition
    /// configured to open 20ms into a run opened 20ns into it. Nothing
    /// failed -- the fault was injected, just never where the scenario put
    /// it, and a scenario whose faults all land at t=0 is not the scenario
    /// anyone wrote.
    ///
    /// So: an entry at 20,000,000 must still be inert at 19ms and live at
    /// 21ms. Both bounds matter. Only checking that it is live afterwards
    /// would pass just as happily if the scheduler fired everything
    /// immediately, which is precisely the bug this pins.
    #[test]
    fn a_schedules_offsets_are_nanoseconds() {
        sim_block_on(|| async {
            let injectors = ScheduledInjectors::new();
            let twenty_millis_in_nanos = 20_000_000u64;
            let schedule = vec![(
                twenty_millis_in_nanos,
                Fault::Net(NetFault::Partition { device_a: 0, device_b: 1 }),
            )];
            let sched_handle = injectors.clone();
            tokio::spawn(async move {
                run_schedule(schedule, sched_handle)
                    .await
                    .expect("the schedule must not name an unknown device")
            });

            tokio::time::sleep(Duration::from_millis(19)).await;
            assert!(
                injectors.net_plan().partition_windows.is_empty(),
                "a fault scheduled 20ms in had already fired at 19ms, so its offset was read \
                 as something smaller than nanoseconds"
            );

            tokio::time::sleep(Duration::from_millis(2)).await;
            assert!(
                !injectors.net_plan().partition_windows.is_empty(),
                "a fault scheduled 20ms in had not fired by 21ms"
            );
        });
    }

    #[test]
    fn a_fault_is_inactive_before_its_time_and_active_at_or_after_it() {
        // A single network drop scheduled at 1ms of simulated time. Driven
        // concurrently with the observing task so we can look at the injector
        // both before and after the window opens -- and confirm the *real*
        // `FaultingChannel` reads the change through the shared handle.
        sim_block_on(|| async {
            let injectors = ScheduledInjectors::new();
            let schedule = vec![(1_000_000u64, Fault::Net(NetFault::Drop))];
            let sched_handle = injectors.clone();
            tokio::spawn(async move {
                run_schedule(schedule, sched_handle)
                    .await
                    .expect("the schedule must not name an unknown device")
            });

            // Halfway to the window: still inert, and the real injector
            // delivers.
            tokio::time::sleep(Duration::from_nanos(500_000)).await;
            assert!(!injectors.net_active(), "must be inactive before its scheduled time");
            assert_eq!(
                FaultingChannel::new(injectors.net_plan()).decide(0),
                FaultDecision::Deliver
            );

            // Past the window: engaged, and the real injector now drops.
            tokio::time::sleep(Duration::from_nanos(1_000_000)).await;
            assert!(injectors.net_active(), "must be active at/after its scheduled time");
            assert_eq!(FaultingChannel::new(injectors.net_plan()).decide(0), FaultDecision::Drop);
        });
    }

    #[test]
    fn two_faults_at_different_times_both_fire_in_scheduled_order() {
        sim_block_on(|| async {
            let injectors = ScheduledInjectors::new();
            let schedule = vec![
                (1_000u64, Fault::Net(NetFault::Drop)),
                (2_000u64, Fault::Disk(DiskFault::Eio)),
            ];
            run_schedule(schedule, injectors.clone())
                .await
                .expect("the schedule must not name an unknown device");

            assert!(injectors.net_active());
            assert!(injectors.disk_active());
            assert_eq!(
                injectors.trace(),
                vec![
                    Activation::Engaged { at_nanos: 1_000, injector: InjectorKind::Net },
                    Activation::Engaged { at_nanos: 2_000, injector: InjectorKind::Disk },
                ]
            );
        });
    }

    #[test]
    fn an_empty_schedule_is_a_noop() {
        sim_block_on(|| async {
            let injectors = ScheduledInjectors::new();
            run_schedule(Vec::new(), injectors.clone())
                .await
                .expect("the schedule must not name an unknown device");

            assert!(!injectors.net_active());
            assert!(!injectors.disk_active());
            assert!(!injectors.sqlite_active());
            assert!(injectors.trace().is_empty());
        });
    }

    #[test]
    fn a_partition_then_heal_opens_then_closes_the_network_window() {
        sim_block_on(|| async {
            let injectors = ScheduledInjectors::new();
            let schedule = vec![
                (1_000u64, Fault::Net(NetFault::Partition { device_a: 0, device_b: 1 })),
                (2_000u64, Fault::Net(NetFault::Heal { device_a: 0, device_b: 1 })),
            ];
            run_schedule(schedule, injectors.clone())
                .await
                .expect("the schedule must not name an unknown device");

            // The window opened and then closed: inert again at the end.
            assert!(!injectors.net_active(), "heal must clear the partition window");
            assert_eq!(
                injectors.trace(),
                vec![
                    Activation::Engaged { at_nanos: 1_000, injector: InjectorKind::Net },
                    Activation::Cleared { at_nanos: 2_000, injector: InjectorKind::Net },
                ]
            );
        });
    }

    #[test]
    fn same_timestamp_entries_apply_in_input_order() {
        // Deterministic tie-break: two entries sharing a timestamp apply in
        // the order they appear in the schedule (stable sort).
        sim_block_on(|| async {
            let injectors = ScheduledInjectors::new();
            let schedule = vec![
                (1_000u64, Fault::Net(NetFault::Drop)),
                (1_000u64, Fault::Disk(DiskFault::Eio)),
            ];
            run_schedule(schedule, injectors.clone())
                .await
                .expect("the schedule must not name an unknown device");

            assert_eq!(
                injectors.trace(),
                vec![
                    Activation::Engaged { at_nanos: 1_000, injector: InjectorKind::Net },
                    Activation::Engaged { at_nanos: 1_000, injector: InjectorKind::Disk },
                ]
            );
        });
    }

    #[test]
    fn a_disk_sqlite_fault_routes_to_the_index_injector() {
        // `DiskFault::SqliteBusy`/`SqliteLocked` drive the SQLite plan, not
        // the block-store plan.
        sim_block_on(|| async {
            let injectors = ScheduledInjectors::new();
            let schedule = vec![(1_000u64, Fault::Disk(DiskFault::SqliteBusy))];
            run_schedule(schedule, injectors.clone())
                .await
                .expect("the schedule must not name an unknown device");

            assert!(injectors.sqlite_active(), "sqlite window must open");
            assert!(!injectors.disk_active(), "block-store plan must stay inert");
            assert_eq!(
                injectors.sqlite_plan().decide(SqliteOp::UpsertFile, 1),
                Some(SqliteFaultKind::Busy)
            );
            assert_eq!(
                injectors.trace(),
                vec![Activation::Engaged { at_nanos: 1_000, injector: InjectorKind::Sqlite }]
            );
        });
    }

    #[test]
    fn out_of_scope_faults_are_recorded_but_not_applied() {
        sim_block_on(|| async {
            let injectors = ScheduledInjectors::new();
            let schedule = vec![
                (1_000u64, Fault::ClockSkew { device: 0, delta_nanos: 5 }),
                (2_000u64, Fault::Crash { device: 1 }),
                (3_000u64, Fault::Disk(DiskFault::FsyncFail)),
            ];
            run_schedule(schedule, injectors.clone())
                .await
                .expect("the schedule must not name an unknown device");

            assert!(!injectors.net_active());
            assert!(!injectors.disk_active());
            assert!(!injectors.sqlite_active());
            assert_eq!(
                injectors.trace(),
                vec![
                    Activation::Deferred { at_nanos: 1_000 },
                    Activation::Deferred { at_nanos: 2_000 },
                    Activation::Deferred { at_nanos: 3_000 },
                ]
            );
        });
    }

    #[test]
    fn the_same_schedule_replays_an_identical_activation_trace() {
        // A mixed schedule (all three injectors, a clear, and an out-of-scope
        // entry) run twice against fresh injectors must yield byte-identical
        // traces -- the replay-determinism property.
        fn run_once() -> Vec<Activation> {
            let trace = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let trace_out = trace.clone();
            super::super::sim::block_on(7, move || async move {
                let injectors = ScheduledInjectors::new();
                let schedule = vec![
                    (10u64, Fault::Net(NetFault::Partition { device_a: 0, device_b: 1 })),
                    (10u64, Fault::Disk(DiskFault::TornWrite)),
                    (20u64, Fault::Disk(DiskFault::SqliteLocked)),
                    (30u64, Fault::ClockJump { device: 0, to_unix_nanos: 42 }),
                    (40u64, Fault::Net(NetFault::Heal { device_a: 0, device_b: 1 })),
                ];
                run_schedule(schedule, injectors.clone())
                    .await
                    .expect("the schedule must not name an unknown device");
                *trace_out.lock().unwrap() = injectors.trace();
            });
            std::sync::Arc::try_unwrap(trace).unwrap().into_inner().unwrap()
        }

        let first = run_once();
        let second = run_once();
        assert_eq!(first, second, "the same schedule must replay an identical activation trace");
        // And that trace is the one we expect, in scheduled/tie-broken order.
        assert_eq!(
            first,
            vec![
                Activation::Engaged { at_nanos: 10, injector: InjectorKind::Net },
                Activation::Engaged { at_nanos: 10, injector: InjectorKind::Disk },
                Activation::Engaged { at_nanos: 20, injector: InjectorKind::Sqlite },
                Activation::Deferred { at_nanos: 30 },
                Activation::Cleared { at_nanos: 40, injector: InjectorKind::Net },
            ]
        );
    }
}
