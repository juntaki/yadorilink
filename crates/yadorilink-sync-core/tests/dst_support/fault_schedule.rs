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
//! offset on `tokio::time` (the simulated clock under `--cfg madsim`) and
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
//! `#![cfg(madsim)]`-gated like every DST scenario file.

#![cfg(madsim)]
#![allow(dead_code)] // not every scenario drives every injector/accessor yet

use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::case_ir::{DiskFault, Fault, FaultPlan, NetFault};
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
        }
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
    fn apply(&self, at_nanos: u64, fault: &Fault) {
        match fault {
            Fault::Net(net_fault) => self.apply_net(at_nanos, net_fault),
            Fault::Disk(disk_fault) => self.apply_disk(at_nanos, disk_fault),
            // No clock-injector or device-lifecycle seam exists at this layer;
            // recorded so the timeline is complete, not applied.
            Fault::ClockSkew { .. }
            | Fault::ClockJump { .. }
            | Fault::Crash { .. }
            | Fault::Restart { .. } => self.record(Activation::Deferred { at_nanos }),
        }
    }

    fn apply_net(&self, at_nanos: u64, net_fault: &NetFault) {
        let mut plan = lock(&self.net);
        let activation = match net_fault {
            NetFault::Partition { .. } => {
                // An open-ended cut from now on; a later `Heal` closes it.
                plan.partition_windows = vec![(0, i64::MAX)];
                Activation::Engaged { at_nanos, injector: InjectorKind::Net }
            }
            NetFault::Heal { .. } => {
                *plan = FaultPlan::default();
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
/// simulated clock under `--cfg madsim`), the schedule is stable-sorted so
/// equal timestamps keep input order, and `apply` depends only on
/// `(offset, fault)`. The same schedule therefore produces an identical
/// activation trace on every replay.
///
/// Takes owned values so the task is `'static` (spawnable): a scenario clones
/// the `ScheduledInjectors` handle (cheap -- all `Arc`s) to keep its own copy
/// for the injectors it built from the same handles.
pub async fn run_schedule(mut schedule: Vec<(u64, Fault)>, injectors: ScheduledInjectors) {
    // Defensive stable sort: the IR states `fault_schedule` is already sorted
    // by `virtual_ts`, but sorting here makes the scheduler correct for an
    // out-of-order input too, and `sort_by_key` is stable so same-timestamp
    // entries stay in input order (the deterministic tie-break).
    schedule.sort_by_key(|(ts, _)| *ts);

    let start = tokio::time::Instant::now();
    for (ts, fault) in &schedule {
        let target = start + Duration::from_nanos(*ts);
        let now = tokio::time::Instant::now();
        if target > now {
            tokio::time::sleep(target - now).await;
        }
        injectors.apply(*ts, fault);
    }
}

#[cfg(test)]
mod tests {
    use super::super::fault::{FaultDecision, FaultingChannel};
    use super::*;

    fn madsim_block_on<F: std::future::Future<Output = ()>>(f: impl FnOnce() -> F) {
        let rt = madsim::runtime::Runtime::with_seed_and_config(1, madsim::Config::default());
        rt.block_on(f());
    }

    #[test]
    fn a_fault_is_inactive_before_its_time_and_active_at_or_after_it() {
        // A single network drop scheduled at 1ms of simulated time. Driven
        // concurrently with the observing task so we can look at the injector
        // both before and after the window opens -- and confirm the *real*
        // `FaultingChannel` reads the change through the shared handle.
        madsim_block_on(|| async {
            let injectors = ScheduledInjectors::new();
            let schedule = vec![(1_000_000u64, Fault::Net(NetFault::Drop))];
            let sched_handle = injectors.clone();
            tokio::spawn(async move { run_schedule(schedule, sched_handle).await });

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
        madsim_block_on(|| async {
            let injectors = ScheduledInjectors::new();
            let schedule = vec![
                (1_000u64, Fault::Net(NetFault::Drop)),
                (2_000u64, Fault::Disk(DiskFault::Eio)),
            ];
            run_schedule(schedule, injectors.clone()).await;

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
        madsim_block_on(|| async {
            let injectors = ScheduledInjectors::new();
            run_schedule(Vec::new(), injectors.clone()).await;

            assert!(!injectors.net_active());
            assert!(!injectors.disk_active());
            assert!(!injectors.sqlite_active());
            assert!(injectors.trace().is_empty());
        });
    }

    #[test]
    fn a_partition_then_heal_opens_then_closes_the_network_window() {
        madsim_block_on(|| async {
            let injectors = ScheduledInjectors::new();
            let schedule = vec![
                (1_000u64, Fault::Net(NetFault::Partition { device_a: 0, device_b: 1 })),
                (2_000u64, Fault::Net(NetFault::Heal { device_a: 0, device_b: 1 })),
            ];
            run_schedule(schedule, injectors.clone()).await;

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
        madsim_block_on(|| async {
            let injectors = ScheduledInjectors::new();
            let schedule = vec![
                (1_000u64, Fault::Net(NetFault::Drop)),
                (1_000u64, Fault::Disk(DiskFault::Eio)),
            ];
            run_schedule(schedule, injectors.clone()).await;

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
        madsim_block_on(|| async {
            let injectors = ScheduledInjectors::new();
            let schedule = vec![(1_000u64, Fault::Disk(DiskFault::SqliteBusy))];
            run_schedule(schedule, injectors.clone()).await;

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
        madsim_block_on(|| async {
            let injectors = ScheduledInjectors::new();
            let schedule = vec![
                (1_000u64, Fault::ClockSkew { device: 0, delta_nanos: 5 }),
                (2_000u64, Fault::Crash { device: 1 }),
                (3_000u64, Fault::Disk(DiskFault::FsyncFail)),
            ];
            run_schedule(schedule, injectors.clone()).await;

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
            let rt = madsim::runtime::Runtime::with_seed_and_config(7, madsim::Config::default());
            rt.block_on(async move {
                let injectors = ScheduledInjectors::new();
                let schedule = vec![
                    (10u64, Fault::Net(NetFault::Partition { device_a: 0, device_b: 1 })),
                    (10u64, Fault::Disk(DiskFault::TornWrite)),
                    (20u64, Fault::Disk(DiskFault::SqliteLocked)),
                    (30u64, Fault::ClockJump { device: 0, to_unix_nanos: 42 }),
                    (40u64, Fault::Net(NetFault::Heal { device_a: 0, device_b: 1 })),
                ];
                run_schedule(schedule, injectors.clone()).await;
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
