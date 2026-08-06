//! The commit-path orchestration engine: `orchestrator::run_slice` drives one
//! placement slice from allocation through release (with [`commit_path_locks`]
//! serialising the in-process half of its commit boundary, see that module's
//! own doc), and [`plan_driver::drive_plan`] is the plan/prepare/revalidate/
//! replan loop that repeatedly calls it as the DAG frontier moves underneath
//! a long-running transaction.
//!
//! Moved here as one unit from `yadorilink-sync-core` (7D-9E): `orchestrator`
//! and `plan_driver` have a real, one-directional in-crate dependency
//! (`plan_driver` calls `orchestrator`, never the reverse), and
//! `commit_path_locks` is `orchestrator`'s own private lock registry with no
//! caller outside it. None of the three had any real caller anywhere in the
//! workspace outside their own tests at the time of the move — this crate
//! does not yet wire `orchestrator::run_slice`/`plan_driver::drive_plan` into
//! a real commit path, matching the composition every one of these modules'
//! own doc comments already described as its intended home
//! (`daemon/src/application` or equivalent) once every module it depends on
//! had a stable location outside `sync-core`. Wiring a real caller is future
//! work, not part of this move.
pub(crate) mod commit_path_locks;
pub(crate) mod orchestrator;
pub(crate) mod plan_driver;
/// Identity-checked physical unlink for retained preimages (moved from
/// `yadorilink-sync-core`, see this module's own doc comment).
pub(crate) mod retained_obligation;
