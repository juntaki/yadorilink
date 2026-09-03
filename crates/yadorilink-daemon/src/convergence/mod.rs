//! The Convergence Engine: a durable, persistent-state process that plans,
//! fetches, and materializes DAG-resolved file content independently of
//! message handling.
//!
//! `peer_session.rs`'s `handle_message` does authentication, DAG admission,
//! and writes a `materialization_jobs` row (see
//! `yadorilink_sync_sqlite::materialization_jobs`), then returns — releasing
//! its bounded `message_slots` permit without ever awaiting network or disk
//! content I/O. This module is what turns that row into on-disk bytes, on
//! its own schedule, decoupled from any specific peer's message-processing
//! capacity.

pub mod backoff;
#[path = "engine_wrapper.rs"]
pub mod engine;
#[path = "engine.rs"]
mod engine_impl;
pub mod retirement_service;

// `planner`/`job_store` are deliberately NOT separate modules here: the
// pure path-resolution logic they'd contain already exists, unchanged, as
// `PeerSyncSession::reconcile_group_paths` (called via
// `reconcile_paths_directly`, this engine's own bounded direct path --
// the legacy `reproject_unapplied_changes` executor has been retired;
// ordinary projection now has exactly this one scheduling source and one
// driver), and the worklist itself is
// `yadorilink_sync_sqlite::projection_obligations` (`materialization_jobs`
// is a retired, no-longer-scheduled-off-of table). `engine.rs` drives
// both via `DaemonState`.
//
// `availability`/`scheduler` as their own modules are stage-3/stage-2
// concerns (block-availability advertisement, source-side serve credit) not
// yet built — `engine.rs`'s own scheduling loop is small enough for stage 1
// that splitting it out prematurely would be an empty file, not a real
// module boundary.
