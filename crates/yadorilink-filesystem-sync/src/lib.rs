//! Real filesystem execution: the platform-level commit adapter that
//! atomically swaps a prepared replacement into a live filesystem
//! location.

pub mod block_deletion;
pub mod block_liveness;
pub mod debounce;
pub mod materialization_eviction;
pub mod materialization_execution;
pub mod materialization_repair;
pub mod placeholder_backend;
pub mod snapshot_install_reconcile;
pub mod stale_temp_files;
pub mod watcher;
