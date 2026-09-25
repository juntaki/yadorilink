//! Real-hardware acceptance coverage: rename/delete correctness at a modest
//! real scale (hundreds of files), through the full daemon stack (real
//! directly-paired peer sessions, the real OS filesystem watcher via
//! `LinkRuntimeController`).
//!
//! Scope: a large batch of plain deletes must converge as reliably as a
//! large batch of renames (every delete must reach the peer, not just most
//! of them), using the direct-pairing topology `large_folder_scale_sanity.rs`
//! establishes.
//!
//! `load_many_small_files.rs` already covers bulk *create* plus one
//! incremental *create* at a similar file count, but never renames or
//! deletes any of the bulk-created files -- this closes that gap.
//!
//! Not run in CI, same rationale as `load_many_small_files.rs`'s identically
//! tagged test. Run with `cargo test -- --ignored`.

mod support;

use std::time::Duration;

const FILE_COUNT: usize = 1800;
const CONVERGENCE_TIMEOUT: Duration = Duration::from_secs(180);
/// Generous, load-tolerant bound: 90s proved too tight on a loaded host that
/// was still making steady incremental progress. A real regression shows up
/// as no progress at all, not a borderline timing race.
const RENAME_DELETE_TIMEOUT: Duration = Duration::from_secs(240);
