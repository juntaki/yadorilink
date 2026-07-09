//! Peer-to-peer folder replication engine (see openspec `sync-engine` spec).
//!
//! Layering:
//! - [`version_vector`]: causality tracking for conflict detection.
//! - [`chunker`]: fixed-size content-addressed block splitting ().
//! - [`index`]: durable local state — the per-device file index and
//!   folder-link registration.
//! - [`ignore_patterns`]: per-link `.yadorilinkignore` parsing and matching.
//! - [`watcher`] + [`local_change`]: turns raw filesystem events into
//!   indexed, chunked records.
//! - [`conflict`]: deterministic conflict-copy naming.
//! - [`peer_session`]: the actual wire protocol, run over one
//!   `yadorilink_transport::PeerChannel` per peer.

pub mod adaptive_window;
pub mod chunker;
pub mod conflict;
pub mod content_crypto;
pub mod debounce;
mod error;
pub mod hazard;
pub mod ignore_patterns;
pub mod index;
/// Shared link preflight model (folder existence/empty-state/free-space/
/// ignored-summary/risky-location checks) used by both `yadorilink-cli`'s
/// client-side dry-run/confirmation gate and `yadorilink-daemon`'s
/// defense-in-depth re-check.
pub mod link_preflight;
pub mod local_change;
pub mod materialization;
pub mod peer_session;
pub mod presence;
pub mod rate_limiter;
pub mod types;
pub mod version_vector;
pub mod watcher;

pub use error::SyncError;
