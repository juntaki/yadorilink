//! Peer-to-peer folder replication engine.
//!
//! Layering:
//! - [`version_vector`]: causality tracking for conflict detection.
//! - [`chunker`]: fixed-size content-addressed block splitting.
//! - [`index`]: durable local state — the per-device file index and
//!   folder-link registration.
//! - [`ignore_patterns`]: per-link `.yadorilinkignore` parsing and matching.
//! - [`watcher`] + [`local_change`]: turns raw filesystem events into
//!   indexed, chunked records.
//! - [`conflict`]: deterministic conflict-copy naming.
//! - [`peer_session`]: the actual wire protocol, run over one
//!   `yadorilink_transport::PeerChannel` per peer.

pub mod adaptive_window;
pub mod authenticated_history;
pub mod block_deletion;
pub mod block_liveness;
pub mod change;
pub mod chunker;
pub mod compaction;
pub mod conflict;
pub mod custody;
pub mod dag_import;
pub mod dag_store;
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
pub mod rate_limiter;
pub mod rebootstrap;
pub mod rebootstrap_snapshot;
/// Sync-root identity: proves the directory a scan is about to treat as
/// authoritative is really this link's folder, and not the bare mountpoint an
/// unmounted volume leaves behind — which every existence check accepts and
/// every scan would otherwise read as "the user deleted everything".
pub mod root_identity;
pub mod types;
pub mod version_vector;
pub mod watcher;

pub use error::SyncError;
