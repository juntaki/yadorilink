//! Shared change-history-DAG propagation wiring for the DST scenarios that
//! drive convergence over the real `run()` loop (HeadsAnnounce ->
//! ChangeRequest -> ChangeBatch) instead of the direct index exchange.
//!
//! A scenario gives each device's `LocalChangeProcessor` a signed
//! [`ChangeEmitter`] (so every accepted local mutation appends a signed
//! change to the history DAG in the same transaction as its index write),
//! pins every device's verifying key on every session via a
//! [`PinnedAuthenticator`], and then propagates a committed edit by announcing
//! the new heads rather than pushing an index update. The peer diffs the
//! announced heads against its own store and pulls exactly the ancestry it is
//! missing, materializing the same converged state on both sides.
//!
//! Lives in a `tests/` *subdirectory* so Cargo does not build it as its own
//! integration-test binary (only top-level `tests/*.rs` are targets); each
//! scenario pulls it in with `mod dst_dag_migrate_b2;`. It references only the
//! `yadorilink-sync-core` public API and `ed25519-dalek`, never `dst_support`,
//! so it compiles standalone in each binary that includes it.

#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_peer_session::block_serve::BlockServeEngine;
use yadorilink_peer_session::peer_session::{ChangeAuthenticator, PeerSyncSession};
use yadorilink_sync_sqlite::dag_store::ChangeEmitter;

/// Heads-announce re-drive cadence. The `run()` loop's periodic frontier
/// audit re-sends an idempotent `HeadsAnnounce` every
/// `maintenance_reconcile_interval`; the migrated scenarios shorten it far below
/// the 90s production default so DAG catch-up stays prompt under packet loss
/// and heals quickly after a partition window. A test-harness measure (the
/// production periodic is unchanged), analogous to the scenarios' own short
/// settle windows.
pub const HEADS_ANNOUNCE_CADENCE: Duration = Duration::from_millis(50);

/// A deterministic per-device Ed25519 signing key derived from the device id,
/// so the same device id maps to the same key across every session in a run
/// (the emitter that signs and the authenticator that pins must agree).
pub fn signing_key_for(device_id: &str) -> SigningKey {
    let mut seed = [0u8; 32];
    // Fold the id into the seed; distinct ids yield distinct keys. A trailing
    // domain tag keeps a short id (e.g. "device-a") well away from all-zero.
    for (i, b) in device_id.as_bytes().iter().enumerate() {
        seed[i % 32] ^= *b;
    }
    for (i, b) in b"dst-dag-migrate".iter().enumerate() {
        seed[16 + (i % 16)] ^= *b;
    }
    seed[0] = seed[0].wrapping_add(1);
    SigningKey::from_bytes(&seed)
}

/// The signed change emitter for `device_id`, wired into that device's
/// `LocalChangeProcessor` via `with_change_emitter`.
pub fn emitter_for(device_id: &str) -> Arc<ChangeEmitter> {
    Arc::new(ChangeEmitter::new(device_id, signing_key_for(device_id)))
}

/// A change authenticator that pins every participating device's verifying
/// key and treats each as a writer — the two-device DST analogue of the
/// daemon's netmap-backed authenticator, with the run's devices mutually
/// trusted. Pinning both keys on both sessions is what lets each device admit
/// the other's signed changes.
pub struct PinnedAuthenticator {
    keys: HashMap<String, [u8; 32]>,
}

impl PinnedAuthenticator {
    pub fn new<'a>(device_ids: impl IntoIterator<Item = &'a str>) -> Arc<Self> {
        let keys = device_ids
            .into_iter()
            .map(|id| (id.to_string(), signing_key_for(id).verifying_key().to_bytes()))
            .collect();
        Arc::new(Self { keys })
    }
}

impl ChangeAuthenticator for PinnedAuthenticator {
    fn signing_key(&self, device_id: &str) -> Option<[u8; 32]> {
        self.keys.get(device_id).copied()
    }
    fn is_writer(&self, _device_id: &str, _group_id: &str) -> bool {
        true
    }
}

/// Fallback poll interval for `spawn_test_convergence_driver` when the wake
/// notification is missed (mirrors the production engine's own event+fallback
/// `tokio::select!` shape in `daemon/src/convergence/engine.rs`).
const MATERIALIZATION_FALLBACK: Duration = Duration::from_millis(100);

/// The production daemon's `ConvergenceEngine` is the only thing that turns an
/// admitted DAG change into on-disk content: `handle_change_batch` now only
/// admits the change and enqueues a `materialization_jobs` row. These
/// migrated DST scenarios have no daemon and thus no engine, so any scenario
/// that asserts on disk content (not just DAG admission/settle state) needs
/// this driver running, or it hangs until its own timeout regardless of how
/// correct the sync logic is.
pub fn spawn_test_convergence_driver(
    session: &Arc<PeerSyncSession>,
    state: Arc<ReplicaCoordinator>,
    group_ids: Vec<String>,
) {
    // Delegates to the canonical shared driver (see
    // `dst_support::convergence_driver`'s doc for why every DST harness
    // must run one); kept as a thin alias so existing call sites and the
    // single-session shape stay source-compatible.
    crate::dst_support::convergence_driver::spawn_convergence_driver(
        state,
        vec![Arc::downgrade(session)],
        group_ids,
    );
}

/// Installs the session-side pieces every migrated scenario needs after
/// construction and before `run()`: the short heads-announce cadence (so the
/// periodic frontier audit re-drives catch-up promptly under fault), a
/// generous block-serve engine (every real, `DaemonState`-backed session
/// always has one installed; without it an incoming `BlockRequest` fails
/// closed), and the test convergence driver described above.
///
/// The all-device pinned authenticator this used to install here too is now
/// a `PeerSyncSessionDeps::change_authenticator` construction-only field
/// (`ChangeAuthenticator` is no longer settable after a session exists) --
/// every caller must build its session via `PeerSyncSession::
/// new_with_dependencies` with `PinnedAuthenticator::new(device_ids)`
/// already supplied, before calling this. `device_ids` is kept as a
/// parameter (unused here) so call sites don't need to change their own
/// signature/argument list, and so a future caller relying on this
/// function's doc comment for "which device IDs does wiring need" still
/// finds the answer here.
pub fn wire_dag_session(
    session: &Arc<PeerSyncSession>,
    state: Arc<ReplicaCoordinator>,
    device_ids: &[&str],
    group_ids: &[&str],
) {
    let _ = device_ids;
    // Shorten the periodic frontier audit far below the 90s production default:
    // the run() loop re-announces an idempotent HeadsAnnounce every interval, so
    // a committed edit (announced once via `announce_local_commit` at the call
    // site) is re-driven on this cadence and rides through packet loss / a
    // partition window. A test-harness measure; the production periodic is
    // unchanged.
    session.set_maintenance_reconcile_interval(HEADS_ANNOUNCE_CADENCE);
    // Under the current protocol a `BlockRequest` with no engine installed
    // fails closed.
    session.set_block_serve_engine(BlockServeEngine::new(u64::MAX, u64::MAX, u64::MAX, 1_000));

    let groups = group_ids.iter().map(|group_id| (*group_id).to_string()).collect::<Vec<_>>();
    spawn_test_convergence_driver(session, state, groups);
}
