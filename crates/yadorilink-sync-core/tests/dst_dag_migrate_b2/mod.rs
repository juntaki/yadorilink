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
use yadorilink_sync_core::dag_store::ChangeEmitter;
use yadorilink_sync_core::peer_session::{ChangeAuthenticator, PeerSyncSession};

/// Heads-announce re-drive cadence. The `run()` loop's periodic frontier
/// audit re-sends an idempotent `HeadsAnnounce` every
/// `full_index_resync_interval`; the migrated scenarios shorten it far below
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

/// Installs the two session-side pieces every migrated scenario needs after
/// construction and before `run()`: the all-device pinned authenticator (so
/// incoming signed changes verify), and the short heads-announce cadence (so
/// the periodic frontier audit re-drives catch-up promptly under fault).
pub fn wire_dag_session(session: &Arc<PeerSyncSession>, device_ids: &[&str]) {
    session.set_change_authenticator(PinnedAuthenticator::new(device_ids.iter().copied()));
    // Shorten the periodic frontier audit far below the 90s production default:
    // the run() loop re-announces an idempotent HeadsAnnounce every interval, so
    // a committed edit (announced once via `announce_local_commit` at the call
    // site) is re-driven on this cadence and rides through packet loss / a
    // partition window. A test-harness measure; the production periodic is
    // unchanged.
    session.set_full_index_resync_interval(HEADS_ANNOUNCE_CADENCE);
}
