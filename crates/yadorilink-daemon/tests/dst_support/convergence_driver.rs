//! The Convergence Engine stand-in every DST harness MUST run.
//!
//! Since materialization was split out of the admission path onto
//! `yadorilink-daemon`'s Convergence Engine, an admitted change only
//! ENQUEUES a durable materialization job — executing it is the engine's
//! job, and a sync-core-only harness does not run the engine. A harness
//! without this driver silently stops materializing anything an admitted
//! change carries; that exact omission zeroed the scenario coverage of two
//! DST binaries (`dst_three_device_mesh_chaos`, `dst_peer_reconcile_race`)
//! for weeks while both reported green/skip — misattributed to a
//! WireGuard-handshake livelock (issue #26) until transport traces showed
//! the handshake completing fine. Centralized here so new harnesses import
//! one canonical driver instead of hand-rolling (or forgetting) it.
//!
//! One driver per DEVICE, handed every session of that device, explicitly
//! round-robining them: an audit block-fetches only through the session it
//! ran on, and multiple per-session drivers racing one per-state wake with
//! the audit guard admitting a single winner would let a deterministic
//! scheduler pin a device's fetches to one peer forever (the daemon
//! rotates candidates with an explicit cursor for exactly this reason).
//! With a single session the round-robin degenerates to the old
//! per-session behavior.

use std::sync::{Arc, Weak};
use std::time::Duration;

use yadorilink_daemon::replica_coordinator::ReplicaCoordinator;
use yadorilink_peer_session::peer_session::PeerSyncSession;

/// Fallback poll cadence when no materialization wake arrives — the same
/// value the migrated scenarios have always used.
pub const MATERIALIZATION_FALLBACK: Duration = Duration::from_millis(100);

pub fn spawn_convergence_driver(
    state: Arc<ReplicaCoordinator>,
    sessions: Vec<Weak<PeerSyncSession>>,
    group_ids: Vec<String>,
) {
    assert!(!sessions.is_empty(), "a convergence driver needs at least one session");
    tokio::spawn(async move {
        let mut next = 0usize;
        loop {
            let Some(session) = sessions[next % sessions.len()].upgrade() else { return };
            next += 1;
            for group_id in &group_ids {
                let _ = session.clone().reconcile_local_materialization_audit(group_id).await;
            }
            drop(session);
            tokio::select! {
                _ = state.materialization_wake().materialization_wake_notified() => {}
                _ = tokio::time::sleep(MATERIALIZATION_FALLBACK) => {}
            }
        }
    });
}
