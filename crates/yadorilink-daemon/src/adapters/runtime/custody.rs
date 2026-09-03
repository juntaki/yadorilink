//! Production custody confirmer: performs the peer-to-peer version-present
//! query via `DaemonState::confirm_version_present_witness_via_peer`. The
//! eviction sweep is synchronous, so this bridges to the async query with
//! `block_in_place`, guarded the same way as every other `block_in_place`
//! call site in this crate (see `confirms_present`'s doc comment for why
//! this one can't share the crate's `run_blocking_sweep_offloaded` helper).
//! Holds a weak reference so it never keeps the daemon alive.
//!
//! Lives here, not in `durability_service.rs`, so that module never depends
//! on `DaemonState` -- this is the one adapter allowed to know both sides.

use std::sync::Weak;

use yadorilink_replica_domain::file::VersionBlock;
use yadorilink_replica_domain::ids::VersionHash;
use yadorilink_replica_engine::custody::CustodyStamp;

use crate::daemon_state::DaemonState;
use crate::durability_service::CustodyConfirmer;

pub(crate) struct P2pCustodyConfirmer {
    state: Weak<DaemonState>,
}

impl P2pCustodyConfirmer {
    pub(crate) fn new(state: &std::sync::Arc<DaemonState>) -> Self {
        Self { state: std::sync::Arc::downgrade(state) }
    }
}

impl CustodyConfirmer for P2pCustodyConfirmer {
    // The caller, `yadorilink_replica_engine::custody::verify_reclaim_custody`,
    // fails closed to `None` up front while `REMOTE_CUSTODY_LEASES_SUPPORTED`
    // is `false` (physical reclamation isn't shipped yet -- see
    // `DaemonState::install_p2p_custody_confirmer`'s doc comment), so this
    // method is not actually reachable in any build today. madsim's
    // simulated runtime has no `Handle::block_on`/`block_in_place` -- real
    // blocking would break its deterministic single-threaded-per-node
    // scheduling -- so the bridge below is real-runtime-only; the madsim
    // build gets the same always-`None` answer this path already produces
    // everywhere until the lease feature ships and this needs a real
    // non-blocking bridge.
    // `block_in_place` panics if called on a current-thread tokio runtime,
    // so the offload path below can only be taken when a *multi-threaded*
    // runtime is actually current -- the same guard used at every other
    // `block_in_place` call site in this crate (see
    // `daemon_state::run_blocking_sweep_offloaded`'s doc comment for the
    // full list). This site can't reuse that shared helper: the helper's
    // non-offloaded branch just runs the same synchronous closure inline,
    // but there is no synchronous implementation of a peer query to fall
    // back to here -- `confirms_present` must return synchronously, and the
    // only way to answer it inline on a non-multi-thread runtime would be
    // another blocking call (e.g. a bare `block_on`), which panics for the
    // same reason `block_in_place` does. So the non-multi-thread branch
    // can't do the work at all; per this impl's doc comment above, that
    // branch also isn't reachable in any build today
    // (`REMOTE_CUSTODY_LEASES_SUPPORTED` is `false`), so if it's ever hit it
    // means either that flag shipped without this bridge being revisited, or
    // `confirms_present` grew a caller off a non-multi-thread runtime --
    // both worth surfacing loudly rather than silently returning "no
    // confirmation", which would look identical to an ordinary "peer didn't
    // confirm" result.
    #[cfg(not(madsim))]
    fn confirms_present(
        &self,
        group_id: &str,
        path: &str,
        version_hash: &VersionHash,
        blocks: &[VersionBlock],
    ) -> Option<CustodyStamp> {
        let state = self.state.upgrade()?;
        let group_id = group_id.to_string();
        let path = path.to_string();
        let version_hash = *version_hash;
        let blocks = blocks.to_vec();
        match tokio::runtime::Handle::try_current() {
            Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
                tokio::task::block_in_place(move || {
                    tokio::runtime::Handle::current().block_on(async move {
                        state
                            .confirm_version_present_witness_via_peer(
                                &group_id,
                                &path,
                                version_hash,
                                &blocks,
                            )
                            .await
                    })
                })
            }
            _ => {
                tracing::error!(
                    group_id,
                    path,
                    "P2pCustodyConfirmer::confirms_present called off a non-multi-thread tokio \
                     runtime; this should be unreachable today -- block_in_place would panic \
                     here, so reporting no custody confirmation instead of blocking"
                );
                None
            }
        }
    }

    #[cfg(madsim)]
    fn confirms_present(
        &self,
        _group_id: &str,
        _path: &str,
        _version_hash: &VersionHash,
        _blocks: &[VersionBlock],
    ) -> Option<CustodyStamp> {
        None
    }

    fn confirmation_still_valid(&self, group_id: &str, stamp: &CustodyStamp) -> bool {
        let Some(state) = self.state.upgrade() else {
            return false;
        };
        state.membership_generation() == stamp.membership_generation()
            && state.peer_group_is_full_replica(stamp.peer_id(), group_id)
            && state.peer_is_writer(stamp.peer_id(), group_id)
    }
}
