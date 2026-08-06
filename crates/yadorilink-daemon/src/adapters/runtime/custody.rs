//! Production custody confirmer: performs the peer-to-peer version-present
//! query via `DaemonState::confirm_version_present_witness_via_peer`. The
//! eviction sweep is synchronous, so this bridges to the async query with
//! `block_in_place` -- valid because the daemon runs on a multi-threaded
//! runtime and the sweep is driven from an async task. Holds a weak
//! reference so it never keeps the daemon alive.
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

    fn confirmation_still_valid(&self, group_id: &str, stamp: &CustodyStamp) -> bool {
        let Some(state) = self.state.upgrade() else {
            return false;
        };
        state.membership_generation() == stamp.membership_generation()
            && state.peer_group_is_full_replica(stamp.peer_id(), group_id)
            && state.peer_is_writer(stamp.peer_id(), group_id)
    }
}
