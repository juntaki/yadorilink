//! `Status`'s full read model -- links, peers, configured limits and
//! current measured rates, per-volume free space, embedded update status,
//! block-store usage, GC health, active transfers, and recent errors.
//! Built on top of `link_status`'s and `update_status`'s already-landed
//! slices rather than re-deriving link/update data a second way.

use std::sync::Arc;

use yadorilink_local_storage::BlockStore;

use crate::gc_state::GcState;
use crate::governance_config::GovernanceConfigStore;
use crate::peer_registry::{PeerReachability, PeerRegistry};
use crate::queries::link_status::{LinkStatusQueryService, LinkStatusView};
use crate::queries::update_status::{UpdateStatusQueryService, UpdateStatusView};
use crate::runtime_telemetry::RuntimeTelemetry;
use yadorilink_peer_session::rate_limiter::RateLimiters;

#[derive(Debug, Clone)]
pub(crate) struct PeerStatusView {
    pub(crate) device_id: String,
    pub(crate) reachability: PeerReachability,
}

#[derive(Debug, Clone)]
pub(crate) struct VolumeSpaceView {
    pub(crate) path: String,
    pub(crate) state: String,
    pub(crate) available_bytes: u64,
    pub(crate) headroom_bytes: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct ActiveTransferView {
    pub(crate) group_id: String,
    pub(crate) path: String,
    pub(crate) bytes_done: u64,
    pub(crate) bytes_total: u64,
    pub(crate) blocks_done: u64,
    pub(crate) blocks_total: u64,
    pub(crate) source_peer: String,
    pub(crate) started_at_unix: i64,
}

#[derive(Debug, Clone)]
pub(crate) struct RecentErrorView {
    pub(crate) category: String,
    pub(crate) timestamp_unix: i64,
    pub(crate) coarse_context: String,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct BlockStoreUsageView {
    pub(crate) total_bytes: u64,
    pub(crate) block_count: u64,
}

pub(crate) struct RuntimeStatusView {
    pub(crate) links: Vec<LinkStatusView>,
    pub(crate) peers: Vec<PeerStatusView>,
    pub(crate) upload_limit_bytes_per_sec: u64,
    pub(crate) download_limit_bytes_per_sec: u64,
    pub(crate) current_upload_bytes_per_sec: u64,
    pub(crate) current_download_bytes_per_sec: u64,
    pub(crate) volumes: Vec<VolumeSpaceView>,
    pub(crate) update: UpdateStatusView,
    pub(crate) block_store: BlockStoreUsageView,
    pub(crate) last_gc_unix: i64,
    pub(crate) gc_reclaimable_estimate_bytes: u64,
    pub(crate) active_transfers: Vec<ActiveTransferView>,
    pub(crate) recent_errors: Vec<RecentErrorView>,
}

pub(crate) struct RuntimeStatusQueryService {
    link_status: Arc<LinkStatusQueryService>,
    update_status: Arc<UpdateStatusQueryService>,
    peers: Arc<PeerRegistry>,
    telemetry: Arc<RuntimeTelemetry>,
    governance: Arc<GovernanceConfigStore>,
    block_store: Arc<dyn BlockStore + Send + Sync>,
    gc: Arc<GcState>,
    rate_limiters: Arc<RateLimiters>,
}

impl RuntimeStatusQueryService {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        link_status: Arc<LinkStatusQueryService>,
        update_status: Arc<UpdateStatusQueryService>,
        peers: Arc<PeerRegistry>,
        telemetry: Arc<RuntimeTelemetry>,
        governance: Arc<GovernanceConfigStore>,
        block_store: Arc<dyn BlockStore + Send + Sync>,
        gc: Arc<GcState>,
        rate_limiters: Arc<RateLimiters>,
    ) -> Self {
        Self {
            link_status,
            update_status,
            peers,
            telemetry,
            governance,
            block_store,
            gc,
            rate_limiters,
        }
    }

    pub(crate) fn snapshot(&self) -> Result<RuntimeStatusView, crate::sync_error::SyncError> {
        let links = self.link_status.list_links()?;
        let peers = self
            .peers
            .snapshot()
            .into_iter()
            .map(|snapshot| {
                let mut reachability = snapshot.reachability;
                if reachability.is_connected() && snapshot.protocol_incompatible {
                    reachability = PeerReachability::ProtocolIncompatible;
                }
                PeerStatusView { device_id: snapshot.device_id, reachability }
            })
            .collect();
        let governance = self.governance.load_or_default();
        let volumes = self.volumes_free_space(&links);
        let update = self.update_status.snapshot();
        let block_store_usage = self.block_store.usage().unwrap_or_default();
        let active_transfers = self
            .telemetry
            .active_transfer_snapshot()
            .into_iter()
            .map(|t| ActiveTransferView {
                group_id: t.group_id,
                path: t.path,
                bytes_done: t.bytes_done,
                bytes_total: t.bytes_total,
                blocks_done: t.blocks_done,
                blocks_total: t.blocks_total,
                source_peer: t.source_peer,
                started_at_unix: t.started_at_unix,
            })
            .collect();
        let recent_errors = self
            .telemetry
            .recent_error_snapshot()
            .into_iter()
            .map(|e| RecentErrorView {
                category: e.category.to_string(),
                timestamp_unix: e.timestamp_unix,
                coarse_context: e.coarse_context,
            })
            .collect();

        Ok(RuntimeStatusView {
            links,
            peers,
            upload_limit_bytes_per_sec: governance.upload_limit_bytes_per_sec,
            download_limit_bytes_per_sec: governance.download_limit_bytes_per_sec,
            current_upload_bytes_per_sec: self.rate_limiters.upload.current_rate_bytes_per_sec(),
            current_download_bytes_per_sec: self
                .rate_limiters
                .download
                .current_rate_bytes_per_sec(),
            volumes,
            update,
            block_store: BlockStoreUsageView {
                total_bytes: block_store_usage.total_bytes,
                block_count: block_store_usage.block_count,
            },
            last_gc_unix: self.gc.last_run_unix(),
            gc_reclaimable_estimate_bytes: self.gc.reclaimable_estimate_bytes(),
            active_transfers,
            recent_errors,
        })
    }

    /// Free-space state for every volume hosting the block store or a
    /// linked folder -- the block-store root (via `BlockStore::free_space`,
    /// `None` for a backend with no real volume concept) plus one entry
    /// per distinct link `local_path` (paths can collide if a device
    /// somehow links the same directory twice, so this dedups by path
    /// rather than by link count). Best-effort: a link whose volume can't
    /// currently be queried is silently omitted, matching every other
    /// silent-degrade in this snapshot -- `Status` reports what it can,
    /// never fails wholesale over one unreadable volume.
    pub(crate) fn volumes_free_space(&self, links: &[LinkStatusView]) -> Vec<VolumeSpaceView> {
        let headroom_override = self.governance.load_or_default().headroom_override_bytes;
        let mut seen_paths = std::collections::HashSet::new();
        let mut volumes = Vec::new();

        if let Ok(Some(space)) = self.block_store.free_space() {
            volumes.push(VolumeSpaceView {
                path: "<block store>".to_string(),
                state: space.classify().as_str().to_string(),
                available_bytes: space.available_bytes,
                headroom_bytes: space.headroom_bytes,
            });
        }

        for link in links {
            if !seen_paths.insert(link.local_path.clone()) {
                continue;
            }
            if let Ok(space) = yadorilink_local_storage::free_space::classify_volume(
                std::path::Path::new(&link.local_path),
                headroom_override,
            ) {
                volumes.push(VolumeSpaceView {
                    path: link.local_path.clone(),
                    state: space.classify().as_str().to_string(),
                    available_bytes: space.available_bytes,
                    headroom_bytes: space.headroom_bytes,
                });
            }
        }
        volumes
    }
}
