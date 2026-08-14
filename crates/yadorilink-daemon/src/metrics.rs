//! The daemon's opt-in Prometheus/OpenMetrics `/metrics` endpoint —
//! manual, no-framework text rendering that reaches directly into the same
//! shared `DaemonState` the control socket's `status` handler already
//! reads, rather than a parallel bookkeeping path.
//!
//! Metric families: `yadorilink_transfer_bytes_total` (counter),
//! `yadorilink_active_transfers` (gauge), `yadorilink_active_peers` (gauge),
//! `yadorilink_sync_errors_total{category}` (counter),
//! `yadorilink_block_fetch_seconds` (histogram). Every label/value here is a
//! count or a bounded-cardinality category string — the test
//! (`tests::privacy_safe_metrics_never_contain_content_paths_keys_tokens_or_ips`)
//! asserts none of them ever carries content, a file name, an absolute
//! path, a key, a token, or a peer IP.

use std::sync::Arc;

use crate::daemon_state::DaemonState;

#[derive(Clone)]
pub struct DaemonMetrics {
    state: Arc<DaemonState>,
}

impl DaemonMetrics {
    pub fn new(state: Arc<DaemonState>) -> Self {
        Self { state }
    }

    pub fn render_openmetrics(&self) -> String {
        let active_transfers = self.state.telemetry.active_transfer_count();
        let active_peers = self.state.peers.connected_peer_count();
        let transfer_bytes_total = self.state.telemetry.transfer_bytes_total();

        let mut out = String::new();
        out += "# TYPE yadorilink_transfer_bytes_total counter\n";
        out += &format!("yadorilink_transfer_bytes_total {transfer_bytes_total}\n");
        out += "# TYPE yadorilink_active_transfers gauge\n";
        out += &format!("yadorilink_active_transfers {active_transfers}\n");
        out += "# TYPE yadorilink_active_peers gauge\n";
        out += &format!("yadorilink_active_peers {active_peers}\n");

        out += "# TYPE yadorilink_sync_errors_total counter\n";
        let mut category_counts = self.state.telemetry.recent_error_category_counts();
        // Deterministic ordering — cosmetic only (a `HashMap` iteration
        // order would still be a valid OpenMetrics document), but makes
        // the endpoint's output byte-stable for a fixed set of categories,
        // which is nicer for anything diffing scrape output.
        category_counts.sort_by_key(|(category, _)| *category);
        for (category, count) in category_counts {
            out += &format!("yadorilink_sync_errors_total{{category=\"{category}\"}} {count}\n");
        }

        out += &self.state.telemetry.render_block_fetch_histogram();
        out
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::replica_coordinator::ReplicaCoordinator;
    use yadorilink_local_storage::FsBlockStore;

    use super::*;
    use crate::daemon_state::DaemonState;
    use crate::peer_registry::{PeerReachability, UnreachableCategory};

    fn test_state() -> Arc<DaemonState> {
        let store_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
        let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
        DaemonState::new("device-a".into(), sync_state, store)
    }

    #[tokio::test]
    async fn renders_every_documented_metric_family() {
        let state = test_state();
        let metrics = DaemonMetrics::new(state);
        let rendered = metrics.render_openmetrics();

        assert!(rendered.contains("yadorilink_transfer_bytes_total"));
        assert!(rendered.contains("yadorilink_active_transfers"));
        assert!(rendered.contains("yadorilink_active_peers"));
        assert!(rendered.contains("yadorilink_sync_errors_total"));
        assert!(rendered.contains("yadorilink_block_fetch_seconds"));
    }

    #[tokio::test]
    async fn reflects_live_state_active_peers_transfers_bytes_and_errors() {
        let state = test_state();
        state.peers.set_reachability(
            "peer-a".to_string(),
            PeerReachability::Connected(crate::route::RouteKind::Direct),
        );
        state.peers.set_reachability(
            "peer-b".to_string(),
            PeerReachability::Unreachable(UnreachableCategory::NoResponse),
        );
        let _guard = state.telemetry.begin_transfer("group-1", "big.bin", 100, 1);
        state.telemetry.record_transfer_block_done("group-1", "big.bin", 42, "peer-a");
        state.telemetry.record_recent_error("disk_pressure", "sweep");
        state.telemetry.record_recent_error("disk_pressure", "sweep");

        let metrics = DaemonMetrics::new(state);
        let rendered = metrics.render_openmetrics();

        assert!(rendered.contains("yadorilink_active_peers 1"));
        assert!(rendered.contains("yadorilink_active_transfers 1"));
        assert!(rendered.contains("yadorilink_transfer_bytes_total 42"));
        assert!(rendered.contains("yadorilink_sync_errors_total{category=\"disk_pressure\"} 2"));
    }

    /// No label or value may contain a device id, a path, a token, or a
    /// peer address, even once real (test) activity has been recorded.
    #[tokio::test]
    async fn privacy_safe_metrics_never_contain_content_paths_keys_tokens_or_ips() {
        let state = test_state();
        state.peers.set_reachability(
            "peer-secret-device-id".to_string(),
            PeerReachability::Connected(crate::route::RouteKind::Direct),
        );
        let _guard =
            state.telemetry.begin_transfer("group-1", "/Users/alice/secret-plans.docx", 1000, 10);
        state.telemetry.record_transfer_block_done(
            "group-1",
            "/Users/alice/secret-plans.docx",
            500,
            "peer-secret-device-id",
        );
        state.telemetry.record_recent_error("disk_pressure", "hydration");

        let metrics = DaemonMetrics::new(state);
        let rendered = metrics.render_openmetrics();

        assert!(!rendered.contains("peer-secret-device-id"));
        assert!(!rendered.contains("secret-plans"));
        assert!(!rendered.contains("/Users/alice"));
        assert!(!rendered.contains("127.0.0.1"));
        assert!(!rendered.contains("token"));
        assert!(!rendered.contains("key"));
    }
}
