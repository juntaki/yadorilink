//! Serving and collecting a re-bootstrap snapshot on the history lane.
//!
//! The manifest came back on the service lane; these are the two ends of the
//! second leg. The `snapshot_hash` the manifest names is the only correlation
//! between them — no request id is allocated for either.

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use yadorilink_peer_session::ports::{PreparedSnapshotStore, SnapshotFetch};
use yadorilink_sync_substrate::{HistoryStreamKind, Lane, LaneStream, PeerLink};
use yadorilink_transport::TransportError;

use crate::directory::PeerDirectory;
use crate::prepared_snapshots::PreparedSnapshots;
use crate::snapshot_stream::{receive_snapshot_into, send_snapshot};

impl PreparedSnapshotStore for PreparedSnapshots {
    fn prepare(&self, group_id: &str, snapshot_hash: [u8; 32], bytes: Arc<Vec<u8>>) {
        PreparedSnapshots::prepare(self, group_id, snapshot_hash, bytes)
    }

    fn take_for(&self, group_id: &str, snapshot_hash: &[u8; 32]) -> Option<Arc<Vec<u8>>> {
        PreparedSnapshots::take_for(self, group_id, snapshot_hash)
    }
}

/// Answer one inbound `RebootstrapSnapshot` history stream.
///
/// The group comes from the stream's own hello, not from the request, so a
/// peer cannot name one group in the hello and reach another's snapshot. And
/// authorization is checked *here*, at collection: a peer authorized when the
/// manifest was issued may have been revoked since, and a manifest it was
/// handed earlier is not a capability.
pub async fn serve_snapshot_stream<D: PeerDirectory + ?Sized>(
    mut lane: LaneStream,
    peer_endpoint: &[u8; 32],
    group_id: &str,
    directory: &D,
    prepared: &PreparedSnapshots,
) {
    let mut requested = [0u8; 32];
    if lane.read_exact(&mut requested).await.is_err() {
        return;
    }

    let authorized = directory
        .device_for_endpoint(peer_endpoint)
        .is_some_and(|device| directory.is_authorized(&device, group_id));
    if !authorized {
        tracing::warn!(group_id, "refusing a snapshot fetch for an unauthorized group");
        // Ends the stream with nothing. Indistinguishable from having no such
        // snapshot, which is the same reasoning the service lane's refusals
        // follow.
        let _ = lane.finish();
        return;
    }

    let Some(bytes) = prepared.take_for(group_id, &requested) else {
        // Nothing prepared under that hash for this group: the daemon may
        // have restarted, or it may never have been prepared. Either way the
        // requester asks again from the top.
        tracing::debug!(group_id, "no prepared snapshot for the requested hash");
        let _ = lane.finish();
        return;
    };

    if let Err(error) = send_snapshot(&mut lane, &bytes).await {
        tracing::debug!(group_id, %error, "snapshot could not be sent");
    }
}

/// Collects a snapshot from one peer over the history lane.
pub struct LaneSnapshotFetch {
    link: Arc<PeerLink>,
}

impl LaneSnapshotFetch {
    pub fn new(link: Arc<PeerLink>) -> Self {
        Self { link }
    }
}

#[async_trait::async_trait]
impl SnapshotFetch for LaneSnapshotFetch {
    async fn fetch(
        &self,
        group_id: &str,
        snapshot_hash: [u8; 32],
    ) -> Result<Vec<u8>, TransportError> {
        let mut lane = self
            .link
            .open_lane(Lane::History)
            .await
            .map_err(|error| TransportError::NoRoute(error.to_string()))?;
        yadorilink_sync_protocol::session::open_lane(
            &mut lane,
            &yadorilink_sync_protocol::ports::GroupId(group_id.to_string()),
        )
        .await
        .map_err(|error| TransportError::NoRoute(error.to_string()))?;
        yadorilink_sync_runtime::write_history_kind(
            &mut lane,
            HistoryStreamKind::RebootstrapSnapshot,
        )
        .await?;
        lane.write_all(&snapshot_hash).await?;
        lane.flush().await?;

        // Grows as bytes actually arrive. Nothing here reserves memory on the
        // peer's say-so, because there is no declared length to believe —
        // the hash the manifest fixed is what makes the result trustworthy.
        //
        // The spool is memory today because a base is verified and merged
        // from a slice (`verify_foreign_base`); `receive_snapshot_into` writes to any `AsyncWrite`, so
        // moving it to a file is a change at this call site alone.
        let mut spool = Vec::new();
        receive_snapshot_into(&mut lane, &mut spool, &snapshot_hash)
            .await
            .map_err(|error| TransportError::NoRoute(error.to_string()))?;
        Ok(spool)
    }
}
