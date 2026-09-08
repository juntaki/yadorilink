//! Track Send daemon integration: a one-shot P2P file send/receive lane,
//! deliberately separate from the sync/materialization machinery every
//! other module in this crate ultimately serves. See `yadorilink-send`'s
//! own crate doc comment for the full design; this module is only the
//! daemon-side glue that:
//!
//! - implements [`yadorilink_send::DeviceDirectory`] against this
//!   daemon's already-known device list (`DaemonState::peer_signing_key`/
//!   `peer_candidate_addresses`/`device_id_for_signing_key` -- all
//!   connectivity/identity bookkeeping, never anything DAG- or
//!   materialization-related);
//! - waits for `peer_orchestrator`'s lazily-built `QuicPeerEndpoint` to
//!   exist, then builds and publishes this device's one
//!   `yadorilink_send::SendService`;
//! - runs its inbound-connection dispatcher for the life of the daemon;
//! - exposes the two thin control-socket-facing wrappers
//!   ([`SendTransferService`] for `send`/`receive`,
//!   [`InboxQueries`] for `inbox`) that `adapters::build_application_
//!   services`/`build_query_services` wire in like any other narrow
//!   port -- `control_context.rs`'s own doc comment is explicit that
//!   `ControlContext` itself must never gain a raw `DaemonState` field,
//!   so this module deliberately does not ask for one.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use yadorilink_send::{
    DeviceDirectory, GrantedDevice, InboxEntry, ReceiveOutcome, ResolvedDevice, SendOfferOutcome,
    SendService,
};

use crate::daemon_state::{DaemonState, SendGrantPeer};

/// How often this device checks whether `peer_orchestrator` has published
/// a `QuicPeerEndpoint` yet, before Track Send has anything to dial or
/// accept on. Only matters for the (short) window right after daemon
/// startup, before the first coordination-plane netmap push has been
/// applied.
const ENDPOINT_POLL_INTERVAL: Duration = Duration::from_millis(500);

struct DaemonDeviceDirectory {
    state: Arc<DaemonState>,
}

#[async_trait::async_trait]
impl DeviceDirectory for DaemonDeviceDirectory {
    fn resolve(&self, device_query: &str) -> Option<ResolvedDevice> {
        if let Some(signing_key) = self.state.peer_signing_key(device_query) {
            let candidate_addresses: Vec<SocketAddr> =
                self.state.peer_candidate_addresses(device_query);
            return Some(ResolvedDevice {
                device_id: device_query.to_string(),
                signing_key,
                candidate_addresses,
            });
        }
        // Fallback for a device this daemon has no ordinary netmap
        // relationship with, but currently knows about through a Track
        // Send grant -- see `DaemonState::send_grant_peers`'s own doc
        // comment. This is what lets `receive_transfer`'s later pull-dial
        // resolve a grant-based sender: `handle_offer` recorded it here
        // (via `consume_grant`, keyed by the authenticated peer key) the
        // moment it accepted that sender's offer.
        let grant_peer = self.state.send_grant_peer_by_device_id(device_query)?;
        Some(ResolvedDevice {
            device_id: grant_peer.device_id,
            signing_key: grant_peer.signing_key,
            candidate_addresses: grant_peer.candidate_addresses,
        })
    }

    fn device_id_for_key(&self, signing_key: &[u8; 32]) -> Option<String> {
        self.state
            .device_id_for_signing_key(signing_key)
            .or_else(|| self.state.send_grant_peer_by_key(signing_key).map(|p| p.device_id))
    }

    async fn request_grant(&self, receiver_device_query: &str) -> Option<GrantedDevice> {
        let config = self.state.coordination_client_config()?.clone();
        let grant = crate::coordination_client::request_send_authorization(
            &config.addr,
            &config.access_token,
            &self.state.device_id,
            receiver_device_query,
        )
        .await
        .inspect_err(|e| {
            tracing::debug!(
                error = %e,
                target = receiver_device_query,
                "Track Send authorization request failed"
            );
        })
        .ok()?;
        let receiver_candidates: Vec<SocketAddr> =
            grant.receiver_candidates.iter().filter_map(|c| c.address.parse().ok()).collect();
        // Symmetric bookkeeping with the receiver side's own record below:
        // this device (the sender) may be dialed BACK during the pull
        // phase, and `device_id_for_key`/`resolve` fall back to this same
        // cache for any later grant-scoped lookup naming the receiver.
        self.state.record_send_grant_peer(SendGrantPeer {
            device_id: grant.receiver_device_id.clone(),
            signing_key: grant.receiver_signing_key,
            candidate_addresses: receiver_candidates.clone(),
            grant_id: grant.grant_id.clone(),
            nonce: grant.nonce.clone(),
            expires_at_unix: grant.expires_at_unix,
        });
        Some(GrantedDevice {
            device: ResolvedDevice {
                device_id: grant.receiver_device_id,
                signing_key: grant.receiver_signing_key,
                candidate_addresses: receiver_candidates,
            },
            grant_id: grant.grant_id,
            grant_nonce: grant.nonce,
            expires_at_unix: grant.expires_at_unix,
        })
    }

    async fn consume_grant(
        &self,
        grant_id: &str,
        grant_nonce: &str,
        peer_key: &[u8; 32],
    ) -> std::result::Result<(), String> {
        // The load-bearing identity binding: `pending.device_id` was
        // derived from `peer_key` -- the QUIC-authenticated key THIS
        // connection actually holds the private half of -- never from
        // anything the offer's own envelope claims. See `consume_grant`'s
        // own trait doc comment.
        let pending = self.state.send_grant_peer_by_key(peer_key).ok_or_else(|| {
            "no pending Track Send authorization for this connection's authenticated key"
                .to_string()
        })?;
        // Cheap local reject for an obviously-wrong grant id/nonce before
        // spending a coordination-plane round trip -- defense in depth,
        // not the real guard; see `SendGrantPeer`'s own doc comment.
        if pending.grant_id != grant_id || pending.nonce != grant_nonce {
            return Err("send authorization is invalid, expired, or already used".to_string());
        }
        let config = self
            .state
            .coordination_client_config()
            .ok_or_else(|| "not connected to the coordination plane".to_string())?
            .clone();
        crate::coordination_client::consume_send_authorization(
            &config.addr,
            &config.access_token,
            grant_id,
            grant_nonce,
            &pending.device_id,
            &self.state.device_id,
        )
        .await?;
        Ok(())
    }
}

/// Waits for `peer_orchestrator` to publish this device's `QuicPeerEndpoint`
/// (built lazily, on the first applied netmap push -- see
/// `DaemonState::shared_quic_peer_endpoint`'s own doc comment), then builds
/// and publishes this device's `SendService` and runs its inbound-connection
/// dispatcher for the life of the daemon.
///
/// `config_dir` is this device's own config directory -- Track Send's own
/// subdirectory of it (`config_dir/send`) is sibling to, and never shares a
/// file with, `block_store_root`/`sync_db_path` (the sync engine's paths).
/// Threaded in explicitly by the caller (production: `DaemonConfig::
/// config_dir`, matching every other per-device path this daemon derives
/// from it) rather than re-read from `crate::device_config::config_dir()`
/// in here, since that reads a single process-wide env var -- fine for one
/// device per process in production, but wrong for a test harness running
/// several `DaemonState`s in one process (`tests/support/topology.rs`),
/// where each device needs its OWN isolated Track Send store.
///
/// Spawned as a `supervise::spawn_logged` background task alongside
/// `peer_orchestrator::run` -- only when this device is logged in and
/// registered (Track Send needs the same coordination-plane device
/// identity `peer_orchestrator` does), never started otherwise.
pub async fn run(
    state: Arc<DaemonState>,
    config_dir: PathBuf,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let endpoint = loop {
        if let Some(endpoint) = state.shared_quic_peer_endpoint() {
            break endpoint;
        }
        tokio::time::sleep(ENDPOINT_POLL_INTERVAL).await;
    };

    let base_dir = config_dir.join("send");
    let store_db_path = base_dir.join("store.sqlite3");
    let block_store_root = base_dir.join("blocks");
    let default_inbox_dir = base_dir.join("inbox");
    let directory: Arc<dyn DeviceDirectory> =
        Arc::new(DaemonDeviceDirectory { state: state.clone() });

    let service = Arc::new(SendService::new(
        endpoint,
        store_db_path,
        block_store_root,
        directory,
        default_inbox_dir,
    )?);
    state.set_send_service(service.clone());

    service.run_inbound_dispatcher().await;
    Ok(())
}

/// The `send`/`receive` half of Track Send's control-socket surface --
/// `ApplicationServices`' one Track Send field, matching every other
/// mutating command's own service. Read-only `inbox` is
/// [`InboxQueries`] instead, in `QueryServices`, mirroring this crate's
/// existing command/query split (e.g. `link_lifecycle` vs `link_status`).
pub(crate) struct SendTransferService {
    state: Arc<DaemonState>,
}

impl SendTransferService {
    pub(crate) fn new(state: Arc<DaemonState>) -> Self {
        Self { state }
    }

    fn service(&self) -> Result<Arc<SendService>, String> {
        self.state.send_service().ok_or_else(|| {
            "Track Send is not ready yet (this device has no coordination-plane connectivity \
             established)"
                .to_string()
        })
    }

    pub(crate) async fn send(
        &self,
        source_path: &str,
        target_device: &str,
    ) -> Result<SendOfferOutcome, String> {
        let service = self.service()?;
        service
            .offer_send(std::path::Path::new(source_path), target_device)
            .await
            .map_err(|e| e.to_string())
    }

    pub(crate) async fn receive(
        &self,
        transfer_id: &str,
        destination_dir: Option<&str>,
    ) -> Result<ReceiveOutcome, String> {
        let service = self.service()?;
        let destination_dir = destination_dir.map(std::path::Path::new);
        service.receive_transfer(transfer_id, destination_dir).await.map_err(|e| e.to_string())
    }
}

pub(crate) struct InboxQueries {
    state: Arc<DaemonState>,
}

impl InboxQueries {
    pub(crate) fn new(state: Arc<DaemonState>) -> Self {
        Self { state }
    }

    pub(crate) fn list(&self) -> Result<Vec<InboxEntry>, String> {
        let service = self.state.send_service().ok_or_else(|| {
            "Track Send is not ready yet (this device has no coordination-plane connectivity \
             established)"
                .to_string()
        })?;
        service.list_inbox().map_err(|e| e.to_string())
    }
}
