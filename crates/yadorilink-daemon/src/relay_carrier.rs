//! M3 Pass 6: wires `DaemonState` up as this crate's implementation of
//! `yadorilink_transport::peer_channel::RelayCarrier` -- the seam
//! `PeerChannel::send_batch_direct` falls back to once direct sending has
//! given up (`Unreachable`) or is already using a relay (`ConnectedRelay`),
//! see that trait's own doc comment.
//!
//! This is the relay-REQUESTING side ("A"), the mirror of `relay_session_
//! handler.rs`'s relay-PROVIDING side ("B"): find a relay candidate,
//! obtain a signed grant, open a session over an existing `PeerSyncSession`
//! with that candidate, and route subsequent datagrams -- both outbound
//! (`send_via_relay`) and the destination's replies, which arrive back on
//! that SAME session as ordinary `RelayData` frames (`relay_session_
//! handler::handle_relay_data`'s own requester-side branch routes those
//! into the right `PeerChannel` via `deliver_relay_datagram`).

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use bytes::Bytes;
use yadorilink_sync_wire::{RelayOpenFrame, RelayOpenedFrame};

use crate::daemon_state::DaemonState;
use crate::relay_grant::RelayGrant;

/// How long `send_via_relay` waits for a `RelayOpenedFrame` reply before
/// giving up on this attempt -- generous relative to a single wire
/// round-trip (this is a fallback path, not latency-sensitive the way a
/// direct send is), but still bounded so a relay candidate that never
/// answers cannot stall an outbound datagram indefinitely.
const RELAY_OPEN_REPLY_TIMEOUT: Duration = Duration::from_secs(5);

/// M3 Pass 6: how this device, acting as relay REQUESTER, obtains a
/// signed [`RelayGrant`] authorizing `relay_device_id` to forward this
/// device's traffic to `destination_device_id` within `group_id` -- see
/// [`relay_grant::verify_relay_grant`](crate::relay_grant::verify_relay_grant)
/// for what the relay itself checks on the other end.
///
/// **No production implementation exists yet.** Issuing this grant is a
/// coordination-plane (backend) responsibility; `coordination_client.rs`
/// (this device's only real coordination-plane client) has no
/// relay-grant-issuance endpoint today -- every other method there
/// (`request_handoff_lease`, `resolve_edge`, and so on) calls a real
/// backend route, and this one currently has none to call. Rather than
/// invent a wire contract for a backend this codebase has no visibility
/// into, `DaemonState::relay_grant_source` is built against this
/// abstract port and left `None` in production
/// (`RelayCarrier::send_via_relay` degrades to "relay unavailable",
/// exactly like today's unconfirmed-direct-candidate case) until a real
/// endpoint exists to implement it against. Tests supply `FakeCoordination`
/// as a `RelayGrantSource` instead.
pub trait RelayGrantSource: Send + Sync {
    fn request_relay_grant<'a>(
        &'a self,
        destination_device_id: &'a str,
        relay_device_id: &'a str,
        group_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = Option<RelayGrant>> + Send + 'a>>;
}

impl yadorilink_transport::RelayCarrier for DaemonState {
    fn send_via_relay<'a>(
        &'a self,
        peer_public: &'a [u8; 32],
        datagram: Bytes,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        Box::pin(async move {
            let Some(destination_device_id) = self.device_id_for_peer_public(peer_public) else {
                tracing::debug!("relay send requested for a peer with no known channel; dropping");
                return false;
            };

            // Reuse an already-open requester session for this destination,
            // if one exists and its relay session is still live.
            if let Some((session_id, relay_device_id)) =
                self.requester_relay_session_for_destination(peer_public)
            {
                if let Some(session) = self.peers.session(&relay_device_id) {
                    session.send_relay_data(session_id, datagram.to_vec());
                    return true;
                }
                // The session to the relay itself is gone (disconnected) --
                // forget this requester session (it cannot possibly still
                // be forwarding) and fall through to opening a fresh one.
                self.forget_requester_relay_session(session_id);
            }

            let Some(grant_source) = self.relay_grant_source() else {
                return false;
            };

            for (relay_device_id, group_id) in self.relay_candidates(&destination_device_id) {
                let Some(session) = self.peers.session(&relay_device_id) else {
                    continue;
                };
                let Some(grant) = grant_source
                    .request_relay_grant(&destination_device_id, &relay_device_id, &group_id)
                    .await
                else {
                    continue;
                };

                let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
                self.register_pending_relay_open(
                    grant.grant_id.clone(),
                    relay_device_id.clone(),
                    reply_tx,
                );

                let open = RelayOpenFrame {
                    version: grant.version,
                    grant_id: grant.grant_id.clone(),
                    group_id: grant.group_id.clone(),
                    source_device_id: grant.source_device_id.clone(),
                    relay_device_id: grant.relay_device_id.clone(),
                    destination_device_id: grant.destination_device_id.clone(),
                    not_before_unix: grant.not_before_unix,
                    expires_at_unix: grant.expires_at_unix,
                    max_session_bytes: grant.max_session_bytes.unwrap_or(0),
                    signature: grant.signature.clone(),
                };
                if session.send_relay_open(open).await.is_err() {
                    continue;
                }

                let opened: RelayOpenedFrame =
                    match tokio::time::timeout(RELAY_OPEN_REPLY_TIMEOUT, reply_rx).await {
                        Ok(Ok(opened)) => opened,
                        // Timed out, or the sender was dropped without ever
                        // sending (the session tore down mid-wait) -- try
                        // the next candidate rather than giving up entirely.
                        _ => continue,
                    };
                if !opened.granted {
                    continue;
                }

                self.record_requester_relay_session(
                    opened.session_id,
                    relay_device_id,
                    *peer_public,
                );
                session.send_relay_data(opened.session_id, datagram.to_vec());
                return true;
            }

            false
        })
    }
}
