//! The relay-REQUESTING side ("A"), mirror of `relay_session_handler.rs`'s
//! relay-PROVIDING side ("B"): find a relay candidate, obtain a signed
//! grant, and open a forwarding session over the existing `PeerSyncSession`
//! with that candidate.
//!
//! What comes back is a **path**, not a message-level fallback. The relay
//! is a carrier for this device's own QUIC packets, so the session opened
//! here is paired with a synthetic address
//! (`yadorilink_transport::relay_path`) that the connection supervisor then
//! dials as though it were an ordinary endpoint. Everything above the
//! transport hub -- the peer session, the block protocol, the sync engine
//! -- is unchanged and unaware, which is the point: relay is a route, and
//! routes do not belong in an application message channel.
//!
//! Nothing here relaxes an authorization check. The grant is issued by the
//! coordination plane, the relaying device independently re-verifies it and
//! the group co-membership of all three devices on open and on every
//! datagram, and this side additionally refuses to open a session through a
//! relay it is not itself *directly* connected to, which is what keeps a
//! relay from silently becoming a second hop.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use yadorilink_sync_wire::{RelayOpenFrame, RelayOpenedFrame};

use crate::daemon_state::DaemonState;
use crate::relay_grant::RelayGrant;

/// How long [`open_relay_path`] waits for a `RelayOpened` reply before
/// giving up on a candidate -- generous relative to a single wire round
/// trip, but bounded, so a relay that never answers cannot stall a
/// connection attempt indefinitely.
const RELAY_OPEN_REPLY_TIMEOUT: Duration = Duration::from_secs(5);

/// M3 Pass 6: how this device, acting as relay REQUESTER, obtains a
/// signed [`RelayGrant`] authorizing `relay_device_id` to forward this
/// device's traffic to `destination_device_id` within `group_id` -- see
/// [`relay_grant::verify_relay_grant`](crate::relay_grant::verify_relay_grant)
/// for what the relay itself checks on the other end.
///
/// P0-A: [`ProductionRelayGrantSource`] (below) is the real implementation,
/// installed unconditionally by `app.rs` at startup, calling
/// `coordination_client::request_relay_grant` against coordination-worker's
/// `POST /shares/groups/:groupId/relay/grant`. Tests supply
/// `FakeCoordination` as a `RelayGrantSource` instead (a separate
/// compilation unit, `tests/`, so it needs its own implementation rather
/// than reusing this one).
pub trait RelayGrantSource: Send + Sync {
    fn request_relay_grant<'a>(
        &'a self,
        destination_device_id: &'a str,
        relay_device_id: &'a str,
        group_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = Option<RelayGrant>> + Send + 'a>>;
}

/// P0-A: the production [`RelayGrantSource`] -- a thin wrapper over
/// `coordination_client::request_relay_grant`, holding only the plain
/// values that call needs (not an `Arc<DaemonState>` back-reference, which
/// `DaemonState::relay_grant_source` itself holding this object as an
/// `Arc<dyn RelayGrantSource>` would turn into a genuine reference cycle).
/// `coordination_addr`/`access_token` are snapshotted once at construction
/// -- matching how every other coordination-plane caller in this crate
/// already treats `CoordinationClientConfig` (a `OnceLock`, set once for
/// the daemon's lifetime, never rotated in place).
pub struct ProductionRelayGrantSource {
    coordination_addr: String,
    access_token: String,
    source_device_id: String,
}

impl ProductionRelayGrantSource {
    pub fn new(coordination_addr: String, access_token: String, source_device_id: String) -> Self {
        Self { coordination_addr, access_token, source_device_id }
    }
}

impl RelayGrantSource for ProductionRelayGrantSource {
    fn request_relay_grant<'a>(
        &'a self,
        destination_device_id: &'a str,
        relay_device_id: &'a str,
        group_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = Option<RelayGrant>> + Send + 'a>> {
        Box::pin(async move {
            crate::coordination_client::request_relay_grant(
                &self.coordination_addr,
                &self.access_token,
                group_id,
                &self.source_device_id,
                relay_device_id,
                destination_device_id,
            )
            .await
        })
    }
}

/// A relay session this device has opened as the requester, together with
/// the synthetic address its QUIC packets to the destination should be
/// addressed to.
///
/// The handle is what owns the path: dropping it closes the synthetic
/// address, so a relay route cannot outlive the bookkeeping that describes
/// it. `Arc` because both the connection supervisor running on the path and
/// this device's inbound `RelayData` dispatch need to reach it.
pub struct OpenedRelayPath {
    pub relay_device_id: String,
    pub session_id: u64,
    pub path: Arc<yadorilink_transport::RelayPathHandle>,
}

/// Where the QUIC packets addressed to a relay path's synthetic address are
/// handed off: as `RelayData` on the control connection with the relay.
///
/// `Weak` on the session, so this never keeps a dead `PeerSyncSession`
/// alive. A session that has gone is reported as a refused send, which is
/// the truthful answer -- the relay cannot be reached over a connection
/// that no longer exists -- and is indistinguishable from packet loss to
/// the QUIC connection riding the path, which is what it effectively is.
struct RelaySessionEgress {
    session: std::sync::Weak<yadorilink_peer_session::peer_session::PeerSyncSession>,
    session_id: u64,
}

impl yadorilink_transport::RelayControlEgress for RelaySessionEgress {
    fn send_relay_data(&self, payload: Vec<u8>) -> bool {
        match self.session.upgrade() {
            Some(session) => session.send_relay_data(self.session_id, payload),
            None => false,
        }
    }
}

/// Opens a relay path toward `destination_device_id`, or reports that no
/// relay is available.
///
/// Tries each relay candidate in turn and stops at the first that grants.
/// A candidate is only tried at all if this device already has a live,
/// *direct* session with it -- this function never dials anyone to use them
/// as a relay, and never chains through a relay of its own.
pub(crate) async fn open_relay_path(
    state: &Arc<DaemonState>,
    destination_device_id: &str,
    destination_peer_public: &[u8; 32],
) -> Option<OpenedRelayPath> {
    let hub = state.shared_socket()?;
    let grant_source = state.relay_grant_source()?;

    for (relay_device_id, group_id) in state.relay_candidates(destination_device_id) {
        let Some(session) = state.peers.session(&relay_device_id) else {
            continue;
        };
        let Some(grant) = grant_source
            .request_relay_grant(destination_device_id, &relay_device_id, &group_id)
            .await
        else {
            continue;
        };

        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        state.register_pending_relay_open(
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
        // Re-verified immediately before actually sending: the grant round
        // trip just awaited above is real wall-clock time during which this
        // device's own route to `relay_device_id` could have stopped being
        // direct (it could itself have started relaying through a third
        // device). A stale grant is harmless on its own -- the relay
        // independently re-validates its own leg to the destination on open
        // and on every subsequent datagram -- but this check is what keeps
        // the leg to the relay from silently becoming a second hop.
        if !state.is_directly_reachable(&relay_device_id) {
            state.forget_pending_relay_open(&grant.grant_id);
            continue;
        }
        if session.send_relay_open(open).await.is_err() {
            // The open never reached the wire, so the reply this device
            // registered for above will never arrive. Remove the pending
            // entry now rather than leaving it for nothing to resolve;
            // every `continue` below does the same, for the same reason.
            state.forget_pending_relay_open(&grant.grant_id);
            continue;
        }

        let opened: RelayOpenedFrame =
            match tokio::time::timeout(RELAY_OPEN_REPLY_TIMEOUT, reply_rx).await {
                Ok(Ok(opened)) => opened,
                // Timed out, or the sender was dropped without ever sending
                // (the session tore down mid-wait) -- try the next candidate
                // rather than giving up entirely.
                _ => {
                    state.forget_pending_relay_open(&grant.grant_id);
                    continue;
                }
            };
        if !opened.granted {
            continue;
        }

        // The synthetic address exists only once the session behind it does,
        // so a path can never be dialed before there is anything to carry
        // its packets. If the hub refuses -- this device already holds as
        // many relay paths as it will -- the session just opened is closed
        // again rather than left running with no route attached to it.
        let egress = Arc::new(RelaySessionEgress {
            session: Arc::downgrade(&session),
            session_id: opened.session_id,
        });
        let path = match hub.open_relay_path(egress) {
            Ok(path) => Arc::new(path),
            Err(error) => {
                tracing::warn!(
                    relay = %relay_device_id,
                    %error,
                    "no relay path could be opened for a session that was just granted"
                );
                session.send_relay_close(opened.session_id, "no_local_relay_path");
                continue;
            }
        };

        state.record_requester_relay_session(
            opened.session_id,
            relay_device_id.clone(),
            *destination_peer_public,
            grant.expires_at_unix,
            path.clone(),
        );
        tracing::info!(
            relay = %relay_device_id,
            destination = %destination_device_id,
            session_id = opened.session_id,
            "opened a relay path to a peer with no direct route"
        );
        return Some(OpenedRelayPath { relay_device_id, session_id: opened.session_id, path });
    }

    None
}

/// Opens a relay path the way the connection supervisor does, for tests
/// that exercise a relay's forwarding and session isolation directly rather
/// than through a full peer connection.
///
/// `pub` under this cfg for the same reason `set_relay_grant_source` is: an
/// integration test in `tests/` is a separate compilation unit and cannot
/// reach a `pub(crate)` item. It is the same function production uses, not a
/// permissive stand-in -- every authorization step still runs.
#[cfg(any(test, feature = "test-support"))]
pub async fn open_relay_path_for_test(
    state: &Arc<DaemonState>,
    destination_device_id: &str,
    destination_peer_public: &[u8; 32],
) -> Option<OpenedRelayPath> {
    open_relay_path(state, destination_device_id, destination_peer_public).await
}

/// Tears down a relay session this device opened, in both places that
/// remember it: this device's own bookkeeping, and the relay's forwarding
/// actor.
///
/// Told explicitly rather than left to the relay's idle timeout, so a
/// device that has just promoted back to a direct path stops occupying one
/// of the relay's bounded session slots immediately.
pub(crate) fn close_relay_path(state: &DaemonState, opened: &OpenedRelayPath) {
    if let Some(session) = state.peers.session(&opened.relay_device_id) {
        session.send_relay_close(opened.session_id, "requester_closed");
    }
    state.forget_requester_relay_session(&opened.relay_device_id, opened.session_id);
}
