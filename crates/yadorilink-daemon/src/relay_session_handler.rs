//! M3 Pass 5g: wires `DaemonState` up as this crate's implementation of
//! `yadorilink_peer_session::peer_session::RelaySessionHandler` -- the
//! seam `PeerSyncSession` dispatches `RelayOpen`/`RelayData`/`RelayClose`
//! through (see that trait's own doc comment for why the port lives in
//! the peer-session crate but its implementation lives here: this crate
//! depends on that one, never the reverse).
//!
//! This is purely composition: every real decision (grant verification,
//! stateful admission, forwarding) already lives in `relay_grant`/
//! `relay_session`/`relay_forwarder`. This module's only job is
//! assembling their inputs from live `DaemonState` and reporting the
//! result back over the wire -- see `relay_session::admit_relay_open`'s
//! own doc comment for the authorization boundary this whole pass exists
//! to prove ("no new connectivity authority"), which this module must not
//! weaken by, for example, skipping a check the admission function
//! itself doesn't perform (there are none here: every field on
//! `RelayAdmissionContext` below is filled from a real, independent
//! source, never hardcoded to a permissive value).

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use yadorilink_peer_session::peer_session::{RelayReplySink, RelaySessionHandler};
use yadorilink_sync_wire::{RelayCloseFrame, RelayDataFrame, RelayOpenFrame, RelayOpenedFrame};

use crate::daemon_state::DaemonState;
use crate::peer_registry::PeerReachability;
use crate::relay_grant::RelayGrant;
use crate::relay_session::{admit_relay_open, RelayAdmissionContext};
use crate::route::RouteKind;

fn now_unix_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn now_unix_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

impl RelaySessionHandler for DaemonState {
    fn handle_relay_open<'a>(
        &'a self,
        open: RelayOpenFrame,
        authenticated_peer_device_id: &'a str,
        reply_sink: Arc<dyn RelayReplySink>,
    ) -> Pin<Box<dyn Future<Output = RelayOpenedFrame> + Send + 'a>> {
        Box::pin(async move {
            let grant_id = open.grant_id.clone();
            let denied = |grant_id: String| RelayOpenedFrame { grant_id, granted: false, session_id: 0 };

            let grant = RelayGrant {
                version: open.version,
                grant_id: open.grant_id.clone(),
                group_id: open.group_id.clone(),
                source_device_id: open.source_device_id.clone(),
                relay_device_id: open.relay_device_id.clone(),
                destination_device_id: open.destination_device_id.clone(),
                not_before_unix: open.not_before_unix,
                expires_at_unix: open.expires_at_unix,
                max_session_bytes: if open.max_session_bytes == 0 {
                    None
                } else {
                    Some(open.max_session_bytes)
                },
                signature: open.signature.clone(),
            };

            // Fail closed on every input this device cannot independently
            // establish -- see this module's own doc comment.
            let Some(service_public_key) = self.pinned_coordination_service_key() else {
                return denied(grant_id);
            };
            let Some(direct_channel) = self.direct_channel(&grant.destination_device_id) else {
                return denied(grant_id);
            };
            let Some(destination_addr) = direct_channel.confirmed_direct_addr() else {
                return denied(grant_id);
            };

            let ctx = RelayAdmissionContext {
                this_device_id: &self.device_id,
                authenticated_peer_device_id,
                service_public_key: &service_public_key,
                now_unix: now_unix_seconds(),
                source_is_group_member: self
                    .peer_is_writer(&grant.source_device_id, &grant.group_id),
                relay_is_group_member: self.is_local_group_member(&grant.group_id),
                destination_is_group_member: self
                    .peer_is_writer(&grant.destination_device_id, &grant.group_id),
                relay_capability: if self.is_local_relay_capable() {
                    crate::route::RelayCapability::Capable
                } else {
                    crate::route::RelayCapability::Disabled
                },
                // The direct-route check is `RouteKind::Direct`
                // specifically, not merely "has a channel" -- a channel
                // can exist while still `Connecting`/`Unreachable`; only
                // a CONFIRMED direct path counts, matching `relay_
                // session`'s own no-chaining reasoning exactly (this
                // device must never dial or wait for a new connection on
                // the relay's own behalf).
                has_direct_route_to_destination: matches!(
                    self.peers.reachability(&grant.destination_device_id),
                    Some(PeerReachability::Connected(RouteKind::Direct))
                ),
                active_relay_session_count: self.relay_forwarder.active_session_count(),
                max_concurrent_relay_sessions: crate::relay_forwarder::RELAY_MAX_CONCURRENT_SESSIONS,
            };

            if let Err(error) = admit_relay_open(&grant, &ctx, &self.relay_replay_guard) {
                tracing::warn!(
                    grant_id = %grant.grant_id,
                    source = %grant.source_device_id,
                    destination = %grant.destination_device_id,
                    group_id = %grant.group_id,
                    error = %error,
                    "relay open refused"
                );
                return denied(grant_id);
            }

            match self.relay_forwarder.open_session(
                destination_addr,
                grant.max_session_bytes,
                grant.expires_at_unix,
                now_unix_millis(),
                reply_sink,
            ) {
                Ok(session_id) => {
                    tracing::info!(
                        grant_id = %grant.grant_id,
                        source = %grant.source_device_id,
                        destination = %grant.destination_device_id,
                        session_id,
                        "relay session opened"
                    );
                    RelayOpenedFrame { grant_id, granted: true, session_id }
                }
                Err(error) => {
                    tracing::warn!(grant_id = %grant.grant_id, error = %error, "relay forwarder refused to open a session");
                    denied(grant_id)
                }
            }
        })
    }

    fn handle_relay_data<'a>(
        &'a self,
        data: RelayDataFrame,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            // An unknown session id (never granted, or already closed) is
            // dropped silently -- see `RelayData`'s own `.proto` doc
            // comment for why: replying to a probe for a session id an
            // attacker doesn't actually hold gives them a signal, so this
            // stays indistinguishable from ordinary packet loss.
            let _ = self
                .relay_forwarder
                .forward_from_source(data.session_id, &data.payload, now_unix_millis())
                .await;
        })
    }

    fn handle_relay_close<'a>(
        &'a self,
        close: RelayCloseFrame,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            self.relay_forwarder.close_session(close.session_id, "requester_closed");
        })
    }
}
