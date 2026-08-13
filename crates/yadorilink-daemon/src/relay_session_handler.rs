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
            #[cfg(any(test, feature = "test-support"))]
            {
                // The `MutexGuard` must not live across the `.await`
                // below -- cloning into this local binding first (rather
                // than matching directly on the locked expression) drops
                // it immediately, before any `.await` point.
                let test_handler = self
                    .test_relay_session_handler
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .clone();
                if let Some(test_handler) = test_handler {
                    return test_handler
                        .handle_relay_open(open, authenticated_peer_device_id, reply_sink)
                        .await;
                }
            }

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
                grant.source_device_id.clone(),
                destination_addr,
                grant.max_session_bytes,
                grant.expires_at_unix,
                now_unix_millis(),
                reply_sink,
            ) {
                Ok(session_id) => {
                    self.record_relay_session(
                        session_id,
                        grant.source_device_id.clone(),
                        grant.group_id.clone(),
                        grant.destination_device_id.clone(),
                    );
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
        authenticated_peer_device_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            #[cfg(any(test, feature = "test-support"))]
            {
                let test_handler = self
                    .test_relay_session_handler
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .clone();
                if let Some(test_handler) = test_handler {
                    return test_handler.handle_relay_data(data, authenticated_peer_device_id).await;
                }
            }

            // M3 Pass 6: this device opened `data.session_id` itself, as
            // relay REQUESTER (`RelayCarrier::send_via_relay`) -- an
            // inbound `RelayData` for it is the destination's reply routed
            // back by the relay, never a forward request THIS device is
            // being asked to admit. Checked first, and returns either way,
            // so a requester session id can never fall through into the
            // provider-side admission/forwarding path below.
            if let Some((relay_device_id, destination_peer_public)) =
                self.requester_relay_session(data.session_id)
            {
                if relay_device_id != authenticated_peer_device_id {
                    // Same ownership reasoning as independent-review
                    // finding H1 on the provider side: two different
                    // relays' own independent session-id counters can
                    // coincide, so only the relay THIS device actually
                    // opened this session through may deliver to it.
                    tracing::debug!(
                        session_id = data.session_id,
                        peer = authenticated_peer_device_id,
                        "relay data for a requester session opened via a different relay; dropping"
                    );
                    return;
                }
                if let Some(device_id) = self.device_id_for_peer_public(&destination_peer_public) {
                    if let Some(channel) = self.direct_channel(&device_id) {
                        channel.deliver_relay_datagram(data.payload);
                    }
                }
                return;
            }

            // M3 Pass 5 (independent-review finding H2): re-runs the exact
            // same authorization checks `admit_relay_open` ran at OPEN
            // time, against THIS device's CURRENT live state, on EVERY
            // datagram -- not just once at open. A group-edge revoke, a
            // relay-capability disablement, or the destination's route
            // dropping out of `RouteKind::Direct` (independent-review
            // finding M3 -- covers a route that stops being direct
            // WITHOUT the channel object itself being removed, which
            // `remove_direct_channel`'s own route-loss cleanup wouldn't
            // otherwise catch) all take effect on the very next datagram,
            // not merely "eventually, at grant expiry".
            if let Err(reason) = self.revalidate_relay_session(data.session_id) {
                tracing::warn!(
                    session_id = data.session_id,
                    peer = authenticated_peer_device_id,
                    reason,
                    "relay session failed revalidation; closing"
                );
                self.relay_forwarder.close_session(data.session_id, reason);
                self.forget_relay_session(data.session_id);
                return;
            }

            // An unknown session id (never granted, or already closed), OR
            // one this peer never opened (independent-review finding H1 --
            // `forward_from_source` verifies ownership before sending
            // anything) is dropped silently -- see `RelayData`'s own
            // `.proto` doc comment for why: replying to a probe an
            // attacker doesn't actually own gives them a signal, so both
            // cases stay indistinguishable from ordinary packet loss.
            if let Err(error) = self
                .relay_forwarder
                .forward_from_source(
                    data.session_id,
                    authenticated_peer_device_id,
                    &data.payload,
                    now_unix_millis(),
                )
                .await
            {
                tracing::debug!(
                    session_id = data.session_id,
                    peer = authenticated_peer_device_id,
                    error = %error,
                    "relay data refused"
                );
            }
        })
    }

    fn handle_relay_close<'a>(
        &'a self,
        close: RelayCloseFrame,
        authenticated_peer_device_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            #[cfg(any(test, feature = "test-support"))]
            {
                let test_handler = self
                    .test_relay_session_handler
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .clone();
                if let Some(test_handler) = test_handler {
                    return test_handler.handle_relay_close(close, authenticated_peer_device_id).await;
                }
            }

            // M3 Pass 6: same requester-session short-circuit as `handle_
            // relay_data`'s own -- the relay this device opened the
            // session through is reporting it closed (route lost, idle
            // timeout, byte cap). Nothing on this device to close in turn
            // (there is no local forwarding actor for a requester
            // session); just stop treating it as usable so a later `send_
            // via_relay` opens a fresh one instead of sending into a
            // session the relay has already torn down.
            if let Some((relay_device_id, _)) = self.requester_relay_session(close.session_id) {
                if relay_device_id == authenticated_peer_device_id {
                    self.forget_requester_relay_session(close.session_id);
                }
                return;
            }

            // Ownership-checked (independent-review finding H1) -- an
            // ownership MISMATCH is logged; "already gone" (Ok from a
            // close racing the session's own natural end) is not.
            match self.relay_forwarder.close_session_as(
                close.session_id,
                authenticated_peer_device_id,
                "requester_closed",
            ) {
                Ok(()) => self.forget_relay_session(close.session_id),
                Err(error) => {
                    tracing::debug!(
                        session_id = close.session_id,
                        peer = authenticated_peer_device_id,
                        error = %error,
                        "relay close refused"
                    );
                }
            }
        })
    }

    fn handle_relay_opened<'a>(
        &'a self,
        opened: RelayOpenedFrame,
        authenticated_peer_device_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            #[cfg(any(test, feature = "test-support"))]
            {
                let test_handler = self
                    .test_relay_session_handler
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .clone();
                if let Some(test_handler) = test_handler {
                    return test_handler
                        .handle_relay_opened(opened, authenticated_peer_device_id)
                        .await;
                }
            }
            // M3 Pass 6: resolves the oneshot `RelayCarrier::send_via_relay`
            // registered under `opened.grant_id` before sending the
            // matching `RelayOpen` -- see `pending_relay_opens`'s and
            // `resolve_pending_relay_open`'s own doc comments for the
            // sender-identity check this performs.
            self.resolve_pending_relay_open(opened, authenticated_peer_device_id);
        })
    }
}
