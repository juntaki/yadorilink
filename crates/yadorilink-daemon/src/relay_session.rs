//! M3 Pass 5b: the STATEFUL half of Peer Relay's authorization boundary --
//! see `crate::relay_grant`'s own doc comment for the pure half (signature/
//! version/validity-window/relay-identity) and exactly why the split
//! exists. This module answers the question a valid signature alone
//! cannot: is this grant STILL good, right now, on THIS device's own live
//! view of the world?
//!
//! A `RelayGrant` proves the coordination plane issued it at some point.
//! It does not prove:
//! - the datagram actually came from the device the grant names as
//!   `source_device_id` (a stolen/forwarded grant could be presented by
//!   anyone) -- checked against the identity of the ALREADY-AUTHENTICATED
//!   `PeerChannel` it arrived on, never trusted from the grant's own
//!   claim;
//! - `source_device_id`/`relay_device_id` (self)/`destination_device_id`
//!   are STILL, right now, all members of `group_id` -- membership can
//!   change after issuance (a revoke), and a validly-signed grant for a
//!   now-stale membership state must still fail closed;
//! - this device has actually declared `RelayCapability::Capable` (a
//!   grant naming this device as relay is meaningless if this device
//!   never opted in -- the coordination plane SHOULD only ever issue such
//!   a grant, but this device does not trust that alone);
//! - this device has a genuine, already-established DIRECT route to
//!   `destination_device_id` -- relaying never triggers a NEW connection
//!   attempt to the destination, and never itself relays through a THIRD
//!   party to reach it (no relay chaining/recursion: see this module's
//!   own `has_direct_route_to_destination` field);
//! - the grant hasn't already been used once (replay).
//!
//! **No new connectivity authority.** The invariant this whole boundary
//! exists to prove (the user's own framing, verbatim in translation):
//! "The coordination plane may issue a short-lived capability, scoped to
//! (A, B, C, G, expiry), for a SPECIFIC B, ONLY for an A<->C communication
//! that is already authorized to occur directly. B forwards no datagram
//! other than one bound to that capability." Every check in `admit_relay_
//! open` exists to make that literally true regardless of what the grant
//! itself claims.

use crate::relay_grant::{self, RelayGrant, RelayGrantError};
use crate::route::RelayCapability;

/// Bounded, cheap-to-construct snapshot of everything `admit_relay_open`
/// needs from live daemon state, assembled by the caller (not this
/// module) -- keeps this module's own admission logic a plain, exhaustively
/// testable function of its inputs, the same shape as `relay_grant::
/// verify_relay_grant`, rather than reaching into `DaemonState` itself.
pub struct RelayAdmissionContext<'a> {
    pub this_device_id: &'a str,
    /// The identity of the ALREADY-AUTHENTICATED `PeerChannel` this
    /// `RelayOpen` arrived on -- never the grant's own claimed
    /// `source_device_id`, which is untrusted input from whoever sent the
    /// message.
    pub authenticated_peer_device_id: &'a str,
    pub service_public_key: &'a [u8; 32],
    pub now_unix: i64,
    /// Whether `grant.source_device_id` is CURRENTLY a member of
    /// `grant.group_id`, per this device's own live authorization view.
    pub source_is_group_member: bool,
    /// Whether THIS device (`grant.relay_device_id`, already confirmed ==
    /// `this_device_id` by `relay_grant::verify_relay_grant`) is currently
    /// a member of `grant.group_id`.
    pub relay_is_group_member: bool,
    /// Whether `grant.destination_device_id` is CURRENTLY a member of
    /// `grant.group_id`. All three membership checks target the SAME
    /// `group_id` -- this is what prevents a relay from bridging two
    /// otherwise-disjoint groups (e.g. B in group X with A and group Y
    /// with C, but A and C never sharing a group at all): the grant names
    /// exactly one group, and all three parties must be members of THAT
    /// one.
    pub destination_is_group_member: bool,
    pub relay_capability: RelayCapability,
    /// Whether this device already has a live, established DIRECT
    /// (`RouteKind::Direct`) route to `grant.destination_device_id` --
    /// checking this, and refusing to open a NEW connection attempt or
    /// relay through a third party when it's false, is what forbids relay
    /// chaining/recursion entirely.
    pub has_direct_route_to_destination: bool,
    pub active_relay_session_count: usize,
    pub max_concurrent_relay_sessions: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RelayAdmissionError {
    #[error("grant verification failed: {0}")]
    GrantVerification(#[from] RelayGrantError),
    #[error(
        "grant names source_device_id={grant_source}, but the channel this RelayOpen arrived on \
         is authenticated as {authenticated_peer} -- a grant may only be presented by the device \
         it was issued to"
    )]
    AuthenticatedPeerMismatch { grant_source: String, authenticated_peer: String },
    #[error("{device_id} is not currently a member of group {group_id} on this device's own view")]
    NotAGroupMember { device_id: String, group_id: String },
    #[error("this device has not declared RelayCapability::Capable")]
    RelayNotCapable,
    #[error(
        "this device has no established DIRECT route to the destination -- relay never opens a \
         new connection attempt or forwards through a third party (no relay chaining)"
    )]
    NoDirectRouteToDestination,
    #[error("grant {grant_id} has already been used to open a relay session (replay)")]
    GrantReplayed { grant_id: String },
    #[error(
        "relay slot limit reached ({active}/{max}); this device is not accepting new relay \
         sessions until one closes or expires"
    )]
    RelaySlotLimitReached { active: usize, max: usize },
}

/// The one function that decides whether a `RelayOpen(grant)` may be
/// admitted -- see this module's own doc comment for exactly what each
/// check defends against. Order matters only for which error a caller
/// SEES first when multiple checks would fail; every check is
/// independently necessary, none is a substitute for another.
pub fn admit_relay_open(
    grant: &RelayGrant,
    ctx: &RelayAdmissionContext<'_>,
    replay_guard: &RelayReplayGuard,
) -> Result<(), RelayAdmissionError> {
    relay_grant::verify_relay_grant(
        grant,
        ctx.service_public_key,
        ctx.now_unix,
        ctx.this_device_id,
    )?;

    if grant.source_device_id != ctx.authenticated_peer_device_id {
        return Err(RelayAdmissionError::AuthenticatedPeerMismatch {
            grant_source: grant.source_device_id.clone(),
            authenticated_peer: ctx.authenticated_peer_device_id.to_string(),
        });
    }

    if !ctx.source_is_group_member {
        return Err(RelayAdmissionError::NotAGroupMember {
            device_id: grant.source_device_id.clone(),
            group_id: grant.group_id.clone(),
        });
    }
    if !ctx.relay_is_group_member {
        return Err(RelayAdmissionError::NotAGroupMember {
            device_id: grant.relay_device_id.clone(),
            group_id: grant.group_id.clone(),
        });
    }
    if !ctx.destination_is_group_member {
        return Err(RelayAdmissionError::NotAGroupMember {
            device_id: grant.destination_device_id.clone(),
            group_id: grant.group_id.clone(),
        });
    }

    if !ctx.relay_capability.is_capable() {
        return Err(RelayAdmissionError::RelayNotCapable);
    }

    if !ctx.has_direct_route_to_destination {
        return Err(RelayAdmissionError::NoDirectRouteToDestination);
    }

    if ctx.active_relay_session_count >= ctx.max_concurrent_relay_sessions {
        return Err(RelayAdmissionError::RelaySlotLimitReached {
            active: ctx.active_relay_session_count,
            max: ctx.max_concurrent_relay_sessions,
        });
    }

    if !replay_guard.check_and_record(&grant.grant_id, grant.expires_at_unix, ctx.now_unix) {
        return Err(RelayAdmissionError::GrantReplayed { grant_id: grant.grant_id.clone() });
    }

    Ok(())
}

/// Tracks `grant_id`s already used to open a relay session, so the SAME
/// grant cannot be presented twice (replay). Bounded by construction: an
/// entry is only ever kept until its own grant's `expires_at_unix` --
/// after that, the grant would already be rejected by `verify_relay_grant`
/// on expiry grounds alone, so retaining it here forever would only leak
/// memory, never add security.
pub struct RelayReplayGuard {
    seen: std::sync::Mutex<std::collections::HashMap<String, i64>>,
}

impl RelayReplayGuard {
    pub fn new() -> Self {
        Self { seen: std::sync::Mutex::new(std::collections::HashMap::new()) }
    }

    /// Returns `true` and records `grant_id` the FIRST time it's seen;
    /// returns `false` (does not re-record) on every subsequent call for
    /// the same `grant_id` until it naturally expires and is pruned.
    /// Pruning happens inline on every call -- no separate background
    /// sweep needed, since this guard is never queried at a rate high
    /// enough for that to matter (one call per `RelayOpen`, already rate-
    /// limited upstream by this device's own reconnect/handshake bounds).
    pub fn check_and_record(&self, grant_id: &str, expires_at_unix: i64, now_unix: i64) -> bool {
        let mut seen = self.seen.lock().unwrap_or_else(|p| p.into_inner());
        seen.retain(|_, expiry| *expiry >= now_unix);
        if seen.contains_key(grant_id) {
            return false;
        }
        seen.insert(grant_id.to_string(), expires_at_unix);
        true
    }
}

impl Default for RelayReplayGuard {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::relay_grant::sign_relay_grant;

    fn service_key() -> SigningKey {
        SigningKey::from_bytes(&[9u8; 32])
    }

    fn base_grant(key: &SigningKey, now: i64) -> RelayGrant {
        let grant = RelayGrant {
            version: 1,
            grant_id: "grant-1".to_string(),
            group_id: "group-1".to_string(),
            source_device_id: "device-a".to_string(),
            relay_device_id: "device-b".to_string(),
            destination_device_id: "device-c".to_string(),
            not_before_unix: now - 10,
            expires_at_unix: now + 300,
            max_session_bytes: None,
            signature: Vec::new(),
        };
        sign_relay_grant(grant, key)
    }

    fn valid_ctx(service_public_key: &[u8; 32], now: i64) -> RelayAdmissionContext<'_> {
        RelayAdmissionContext {
            this_device_id: "device-b",
            authenticated_peer_device_id: "device-a",
            service_public_key,
            now_unix: now,
            source_is_group_member: true,
            relay_is_group_member: true,
            destination_is_group_member: true,
            relay_capability: RelayCapability::Capable,
            has_direct_route_to_destination: true,
            active_relay_session_count: 0,
            max_concurrent_relay_sessions: 4,
        }
    }

    /// 1. valid A-B-C grant -> OPEN.
    #[test]
    fn fully_valid_grant_and_context_is_admitted() {
        let key = service_key();
        let pk = key.verifying_key().to_bytes();
        let now = 1_000_000;
        let grant = base_grant(&key, now);
        let ctx = valid_ctx(&pk, now);
        let guard = RelayReplayGuard::new();
        assert_eq!(admit_relay_open(&grant, &ctx, &guard), Ok(()));
    }

    /// 2. grant issued for A, presented by X -> reject (stolen-token
    /// scenario: the grant's own claimed source doesn't match who
    /// actually authenticated on the wire).
    #[test]
    fn grant_presented_by_a_different_authenticated_peer_is_rejected() {
        let key = service_key();
        let pk = key.verifying_key().to_bytes();
        let now = 1_000_000;
        let grant = base_grant(&key, now);
        let mut ctx = valid_ctx(&pk, now);
        ctx.authenticated_peer_device_id = "device-x";
        let guard = RelayReplayGuard::new();
        assert_eq!(
            admit_relay_open(&grant, &ctx, &guard),
            Err(RelayAdmissionError::AuthenticatedPeerMismatch {
                grant_source: "device-a".to_string(),
                authenticated_peer: "device-x".to_string(),
            })
        );
    }

    /// 4. grant for A->C used for A->D -- modeled here as: the grant's
    /// own destination (C) is not a member of the group on this device's
    /// live view (the closest analog without a second full grant fixture;
    /// substituting a different destination_device_id in the grant itself
    /// would just fail signature verification, which `tampered_grant_is_
    /// rejected` in `relay_grant.rs` already covers -- this test instead
    /// exercises what happens if a grant that WAS validly issued for C
    /// turns out to no longer have C as a group member, i.e. a stale
    /// grant, the actual "destination substitution can't be used to reach
    /// somewhere new" guarantee this layer provides).
    #[test]
    fn destination_no_longer_a_group_member_is_rejected() {
        let key = service_key();
        let pk = key.verifying_key().to_bytes();
        let now = 1_000_000;
        let grant = base_grant(&key, now);
        let mut ctx = valid_ctx(&pk, now);
        ctx.destination_is_group_member = false;
        let guard = RelayReplayGuard::new();
        assert_eq!(
            admit_relay_open(&grant, &ctx, &guard),
            Err(RelayAdmissionError::NotAGroupMember {
                device_id: "device-c".to_string(),
                group_id: "group-1".to_string(),
            })
        );
    }

    /// 5 / 6. A/B/C not all in the SAME authorization group -- modeled as
    /// each of the three membership booleans failing independently, since
    /// this device only ever re-checks membership in `grant.group_id`
    /// (the one group the grant names), never any other group any party
    /// might separately belong to. This is exactly what prevents "A-B
    /// group X + B-C group Y only" bridging: there is no group in which
    /// all three are checked simultaneously unless all three are actually
    /// members of ONE group.
    #[test]
    fn source_not_in_the_grants_group_is_rejected() {
        let key = service_key();
        let pk = key.verifying_key().to_bytes();
        let now = 1_000_000;
        let grant = base_grant(&key, now);
        let mut ctx = valid_ctx(&pk, now);
        ctx.source_is_group_member = false;
        let guard = RelayReplayGuard::new();
        assert_eq!(
            admit_relay_open(&grant, &ctx, &guard),
            Err(RelayAdmissionError::NotAGroupMember {
                device_id: "device-a".to_string(),
                group_id: "group-1".to_string(),
            })
        );
    }

    #[test]
    fn relay_self_not_in_the_grants_group_is_rejected() {
        let key = service_key();
        let pk = key.verifying_key().to_bytes();
        let now = 1_000_000;
        let grant = base_grant(&key, now);
        let mut ctx = valid_ctx(&pk, now);
        ctx.relay_is_group_member = false;
        let guard = RelayReplayGuard::new();
        assert_eq!(
            admit_relay_open(&grant, &ctx, &guard),
            Err(RelayAdmissionError::NotAGroupMember {
                device_id: "device-b".to_string(),
                group_id: "group-1".to_string(),
            })
        );
    }

    /// 11. B.RelayCapability=false -- modeled at the admission layer as a
    /// defense-in-depth check (the coordination plane should never have
    /// issued the grant in the first place; this is what happens if one
    /// somehow arrives anyway, e.g. capability was revoked after the
    /// grant's own issuance but before it was presented).
    #[test]
    fn relay_capability_disabled_is_rejected() {
        let key = service_key();
        let pk = key.verifying_key().to_bytes();
        let now = 1_000_000;
        let grant = base_grant(&key, now);
        let mut ctx = valid_ctx(&pk, now);
        ctx.relay_capability = RelayCapability::Disabled;
        let guard = RelayReplayGuard::new();
        assert_eq!(
            admit_relay_open(&grant, &ctx, &guard),
            Err(RelayAdmissionError::RelayNotCapable)
        );
    }

    /// 12. B has no direct route to C -> RelayOpen reject. Also the core
    /// of point 14 (relay-via-relay): a relay MUST already have a direct
    /// route, never opening a new connection or itself relaying to reach
    /// the destination.
    #[test]
    fn no_direct_route_to_destination_is_rejected() {
        let key = service_key();
        let pk = key.verifying_key().to_bytes();
        let now = 1_000_000;
        let grant = base_grant(&key, now);
        let mut ctx = valid_ctx(&pk, now);
        ctx.has_direct_route_to_destination = false;
        let guard = RelayReplayGuard::new();
        assert_eq!(
            admit_relay_open(&grant, &ctx, &guard),
            Err(RelayAdmissionError::NoDirectRouteToDestination)
        );
    }

    /// 13. relay slot limit reached -> bounded reject.
    #[test]
    fn relay_slot_limit_reached_is_rejected() {
        let key = service_key();
        let pk = key.verifying_key().to_bytes();
        let now = 1_000_000;
        let grant = base_grant(&key, now);
        let mut ctx = valid_ctx(&pk, now);
        ctx.active_relay_session_count = ctx.max_concurrent_relay_sessions;
        let guard = RelayReplayGuard::new();
        assert_eq!(
            admit_relay_open(&grant, &ctx, &guard),
            Err(RelayAdmissionError::RelaySlotLimitReached { active: 4, max: 4 })
        );
    }

    /// 10. replayed grant -> reject (the second presentation of the exact
    /// same grant_id, everything else identical and otherwise valid).
    #[test]
    fn replayed_grant_is_rejected_on_second_presentation() {
        let key = service_key();
        let pk = key.verifying_key().to_bytes();
        let now = 1_000_000;
        let grant = base_grant(&key, now);
        let ctx = valid_ctx(&pk, now);
        let guard = RelayReplayGuard::new();
        assert_eq!(admit_relay_open(&grant, &ctx, &guard), Ok(()));
        assert_eq!(
            admit_relay_open(&grant, &ctx, &guard),
            Err(RelayAdmissionError::GrantReplayed { grant_id: "grant-1".to_string() })
        );
    }

    #[test]
    fn replay_guard_allows_a_grant_id_again_once_its_own_expiry_has_passed() {
        let guard = RelayReplayGuard::new();
        assert!(guard.check_and_record("grant-1", 1_000_100, 1_000_000));
        // Same id, but "now" has moved past that recorded grant's own
        // expiry -- a REUSE this far out would already be rejected by
        // `verify_relay_grant`'s own expiry check first, so this guard
        // pruning the entry is a memory-bound guarantee, not a security
        // gap: nothing downstream of this guard ever accepts an expired
        // grant regardless of what this method alone returns.
        assert!(guard.check_and_record("grant-1", 1_000_100, 1_000_200));
    }
}
