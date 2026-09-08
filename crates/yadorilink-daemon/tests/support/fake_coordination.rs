//! In-process fake of the Cloudflare-Worker coordination plane, for the full-
//! stack E2E tests that drive the real [`peer_orchestrator`]. It is a test
//! fixture, not a second coordination implementation: it implements only the
//! four endpoints the daemon touches at runtime, and only enough of each to
//! make peer discovery, per-group write authorization, and revocation happen.
//!
//!   - `GET /netmap/subscribe?deviceId=` (WebSocket): pushes `{type:"netmap"}`
//!     frames — the sole seam that makes the orchestrator spawn and tear down
//!     peer sessions.
//!   - `POST /devices/:id/endpoint`, `/netmap/rendezvous`,
//!     `/devices/:id/signing-key`: answered `204` (best-effort on the daemon).
//!   - `POST /shares/groups/:groupId/relay/grant` (P0-A): the one route this
//!     fake actually implements over real HTTP rather than a blanket `204`
//!     -- see `serve_relay_grant`'s own doc comment for why: it is what lets
//!     [`crate::coordination_client::request_relay_grant`] and
//!     [`crate::relay_carrier::ProductionRelayGrantSource`] be exercised
//!     against something other than the in-process `FakeGrantSource` bypass
//!     every other relay-scenario test uses (`tests/support/topology.rs`).
//!
//! Revocation is expressed exactly as the real plane expresses it: recompute
//! the netmap without the revoked peer or group and push it; the orchestrator
//! diffs against its previous snapshot and drops the session (or the group
//! edge). There is no explicit "removed" field on the wire — a peer simply
//! stops appearing.

#![allow(dead_code)]

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use ed25519_dalek::SigningKey;
use futures_util::SinkExt;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::protocol::Role;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

#[derive(Clone)]
struct DeviceInfo {
    wireguard_public_key_b64: String,
    signing_public_key_b64: String,
    /// Every address this device advertises, in the order the netmap
    /// presents them. A real coordination plane publishes each address a
    /// device might be reachable at -- its LAN interfaces, its reflexive
    /// address, a port-mapped one -- because it cannot know which of them a
    /// given peer can actually use. A list rather than one address
    /// specifically so a test can express the shape that matters: a peer
    /// whose FIRST advertised endpoint does not work.
    endpoints: Vec<String>,
    groups: HashSet<String>,
    full_replica_groups: HashSet<String>,
    /// M3 Pass 4: device-scoped (not group-scoped, unlike
    /// `full_replica_groups`) -- see `crate::route::RelayCapability`.
    relay_capable: bool,
}

#[derive(Default)]
struct Inner {
    devices: HashMap<String, DeviceInfo>,
    snapshot_generation: u64,
    /// device_id -> sender forwarding a netmap JSON text frame to that device's
    /// live WebSocket connection.
    subscribers: HashMap<String, mpsc::UnboundedSender<String>>,
    /// Opt-in signed policy distribution for tests that exercise local writes
    /// after the coordination connection disappears. Other fake users keep the
    /// legacy policy-free frame so their revocation semantics stay unchanged.
    policy_service_key: Option<SigningKey>,
    /// `(viewer_device_id, target_device_id) -> endpoints`, overriding what
    /// `target_device_id`'s own `DeviceInfo::endpoints` would otherwise
    /// publish, but ONLY in the netmap frame `viewer_device_id` itself
    /// receives -- see `FakeCoordination::set_peer_view_endpoints`'s own
    /// doc comment for why this exists (asymmetric reachability, not a
    /// device-global property). Deliberately separate storage from
    /// `DeviceInfo`, not a field on it: a real coordination plane has
    /// exactly one advertised-endpoints list per device, and conflating an
    /// asymmetric test override with that would make `update_endpoints`
    /// (which mutates `DeviceInfo` and models a device's own candidate
    /// republish) silently clobber or be clobbered by this. Survives
    /// `register_device` re-registering `target_device_id` with a fresh
    /// real endpoint -- restart tests specifically need a viewer's view of
    /// a peer to stay overridden across that peer's own reconnect.
    endpoint_view_overrides: HashMap<(String, String), Vec<String>>,
    /// Track Send rendezvous grants -- see `serve_send_authorization_issue`'s
    /// own doc comment. grant_id -> record.
    send_authorizations: HashMap<String, FakeSendAuthorization>,
    /// Per-group, append-only signed policy chain this fake has issued via
    /// `grant_role`, in the exact `PolicyRecord` shape
    /// `yadorilink_daemon::change_policy::verify_group_policy_log` accepts --
    /// built with that same crate's own `change_policy::policy_signing::
    /// grant_record` helper, so a record built here is byte-identical
    /// (preimage, hash chain, signature) to one `coordination-worker`'s real
    /// `recordGrantWithRole` (`src/policy/service.ts`) would produce, not a
    /// hand-rolled approximation of the wire format. A group with no entry
    /// here has never had `grant_role` called for it -- `signed_policy_logs`
    /// then falls back to the historical all-zero, no-records frame every
    /// non-role-aware test already depends on.
    group_policy_chains: HashMap<String, Vec<yadorilink_daemon::change_policy::PolicyRecord>>,
    /// Per-subscriber, per-group "already sent up to this seq" watermark --
    /// mirrors `coordination-worker`'s own per-WebSocket `policyWatermarks`
    /// (`durable-objects/netmap-device.ts`): a group's policy chain is never
    /// resent in full to a subscriber that has already seen a prefix of it,
    /// only the tail beyond what it was last sent, because the daemon's own
    /// `verify_group_policy_log_with_base` only accepts a record tail that
    /// starts exactly at its last verified seq + 1, not a redundant full
    /// resend. Reset (removed) whenever a device (re)subscribes, exactly
    /// like a fresh production WebSocket starts with a fresh (empty)
    /// watermark map for that connection.
    policy_send_watermarks: HashMap<String, HashMap<String, u64>>,
}

/// One in-flight (or already-consumed) Track Send grant this fake has
/// issued. Mirrors coordination-worker's `send_authorizations` table just
/// enough for real daemon-side E2E coverage: identity binding and atomic
/// single-use consumption. Deliberately does not model account scoping
/// (this fake has no account concept for anything else either -- every
/// registered device is implicitly "the same account") or a real TTL sweep
/// -- those properties are exhaustively covered by coordination-worker's
/// own `test/send-authorization.test.ts` against the real Worker; this
/// fake's job is only to exercise the DAEMON side end to end.
#[derive(Clone)]
struct FakeSendAuthorization {
    nonce: String,
    sender_device_id: String,
    receiver_device_id: String,
    consumed: bool,
}

/// A handle to the running fake. Cloneable; every clone shares one server.
#[derive(Clone)]
pub struct FakeCoordination {
    inner: Arc<Mutex<Inner>>,
    addr: String,
    accept_task: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
}

impl FakeCoordination {
    /// Binds a loopback listener and starts serving. The returned address is an
    /// `http://127.0.0.1:PORT` base URL suitable for `OrchestratorConfig::
    /// coordination_addr` (the daemon rewrites it to `ws://` for the netmap
    /// subscription and dials the POST endpoints over http).
    pub async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = format!("http://{}", listener.local_addr().unwrap());
        let inner = Arc::new(Mutex::new(Inner::default()));
        let accept_inner = inner.clone();
        let accept_task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else { return };
                let conn_inner = accept_inner.clone();
                tokio::spawn(async move {
                    let _ = handle_connection(stream, conn_inner).await;
                });
            }
        });
        FakeCoordination { inner, addr, accept_task: Arc::new(Mutex::new(Some(accept_task))) }
    }

    pub fn addr(&self) -> String {
        self.addr.clone()
    }

    pub fn enable_signed_policy(&self) {
        self.inner.lock().unwrap().policy_service_key = Some(SigningKey::from_bytes(&[42u8; 32]));
    }

    /// The service signing key `enable_signed_policy` installed, for a
    /// test that needs to sign something (e.g. a `RelayGrant`) itself the
    /// same way this fake's own `issue_relay_grant` does, rather than
    /// going through that method's own candidate-search logic.
    pub fn policy_signing_key(&self) -> Option<SigningKey> {
        self.inner.lock().unwrap().policy_service_key.clone()
    }

    /// Grants `device_id` a specific writer role for `group_id` by appending
    /// a real, signed `ACTION_GRANT_WITH_ROLE` record to that group's policy
    /// chain and pushing a fresh netmap update -- the fake-coordination
    /// counterpart to a real `share grant --role viewer|editor` request
    /// landing on `coordination-worker`'s `recordGrantWithRole`
    /// (`coordination-worker/src/policy/service.ts`). Built with
    /// `yadorilink_daemon::change_policy::policy_signing::grant_record`, the
    /// SAME helper this crate's own unit tests
    /// (`daemon_state.rs`'s `local_change_auth_provider_withholds_a_viewers_
    /// local_edit_but_allows_an_editor`, `change_auth.rs`'s
    /// `accepts_change_auth_rejects_a_viewer_and_accepts_the_same_device_
    /// as_an_editor`) use to construct a role-carrying Grant -- the record
    /// this produces is therefore byte-identical in shape (preimage, hash
    /// chain, signature) to what a real coordination plane would sign, not
    /// an approximation of `GroupPolicyLogWire`/`WsPolicyRecord`'s wire
    /// contract.
    ///
    /// `device_id` must already be registered (`register_device`) -- the
    /// Grant binds the SHA-256 fingerprint of its currently-registered
    /// signing key, exactly as a real Grant binds a device's registered
    /// key. `enable_signed_policy` must have been called first; panics
    /// otherwise, since there is no service signing key to issue a record
    /// with. Multiple calls for the same group append further records to
    /// that group's chain (seq keeps increasing), so a device's role can be
    /// changed (e.g. Viewer then later Editor) the same way a real grant
    /// chain evolves.
    pub fn grant_role(
        &self,
        device_id: &str,
        group_id: &str,
        role: yadorilink_daemon::change_policy::WriterRole,
    ) {
        use yadorilink_daemon::change_policy::policy_signing::grant_record;
        {
            let mut inner = self.inner.lock().unwrap();
            let signing_key = inner
                .policy_service_key
                .clone()
                .expect("grant_role requires enable_signed_policy() to be called first");
            let device = inner
                .devices
                .get(device_id)
                .unwrap_or_else(|| panic!("grant_role: device {device_id} is not registered"))
                .clone();
            let b64 = base64::engine::general_purpose::STANDARD;
            let signing_public_key: [u8; 32] = b64
                .decode(&device.signing_public_key_b64)
                .expect("registered signing key is valid base64")
                .try_into()
                .expect("registered signing key is 32 bytes");
            let fingerprint: [u8; 32] = Sha256::digest(signing_public_key).into();

            let chain = inner.group_policy_chains.entry(group_id.to_string()).or_default();
            let prev: [u8; 32] = chain
                .last()
                .map(|record| {
                    record.record_hash.as_slice().try_into().expect("record_hash is 32 bytes")
                })
                .unwrap_or([0u8; 32]);
            let seq = chain.last().map(|record| record.seq + 1).unwrap_or(1);
            let record =
                grant_record(&signing_key, group_id, seq, prev, device_id, fingerprint, role);
            chain.push(record);
        }
        self.push();
    }

    /// Changes `device_id`'s role for `group_id` the same way
    /// `coordination-worker`'s live role-change endpoint (`changeDeviceRole`,
    /// `src/shares/service.ts`) does for a DOWNGRADE: a plain `Revoke`
    /// record (bumping the group's `auth_epoch`, exactly like an ordinary
    /// revoke) immediately followed by a `GrantWithRole` record at
    /// `new_role`, at the SAME newly-bumped epoch -- and then a fresh
    /// netmap push, so every subscriber (including `device_id` itself)
    /// re-derives write authorization from the updated chain on its very
    /// next check.
    ///
    /// Unlike a real downgrade, this always appends the chained pair
    /// regardless of whether `new_role` genuinely outranks the device's
    /// current role -- callers that need to distinguish upgrade-vs-downgrade
    /// behavior should call `grant_role` directly for a plain upgrade (no
    /// epoch bump); this helper exists specifically to drive the
    /// epoch-bumping downgrade path end to end. `device_id` must already be
    /// registered and already have a prior `grant_role` call for
    /// `group_id` (there must be a chain to revoke from); panics otherwise.
    pub fn downgrade_role(
        &self,
        device_id: &str,
        group_id: &str,
        new_role: yadorilink_daemon::change_policy::WriterRole,
    ) {
        use yadorilink_daemon::change_policy::policy_signing::{
            grant_record_at_epoch, revoke_record_at_epoch,
        };
        {
            let mut inner = self.inner.lock().unwrap();
            let signing_key = inner
                .policy_service_key
                .clone()
                .expect("downgrade_role requires enable_signed_policy() to be called first");
            let device = inner
                .devices
                .get(device_id)
                .unwrap_or_else(|| panic!("downgrade_role: device {device_id} is not registered"))
                .clone();
            let b64 = base64::engine::general_purpose::STANDARD;
            let signing_public_key: [u8; 32] = b64
                .decode(&device.signing_public_key_b64)
                .expect("registered signing key is valid base64")
                .try_into()
                .expect("registered signing key is 32 bytes");
            let fingerprint: [u8; 32] = Sha256::digest(signing_public_key).into();

            let chain = inner.group_policy_chains.get_mut(group_id).unwrap_or_else(|| {
                panic!("downgrade_role: group {group_id} has no policy chain yet")
            });
            let head = chain.last().expect("downgrade_role: group's policy chain is empty");
            let head_hash: [u8; 32] =
                head.record_hash.as_slice().try_into().expect("record_hash is 32 bytes");
            let new_epoch = head.epoch + 1;
            let revoke_seq = head.seq + 1;
            let revoke = revoke_record_at_epoch(
                &signing_key,
                group_id,
                revoke_seq,
                head_hash,
                new_epoch,
                device_id,
            );
            let revoke_hash: [u8; 32] =
                revoke.record_hash.as_slice().try_into().expect("record_hash is 32 bytes");
            let regrant = grant_record_at_epoch(
                &signing_key,
                group_id,
                revoke_seq + 1,
                revoke_hash,
                new_epoch,
                device_id,
                fingerprint,
                new_role,
            );
            chain.push(revoke);
            chain.push(regrant);
        }
        self.push();
    }

    /// Takes the coordination plane down completely, as a chaos test needs:
    /// aborts the accept loop (freeing the listener, so the bound port stops
    /// answering and any daemon reconnect attempt fails) and drops every live
    /// subscription (closing the daemons' netmap WebSockets). Peer-to-peer
    /// sync, which runs over the direct transport, is unaffected — which is the
    /// whole point of the availability-independence tests.
    pub fn shutdown(&self) {
        if let Some(task) = self.accept_task.lock().unwrap().take() {
            task.abort();
        }
        let mut inner = self.inner.lock().unwrap();
        inner.subscribers.clear();
        inner.devices.clear();
        inner.endpoint_view_overrides.clear();
    }

    /// Records a device's identity and initial group membership, then pushes a
    /// fresh netmap to everyone. A device has one real key now (its Ed25519
    /// signing key), so callers pass the same key for both `wireguard_public_key`
    /// and `signing_public_key` here — the two parameters exist only because
    /// this fake mirrors the coordination plane's real registration schema,
    /// which still names one column after the retired transport key. The
    /// orchestrator pins both from the netmap and verifies every incoming
    /// change against the pinned signing key.
    pub fn register_device(
        &self,
        device_id: &str,
        wireguard_public_key: [u8; 32],
        signing_public_key: [u8; 32],
        endpoint: String,
        groups: &[&str],
    ) {
        let b64 = base64::engine::general_purpose::STANDARD;
        let info = DeviceInfo {
            wireguard_public_key_b64: b64.encode(wireguard_public_key),
            signing_public_key_b64: b64.encode(signing_public_key),
            endpoints: vec![endpoint],
            groups: groups.iter().map(|g| g.to_string()).collect(),
            full_replica_groups: HashSet::new(),
            relay_capable: false,
        };
        self.inner.lock().unwrap().devices.insert(device_id.to_string(), info);
        self.push();
    }

    /// Marks (or clears) a device as a full replica ("store everything") of a
    /// group — mirrored onto peers' `fullReplicaGroupIds`.
    pub fn set_full_replica(&self, device_id: &str, group_id: &str, is_full_replica: bool) {
        {
            let mut inner = self.inner.lock().unwrap();
            if let Some(dev) = inner.devices.get_mut(device_id) {
                if is_full_replica {
                    dev.full_replica_groups.insert(group_id.to_string());
                } else {
                    dev.full_replica_groups.remove(group_id);
                }
            }
        }
        self.push();
    }

    /// M5-A: republishes `device_id`'s advertised endpoint -- mirroring
    /// what a real coordination plane would push over the netmap
    /// subscription if a device's network conditions changed (e.g. a new
    /// reflexive address). This is a device-GLOBAL candidate republish,
    /// the same information every peer's netmap subscription receives --
    /// it does not, and cannot, tear down a live QUIC connection any peer
    /// already has to `device_id`. Production's own orchestrator only
    /// consults candidates when it has no live session (initial dial,
    /// post-failure reconnect): an established connection is left alone
    /// by a bare candidate update, precisely so that address churn during
    /// a live session does not itself cause disruption. A test that needs
    /// to force a genuinely dead path for one specific peer pair, or to
    /// force a currently-live direct connection down, needs
    /// `set_peer_view_endpoints` and/or an explicit live-connection
    /// teardown seam respectively -- see that method's own doc comment.
    #[allow(dead_code)]
    pub fn update_endpoint(&self, device_id: &str, endpoint: String) {
        self.update_endpoints(device_id, vec![endpoint]);
    }

    /// Republishes `device_id`'s advertised endpoints as a whole ordered
    /// list, so a test can express a peer that advertises several addresses
    /// of which only some work -- in particular one whose FIRST advertised
    /// address does not. Device-global, like `update_endpoint`'s own doc
    /// comment explains -- every subscriber sees the same list, subject to
    /// `set_peer_view_endpoints`'s per-viewer override below.
    #[allow(dead_code)]
    pub fn update_endpoints(&self, device_id: &str, endpoints: Vec<String>) {
        {
            let mut inner = self.inner.lock().unwrap();
            if let Some(dev) = inner.devices.get_mut(device_id) {
                dev.endpoints = endpoints;
            }
        }
        self.push();
    }

    /// Overrides the endpoints `viewer_device_id`'s OWN netmap reports for
    /// `target_device_id`, independent of what every other subscriber
    /// sees. A real coordination plane cannot generally do this (it
    /// publishes one endpoint list per device to everyone), but this test
    /// fixture needs it anyway: a relay scenario wants `M` and `W` to be
    /// mutually unreachable while both stay reachable from `N`, and
    /// `update_endpoints`'s device-global republish cannot express that
    /// asymmetry at all -- setting `W`'s endpoint dead would make `N` lose
    /// its own real direct path to `W` too.
    ///
    /// Overriding here has no effect on group membership, full-replica
    /// status, or relay-grant issuance -- purely which address(es)
    /// `viewer_device_id`'s netmap names for `target_device_id`. Survives
    /// `target_device_id` re-registering via `register_device` (a restart
    /// pushing a fresh real endpoint does not implicitly clear a viewer's
    /// override of it -- exactly the shape a restart-while-relayed test
    /// needs: the restarted peer's real address must stay invisible to
    /// the one specific viewer this override targets).
    #[allow(dead_code)]
    pub fn set_peer_view_endpoints(
        &self,
        viewer_device_id: &str,
        target_device_id: &str,
        endpoints: Vec<String>,
    ) {
        {
            let mut inner = self.inner.lock().unwrap();
            inner
                .endpoint_view_overrides
                .insert((viewer_device_id.to_string(), target_device_id.to_string()), endpoints);
        }
        self.push();
    }

    /// Removes a `set_peer_view_endpoints` override, reverting
    /// `viewer_device_id`'s view of `target_device_id` to that device's
    /// own globally-advertised endpoints.
    #[allow(dead_code)]
    pub fn clear_peer_view_endpoints(&self, viewer_device_id: &str, target_device_id: &str) {
        {
            let mut inner = self.inner.lock().unwrap();
            inner
                .endpoint_view_overrides
                .remove(&(viewer_device_id.to_string(), target_device_id.to_string()));
        }
        self.push();
    }

    /// M3 Pass 4: declares (or clears) a device's own relay capability --
    /// mirrored onto peers' `relayCapable`. Deliberately independent of
    /// `set_full_replica`: never coupled, never inferred from one another
    /// (see `crate::route`'s own doc comment).
    #[allow(dead_code)]
    pub fn set_relay_capable(&self, device_id: &str, relay_capable: bool) {
        {
            let mut inner = self.inner.lock().unwrap();
            if let Some(dev) = inner.devices.get_mut(device_id) {
                dev.relay_capable = relay_capable;
            }
        }
        self.push();
    }

    /// M3 Pass 5: synthesizes and signs a `RelayGrant` the way the real
    /// coordination plane would, per this pass's own security spec: finds
    /// a group ALL THREE of (`source_device_id`, some relay-capable
    /// device, `destination_device_id`) are CURRENTLY members of, and
    /// issues a grant scoped to exactly that one group -- never a relay
    /// whose only shared group with the source differs from its only
    /// shared group with the destination (that would bridge two
    /// otherwise-disjoint groups, exactly what `relay_session::
    /// admit_relay_open`'s own group-membership re-verification exists to
    /// refuse regardless of what a grant claims). Returns `None` if no
    /// such group/relay candidate exists, or if `enable_signed_policy`
    /// was never called (no signing key to issue with -- this fake never
    /// issues an unsigned or forged-key grant, matching the real plane's
    /// own contract).
    ///
    /// A plain synchronous method, not an HTTP round trip -- this fake's
    /// own HTTP layer only ever implements the netmap subscription itself
    /// (see this file's own module doc comment); every other
    /// coordination interaction this test suite exercises (`set_full_
    /// replica`, `set_relay_capable`, and now this) is synthesized
    /// directly, matching that established convention, since there is no
    /// real coordination-worker in this repo to test a genuine
    /// POST/response cycle against.
    pub fn issue_relay_grant(
        &self,
        source_device_id: &str,
        destination_device_id: &str,
        ttl_seconds: i64,
    ) -> Option<yadorilink_daemon::relay_grant::RelayGrant> {
        let inner = self.inner.lock().unwrap();
        let signing_key = inner.policy_service_key.clone()?;
        let source_groups = inner.devices.get(source_device_id)?.groups.clone();
        let dest_groups = inner.devices.get(destination_device_id)?.groups.clone();
        let shared_groups: Vec<String> =
            source_groups.intersection(&dest_groups).cloned().collect();
        let mut candidate = None;
        'outer: for group_id in &shared_groups {
            for (relay_id, dev) in &inner.devices {
                if relay_id == source_device_id || relay_id == destination_device_id {
                    continue;
                }
                if dev.relay_capable && dev.groups.contains(group_id) {
                    candidate = Some((relay_id.clone(), group_id.clone()));
                    break 'outer;
                }
            }
        }
        let (relay_device_id, group_id) = candidate?;
        let issued_at = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap();
        let now = issued_at.as_secs() as i64;
        let grant_id =
            format!("grant-{source_device_id}-{destination_device_id}-{}", issued_at.as_nanos());
        let grant = yadorilink_daemon::relay_grant::RelayGrant {
            version: 1,
            grant_id,
            group_id,
            source_device_id: source_device_id.to_string(),
            relay_device_id,
            destination_device_id: destination_device_id.to_string(),
            not_before_unix: now - 5,
            expires_at_unix: now + ttl_seconds,
            max_session_bytes: None,
            signature: Vec::new(),
        };
        Some(yadorilink_daemon::relay_grant::sign_relay_grant(grant, &signing_key))
    }

    /// Revokes a device's access to one group and pushes the new netmap — the
    /// device drops out of that group's membership, so peers sharing only that
    /// group see it disappear and tear the session (or group edge) down.
    pub fn revoke(&self, device_id: &str, group_id: &str) {
        {
            let mut inner = self.inner.lock().unwrap();
            if let Some(dev) = inner.devices.get_mut(device_id) {
                dev.groups.remove(group_id);
                dev.full_replica_groups.remove(group_id);
            }
        }
        self.push();
    }

    /// Removes a device entirely (device removal) and pushes the new netmap;
    /// peers see it vanish and tear the session down.
    pub fn remove_device(&self, device_id: &str) {
        {
            let mut inner = self.inner.lock().unwrap();
            inner.devices.remove(device_id);
            inner
                .endpoint_view_overrides
                .retain(|(viewer, target), _| viewer != device_id && target != device_id);
        }
        self.push();
    }

    /// Recomputes and sends each subscribed device its current netmap: the
    /// other devices that share at least one group with it.
    fn push(&self) {
        let mut inner = self.inner.lock().unwrap();
        let subscribers: Vec<_> = inner
            .subscribers
            .iter()
            .map(|(device_id, tx)| (device_id.clone(), tx.clone()))
            .collect();
        for (subscriber_id, tx) in subscribers {
            let frame = netmap_frame_for(&mut inner, &subscriber_id);
            let _ = tx.send(frame);
        }
    }
}

/// The `{type:"netmap"}` JSON frame for `subscriber_id`: every other device
/// sharing at least one of the subscriber's groups, each with the shared-group
/// subset (membership = bidirectional write authority) and full-replica subset.
fn netmap_frame_for(inner: &mut Inner, subscriber_id: &str) -> String {
    let self_groups =
        inner.devices.get(subscriber_id).map(|d| d.groups.clone()).unwrap_or_default();

    let mut peers = Vec::new();
    for (device_id, dev) in &inner.devices {
        if device_id == subscriber_id {
            continue;
        }
        let shared: Vec<String> = dev.groups.intersection(&self_groups).cloned().collect();
        if shared.is_empty() {
            continue;
        }
        let full_replica: Vec<String> =
            dev.full_replica_groups.intersection(&self_groups).cloned().collect();
        // Per-viewer override wins over the device's own global endpoint
        // list -- see `set_peer_view_endpoints`'s own doc comment.
        let visible_endpoints = inner
            .endpoint_view_overrides
            .get(&(subscriber_id.to_string(), device_id.to_string()))
            .unwrap_or(&dev.endpoints);
        peers.push(serde_json::json!({
            "deviceId": device_id,
            "wireguardPublicKeyBase64": dev.wireguard_public_key_b64,
            "signingPublicKeyBase64": dev.signing_public_key_b64,
            "endpoints": visible_endpoints
                .iter()
                .map(|address| serde_json::json!({ "address": address }))
                .collect::<Vec<_>>(),
            "sharedGroupIds": shared,
            "fullReplicaGroupIds": full_replica,
            "relayCapable": dev.relay_capable,
        }));
    }
    inner.snapshot_generation += 1;
    let mut frame = serde_json::json!({
        "type": "netmap",
        "snapshotGeneration": inner.snapshot_generation.to_string(),
        "peers": peers
    });
    if let Some(service_key) = &inner.policy_service_key {
        frame["serviceSigningPublicKeyBase64"] = serde_json::Value::String(
            base64::engine::general_purpose::STANDARD
                .encode(service_key.verifying_key().to_bytes()),
        );
        frame["groupPolicyLogs"] = signed_policy_logs(inner, subscriber_id, &self_groups);
    }
    frame.to_string()
}

/// The literal `ACTION_GRANT_WITH_ROLE` wire discriminant (see
/// `yadorilink_daemon::change_policy`'s own module doc comment for why this
/// is a distinct shape from plain `ACTION_GRANT`) -- mirrored here rather
/// than importing the crate's private constant, since it decides whether
/// `policy_record_to_wire_json` includes a `role` field at all, exactly like
/// `coordination-worker`'s own `recordToWire` (`src/policy/service.ts`)
/// includes `role` only when `r.action.role !== undefined`.
const WIRE_ACTION_GRANT_WITH_ROLE: u32 = 3;

/// Renders one signed `PolicyRecord` (built by `grant_role` via
/// `policy_signing::grant_record`) into the exact camelCase/base64 wire
/// shape `peer_orchestrator.rs`'s `WsPolicyRecord` deserializes -- the
/// mirror image of that struct's own field-by-field decoding, so a record
/// built here and one built by a real coordination plane are
/// indistinguishable on the wire.
fn policy_record_to_wire_json(
    record: &yadorilink_daemon::change_policy::PolicyRecord,
) -> serde_json::Value {
    let b64 = base64::engine::general_purpose::STANDARD;
    let mut json = serde_json::json!({
        "groupId": record.group_id,
        "seq": record.seq,
        "prevRecordHashBase64": b64.encode(&record.prev_record_hash),
        "recordHashBase64": b64.encode(&record.record_hash),
        "epoch": record.epoch,
        "actionType": record.action_type,
        "deviceId": record.device_id,
        "signingKeyFingerprintBase64": b64.encode(&record.signing_key_fingerprint),
        "newAuthorityKeyBase64": b64.encode(&record.new_authority_key),
        "signerKeyIdBase64": b64.encode(&record.signer_key_id),
        "signatureBase64": b64.encode(&record.signature),
    });
    // Omitted entirely (not merely absent-as-null) for anything but a
    // grant-with-role record -- matches the daemon-side `#[serde(default)]`
    // `Option<u32>` field, which defaults to absent the same way.
    if record.action_type == WIRE_ACTION_GRANT_WITH_ROLE {
        json["role"] = serde_json::Value::from(record.role);
    }
    json
}

/// Builds the `groupPolicyLogs` array for one subscriber's netmap frame:
/// every group it belongs to, each with the group's CURRENT head coordinates
/// (`currentSeq`/`currentEpoch`/`policyHeadBase64`, always the group's real
/// current state, matching `coordination-worker`'s own `toWirePolicyLog`) but
/// only the record TAIL this specific subscriber has not already been sent
/// (`policy_send_watermarks`, matching that same Worker's per-connection
/// `policyWatermarks` filtering in `pushNetmapSerializedSafely`). A group
/// `grant_role` has never touched keeps the historical all-zero, no-records
/// shape every pre-existing (non-role-aware) test in this suite depends on.
fn signed_policy_logs(
    inner: &mut Inner,
    subscriber_id: &str,
    groups: &HashSet<String>,
) -> serde_json::Value {
    let b64 = base64::engine::general_purpose::STANDARD;
    let mut group_ids: Vec<_> = groups.iter().cloned().collect();
    group_ids.sort();
    let logs: Vec<_> = group_ids
        .into_iter()
        .map(|group_id| {
            let chain = inner.group_policy_chains.get(&group_id).cloned().unwrap_or_default();
            let Some(head) = chain.last() else {
                return serde_json::json!({
                    "groupId": group_id,
                    "currentSeq": 0,
                    "currentEpoch": 0,
                    "policyHeadBase64": b64.encode([0u8; 32]),
                    "records": [],
                });
            };
            let current_seq = head.seq;
            let current_epoch = head.epoch;
            let policy_head_b64 = b64.encode(&head.record_hash);
            let watermarks =
                inner.policy_send_watermarks.entry(subscriber_id.to_string()).or_default();
            let since = watermarks.get(&group_id).copied().unwrap_or(0);
            let records: Vec<_> = chain
                .iter()
                .filter(|record| record.seq > since)
                .map(policy_record_to_wire_json)
                .collect();
            watermarks.insert(group_id.clone(), current_seq);
            serde_json::json!({
                "groupId": group_id,
                "currentSeq": current_seq,
                "currentEpoch": current_epoch,
                "policyHeadBase64": policy_head_b64,
                "records": records,
            })
        })
        .collect();
    serde_json::Value::Array(logs)
}

async fn handle_connection(mut stream: TcpStream, inner: Arc<Mutex<Inner>>) -> std::io::Result<()> {
    let (head, leftover) = read_http_head(&mut stream).await?;
    let request_line = head.lines().next().unwrap_or_default().to_string();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let target = parts.next().unwrap_or_default().to_string();

    let is_ws_upgrade = head.to_ascii_lowercase().contains("upgrade: websocket");
    if method == "GET" && target.starts_with("/netmap/subscribe") && is_ws_upgrade {
        serve_netmap_subscription(stream, &head, &target, inner).await
    } else if method == "POST" {
        if let Some(group_id) = parse_relay_grant_target(&target) {
            serve_relay_grant(stream, &head, leftover, group_id, inner).await
        } else if target.split('?').next() == Some("/send/authorization") {
            serve_send_authorization_issue(stream, &head, leftover, inner).await
        } else if let Some(grant_id) = parse_send_authorization_consume_target(&target) {
            serve_send_authorization_consume(stream, &head, leftover, grant_id, inner).await
        } else {
            // Every other endpoint the daemon calls (endpoint report,
            // rendezvous, signing-key backfill) is best-effort: a 204 is all
            // it needs. Drain any request body first so the socket closes
            // cleanly.
            drain_body(&mut stream, &head, leftover).await?;
            stream.write_all(b"HTTP/1.1 204 No Content\r\ncontent-length: 0\r\n\r\n").await?;
            stream.flush().await
        }
    } else {
        drain_body(&mut stream, &head, leftover).await?;
        stream.write_all(b"HTTP/1.1 204 No Content\r\ncontent-length: 0\r\n\r\n").await?;
        stream.flush().await
    }
}

/// Matches `/shares/groups/{groupId}/relay/grant` and extracts `groupId`, or
/// `None` for anything else (including a group id that itself contains a
/// `/`, which cannot be a real path segment).
fn parse_relay_grant_target(target: &str) -> Option<String> {
    let path = target.split('?').next().unwrap_or(target);
    let group_id = path.strip_prefix("/shares/groups/")?.strip_suffix("/relay/grant")?;
    (!group_id.is_empty() && !group_id.contains('/')).then(|| group_id.to_string())
}

/// Matches `/send/authorization/{grantId}/consume` and extracts `grantId`.
fn parse_send_authorization_consume_target(target: &str) -> Option<String> {
    let path = target.split('?').next().unwrap_or(target);
    let grant_id = path.strip_prefix("/send/authorization/")?.strip_suffix("/consume")?;
    (!grant_id.is_empty() && !grant_id.contains('/')).then(|| grant_id.to_string())
}

/// Serves `POST /send/authorization` for real -- Track Send's rendezvous
/// grant, `coordination-worker`'s `routes/send.ts` mirrored just enough to
/// exercise `coordination_client::request_send_authorization` and the
/// `send_authorization` netmap-subscription push end to end against real
/// daemon code, not an in-process bypass. See `FakeSendAuthorization`'s own
/// doc comment for what this deliberately does not model.
async fn serve_send_authorization_issue(
    mut stream: TcpStream,
    head: &str,
    leftover: Vec<u8>,
    inner: Arc<Mutex<Inner>>,
) -> std::io::Result<()> {
    let body = read_body(&mut stream, head, leftover).await?;
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Req {
        sender_device_id: String,
        receiver_device_id: String,
    }
    let Ok(req) = serde_json::from_slice::<Req>(&body) else {
        return respond_json(&mut stream, 400, "Bad Request", r#"{"error":"invalid body"}"#).await;
    };
    if req.sender_device_id == req.receiver_device_id {
        return respond_json(
            &mut stream,
            400,
            "Bad Request",
            r#"{"error":"sender and receiver must differ"}"#,
        )
        .await;
    }

    let (sender, receiver) = {
        let inner = inner.lock().unwrap();
        (
            inner.devices.get(&req.sender_device_id).cloned(),
            inner.devices.get(&req.receiver_device_id).cloned(),
        )
    };
    let (Some(_sender), Some(receiver)) = (sender.clone(), receiver) else {
        return respond_json(&mut stream, 404, "Not Found", r#"{"error":"unknown device"}"#).await;
    };

    let grant_id = uuid_like("grant");
    let nonce = uuid_like("nonce");
    let now = unix_now();
    let expires_at = now + 300;
    {
        let mut inner = inner.lock().unwrap();
        inner.send_authorizations.insert(
            grant_id.clone(),
            FakeSendAuthorization {
                nonce: nonce.clone(),
                sender_device_id: req.sender_device_id.clone(),
                receiver_device_id: req.receiver_device_id.clone(),
                consumed: false,
            },
        );
    }

    // Delivered synchronously, before this responds -- matching
    // coordination-worker's own "push happens inside the request handler"
    // convention (see `routes/send.ts`'s own comment).
    push_send_authorization(
        &inner,
        &req.receiver_device_id,
        &grant_id,
        &nonce,
        &req.sender_device_id,
        expires_at,
    );

    let body = serde_json::json!({
        "grantId": grant_id,
        "nonce": nonce,
        "expiresAt": expires_at,
        "receiver": {
            "deviceId": req.receiver_device_id,
            "signingPublicKeyBase64": receiver.signing_public_key_b64,
            "endpoints": receiver.endpoints
                .iter()
                .map(|address| serde_json::json!({ "address": address, "priority": 0 }))
                .collect::<Vec<_>>(),
        },
    })
    .to_string();
    respond_json(&mut stream, 200, "OK", &body).await
}

/// Serves `POST /send/authorization/:grantId/consume` for real -- the
/// atomic single-use guard `handle_offer`/`DaemonDeviceDirectory::
/// consume_grant` calls before ever recording an inbound offer. Same
/// identity-binding shape as the real Worker's `consumeSendAuthorization`:
/// grant id, nonce, sender, and receiver must all match a still-unconsumed
/// record, checked and flipped to consumed under the SAME lock acquisition
/// (no separate read-then-write), so two concurrent attempts for the same
/// grant can never both succeed.
async fn serve_send_authorization_consume(
    mut stream: TcpStream,
    head: &str,
    leftover: Vec<u8>,
    grant_id: String,
    inner: Arc<Mutex<Inner>>,
) -> std::io::Result<()> {
    let body = read_body(&mut stream, head, leftover).await?;
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Req {
        nonce: String,
        sender_device_id: String,
        receiver_device_id: String,
    }
    let Ok(req) = serde_json::from_slice::<Req>(&body) else {
        return respond_json(&mut stream, 400, "Bad Request", r#"{"error":"invalid body"}"#).await;
    };

    let sender = {
        let mut inner = inner.lock().unwrap();
        let consumable = inner.send_authorizations.get(&grant_id).is_some_and(|g| {
            !g.consumed
                && g.nonce == req.nonce
                && g.sender_device_id == req.sender_device_id
                && g.receiver_device_id == req.receiver_device_id
        }) && inner.devices.contains_key(&req.sender_device_id)
            && inner.devices.contains_key(&req.receiver_device_id);
        if consumable {
            inner.send_authorizations.get_mut(&grant_id).unwrap().consumed = true;
            inner.devices.get(&req.sender_device_id).cloned()
        } else {
            None
        }
    };
    let Some(sender) = sender else {
        return respond_json(
            &mut stream,
            403,
            "Forbidden",
            r#"{"error":"send authorization is invalid, expired, or already used"}"#,
        )
        .await;
    };

    let body = serde_json::json!({
        "sender": {
            "deviceId": req.sender_device_id,
            "signingPublicKeyBase64": sender.signing_public_key_b64,
            "endpoints": sender.endpoints
                .iter()
                .map(|address| serde_json::json!({ "address": address, "priority": 0 }))
                .collect::<Vec<_>>(),
        },
    })
    .to_string();
    respond_json(&mut stream, 200, "OK", &body).await
}

/// Pushes a `{type:"send_authorization",...}` frame to `receiver_device_id`'s
/// live subscription, if it has one -- a no-op wake otherwise, matching
/// `coordination-worker`'s own "content-blind, never stored" delivery
/// contract for this push.
fn push_send_authorization(
    inner: &Arc<Mutex<Inner>>,
    receiver_device_id: &str,
    grant_id: &str,
    nonce: &str,
    sender_device_id: &str,
    expires_at: i64,
) {
    let inner = inner.lock().unwrap();
    let Some(tx) = inner.subscribers.get(receiver_device_id) else { return };
    let Some(sender) = inner.devices.get(sender_device_id) else { return };
    let frame = serde_json::json!({
        "type": "send_authorization",
        "grantId": grant_id,
        "nonce": nonce,
        "from": sender_device_id,
        "senderSigningPublicKeyBase64": sender.signing_public_key_b64,
        "senderCandidates": sender.endpoints
            .iter()
            .map(|address| serde_json::json!({ "address": address, "priority": 0 }))
            .collect::<Vec<_>>(),
        "expiresAt": expires_at,
    })
    .to_string();
    let _ = tx.send(frame);
}

/// A short, sufficiently-unique id for this fake's own grant/nonce values --
/// not a real UUID library dependency, just enough entropy (a monotonic
/// process-wide counter) that two concurrently-issued grants in the same
/// test never collide. `label` distinguishes a grant id from a nonce in
/// test failure output.
fn uuid_like(label: &str) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{label}-{n}-{}", unix_now())
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Serves `POST /shares/groups/:groupId/relay/grant` for real, over the same
/// HTTP connection `coordination_client::request_relay_grant` speaks --
/// unlike every other route this fake answers, which is a blanket `204`
/// the daemon treats as best-effort. This route exists specifically so
/// `ProductionRelayGrantSource` can be exercised end-to-end (request ->
/// real HTTP -> signed response -> `verify_relay_grant`) rather than only
/// through `FakeGrantSource`'s synchronous in-process bypass of
/// `issue_relay_grant`, which every other relay-scenario test uses.
///
/// The authorization performed here mirrors `coordination-worker`'s own
/// `issueRelayGrant` (`src/relay/service.ts`): all three device ids must be
/// registered and current members of `group_id`, the three ids must be
/// pairwise distinct, and `relay_device_id` must have declared relay
/// capability. `not_before_unix`/`expires_at_unix` use the same 30s
/// clock-skew allowance and 60s TTL as the real Worker
/// (`RELAY_GRANT_CLOCK_SKEW_ALLOWANCE_SECONDS`/`RELAY_GRANT_TTL_SECONDS` in
/// `coordination-worker/src/relay/service.ts`), so a test exercising this
/// path sees the same margins production grants actually carry.
async fn serve_relay_grant(
    mut stream: TcpStream,
    head: &str,
    leftover: Vec<u8>,
    group_id: String,
    inner: Arc<Mutex<Inner>>,
) -> std::io::Result<()> {
    let body = read_body(&mut stream, head, leftover).await?;

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Req {
        source_device_id: String,
        relay_device_id: String,
        destination_device_id: String,
    }

    let outcome = match serde_json::from_slice::<Req>(&body) {
        Ok(req) => authorize_and_issue_relay_grant(
            &inner,
            &group_id,
            &req.source_device_id,
            &req.relay_device_id,
            &req.destination_device_id,
        ),
        Err(_) => Err((400, "invalid request body".to_string())),
    };

    match outcome {
        Ok(grant) => {
            let b64 = base64::engine::general_purpose::STANDARD;
            let body = serde_json::json!({
                "grantId": grant.grant_id,
                "version": grant.version,
                "notBeforeUnix": grant.not_before_unix,
                "expiresAtUnix": grant.expires_at_unix,
                "maxSessionBytes": grant.max_session_bytes,
                "signatureBase64": b64.encode(&grant.signature),
            })
            .to_string();
            respond_json(&mut stream, 200, "OK", &body).await
        }
        Err((status, message)) => {
            let body = serde_json::json!({ "error": message }).to_string();
            let reason = match status {
                400 => "Bad Request",
                500 => "Internal Server Error",
                _ => "Error",
            };
            respond_json(&mut stream, status, reason, &body).await
        }
    }
}

/// The synchronous half of [`serve_relay_grant`]: every authorization check
/// plus signing, none of it requiring `.await` -- kept separate so the
/// `Inner` mutex guard never needs to live across an await point.
fn authorize_and_issue_relay_grant(
    inner: &Arc<Mutex<Inner>>,
    group_id: &str,
    source_device_id: &str,
    relay_device_id: &str,
    destination_device_id: &str,
) -> Result<yadorilink_daemon::relay_grant::RelayGrant, (u16, String)> {
    if source_device_id == relay_device_id
        || relay_device_id == destination_device_id
        || source_device_id == destination_device_id
    {
        return Err((
            400,
            "sourceDeviceId, relayDeviceId, and destinationDeviceId must be pairwise distinct"
                .to_string(),
        ));
    }

    let guard = inner.lock().unwrap();
    let signing_key = guard
        .policy_service_key
        .clone()
        .ok_or((500, "no service signing key installed".to_string()))?;
    let source = guard
        .devices
        .get(source_device_id)
        .ok_or((400, "sourceDeviceId is not registered".to_string()))?;
    if !source.groups.contains(group_id) {
        return Err((400, "sourceDeviceId is not an active member of this group".to_string()));
    }
    let relay = guard
        .devices
        .get(relay_device_id)
        .ok_or((400, "relayDeviceId is not registered".to_string()))?;
    if !relay.groups.contains(group_id) {
        return Err((400, "relayDeviceId is not an active member of this group".to_string()));
    }
    if !relay.relay_capable {
        return Err((400, "relayDeviceId has not declared relay capability".to_string()));
    }
    let destination = guard
        .devices
        .get(destination_device_id)
        .ok_or((400, "destinationDeviceId is not registered".to_string()))?;
    if !destination.groups.contains(group_id) {
        return Err((400, "destinationDeviceId is not an active member of this group".to_string()));
    }
    drop(guard);

    let issued_at = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap();
    let now = issued_at.as_secs() as i64;
    let grant_id =
        format!("grant-{source_device_id}-{destination_device_id}-{}", issued_at.as_nanos());
    let grant = yadorilink_daemon::relay_grant::RelayGrant {
        version: 1,
        grant_id,
        group_id: group_id.to_string(),
        source_device_id: source_device_id.to_string(),
        relay_device_id: relay_device_id.to_string(),
        destination_device_id: destination_device_id.to_string(),
        not_before_unix: now - 30,
        expires_at_unix: now + 60,
        max_session_bytes: None,
        signature: Vec::new(),
    };
    Ok(yadorilink_daemon::relay_grant::sign_relay_grant(grant, &signing_key))
}

async fn respond_json(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    body: &str,
) -> std::io::Result<()> {
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await
}

/// Like `drain_body`, but returns the collected bytes instead of discarding
/// them -- `serve_relay_grant` needs the request body itself, unlike every
/// other route this fake answers.
async fn read_body(
    stream: &mut TcpStream,
    head: &str,
    already_read: Vec<u8>,
) -> std::io::Result<Vec<u8>> {
    let content_length = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim().eq_ignore_ascii_case("content-length").then(|| value.trim().to_string())
        })
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = already_read;
    let mut chunk = [0u8; 1024];
    while body.len() < content_length {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(content_length.min(body.len()));
    Ok(body)
}

/// Reads bytes until the end of the HTTP request head (`\r\n\r\n`). Returns the
/// head as a string plus any bytes read past it (the start of a POST body).
async fn read_http_head(stream: &mut TcpStream) -> std::io::Result<(String, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..pos]).into_owned();
            let leftover = buf[pos + 4..].to_vec();
            return Ok((head, leftover));
        }
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            let head = String::from_utf8_lossy(&buf).into_owned();
            return Ok((head, Vec::new()));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

async fn drain_body(
    stream: &mut TcpStream,
    head: &str,
    already_read: Vec<u8>,
) -> std::io::Result<()> {
    let content_length = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim().eq_ignore_ascii_case("content-length").then(|| value.trim().to_string())
        })
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);
    let mut remaining = content_length.saturating_sub(already_read.len());
    let mut chunk = [0u8; 1024];
    while remaining > 0 {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        remaining = remaining.saturating_sub(n);
    }
    Ok(())
}

async fn serve_netmap_subscription(
    mut stream: TcpStream,
    head: &str,
    target: &str,
    inner: Arc<Mutex<Inner>>,
) -> std::io::Result<()> {
    let device_id = target
        .split_once("deviceId=")
        .map(|(_, rest)| rest.split('&').next().unwrap_or("").to_string())
        .unwrap_or_default();
    let key = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim().eq_ignore_ascii_case("sec-websocket-key").then(|| value.trim().to_string())
        })
        .unwrap_or_default();
    let accept = derive_accept_key(key.as_bytes());
    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
    );
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;

    let mut ws = WebSocketStream::from_raw_socket(stream, Role::Server, None).await;

    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
    // Register and immediately send this device its current netmap.
    let initial = {
        let mut guard = inner.lock().unwrap();
        guard.subscribers.insert(device_id.clone(), tx);
        // A brand-new subscription starts with a fresh (empty) per-group
        // policy watermark -- mirrors a real coordination plane's per-
        // WebSocket `policyWatermarks` map starting empty for a new socket
        // (`durable-objects/netmap-device.ts`'s `WeakMap<WebSocket, ...>`),
        // so this device's very first frame on a (re)connect always carries
        // each shared group's policy chain from the beginning, exactly as
        // `verify_group_policy_log_with_base` requires when this device has
        // no retained base state for that group yet.
        guard.policy_send_watermarks.remove(&device_id);
        netmap_frame_for(&mut guard, &device_id)
    };
    if ws.send(Message::Text(initial)).await.is_err() {
        inner.lock().unwrap().subscribers.remove(&device_id);
        return Ok(());
    }

    // Forward every pushed frame; also drain inbound (pings/close) so the
    // connection stays healthy. Ends when either side closes.
    use futures_util::StreamExt;
    loop {
        tokio::select! {
            frame = rx.recv() => match frame {
                Some(text) => {
                    if ws.send(Message::Text(text)).await.is_err() { break; }
                }
                None => break,
            },
            inbound = ws.next() => match inbound {
                Some(Ok(Message::Close(_))) | None => break,
                Some(Ok(_)) => {}
                Some(Err(_)) => break,
            },
        }
    }
    inner.lock().unwrap().subscribers.remove(&device_id);
    Ok(())
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}
