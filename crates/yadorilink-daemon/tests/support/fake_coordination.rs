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
        frame["groupPolicyLogs"] = signed_policy_logs(inner, &self_groups, service_key);
    }
    frame.to_string()
}

fn signed_policy_logs(
    _inner: &Inner,
    groups: &HashSet<String>,
    _service_key: &SigningKey,
) -> serde_json::Value {
    let b64 = base64::engine::general_purpose::STANDARD;
    let mut group_ids: Vec<_> = groups.iter().cloned().collect();
    group_ids.sort();
    let logs: Vec<_> = group_ids
        .into_iter()
        .map(|group_id| {
            serde_json::json!({
                "groupId": group_id,
                "currentSeq": 0,
                "currentEpoch": 0,
                "policyHeadBase64": b64.encode([0u8; 32]),
                "records": [],
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
