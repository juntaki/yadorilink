use base64::Engine;
use futures_util::StreamExt;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::Message;

use std::net::SocketAddr;

use super::*;

#[derive(serde::Deserialize)]
pub(super) struct WsNetmapMessage {
    #[serde(rename = "type")]
    #[allow(dead_code)]
    kind: String,
    #[serde(rename = "snapshotGeneration")]
    snapshot_generation: String,
    /// The key every group policy log in this push is verified against.
    /// Required: a push without it cannot be checked at all, and the
    /// plane sends it on every one.
    #[serde(rename = "serviceSigningPublicKeyBase64")]
    service_signing_public_key_base64: String,
    /// Required. The plane sends this on every push, empty array
    /// included, so an absent field is a malformed push -- not a
    /// device with no groups. Defaulting it to empty would let a
    /// truncated or corrupted message apply as "no policy changed".
    #[serde(rename = "groupPolicyLogs")]
    group_policy_logs: Vec<WsGroupPolicyLog>,
    // Groups the coordination plane isolated out of `group_policy_logs`
    // because their stored policy state (ACL and/or policy log) is
    // malformed or corrupt on its side. Without a field here serde
    // silently drops the list, and nothing ever fails these groups
    // closed; consuming it funnels each named group through the same
    // `mark_group_policy_stale` staleness gate the daemon's own
    // verification failures use.
    /// Required, for the same reason as `group_policy_logs` above.
    #[serde(rename = "policyInvalidGroupIds")]
    policy_invalid_group_ids: Vec<String>,
    peers: Vec<WsNetmapPeer>,
}

/// Type-state boundary for authoritative netmap application. Callers may
/// not inspect or apply a snapshot until its whole peer identity set has
/// been admitted, so a future reordering cannot accidentally mutate
/// policy, diff, pin, or session state before duplicate IDs are rejected.
pub(super) struct AdmittedNetmapMessage {
    message: WsNetmapMessage,
    /// The plane snapshot generation this frame carries, already parsed
    /// and already checked against the newest one admitted this run.
    generation: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum NetmapAdmissionError {
    DuplicateDeviceId,
    InvalidGeneration,
    StaleGeneration,
}

impl AdmittedNetmapMessage {
    pub(super) fn admit(
        message: WsNetmapMessage,
        last_generation: &StdMutex<Option<u64>>,
    ) -> Result<Self, NetmapAdmissionError> {
        if has_duplicate_peer_ids(message.peers.iter().map(|peer| peer.device_id.as_str())) {
            return Err(NetmapAdmissionError::DuplicateDeviceId);
        }
        let generation = message
            .snapshot_generation
            .parse::<u64>()
            .map_err(|_| NetmapAdmissionError::InvalidGeneration)?;
        let mut last = last_generation.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if last.is_some_and(|last| generation <= last) {
            return Err(NetmapAdmissionError::StaleGeneration);
        }
        *last = Some(generation);
        Ok(Self { message, generation })
    }

    fn into_parts(self) -> (WsNetmapMessage, u64) {
        (self.message, self.generation)
    }
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct WsGroupPolicyLog {
    group_id: String,
    current_seq: u64,
    current_epoch: u64,
    policy_head_base64: String,
    /// Required: the plane always emits an array here, empty included.
    records: Vec<WsPolicyRecord>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct WsPolicyRecord {
    group_id: String,
    seq: u64,
    prev_record_hash_base64: String,
    record_hash_base64: String,
    epoch: u64,
    action_type: u32,
    device_id: String,
    signing_key_fingerprint_base64: String,
    /// Grant only; every grant carries one.
    #[serde(default)]
    role: Option<u32>,
    new_authority_key_base64: String,
    signer_key_id_base64: String,
    signature_base64: String,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct WsNetmapPeer {
    device_id: String,
    /// The peer's Ed25519 device key: the one public key a device has,
    /// authenticating both its change history and its transport.
    ///
    /// A peer without one can never authenticate, so the admission path
    /// rejects it and tears down anything it had.
    signing_public_key_base64: String,
    shared_group_ids: Vec<String>,
    /// The subset of `shared_group_ids` this peer syncs as a full replica
    /// ("store everything"). Content-blind (group ids only).
    full_replica_group_ids: Vec<String>,
    /// Where this peer's reconciliation substrate can be reached.
    ///
    /// Absent means this peer's substrate has not published an address
    /// yet, which must NOT be read as "reachable nowhere". Present with
    /// empty lists IS that claim, and clears what was known.
    #[serde(default)]
    substrate_reachability: Option<WsSubstrateReachability>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct WsSubstrateReachability {
    #[serde(default)]
    direct: Vec<String>,
    #[serde(default)]
    relays: Vec<String>,
}

/// A Track Send rendezvous-grant notice, a distinct message type
/// on this same subscription (`{ type: "send_authorization", ... }`) --
/// see `coordination-worker`'s `NetmapDeviceObject.deliverSendAuthorization`
/// for the server side and `crate::send_transfer`'s own module doc
/// comment for the full design. Tells this device to expect an inbound
/// Track Send (`yadorilink/send/v1`) connection from `from` (a same-account device with
/// no shared folder group, so it is otherwise invisible in this
/// device's own netmap) presenting `grant_id`/`nonce`, and carries
/// exactly the connect material needed to also dial `from` BACK during
/// the pull phase.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct WsSendAuthorization {
    grant_id: String,
    nonce: String,
    from: String,
    sender_signing_public_key_base64: String,
    #[serde(default)]
    sender_substrate_reachability: Option<crate::coordination_client::WireSubstrateReachability>,
    expires_at: i64,
}

/// `config.coordination_addr` is the same http(s) base URL used for
/// HTTP coordination service's unary routes; the netmap subscription is
/// just a `wss://`/`ws://` upgrade of the same host at a fixed path,
/// since the client-facing endpoint is a plain WebSocket. Uses the
/// `url` crate to parse/rewrite the address rather than hand-rolled
/// string splitting -- an earlier hand-rolled version
/// of this function split on `:` to find the host, which silently
/// mangled IPv6 literal addresses like `http://[::1]:8787` (the same
/// bug class `yadorilink-cli`'s `http_client.rs`/`yadorilink-desktop-app`'s
/// `google_login.rs` avoided the same way).
pub(super) fn netmap_ws_url(
    coordination_addr: &str,
    device_id: &str,
) -> Result<String, DaemonError> {
    let mut url = url::Url::parse(coordination_addr)
        .map_err(|e| DaemonError::Config(format!("invalid coordination address: {e}")))?;
    let new_scheme = match url.scheme() {
        "https" => "wss",
        "http" if is_loopback_host(&url) => "ws",
        "http" => {
            return Err(DaemonError::Config(
                "remote coordination addresses must use https://".into(),
            ))
        }
        _ => {
            return Err(DaemonError::Config(
                "coordination address must use http:// or https://".into(),
            ))
        }
    };
    // http(s) <-> ws(s) is a "special-to-special" scheme change (per the
    // WHATWG URL spec's special-scheme list), which `url` supports.
    url.set_scheme(new_scheme)
        .map_err(|()| DaemonError::Config("failed to build the netmap websocket URL".into()))?;
    url.set_path("/netmap/subscribe");
    url.query_pairs_mut().clear().append_pair("deviceId", device_id);
    Ok(url.to_string())
}

/// Matches on `url`'s typed `Host` enum rather than `host_str` -- for
/// an IPv6 literal, `host_str` returns the bracketed authority form
/// (`"[::1]"`), which `std::net::IpAddr::from_str` cannot parse; a
/// first attempt at this fix used `host_str` this way and shipped
/// with exactly that bug (caught by
/// `ws_netmap_url_handles_an_ipv6_loopback_literal` below). `Host::Ipv6`
/// carries an already-parsed `Ipv6Addr` directly, so there is no
/// string/bracket handling left to get wrong.
fn is_loopback_host(url: &url::Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

/// Fires once per successful coordination-plane
/// reconnect, flushing every synced group's own locally-pending
/// (uncheckpointed) Changes. Spawned via `spawn_one_shot` rather than
/// awaited inline so a slow or unreachable checkpoint endpoint can
/// never delay `run_netmap_attempt`'s own message loop from reading
/// the netmap/send-authorization pushes it exists to
/// process.
///
/// Silently does nothing for a group with no verified
/// `GroupPolicyState` yet (`state.authority.group_policy_state` returns `None`
/// before the first netmap push for that group has been processed --
/// nothing to resolve an authority key against yet, briefly polled for
/// below since this task is spawned before that same connection's own
/// netmap frame is guaranteed to have been read) or if this device has
/// no signing key configured at all. Neither is an error: both resolve
/// themselves on the next reconnect once the netmap catches up.
fn spawn_flush_pending_checkpoints_on_reconnect(
    config: &OrchestratorConfig,
    state: &Arc<DaemonState>,
) {
    let Some(signing_key) = state.device_signing_key() else { return };
    let own_signing_public_key = signing_key.verifying_key();
    let coordination_addr = config.coordination_addr.clone();
    let access_token = config.auth.clone();
    let device_id = config.device_id.clone();
    let state = Arc::clone(state);

    spawn_one_shot("checkpoint-flush-on-reconnect", async move {
        let source = ProductionCheckpointSource::new(coordination_addr, access_token);
        let links = match state.replica_coordinator.link_repository().list_links() {
            Ok(links) => links,
            Err(e) => {
                tracing::debug!(error = %e, "checkpoint flush: could not list links");
                return Ok(());
            }
        };
        let mut group_ids: Vec<String> = links
            .into_iter()
            .filter(|link| !link.paused && !link.orphaned)
            .map(|link| link.group_id)
            .collect();
        group_ids.sort();
        group_ids.dedup();

        let db = state.replica_coordinator.database();
        for group_id in group_ids {
            // This task is spawned the instant the netmap WebSocket
            // connects -- often before that same connection's first
            // netmap frame has been read and verified, which is what
            // actually populates `group_policy_state`. A single
            // point-in-time check here would then permanently miss this
            // connection's flush window (this function's own doc
            // comment used to say "resolves itself on the very next
            // reconnect", but a device's FIRST ever connection has no
            // earlier reconnect to have caught it, so pending content
            // linked before that first connect would never flush at all
            // during a long-lived healthy session). Poll briefly instead
            // of a single check -- still bounded, still spawned off the
            // netmap message loop, so it cannot delay `run_netmap_
            // attempt`'s own reads either way.
            let mut policy = state.authority.group_policy_state(&group_id);
            if policy.is_none() {
                for _ in 0..50 {
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                    policy = state.authority.group_policy_state(&group_id);
                    if policy.is_some() {
                        break;
                    }
                }
            }
            let Some(policy) = policy else {
                tracing::debug!(group_id, "checkpoint flush: no verified policy state yet");
                continue;
            };
            let resolve_authority_key = |key_id: &[u8; 32], policy_head: &[u8; 32]| {
                policy.resolve_authority_key(key_id, policy_head)
            };
            // Shared with `DaemonState::flush_pending_checkpoint_for_
            // group` (the `broadcast_change` trigger) -- see that
            // field's own doc comment for why a flush must never race
            // its OTHER trigger for the same device.
            let _flush_guard = state.flush_lock.lock().await;
            match flush_pending_checkpoint(
                &db,
                &source,
                &group_id,
                &device_id,
                &own_signing_public_key,
                &resolve_authority_key,
            )
            .await
            {
                Ok(FlushOutcome::NothingPending) => {}
                Ok(FlushOutcome::Flushed { batch_size, checkpoint_seq }) => {
                    tracing::info!(
                        group_id,
                        batch_size,
                        checkpoint_seq,
                        "checkpoint flush: published pending batch"
                    );
                    // A session's own reconcile/handshake already ran
                    // (or is running concurrently) against whatever
                    // heads existed BEFORE this flush attached evidence
                    // -- this Change becoming Published just now has no
                    // OTHER trigger telling an already-connected peer
                    // session to look again. `broadcast_change`'s own
                    // doc comment covers the identical reasoning for the
                    // local-mutation trigger; this is the reconnect
                    // trigger's side of the same fix.
                    state.note_local_commit_for_group(&group_id).await;
                }
                Ok(FlushOutcome::Refused) => {
                    tracing::debug!(
                        group_id,
                        "checkpoint flush: refused (not currently a writer, or unreachable)"
                    );
                }
                Err(e) => {
                    // A verification failure here means the coordination
                    // plane returned a checkpoint that does not verify
                    // against the Changes it claims to cover -- worth a
                    // real warning, not a swallowed debug line, per
                    // FlushError::CheckpointDidNotVerify's own doc comment.
                    tracing::warn!(group_id, error = %e, "checkpoint flush failed");
                }
            }
        }
        Ok(())
    });
}

pub(super) async fn run_netmap_attempt(
    config: &OrchestratorConfig,
    state: &Arc<DaemonState>,
    diff_state: &NetmapDiffState,
) -> Result<(), DaemonError> {
    let url = netmap_ws_url(&config.coordination_addr, &config.device_id)?;
    // Build through tungstenite so the mandatory WebSocket handshake
    // headers (`Sec-WebSocket-Key`, version, upgrade/connection) are
    // present. A bare `http::Request::builder` is accepted by
    // `connect_async` as-is; tungstenite does not retrofit those headers,
    // and every standards-compliant server rejects the handshake.
    let mut request = url
        .clone()
        .into_client_request()
        .map_err(|e| DaemonError::Config(format!("invalid coordination address: {e}")))?;

    // Minted per ATTEMPT, not once per process. Every reconnect is a new
    // handshake and therefore needs a live token and an unspent proof
    // (`jti` is single-use server-side), and a reconnect after an outage
    // is exactly when the previous token is most likely to be dead. This
    // is the only credential the WebSocket ever presents: the upgrade is
    // authenticated once and the stream then outlives the token -- a
    // deliberate property of this connection, not an accident.
    //
    // `htm` is `GET`: a WebSocket upgrade is an HTTP GET, and the resource
    // server compares the proof's `htm` against the request method it
    // actually sees.
    let credential = config.auth.authorize("GET", url.as_str()).await.map_err(|e| {
        DaemonError::Config(format!("could not authenticate the netmap subscription: {e}"))
    })?;
    let auth_value = HeaderValue::from_str(credential.authorization())
        .map_err(|_| DaemonError::Config("the credential is not a valid header value".into()))?;
    request.headers_mut().insert("Authorization", auth_value);
    let proof = HeaderValue::from_str(credential.dpop())
        .map_err(|_| DaemonError::Config("the DPoP proof is not a valid header value".into()))?;
    request.headers_mut().insert("dpop", proof);

    let (mut ws_stream, _response) = tokio_tungstenite::connect_async(request).await?;
    // Record a successful coordination-plane connect so a doctor read
    // mid-outage can see the coordination plane itself is reachable,
    // separately from any peer's direct-path state.
    state.telemetry.record_connection_attempt(
        "",
        CandidateSource::CoordinationPlane,
        AddressClass::Wan,
        AttemptOutcome::Connected,
        0,
        "",
        true,
        Some(true),
    );

    // The coordination plane is reachable again, so this is the moment to flush any locally-pending
    // (uncheckpointed) Changes -- spawned so a slow or stuck
    // checkpoint request can never delay this netmap loop from
    // reading its own inbound messages.
    spawn_flush_pending_checkpoints_on_reconnect(config, state);

    let mut session = NetmapSessionState {
        config,
        state,
        diff_state,
        signing_key_pins: load_signing_key_pins()?,
        service_key_pins: load_service_key_pins()?,
    };

    while let Some(msg) = ws_stream.next().await {
        match session.handle_message(msg?).await? {
            NetmapFrameOutcome::KeepReading => {}
            NetmapFrameOutcome::Closed => break,
        }
    }
    // The server closed the stream without an error — still worth
    // retrying rather than treating as permanent.
    Ok(())
}

fn ws_policy_log_to_record(
    log: &WsGroupPolicyLog,
) -> Result<crate::change_policy::GroupPolicyLog, String> {
    Ok(crate::change_policy::GroupPolicyLog {
        group_id: log.group_id.clone(),
        current_seq: log.current_seq,
        current_epoch: log.current_epoch,
        policy_head: decode_policy_b64(&log.policy_head_base64, "policyHeadBase64")?,
        records: log
            .records
            .iter()
            .map(ws_policy_record_to_record)
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn ws_policy_record_to_record(
    record: &WsPolicyRecord,
) -> Result<crate::change_policy::PolicyRecord, String> {
    // A grant's role is part of what its signature covers, so a grant
    // that arrives without one is refused here rather than given a
    // default. Defaulting would pick a tier nobody signed; the
    // signature check would then fail on the reconstructed preimage,
    // which is the right outcome reached the wrong way -- by accident
    // of the encoding rather than by a rule. Every other action type
    // legitimately carries no role.
    let role = if record.action_type == crate::change_policy::ACTION_GRANT_WITH_ROLE {
        record
            .role
            .ok_or_else(|| format!("policy record {} is a grant with no role", record.seq))?
    } else {
        0
    };
    Ok(crate::change_policy::PolicyRecord {
        group_id: record.group_id.clone(),
        seq: record.seq,
        prev_record_hash: decode_policy_b64(
            &record.prev_record_hash_base64,
            "prevRecordHashBase64",
        )?,
        record_hash: decode_policy_b64(&record.record_hash_base64, "recordHashBase64")?,
        epoch: record.epoch,
        action_type: record.action_type,
        device_id: record.device_id.clone(),
        signing_key_fingerprint: decode_policy_b64(
            &record.signing_key_fingerprint_base64,
            "signingKeyFingerprintBase64",
        )?,
        role,
        new_authority_key: decode_policy_b64(
            &record.new_authority_key_base64,
            "newAuthorityKeyBase64",
        )?,
        signer_key_id: decode_policy_b64(&record.signer_key_id_base64, "signerKeyIdBase64")?,
        signature: decode_policy_b64(&record.signature_base64, "signatureBase64")?,
    })
}

fn decode_policy_b64(value: &str, field: &str) -> Result<Vec<u8>, String> {
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|e| format!("{field}: invalid base64: {e}"))
}

/// What the receive loop does once one inbound frame has been handled.
///
/// Every way a single frame can be abandoned -- unparseable, the wrong
/// shape, an inadmissible snapshot -- keeps the session alive and is
/// `KeepReading`; only the server's close frame ends it. An error that must
/// end the attempt travels as `Err` instead, exactly as the `?` it replaces.
enum NetmapFrameOutcome {
    KeepReading,
    Closed,
}

/// Which family of subscription message one inbound frame's own `type`
/// names. The subscription multiplexes families on one socket, and the set
/// this daemon reads shrinks as well as grows, so "a family this build does
/// not read" is a first-class outcome and not an error.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum SubscriptionMessage {
    /// An authoritative netmap snapshot.
    Netmap,
    /// A Track Send rendezvous-grant notice.
    SendAuthorization,
    /// Any other family, including one that was retired: a frame of it is
    /// dropped silently. Retired here rather than unknown is the common
    /// case, so this must not be reported as a malformed message.
    Unread,
}

pub(super) fn classify_subscription_message(message_type: Option<&str>) -> SubscriptionMessage {
    match message_type {
        Some("netmap") => SubscriptionMessage::Netmap,
        Some("send_authorization") => SubscriptionMessage::SendAuthorization,
        _ => SubscriptionMessage::Unread,
    }
}

/// A netmap peer that has passed phase-1 admission (device key present and
/// matching its pin, full-replica groups a subset of its authorized groups),
/// carried into phase 2. See `NetmapSessionState::apply_snapshot` for why the
/// two phases are kept apart.
struct AdmittedPeer {
    device_id: String,
    signing_key: [u8; 32],
    substrate_reachability: Option<crate::coordination_client::SubstrateReachability>,
    authorized_groups: HashSet<String>,
    full_replica_groups: HashSet<String>,
}

/// The state one netmap WebSocket connection's receive loop works against:
/// the orchestrator's shared handles, plus the two pin caches loaded when
/// this connection opened and mutated by the pushes it reads.
struct NetmapSessionState<'a> {
    config: &'a OrchestratorConfig,
    state: &'a Arc<DaemonState>,
    diff_state: &'a NetmapDiffState,
    signing_key_pins: HashMap<String, String>,
    service_key_pins: HashMap<String, String>,
}

impl NetmapSessionState<'_> {
    /// Dispatch one inbound frame: a send-authorization notice or a netmap
    /// snapshot. Anything unparseable or inadmissible is
    /// abandoned on its own and the session keeps reading.
    ///
    /// Dispatch is on the frame's own `type`, and a frame naming any other
    /// type is ignored silently rather than reported as malformed. The
    /// subscription carries several message families and has carried more
    /// than it does now -- the peer-connection `rendezvous` signal that went
    /// away with the legacy transport is the current example. A well-formed
    /// frame this build has no handler for is a plane speaking a shape this
    /// daemon no longer reads, not corruption, and logging it as malformed
    /// would train the operator to ignore the one message that means the
    /// wire really is broken.
    async fn handle_message(&mut self, msg: Message) -> Result<NetmapFrameOutcome, DaemonError> {
        let text = match msg {
            Message::Text(text) => text,
            Message::Close(_) => return Ok(NetmapFrameOutcome::Closed),
            // Ping/Pong/Binary/Frame: not a netmap update, nothing to do.
            _ => return Ok(NetmapFrameOutcome::KeepReading),
        };
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
            tracing::warn!("received malformed netmap message; ignoring");
            return Ok(NetmapFrameOutcome::KeepReading);
        };
        let message_type = value.get("type").and_then(|t| t.as_str());
        match classify_subscription_message(message_type) {
            SubscriptionMessage::SendAuthorization => {
                self.handle_send_authorization(value);
                return Ok(NetmapFrameOutcome::KeepReading);
            }
            SubscriptionMessage::Netmap => {}
            SubscriptionMessage::Unread => {
                tracing::debug!(
                    message_type = message_type.unwrap_or("<absent>"),
                    "ignoring a subscription message this build does not read"
                );
                return Ok(NetmapFrameOutcome::KeepReading);
            }
        }
        let Ok(update) = serde_json::from_value::<WsNetmapMessage>(value) else {
            tracing::warn!("received malformed netmap message; ignoring");
            return Ok(NetmapFrameOutcome::KeepReading);
        };
        let update = match AdmittedNetmapMessage::admit(
            update,
            &self.diff_state.last_snapshot_generation,
        ) {
            Ok(update) => update,
            Err(NetmapAdmissionError::DuplicateDeviceId) => {
                tracing::error!(
                    "received netmap snapshot with duplicate device ids; rejecting the entire snapshot"
                );
                return Ok(NetmapFrameOutcome::KeepReading);
            }
            Err(NetmapAdmissionError::InvalidGeneration) => {
                tracing::error!(
                    "received netmap snapshot with an invalid generation; rejecting the entire snapshot"
                );
                return Ok(NetmapFrameOutcome::KeepReading);
            }
            Err(NetmapAdmissionError::StaleGeneration) => {
                tracing::warn!(
                    "received stale or replayed netmap snapshot; rejecting the entire snapshot"
                );
                return Ok(NetmapFrameOutcome::KeepReading);
            }
        };
        self.apply_snapshot(update).await?;
        Ok(NetmapFrameOutcome::KeepReading)
    }

    fn handle_send_authorization(&self, value: serde_json::Value) {
        match serde_json::from_value::<WsSendAuthorization>(value) {
            Ok(grant) => {
                let signing_key = base64::engine::general_purpose::STANDARD
                    .decode(&grant.sender_signing_public_key_base64)
                    .ok()
                    .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok());
                let Some(signing_key) = signing_key else {
                    tracing::warn!(
                        "received a send-authorization push with an unparseable sender \
                         signing key; ignoring"
                    );
                    return;
                };
                handle_incoming_send_authorization(
                    grant.grant_id,
                    grant.nonce,
                    grant.from,
                    signing_key,
                    grant.sender_substrate_reachability.map(Into::into).unwrap_or_default(),
                    grant.expires_at,
                    self.state,
                );
            }
            Err(_) => {
                tracing::warn!("received malformed send-authorization push; ignoring");
            }
        }
    }

    /// Apply one admitted netmap snapshot: policy first, then the
    /// plane's policy-invalid marks, then the membership diff, then the
    /// two-phase peer pass and the QUIC authorization set, and finally the
    /// epoch bump that wakes supervisors to the whole update.
    async fn apply_snapshot(&mut self, update: AdmittedNetmapMessage) -> Result<(), DaemonError> {
        let (update, generation) = update.into_parts();
        // Recorded before anything this frame writes, so every row it
        // mirrors carries this frame's provenance: a later run compares a
        // first frame's generation against it to decide whether that frame
        // may prune the cache at all.
        self.state.authority.note_applied_snapshot_generation(generation);
        self.apply_policy_update(&update);

        // Fail closed for every group the coordination plane flagged as
        // policy-invalid. Applied AFTER the policy block above so a group
        // the plane isolated out of `group_policy_logs` (and thus never
        // cleared or re-verified) stays stale: admission, local emission,
        // and status all consult the same `mark_group_policy_stale` gate.
        // Applied regardless of whether this snapshot carried a service
        // key, since the invalid list is independent of the policy logs.
        for group_id in &update.policy_invalid_group_ids {
            self.state.mark_group_policy_stale(group_id);
        }

        self.apply_membership_diff(&update.peers, generation);

        // Scoped to this one netmap-update pass: a group shared by many
        // peers in `update.peers` below is validated once, not once per
        // peer sharing it. See `effective_servable_groups`'s doc comment.
        let retained_group_validation_cache: std::sync::Mutex<HashMap<String, bool>> =
            std::sync::Mutex::new(HashMap::new());

        // Peer processing is two-phase. Phase 1 (admission) below runs
        // EVERY peer's Ed25519 signing-key pin check --
        // teardown-and-skip on any failure -- but
        // does not publish anything into `peer_netmap_metadata` or run
        // any authorization validation yet. Only once every peer in
        // this pass has been fully admitted (or rejected) does Phase 2
        // seed the admitted peers' signing keys and then run
        // authorization validation / session management.
        //
        // A single combined pass could not do this safely: peer A's `validate_retained_group` for a
        // shared group can need peer B's signing key (a retained change
        // in that group authored by B), and that check's `true`/`false`
        // result is cached for the rest of the pass
        // (`retained_group_validation_cache`) to avoid re-walking a
        // group shared by many peers. Publishing each peer's raw,
        // not-yet-pin-checked key as soon as it was decoded (rather
        // than after admission) would open a trust-boundary race: if
        // B's key had actually CHANGED from its pinned value (a
        // `PeerKeyDecision::Mismatch`, which is correctly rejected a
        // few lines later), a single pass could still
        // let A's validation run against that about-to-be-rejected key
        // in the gap before B's own rejection ran, cache `true` for the
        // shared group, and publish A's authorization on that basis --
        // B's later rejection only clears B's own metadata, not the
        // already-cached group result or A's already-published
        // authorization. Doing admission for every peer FIRST, and only
        // publishing/validating with the admitted, pin-checked key
        // set, removes that window entirely.
        let admitted = self.admit_peers(update.peers)?;

        // Phase 2: every peer admitted this pass has already passed its
        // Ed25519 signing-key pin check, so it is now safe to
        // settle ALL of their keys before validating ANY of their shared
        // groups -- no admitted peer's retained-history check can ever
        // race an admitted peer's own not-yet-settled key, and no
        // rejected peer's key is ever published at all.
        //
        // There is no "settle an absence" case to handle any more: a
        // peer with no usable device key never reaches this list, and a
        // peer that stops advertising one is torn down in phase 1, which
        // clears its metadata outright.
        for peer in &admitted {
            self.state.record_peer_signing_key(&peer.device_id, peer.signing_key);
        }

        self.publish_peer_authorization(admitted, &retained_group_validation_cache);
        Ok(())
    }

    /// Verify and record this snapshot's group policy logs, or -- when any
    /// part of the policy portion is invalid -- mark every group its peers
    /// share stale while the rest of the snapshot (peer revocations
    /// included) still applies.
    fn apply_policy_update(&mut self, update: &WsNetmapMessage) {
        if let Err(error) = self.record_policy_logs(update) {
            tracing::warn!(
                error = %error,
                "policy portion of netmap snapshot is invalid; marking its groups stale while still applying peer revocations"
            );
            for group_id in update.peers.iter().flat_map(|peer| peer.shared_group_ids.iter()) {
                self.state.mark_group_policy_stale(group_id);
            }
            return;
        }
        // The startup scan may have advanced the index while its
        // initial DAG import was withheld waiting for this policy.
        // Retry immediately on the admission edge; the periodic
        // audit remains the crash/loss backstop, not the primary
        // path (its 90s cadence exceeds convergence timeouts).
        for policy_log in &update.group_policy_logs {
            let repair_state = self.state.clone();
            let group_id = policy_log.group_id.clone();
            crate::supervise::spawn_one_shot("policy-admission-history-backfill", async move {
                // `backfill_missing_change_history` itself
                // silently skips (deferring to startup, "the
                // audit's first append... permanently closes
                // the fast path" -- see its own doc comment)
                // whenever this group's startup scan is
                // still `Starting` at the instant this runs.
                // This netmap-driven trigger fires the
                // moment policy verifies, which can race
                // AHEAD of startup's own (short, no-backoff)
                // retry loop finishing -- a skip here then
                // has no OTHER near-term trigger before the
                // periodic audit's 90s backstop (confirmed
                // by a real flaky end-to-end failure, not a
                // hypothetical). Calling this again is
                // always safe (idempotent: `NothingMissing`
                // once nothing is left to repair), so retry
                // a few times with a short delay instead of
                // once -- enough for startup's own retries
                // (bounded, no artificial delay of their
                // own) to finish one way or the other.
                for attempt in 0..5 {
                    repair_state.backfill_missing_change_history(&group_id).await;
                    if attempt < 4 {
                        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                    }
                }
                Ok(())
            });
        }
    }

    fn record_policy_logs(&mut self, update: &WsNetmapMessage) -> Result<(), DaemonError> {
        let service_key = base64::engine::general_purpose::STANDARD
            .decode(update.service_signing_public_key_base64.as_str())
            .map_err(|error| {
                DaemonError::Config(format!(
                    "received malformed policy service public key: {error}"
                ))
            })?;
        let policy_logs = update
            .group_policy_logs
            .iter()
            .map(ws_policy_log_to_record)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| {
                DaemonError::Config(format!("received malformed policy log: {error}"))
            })?;
        record_group_policy_states(
            self.state,
            &self.config.coordination_addr,
            &mut self.service_key_pins,
            &service_key,
            &policy_logs,
        )
    }

    /// Diff this snapshot's membership against the netmap this device was
    /// acting on and tear down what it removed -- including, on the run's
    /// first snapshot, a peer restored from the offline cache that the
    /// plane has since removed.
    ///
    /// Every netmap frame carries the plane's whole peer list, so this is
    /// always a full authoritative snapshot; only a group's policy chain
    /// can arrive as a forward extension, and that is handled (and
    /// distinguished) in `record_group_policy_states`.
    fn apply_membership_diff(&self, peers: &[WsNetmapPeer], generation: u64) {
        // Diff this snapshot against the previously-held one *before*
        // acting on the new peer list below — identical to the gRPC
        // path.
        let current_netmap: NetmapSnapshot = peers
            .iter()
            .map(|peer| {
                let groups: HashSet<String> = peer.shared_group_ids.iter().cloned().collect();
                (peer.device_id.clone(), groups)
            })
            .collect();
        apply_netmap_membership(self.state, self.diff_state, generation, current_netmap);
    }

    /// Phase 1: admit every peer of this snapshot, tearing down each one that
    /// fails. Publishes nothing about the admitted ones.
    fn admit_peers(&mut self, peers: Vec<WsNetmapPeer>) -> Result<Vec<AdmittedPeer>, DaemonError> {
        let mut admitted: Vec<AdmittedPeer> = Vec::new();
        for peer in peers {
            // The Ed25519 device key is mandatory, and its absence is
            // not a lesser form of presence. It is what authenticates
            // this device's connection to the peer in both directions,
            // so a netmap entry without one does not describe a peer
            // that can do less -- it describes a peer that can never
            // connect at all. Admitting it would mean carrying an entry
            // that every connect attempt has to reject again, and the
            // only shape of peer it could ever match is one this
            // generation of the protocol does not have.
            let Some(signing_key) = decode_peer_signing_key(&peer.signing_public_key_base64) else {
                tracing::warn!(
                    device_id = %peer.device_id,
                    "netmap peer has no usable Ed25519 device key; revoking any existing session"
                );
                teardown_peer(self.state, &peer.device_id);
                continue;
            };
            if pin_peer_signing_key(&mut self.signing_key_pins, &peer.device_id, &signing_key)? {
                teardown_peer(self.state, &peer.device_id);
                continue;
            }
            let authorized_groups: HashSet<String> =
                peer.shared_group_ids.iter().cloned().collect();
            let full_replica_groups: HashSet<String> =
                peer.full_replica_group_ids.iter().cloned().collect();
            if !full_replica_groups.is_subset(&authorized_groups) {
                tracing::warn!(device_id = %peer.device_id, "netmap peer advertises full-replica groups it is not authorized for; revoking any existing session");
                teardown_peer(self.state, &peer.device_id);
                continue;
            }
            admitted.push(AdmittedPeer {
                device_id: peer.device_id,
                signing_key,
                substrate_reachability: peer.substrate_reachability.map(|r| {
                    crate::coordination_client::SubstrateReachability {
                        direct: r
                            .direct
                            .iter()
                            .filter_map(|a| a.parse::<SocketAddr>().ok())
                            .collect(),
                        relays: r.relays,
                    }
                }),
                authorized_groups,
                full_replica_groups,
            });
        }
        Ok(admitted)
    }

    /// Phase 2, per peer: publish each admitted peer's substrate
    /// reachability and its group authorization.
    fn publish_peer_authorization(
        &self,
        admitted: Vec<AdmittedPeer>,
        retained_group_validation_cache: &std::sync::Mutex<HashMap<String, bool>>,
    ) {
        let state = self.state;
        for peer in admitted {
            // Where the reconciliation substrate can reach this peer.
            // `None` leaves what is already known; `Some` is
            // authoritative, including when it is empty.
            state.record_peer_substrate_reachability(
                &peer.device_id,
                peer.substrate_reachability.clone(),
            );
            apply_authoritative_peer_metadata(
                state,
                &peer.device_id,
                Some(peer.signing_key),
                &peer.authorized_groups,
                &peer.full_replica_groups,
                retained_group_validation_cache,
            );
        }
    }
}
