//! Unary coordination-plane calls the daemon makes outside the netmap
//! subscription: the one-time signing-key backfill, endpoint-candidate
//! reporting, rendezvous requests for hole punching, and the
//! activate/cancel calls `pending_enrollment::reconcile` issues for a
//! create/join left over from a previous run. Each speaks the coordination
//! plane over its HTTP+JSON API, the same host the netmap WebSocket
//! subscription connects to.
//!
//! Every call is best-effort: a failure is logged at debug and swallowed, so
//! a transient coordination-plane outage never takes down the caller's task.
//! The signing-key backfill in particular is set-once on the server (an
//! identical re-upload is a no-op, a mismatch is refused), so it is safe to
//! call unconditionally on every startup. The activate calls below return an
//! [`ActivateOutcome`] (rather than swallowing the result entirely) so
//! `pending_enrollment::reconcile` knows whether it is safe to drop its
//! local marker, must mark the link orphaned, or should leave the marker for
//! the next sweep to retry. The cancel calls stay a bare success/failure
//! bool: `reconcile` treats a cancel as best-effort regardless of why it
//! failed (the coordination plane's own TTL sweep is the eventual backstop
//! either way), so there is no extra outcome for it to branch on.

/// A self-reported reachable address for this device, offered to peers to
/// probe against for a direct connection. Carries only an `ip:port` and a
/// preference, never file content or names.
#[derive(Debug, Clone)]
pub struct EndpointCandidate {
    pub address: String,
    pub priority: i32,
}

/// The result of an `activate_create`/`activate_join` call, distinguished by
/// what the coordination plane's response actually communicates --
/// `pending_enrollment::reconcile` branches on this instead of a bare bool
/// since "already active" and "permanently gone" call for different local
/// follow-up (see its own doc comment).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivateOutcome {
    /// The Pending row was flipped to Active by this call.
    Success,
    /// The row was already Active -- activate is idempotent by
    /// `operation_id`, so a retried call (e.g. this device's own earlier
    /// call already succeeded before a crash) lands here rather than
    /// erroring.
    AlreadyActive,
    /// The coordination-side row this operation id names is permanently
    /// gone (never prepared, or already cancelled/swept) -- a 404 from the
    /// coordination plane. There is nothing left to activate.
    Deleted,
    /// Anything that isn't a clear terminal answer: a network error, a
    /// timeout, or a non-404 rejection. Worth retrying; not a verdict about
    /// the row itself.
    TransientFailure,
}

pub use imp::{
    activate_create, activate_join, cancel_create, cancel_join, commit_handoff_role_loss,
    compensate_handoff_role_loss, find_handoff_lease, release_handoff_lease, report_endpoint,
    request_handoff_lease, send_rendezvous, set_storage_mode, upload_signing_key,
};

/// A successfully-issued full-replica-handoff lease grant — the target-side
/// half of the round trip described on `HandoffLease` (`yadorilink_sync_
/// core::index`) and on the `RequestHandoffLeaseRequest` proto message.
///
/// `expires_at_unix` is the coordination Worker's OWN absolute expiry,
/// stamped against the Worker's clock purely for the Worker's own
/// bookkeeping and TTL sweep -- callers must never store or compare it
/// against a LOCAL clock reading on this device (that cross-clock comparison
/// is exactly the bug `ttl_seconds` exists to avoid: under clock skew it
/// could read a still-live lease as already expired, or vice versa). Any
/// caller that needs to pin something locally (this device's own retention
/// sweep) must derive its own deadline from `ttl_seconds` plus this device's
/// own `now_unix()` -- see `SyncState::record_handoff_lease_atomic`.
#[derive(Debug, Clone)]
pub struct HandoffLeaseGrant {
    pub lease_id: String,
    pub expires_at_unix: i64,
    /// The lease's TTL DURATION, as configured on the coordination Worker --
    /// clock-independent, unlike `expires_at_unix`. This is what a caller
    /// combines with its OWN clock reading to compute a local pin deadline.
    pub ttl_seconds: i64,
}

/// The result of a successful role-loss commit — this is entirely the
/// coordination-plane's own view: it carries no root-digest/content field,
/// since the Worker only ever adjudicates membership/eligibility, never file
/// paths, block hashes, or version content (see `commit_handoff_role_loss`'s
/// doc comment). The `HandoffResult` proto message adds `root_digest` on top
/// of this shape at the call site, populated entirely from the caller's own
/// already-known local digest — never sent to or read back from the Worker.
/// Kept as a plain struct here (rather than constructing the proto type
/// directly) so this module stays free of any dependency on
/// `yadorilink-ipc-proto`, matching every other function in this file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandoffCommitResult {
    pub target_device_id: String,
    pub membership_generation: i64,
    pub lease_id: Option<String>,
}

/// Outcome of a role-loss commit, preserving whether it is safe to discard
/// the source-side Prepared journal row. Only an explicit 4xx response is a
/// protocol-level guarantee that the Worker rejected the transaction before
/// committing it. Transport failures, 5xx responses, and malformed 2xx
/// responses are ambiguous because the Worker may already have committed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoleLossCommitOutcome {
    Committed(HandoffCommitResult),
    DefinitelyRejected(String),
    Ambiguous(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleLossCompensationOutcome {
    Restored,
    Superseded,
}

mod imp {
    use base64::Engine;
    use serde::{Deserialize, Serialize};

    use super::{
        ActivateOutcome, EndpointCandidate, HandoffCommitResult, HandoffLeaseGrant,
        RoleLossCommitOutcome, RoleLossCompensationOutcome,
    };

    #[derive(Serialize)]
    struct WireCandidate {
        address: String,
        priority: i32,
    }

    fn wire_candidates(candidates: &[EndpointCandidate]) -> Vec<WireCandidate> {
        candidates
            .iter()
            .map(|c| WireCandidate { address: c.address.clone(), priority: c.priority })
            .collect()
    }

    async fn post_no_content<B: Serialize>(url: String, access_token: &str, body: &B, what: &str) {
        let result =
            reqwest::Client::new().post(&url).bearer_auth(access_token).json(body).send().await;
        match result {
            Ok(resp) if resp.status().is_success() => {}
            Ok(resp) => {
                tracing::debug!(status = %resp.status(), what, "coordination call rejected")
            }
            Err(e) => tracing::debug!(error = %e, what, "coordination call failed"),
        }
    }

    /// Same shape as `post_no_content`, but reports success/failure back to
    /// the caller instead of only logging it -- `pending_enrollment::reconcile`
    /// needs to know whether it may drop its local marker.
    async fn post_no_content_ok<B: Serialize>(
        url: String,
        access_token: &str,
        body: &B,
        what: &str,
    ) -> bool {
        let result =
            reqwest::Client::new().post(&url).bearer_auth(access_token).json(body).send().await;
        match result {
            Ok(resp) if resp.status().is_success() => true,
            Ok(resp) => {
                tracing::debug!(status = %resp.status(), what, "coordination call rejected");
                false
            }
            Err(e) => {
                tracing::debug!(error = %e, what, "coordination call failed");
                false
            }
        }
    }

    /// The response body an activate call's 2xx response carries: which of
    /// the two non-error outcomes (`ActivateCreateResult`/`ActivateJoinResult`
    /// on the coordination-worker side) it landed on. A response that fails
    /// to parse (an older coordination-worker build that still replies with
    /// an empty 204, or any other unexpected body) is treated as a plain
    /// `Success` -- the status code alone already confirms the row is
    /// active, and "already active" vs. "freshly activated" makes no
    /// difference to any caller of `activate_create`/`activate_join`.
    #[derive(Deserialize)]
    struct ActivateResultBody {
        result: String,
    }

    /// Shared by `activate_create`/`activate_join`: both coordination-worker
    /// routes are 404 on a permanently-gone row and otherwise 2xx with a
    /// `{"result": "activated" | "already_active"}` body -- see
    /// `coordination-worker/src/routes/shares.ts`'s activate handlers.
    async fn post_activate<B: Serialize>(
        url: String,
        access_token: &str,
        body: &B,
        what: &str,
    ) -> ActivateOutcome {
        let result =
            reqwest::Client::new().post(&url).bearer_auth(access_token).json(body).send().await;
        match result {
            Ok(resp) if resp.status() == reqwest::StatusCode::NOT_FOUND => {
                tracing::debug!(what, "coordination call: operation not found (row gone)");
                ActivateOutcome::Deleted
            }
            Ok(resp) if resp.status().is_success() => match resp.json::<ActivateResultBody>().await
            {
                Ok(body) if body.result == "already_active" => ActivateOutcome::AlreadyActive,
                _ => ActivateOutcome::Success,
            },
            Ok(resp) => {
                tracing::debug!(status = %resp.status(), what, "coordination call rejected");
                ActivateOutcome::TransientFailure
            }
            Err(e) => {
                tracing::debug!(error = %e, what, "coordination call failed");
                ActivateOutcome::TransientFailure
            }
        }
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct OperationIdBody<'a> {
        operation_id: &'a str,
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct JoinOperationBody<'a> {
        operation_id: &'a str,
        device_id: &'a str,
    }

    /// Confirms a previously-prepared CREATE enrollment (coordination-worker's
    /// `POST /shares/groups/:groupId/activate`), turning a Pending group +
    /// its creator's Pending eager membership into the real thing. Called
    /// both by the CLI's own create flow (immediately, via its own HTTP
    /// client) and by `pending_enrollment::reconcile` on daemon startup, for
    /// a marker left over from a killed CLI process.
    pub async fn activate_create(
        addr: &str,
        access_token: &str,
        group_id: &str,
        operation_id: &str,
    ) -> ActivateOutcome {
        post_activate(
            format!("{addr}/shares/groups/{group_id}/activate"),
            access_token,
            &OperationIdBody { operation_id },
            "create activate",
        )
        .await
    }

    /// The compensating call for a CREATE enrollment that will never be
    /// activated (`POST /shares/groups/:groupId/cancel`) -- a no-op on the
    /// server if the group was already activated or is already gone.
    pub async fn cancel_create(
        addr: &str,
        access_token: &str,
        group_id: &str,
        operation_id: &str,
    ) -> bool {
        post_no_content_ok(
            format!("{addr}/shares/groups/{group_id}/cancel"),
            access_token,
            &OperationIdBody { operation_id },
            "create cancel",
        )
        .await
    }

    /// Confirms a previously-prepared JOIN enrollment (`POST
    /// /shares/groups/:groupId/join/activate`), turning a Pending membership
    /// into the real thing.
    pub async fn activate_join(
        addr: &str,
        access_token: &str,
        group_id: &str,
        operation_id: &str,
        device_id: &str,
    ) -> ActivateOutcome {
        post_activate(
            format!("{addr}/shares/groups/{group_id}/join/activate"),
            access_token,
            &JoinOperationBody { operation_id, device_id },
            "join activate",
        )
        .await
    }

    /// The compensating call for a JOIN enrollment that will never be
    /// activated (`POST /shares/groups/:groupId/join/cancel`) -- deletes
    /// only the membership, never the group; a no-op on the server if it
    /// was already activated or is already gone.
    pub async fn cancel_join(
        addr: &str,
        access_token: &str,
        group_id: &str,
        operation_id: &str,
        device_id: &str,
    ) -> bool {
        post_no_content_ok(
            format!("{addr}/shares/groups/{group_id}/join/cancel"),
            access_token,
            &JoinOperationBody { operation_id, device_id },
            "join cancel",
        )
        .await
    }

    pub async fn upload_signing_key(
        addr: &str,
        access_token: &str,
        device_id: String,
        signing_public_key: Vec<u8>,
    ) {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Body {
            signing_public_key_base64: String,
        }
        let body = Body {
            signing_public_key_base64: base64::engine::general_purpose::STANDARD
                .encode(&signing_public_key),
        };
        post_no_content(
            format!("{addr}/devices/{device_id}/signing-key"),
            access_token,
            &body,
            "signing-key backfill",
        )
        .await;
    }

    pub async fn report_endpoint(
        addr: &str,
        access_token: &str,
        device_id: String,
        candidates: &[EndpointCandidate],
    ) {
        #[derive(Serialize)]
        struct Body {
            candidates: Vec<WireCandidate>,
        }
        let body = Body { candidates: wire_candidates(candidates) };
        post_no_content(
            format!("{addr}/devices/{device_id}/endpoint"),
            access_token,
            &body,
            "endpoint report",
        )
        .await;
    }

    /// Looks up whether `target_device_id` currently holds a live handoff
    /// lease for `group_id` (`GET /shares/groups/:groupId/handoff/lease?
    /// targetDeviceId=...`) -- the SOURCE side of the round trip
    /// `request_handoff_lease` starts on the TARGET side. Called by a
    /// source-side role-loss commit path just before
    /// `commit_handoff_role_loss`, so a target that already requested a
    /// lease (because it independently verified readiness) has that lease
    /// actually presented and confirmed as part of the commit, instead of
    /// the commit always going through with `lease_id: None` and the lease
    /// being left to expire on its own. `None` on any failure (unreachable
    /// coordination plane, rejected request, unparseable response, or no
    /// live lease found) -- the caller treats this exactly like "no lease
    /// to present": `commit_handoff_role_loss` still succeeds on the
    /// Active+eager guard alone (a lease is retention-protection insurance
    /// for the target, not a hard prerequisite for the role-loss
    /// authorization itself).
    pub async fn find_handoff_lease(
        addr: &str,
        access_token: &str,
        group_id: &str,
        target_device_id: &str,
    ) -> Option<String> {
        #[derive(Deserialize)]
        struct LeaseInfo {
            #[serde(rename = "leaseId")]
            lease_id: String,
        }
        #[derive(Deserialize)]
        struct Resp {
            lease: Option<LeaseInfo>,
        }
        let url = match url::Url::parse(&format!("{addr}/shares/groups/{group_id}/handoff/lease")) {
            Ok(mut u) => {
                u.query_pairs_mut().append_pair("targetDeviceId", target_device_id);
                u
            }
            Err(e) => {
                tracing::debug!(error = %e, "handoff lease lookup: could not build request URL");
                return None;
            }
        };
        let result = reqwest::Client::new().get(url).bearer_auth(access_token).send().await;
        match result {
            Ok(resp) if resp.status().is_success() => match resp.json::<Resp>().await {
                Ok(r) => r.lease.map(|l| l.lease_id),
                Err(e) => {
                    tracing::debug!(error = %e, "handoff lease lookup: unparseable response");
                    None
                }
            },
            Ok(resp) => {
                tracing::debug!(status = %resp.status(), "handoff lease lookup rejected");
                None
            }
            Err(e) => {
                tracing::debug!(error = %e, "handoff lease lookup failed");
                None
            }
        }
    }

    /// Requests a full-replica-handoff lease from coordination-worker
    /// (`POST /shares/groups/:groupId/handoff/lease`), called by the handoff
    /// TARGET immediately after its own local readiness check confirms it
    /// holds every root of the group. Carries no digest or other
    /// content-derived value -- the request is purely `(group_id,
    /// target_device_id)`; the Worker's whole contribution to a handoff is
    /// confirming device/group membership and eligibility, never anything
    /// about the actual files or versions involved. `None` on any failure
    /// (unreachable coordination plane, rejected request, or an unparseable
    /// response) -- the caller (`daemon_state`'s handoff-lease request path)
    /// treats this exactly like an unconfirmed local readiness check: no
    /// lease was requested or recorded, and the caller's own TTL/retry story
    /// (retry the whole check-then-request sequence later) is unaffected.
    pub async fn request_handoff_lease(
        addr: &str,
        access_token: &str,
        group_id: &str,
        target_device_id: &str,
    ) -> Option<HandoffLeaseGrant> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Body<'a> {
            target_device_id: &'a str,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Resp {
            lease_id: String,
            expires_at: i64,
            ttl_seconds: i64,
        }
        let url = format!("{addr}/shares/groups/{group_id}/handoff/lease");
        let body = Body { target_device_id };
        let result =
            reqwest::Client::new().post(&url).bearer_auth(access_token).json(&body).send().await;
        match result {
            Ok(resp) if resp.status().is_success() => match resp.json::<Resp>().await {
                Ok(r) => Some(HandoffLeaseGrant {
                    lease_id: r.lease_id,
                    expires_at_unix: r.expires_at,
                    ttl_seconds: r.ttl_seconds,
                }),
                Err(e) => {
                    tracing::debug!(error = %e, "handoff lease request: unparseable response");
                    None
                }
            },
            Ok(resp) => {
                tracing::debug!(status = %resp.status(), "handoff lease request rejected");
                None
            }
            Err(e) => {
                tracing::debug!(error = %e, "handoff lease request failed");
                None
            }
        }
    }

    /// Explicitly releases a still-provisional handoff lease this device (as
    /// the target) decided not to use after all
    /// (`POST /shares/groups/:groupId/handoff/lease/:leaseId/release`) —
    /// called when the atomic local verify+pin
    /// (`SyncState::record_handoff_lease_atomic`) finds the durability-root
    /// set has moved since the readiness digest this lease was requested
    /// against was captured, so the lease is abandoned rather than kept
    /// around under a set it no longer matches. Carries no digest or other
    /// content-derived value, matching every other call in this module — just
    /// the opaque `lease_id` plus `(group_id, target_device_id)`. Best-effort
    /// like `find_handoff_lease`/`request_handoff_lease`: a failure here just
    /// means the lease is instead cleaned up later by coordination-worker's
    /// own TTL sweep, so it is logged at debug and swallowed rather than
    /// surfaced to the caller.
    pub async fn release_handoff_lease(
        addr: &str,
        access_token: &str,
        group_id: &str,
        target_device_id: &str,
        lease_id: &str,
    ) {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Body<'a> {
            target_device_id: &'a str,
        }
        let url = format!("{addr}/shares/groups/{group_id}/handoff/lease/{lease_id}/release");
        let body = Body { target_device_id };
        let result =
            reqwest::Client::new().post(&url).bearer_auth(access_token).json(&body).send().await;
        match result {
            Ok(resp) if resp.status().is_success() => {}
            Ok(resp) => {
                tracing::debug!(status = %resp.status(), "handoff lease release rejected");
            }
            Err(e) => {
                tracing::debug!(error = %e, "handoff lease release failed");
            }
        }
    }

    /// Commits a source device's full-replica-handoff role loss
    /// (`POST /shares/groups/:groupId/handoff/commit`) — coordination-worker
    /// atomically confirms `target_device_id` is currently an Active, eager
    /// full replica before committing `action` (`"demote"`: this device's own
    /// ACL edge narrows to on-demand; `"revoke"`: some other device's edge is
    /// removed entirely) and, if `lease_id` is set, confirms that lease (an
    /// opaque token scoped to `(group_id, target_device_id)`) in the same
    /// write. Carries no digest or other content-derived value, matching
    /// `request_handoff_lease` — the coordination plane's role here is
    /// entirely membership/eligibility adjudication; the "is this still the
    /// version I verified" question stays peer-attested and local (this
    /// device's own pre-existing digest-recapture-then-recheck gate, e.g.
    /// `SyncState::recheck_digest_then_remove_link`), never something the
    /// Worker checks. Unlike every other call in this module, this one
    /// surfaces its failure to the caller instead of swallowing it: the CLI
    /// call sites (`commands::share`, `commands::durability_force`) must not
    /// proceed to commit the LOCAL side of a role loss (removing a link,
    /// flipping local materialization policy) when the coordination-plane
    /// commit itself was refused or unreachable.
    pub async fn commit_handoff_role_loss(
        addr: &str,
        access_token: &str,
        group_id: &str,
        source_device_id: &str,
        target_device_id: &str,
        lease_id: Option<&str>,
        action: &str,
    ) -> RoleLossCommitOutcome {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Body<'a> {
            source_device_id: &'a str,
            target_device_id: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            lease_id: Option<&'a str>,
            action: &'a str,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Resp {
            target_device_id: String,
            membership_generation: i64,
            lease_id: Option<String>,
        }
        let url = format!("{addr}/shares/groups/{group_id}/handoff/commit");
        let body = Body { source_device_id, target_device_id, lease_id, action };
        let resp = match reqwest::Client::new()
            .post(&url)
            .bearer_auth(access_token)
            .json(&body)
            .send()
            .await
        {
            Ok(resp) => resp,
            Err(e) => {
                return RoleLossCommitOutcome::Ambiguous(format!(
                    "could not confirm the coordination-plane commit: {e}"
                ));
            }
        };
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            let detail =
                format!("coordination plane refused the handoff commit ({status}): {text}");
            return if status.is_client_error() {
                RoleLossCommitOutcome::DefinitelyRejected(detail)
            } else {
                RoleLossCommitOutcome::Ambiguous(detail)
            };
        }
        let parsed: Resp = match resp.json().await {
            Ok(parsed) => parsed,
            Err(e) => {
                return RoleLossCommitOutcome::Ambiguous(format!(
                    "handoff commit succeeded but its response was unparseable: {e}"
                ));
            }
        };
        RoleLossCommitOutcome::Committed(HandoffCommitResult {
            target_device_id: parsed.target_device_id,
            membership_generation: parsed.membership_generation,
            lease_id: parsed.lease_id,
        })
    }

    pub async fn compensate_handoff_role_loss(
        addr: &str,
        access_token: &str,
        group_id: &str,
        source_device_id: &str,
        target_device_id: &str,
        lease_id: &str,
        expected_membership_generation: Option<i64>,
    ) -> Result<RoleLossCompensationOutcome, String> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Body<'a> {
            source_device_id: &'a str,
            target_device_id: &'a str,
            lease_id: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            expected_membership_generation: Option<i64>,
        }
        #[derive(Deserialize)]
        struct Resp {
            status: String,
        }
        let response = reqwest::Client::new()
            .post(format!("{addr}/shares/groups/{group_id}/handoff/compensate"))
            .bearer_auth(access_token)
            .json(&Body {
                source_device_id,
                target_device_id,
                lease_id,
                expected_membership_generation,
            })
            .send()
            .await
            .map_err(|e| format!("could not confirm role-loss compensation: {e}"))?;
        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await.unwrap_or_default();
            return Err(format!(
                "coordination plane rejected role-loss compensation ({status}): {text}"
            ));
        }
        match response.json::<Resp>().await.map_err(|e| e.to_string())?.status.as_str() {
            "restored" => Ok(RoleLossCompensationOutcome::Restored),
            "superseded" => Ok(RoleLossCompensationOutcome::Superseded),
            other => Err(format!("unknown role-loss compensation status: {other}")),
        }
    }

    /// Reports this device's storage mode for a folder group
    /// (`POST /shares/groups/:groupId/storage-mode`) -- coordination-worker's
    /// single writer of `storage_mode` for a PROMOTION (on-demand -> eager).
    /// A DEMOTION instead writes `storage_mode` through
    /// `commit_handoff_role_loss`'s role-loss commit, which additionally
    /// confirms the handoff target and any presented lease atomically with
    /// the write; a promotion has no such hazard (gaining a durable copy is
    /// always safe), so this is a plain, unconditional write. Carries only
    /// the group id, this device's id, and the mode literal -- content-blind,
    /// like every other call in this module. Unlike most calls here, this one
    /// surfaces its failure to the caller instead of swallowing it: the
    /// daemon's `control_socket::set_storage_mode` must not proceed to flip
    /// local policy to eager when this write did not land, since that would
    /// leave this device locally eager while the coordination plane (and any
    /// peer reading its pushed netmap) still believes it is on-demand.
    pub async fn set_storage_mode(
        addr: &str,
        access_token: &str,
        group_id: &str,
        device_id: &str,
        storage_mode: &str,
    ) -> Result<(), String> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Body<'a> {
            device_id: &'a str,
            storage_mode: &'a str,
        }
        let url = format!("{addr}/shares/groups/{group_id}/storage-mode");
        let body = Body { device_id, storage_mode };
        let resp = reqwest::Client::new()
            .post(&url)
            .bearer_auth(access_token)
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("could not reach the coordination plane: {e}"))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(format!(
                "coordination plane refused the storage-mode change ({status}): {text}"
            ));
        }
        Ok(())
    }

    pub async fn send_rendezvous(
        addr: &str,
        access_token: &str,
        device_id: String,
        target_device_id: String,
        candidates: &[EndpointCandidate],
    ) {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Body {
            device_id: String,
            target_device_id: String,
            candidates: Vec<WireCandidate>,
        }
        let body = Body { device_id, target_device_id, candidates: wire_candidates(candidates) };
        post_no_content(
            format!("{addr}/netmap/rendezvous"),
            access_token,
            &body,
            "rendezvous send",
        )
        .await;
    }
}
