//! Unary coordination-plane calls the daemon makes outside the netmap
//! subscription: the one-time signing-key backfill, endpoint-candidate
//! reporting, rendezvous requests for hole punching, and the
//! activate/cancel calls `EnrollmentRecoveryService::reconcile_once` issues for a
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
//! `EnrollmentRecoveryService::reconcile_once` knows whether it is safe to drop its
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
/// `EnrollmentRecoveryService::reconcile_once` branches on this instead of a bare bool
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

/// The classified result of a coordination-plane enrollment PREPARE call
/// (create or join) -- distinct from a plain success/failure `Result` so a
/// caller can tell "definitely never committed" (safe to discard the local
/// journal row) apart from "may have committed, response merely lost" (must
/// never discard, must resend under the same operation_id).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnrollmentPrepareOutcome {
    Prepared {
        group_id: String,
    },
    /// 4xx (other than 409). The remote prepare was NOT committed.
    DefinitelyRejected(String),
    /// 409 -- this operation_id already names a differently-shaped request.
    Conflict(String),
    /// Transport failure, 5xx, or an unparseable 2xx create response.
    Ambiguous(String),
}

/// The classified result of a coordination-plane enrollment CANCEL call --
/// mirrors [`EnrollmentPrepareOutcome`]. Unlike prepare, the Worker's own
/// cancel routes treat "already gone"/"already active" as an ordinary 2xx
/// no-op (see `coordination-worker`'s own idempotent-cancel contract), so a
/// 404 here is NOT a routine "already cancelled" -- it means this
/// operation_id's identity itself doesn't match what the Worker expects,
/// same as a 409.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnrollmentCancelOutcome {
    /// 2xx -- includes an already-deleted/already-swept/already-active
    /// no-op.
    Confirmed,
    /// 409 or 404 -- a request-identity mismatch, not a routine absence.
    Conflict(String),
    /// Transport failure or 5xx.
    Ambiguous(String),
}

#[derive(Debug, Clone, Copy)]
pub struct RoleLossCommitRequest<'a> {
    pub group_id: &'a str,
    pub source_device_id: &'a str,
    pub target_device_id: &'a str,
    pub lease_id: Option<&'a str>,
    pub action: &'a str,
    pub operation_id: &'a str,
}

pub use imp::{
    activate_create, activate_join, cancel_create, cancel_create_classified, cancel_join,
    cancel_join_classified, commit_handoff_role_loss, compensate_handoff_role_loss,
    find_handoff_lease, prepare_create, prepare_join, query_enrollment_operation,
    query_membership_operation, query_membership_operation_categorized, query_role_loss_operation,
    release_handoff_lease, report_endpoint, request_handoff_lease, request_relay_grant,
    resolve_edge, send_rendezvous, set_storage_mode, upload_signing_key,
};

/// Why a remote-evidence lookup could not be answered -- see
/// `RemoteEvidence`'s own doc comment for the
/// contract this backs: NONE of these categories may ever be treated as
/// "the operation doesn't exist" (only a genuine HTTP 404 means that).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteEvidenceErrorCategory {
    /// The request never reached the coordination plane at all (DNS,
    /// connection refused, TLS failure, ...).
    Network,
    /// The request timed out waiting for a response.
    Timeout,
    /// The coordination plane responded, but with a server-side failure
    /// (5xx) or an unexpected non-success status this lookup has no more
    /// specific category for.
    ServerError,
    /// The coordination plane rejected the request's credentials (401/403)
    /// -- distinct from every other category because it likely means this
    /// device's own access token needs refreshing, not that the operation
    /// itself is unreachable.
    Unauthorized,
    /// A 2xx response whose body could not be parsed as the expected
    /// shape.
    MalformedResponse,
    /// The coordination plane responded successfully but the response
    /// shape names something this build does not recognize (e.g. a
    /// `status`/`kind` string added by a newer Worker deploy) -- distinct
    /// from `MalformedResponse` (which means the JSON itself didn't even
    /// parse) so a caller can tell "the plane is ahead of this build" apart
    /// from "the plane sent garbage".
    Unsupported,
}

/// A remote-evidence lookup's failure: the category above, plus a
/// human-readable detail for logs. Never constructed for a 404 -- that is
/// `RemoteEvidence::RecordNotFound`, not an
/// error.
#[derive(Debug, Clone)]
pub struct RemoteQueryError {
    pub category: RemoteEvidenceErrorCategory,
    pub message: String,
}

impl std::fmt::Display for RemoteQueryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

fn categorize_transport_error(error: &reqwest::Error) -> RemoteEvidenceErrorCategory {
    if error.is_timeout() {
        RemoteEvidenceErrorCategory::Timeout
    } else {
        RemoteEvidenceErrorCategory::Network
    }
}

/// Bounded so a recovery-evidence lookup can genuinely produce
/// [`RemoteEvidenceErrorCategory::Timeout`] rather than hang indefinitely
/// (this file's other calls use a plain, timeout-less `reqwest::Client::new()`
/// -- fine for a best-effort background call, wrong for an operator-facing
/// diagnosis command that must return in bounded time either way).
pub const EVIDENCE_LOOKUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

pub fn evidence_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(EVIDENCE_LOOKUP_TIMEOUT)
        .build()
        .expect("building the recovery-evidence HTTP client")
}

fn categorize_error_status(status: reqwest::StatusCode) -> RemoteEvidenceErrorCategory {
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        RemoteEvidenceErrorCategory::Unauthorized
    } else {
        // Every other non-success, non-404 status -- including a genuine
        // 5xx, but also any other unexpected code this lookup has no more
        // specific category for. Never `RecordNotFound`: only a literal
        // 404 means that.
        RemoteEvidenceErrorCategory::ServerError
    }
}

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
pub(crate) use crate::application::model::membership::{
    HandoffCommitResult, MembershipOperationLookup, MembershipOperationRecord,
    MembershipRemoteRequest, MembershipRemoteRequestGroup, MembershipRemoteResult,
    MembershipRemoteStatus, RoleLossCommitOutcome,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleLossCompensationOutcome {
    Restored,
    Superseded,
}

/// Which stage of the create/join enrollment saga a Worker-side ledger row
/// (`enrollment_operations`) reports -- mirrors
/// `yadorilink_sync_core::recovery`'s own domain-specific state strings,
/// but as a typed enum here since this is the coordination plane's OWN
/// state machine, not a local journal state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollmentRemoteStatus {
    Preparing,
    Prepared,
    Active,
    Cancelled,
}

/// The exact canonical request the coordination plane fingerprinted
/// `operation_id` against, mirroring `MembershipRemoteRequest`'s own
/// identity-comparison role. `Create`'s `storage_mode` is not actually a
/// wire field (a CREATE's creator edge is always `"eager"` by construction
/// -- see `prepareCreateFolderGroupRow`'s own doc comment on the Worker
/// side) -- it is filled in as that fixed constant here so both variants
/// present the same shape for identity comparison against a local
/// enrollment journal row, which always has a `storage_mode` regardless of
/// `kind`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnrollmentRemoteRequest {
    Create { group_name: String, device_id: String, storage_mode: String },
    Join { group_id: String, device_id: String, storage_mode: String },
}

/// An enrollment operation record read back from the coordination plane,
/// scoped by this device's own account (the Worker's
/// `/devices/enrollment-operations/:operationId` route is itself
/// `userId`-scoped).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentOperationRecord {
    pub status: EnrollmentRemoteStatus,
    pub request_fingerprint: String,
    pub request: EnrollmentRemoteRequest,
    /// The `groupId` from the ledger row's own `result` payload, when
    /// present (set once `prepared`/`active`). `None` while still
    /// `preparing`, or if the Worker response omitted it.
    pub result_group_id: Option<String>,
}

/// A role-loss-commit receipt read back from the coordination plane's
/// `role_loss_operation_receipts` table (Phase 2.1-C1) -- its mere
/// existence IS the evidence: a receipt means the underlying acl mutation
/// committed, full stop, there is no separate `status` field the way
/// enrollment/membership have one. See
/// `coordination-worker/src/db/queries.ts`'s `commitRoleLossGuarded` for
/// why this receipt is reliable (a `changes()`-chained, replay-idempotent
/// UPSERT) rather than a best-effort side record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleLossOperationRecord {
    pub group_id: String,
    pub source_device_id: String,
    pub target_device_id: String,
    pub lease_id: Option<String>,
    /// `"demote"` or `"revoke"` -- the Worker's own wire action string (see
    /// `commitHandoffRoleLoss`'s own doc comment for why the daemon's own
    /// `Unlink` role-loss action is sent to the Worker as `"demote"` too).
    pub action: String,
    /// Never `None` once decode succeeds -- `query_role_loss_operation`
    /// itself rejects a NULL generation as `Unsupported` before this type is
    /// ever constructed (generation 8's column is `NOT NULL`), so this field
    /// is non-optional rather than a redundant always-`Some` wrapper.
    pub membership_generation: i64,
    pub committed_at_unix: i64,
}

mod imp {
    use base64::Engine;
    use serde::{Deserialize, Serialize};

    use crate::relay_grant::RelayGrant;

    use super::{
        categorize_error_status, categorize_transport_error, evidence_http_client, ActivateOutcome,
        EndpointCandidate, EnrollmentOperationRecord, EnrollmentRemoteRequest,
        EnrollmentRemoteStatus, HandoffCommitResult, HandoffLeaseGrant, MembershipOperationLookup,
        MembershipOperationRecord, MembershipRemoteRequest, MembershipRemoteRequestGroup,
        MembershipRemoteResult, MembershipRemoteStatus, RemoteEvidenceErrorCategory,
        RemoteQueryError, RoleLossCommitOutcome, RoleLossCommitRequest,
        RoleLossCompensationOutcome, RoleLossOperationRecord,
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
    /// the caller instead of only logging it -- `EnrollmentRecoveryService::reconcile_once`
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
    /// client) and by `EnrollmentRecoveryService::reconcile_once` on daemon startup, for
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

    /// Sends the create-prepare request and classifies the response -- see
    /// [`super::EnrollmentPrepareOutcome`].
    pub async fn prepare_create(
        addr: &str,
        access_token: &str,
        operation_id: &str,
        name: &str,
        device_id: &str,
    ) -> super::EnrollmentPrepareOutcome {
        use super::EnrollmentPrepareOutcome;

        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Body<'a> {
            operation_id: &'a str,
            name: &'a str,
            creating_device_id: &'a str,
        }
        #[derive(Deserialize)]
        struct Response {
            group_id: String,
        }

        let response = match reqwest::Client::new()
            .post(format!("{addr}/shares/groups/prepare"))
            .bearer_auth(access_token)
            .json(&Body { operation_id, name, creating_device_id: device_id })
            .send()
            .await
        {
            Ok(response) => response,
            Err(error) => return EnrollmentPrepareOutcome::Ambiguous(error.to_string()),
        };
        let status = response.status();
        if status == reqwest::StatusCode::CONFLICT {
            return EnrollmentPrepareOutcome::Conflict(response.text().await.unwrap_or_default());
        }
        if status.is_client_error() {
            return EnrollmentPrepareOutcome::DefinitelyRejected(format!(
                "create prepare returned HTTP {status}: {}",
                response.text().await.unwrap_or_default()
            ));
        }
        if !status.is_success() {
            return EnrollmentPrepareOutcome::Ambiguous(format!(
                "create prepare returned HTTP {status}: {}",
                response.text().await.unwrap_or_default()
            ));
        }
        match response.json::<Response>().await {
            Ok(body) if !body.group_id.is_empty() => {
                EnrollmentPrepareOutcome::Prepared { group_id: body.group_id }
            }
            Ok(_) => EnrollmentPrepareOutcome::Ambiguous(
                "create prepare returned an empty group_id".to_string(),
            ),
            Err(error) => EnrollmentPrepareOutcome::Ambiguous(format!(
                "create prepare may have committed but its response was unparseable: {error}"
            )),
        }
    }

    /// Sends the join-prepare request and classifies the response. Unlike
    /// create, the group id is already known (it names the group being
    /// joined), so a bare 2xx is enough to confirm `Prepared`.
    pub async fn prepare_join(
        addr: &str,
        access_token: &str,
        operation_id: &str,
        group_id: &str,
        device_id: &str,
        storage_mode: &str,
    ) -> super::EnrollmentPrepareOutcome {
        use super::EnrollmentPrepareOutcome;

        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Body<'a> {
            operation_id: &'a str,
            device_id: &'a str,
            storage_mode: &'a str,
        }

        let response = match reqwest::Client::new()
            .post(format!("{addr}/shares/groups/{group_id}/join/prepare"))
            .bearer_auth(access_token)
            .json(&Body { operation_id, device_id, storage_mode })
            .send()
            .await
        {
            Ok(response) => response,
            Err(error) => return EnrollmentPrepareOutcome::Ambiguous(error.to_string()),
        };
        let status = response.status();
        if status.is_success() {
            return EnrollmentPrepareOutcome::Prepared { group_id: group_id.to_string() };
        }
        let detail = format!(
            "join prepare returned HTTP {status}: {}",
            response.text().await.unwrap_or_default()
        );
        if status == reqwest::StatusCode::CONFLICT {
            EnrollmentPrepareOutcome::Conflict(detail)
        } else if status.is_client_error() {
            EnrollmentPrepareOutcome::DefinitelyRejected(detail)
        } else {
            EnrollmentPrepareOutcome::Ambiguous(detail)
        }
    }

    async fn classify_cancel_response(
        response: Result<reqwest::Response, reqwest::Error>,
    ) -> super::EnrollmentCancelOutcome {
        use super::EnrollmentCancelOutcome;

        let response = match response {
            Ok(response) => response,
            Err(error) => return EnrollmentCancelOutcome::Ambiguous(error.to_string()),
        };
        let status = response.status();
        if status.is_success() {
            return EnrollmentCancelOutcome::Confirmed;
        }
        let detail =
            format!("cancel returned HTTP {status}: {}", response.text().await.unwrap_or_default());
        // A 404 here is NOT a routine "already gone" -- the Worker's own
        // cancel routes already fold that into an ordinary 2xx no-op, so a
        // 404 or 409 means this operation_id's identity itself doesn't
        // match.
        if status == reqwest::StatusCode::CONFLICT || status == reqwest::StatusCode::NOT_FOUND {
            EnrollmentCancelOutcome::Conflict(detail)
        } else {
            EnrollmentCancelOutcome::Ambiguous(detail)
        }
    }

    /// Sends the create-cancel request and classifies the response -- see
    /// [`super::EnrollmentCancelOutcome`]. Distinct from the plain bool
    /// [`cancel_create`] above: `EnrollmentService`'s own compensation
    /// sequence needs to tell a confirmed identity mismatch apart from a
    /// merely-ambiguous transport failure, which a bare bool cannot.
    pub async fn cancel_create_classified(
        addr: &str,
        access_token: &str,
        group_id: &str,
        operation_id: &str,
    ) -> super::EnrollmentCancelOutcome {
        classify_cancel_response(
            reqwest::Client::new()
                .post(format!("{addr}/shares/groups/{group_id}/cancel"))
                .bearer_auth(access_token)
                .json(&OperationIdBody { operation_id })
                .send()
                .await,
        )
        .await
    }

    /// Sends the join-cancel request and classifies the response -- see
    /// [`cancel_create_classified`]'s own doc comment.
    pub async fn cancel_join_classified(
        addr: &str,
        access_token: &str,
        group_id: &str,
        operation_id: &str,
        device_id: &str,
    ) -> super::EnrollmentCancelOutcome {
        classify_cancel_response(
            reqwest::Client::new()
                .post(format!("{addr}/shares/groups/{group_id}/join/cancel"))
                .bearer_auth(access_token)
                .json(&JoinOperationBody { operation_id, device_id })
                .send()
                .await,
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
        // P0-A: this device's own declared relay-capability, reported on
        // this SAME path (the daemon already sends one report
        // unconditionally at startup and again on every candidate change --
        // see nat_traversal.rs's `report_candidates_on_change` -- so this
        // rides an existing schedule rather than needing a dedicated
        // capability endpoint). See coordination-worker's `NetmapPeer.
        // relayCapable` for the other end of this value's journey.
        relay_capable: bool,
    ) {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Body {
            candidates: Vec<WireCandidate>,
            relay_capable: bool,
        }
        let body = Body { candidates: wire_candidates(candidates), relay_capable };
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

    /// M3 Pass 6 / P0-A: requests a signed [`crate::relay_grant::RelayGrant`]
    /// authorizing `relay_device_id` to forward opaque QUIC datagrams
    /// between this device (`source_device_id`) and `destination_device_id`,
    /// all three members of `group_id`
    /// (`POST /shares/groups/:groupId/relay/grant`). `source_device_id` is
    /// this device's own id -- the Bearer token authenticates only the
    /// account, never a specific device, so the coordination plane cannot
    /// derive it and it must be sent explicitly (verified server-side
    /// against the account's own device ownership; see the Worker's
    /// `issueRelayGrant` doc comment).
    ///
    /// Reconstructs the full [`RelayGrant`] from what the CALLER already
    /// knows (`group_id`/`source_device_id`/`relay_device_id`/
    /// `destination_device_id`, exactly what was just requested) plus what
    /// the plane decided (`grant_id`/`version`/validity window/
    /// `max_session_bytes`/signature) -- the response never re-states the
    /// four ids, so there is nothing for a caller to reconcile against a
    /// possibly-differing echo.
    ///
    /// `None` on any failure (unreachable plane, rejected request --
    /// unauthorized, not a member, relay not capable -- or an unparseable
    /// response), matching every other best-effort call in this module and
    /// [`crate::relay_carrier::RelayGrantSource`]'s own documented "no new
    /// connectivity authority" contract: a missing grant here is
    /// indistinguishable from any other reason a relay candidate didn't
    /// pan out, and [`crate::relay_carrier::open_relay_path`] simply tries
    /// the next one.
    pub async fn request_relay_grant(
        addr: &str,
        access_token: &str,
        group_id: &str,
        source_device_id: &str,
        relay_device_id: &str,
        destination_device_id: &str,
    ) -> Option<RelayGrant> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Body<'a> {
            source_device_id: &'a str,
            relay_device_id: &'a str,
            destination_device_id: &'a str,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Resp {
            grant_id: String,
            version: u32,
            not_before_unix: i64,
            expires_at_unix: i64,
            max_session_bytes: Option<u64>,
            signature_base64: String,
        }
        let url = format!("{addr}/shares/groups/{group_id}/relay/grant");
        let body = Body { source_device_id, relay_device_id, destination_device_id };
        let result =
            reqwest::Client::new().post(&url).bearer_auth(access_token).json(&body).send().await;
        match result {
            Ok(resp) if resp.status().is_success() => match resp.json::<Resp>().await {
                Ok(r) => {
                    let signature = match base64::engine::general_purpose::STANDARD
                        .decode(&r.signature_base64)
                    {
                        Ok(bytes) => bytes,
                        Err(e) => {
                            tracing::debug!(error = %e, "relay grant request: unparseable signature");
                            return None;
                        }
                    };
                    Some(RelayGrant {
                        version: r.version,
                        grant_id: r.grant_id,
                        group_id: group_id.to_string(),
                        source_device_id: source_device_id.to_string(),
                        relay_device_id: relay_device_id.to_string(),
                        destination_device_id: destination_device_id.to_string(),
                        not_before_unix: r.not_before_unix,
                        expires_at_unix: r.expires_at_unix,
                        max_session_bytes: r.max_session_bytes,
                        signature,
                    })
                }
                Err(e) => {
                    tracing::debug!(error = %e, "relay grant request: unparseable response");
                    None
                }
            },
            Ok(resp) => {
                tracing::debug!(status = %resp.status(), "relay grant request rejected");
                None
            }
            Err(e) => {
                tracing::debug!(error = %e, "relay grant request failed");
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
        request: RoleLossCommitRequest<'_>,
    ) -> RoleLossCommitOutcome {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Body<'a> {
            source_device_id: &'a str,
            target_device_id: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            lease_id: Option<&'a str>,
            action: &'a str,
            operation_id: &'a str,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Resp {
            target_device_id: String,
            membership_generation: i64,
            lease_id: Option<String>,
        }
        let url = format!("{addr}/shares/groups/{}/handoff/commit", request.group_id);
        let body = Body {
            source_device_id: request.source_device_id,
            target_device_id: request.target_device_id,
            lease_id: request.lease_id,
            action: request.action,
            operation_id: request.operation_id,
        };
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
            return if status == reqwest::StatusCode::CONFLICT {
                RoleLossCommitOutcome::Conflict(detail)
            } else if status.is_client_error() {
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

    /// Resolves a share edge id to its `(group_id, device_id)` by listing
    /// the account's own share edges, the same `/shares` route the CLI used
    /// to call directly. Kept here so `revoke_edge` is fully daemon-owned:
    /// the CLI never sees the edge listing or issues a raw HTTP delete
    /// against the coordination plane for it (see
    /// `ReplicaMembershipService::revoke_edge`'s doc comment).
    pub async fn resolve_edge(
        addr: &str,
        access_token: &str,
        edge_id: &str,
    ) -> Result<Option<(String, String)>, String> {
        #[derive(Deserialize)]
        struct EdgeInfo {
            edge_id: String,
            group_id: String,
            device_id: String,
        }
        #[derive(Deserialize)]
        struct Resp {
            edges: Vec<EdgeInfo>,
        }
        let resp = reqwest::Client::new()
            .get(format!("{addr}/shares"))
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if !resp.status().is_success() {
            return Err(format!("listing shares returned HTTP {}", resp.status()));
        }
        let parsed: Resp = resp.json().await.map_err(|e| e.to_string())?;
        Ok(parsed
            .edges
            .into_iter()
            .find(|edge| edge.edge_id == edge_id)
            .map(|edge| (edge.group_id, edge.device_id)))
    }

    /// Confirms whether a daemon-driven membership mutation actually landed,
    /// by `operation_id` -- see `MembershipOperationLookup`'s doc comment.
    /// Scoped by this device's own account, never by device ownership, so it
    /// keeps answering correctly after the removed device's own row is gone
    /// (unlike `resolve_edge`/eager-groups above). `Ok(NotFound)` means a
    /// genuine HTTP 404 -- no durable operation record was returned for
    /// this operation id at lookup time. It does NOT prove that the
    /// request was definitely rejected, that no historical mutation
    /// occurred, or that treating this operation as resolved is safe --
    /// see `RemoteEvidence`'s own doc comment
    /// for the same contract stated once, generally. Distinct from `Err`,
    /// which means the query itself couldn't be answered (network error,
    /// 5xx) and the caller must treat the operation's outcome as still
    /// unknown, not as rejected.
    pub async fn query_membership_operation(
        addr: &str,
        access_token: &str,
        operation_id: &str,
    ) -> Result<MembershipOperationLookup, String> {
        query_membership_operation_categorized(
            &evidence_http_client(),
            addr,
            access_token,
            operation_id,
        )
        .await
        .map_err(|e| e.message)
    }

    /// Same lookup as [`query_membership_operation`], sharing its entire
    /// request-building/parsing implementation, but with the failure
    /// categorized -- see [`RemoteEvidenceErrorCategory`]'s own doc
    /// comment. Used by the recovery-evidence module's
    /// `RecoveryEvidenceSource` implementation, which must distinguish a
    /// timeout/network/server error (still `Unavailable`, might resolve on
    /// retry) from a 404 (`RecordNotFound`, a real answer) -- a
    /// distinction the plain `String` error above deliberately does not
    /// expose to its own (pre-existing) callers, which never needed it.
    /// Takes `client` explicitly (rather than building one internally, the
    /// way every other function in this file does) so a test can inject a
    /// short-timeout client and exercise a genuine, real `Timeout`
    /// classification end to end, through `WorkerEvidenceSource` itself,
    /// instead of only unit-testing `categorize_transport_error` in
    /// isolation against a raw `reqwest::Error`.
    pub async fn query_membership_operation_categorized(
        client: &reqwest::Client,
        addr: &str,
        access_token: &str,
        operation_id: &str,
    ) -> Result<MembershipOperationLookup, RemoteQueryError> {
        // Decoded as a plain `String` below, not a serde enum -- see
        // `query_enrollment_operation`'s identical reasoning for why an
        // unrecognized-but-well-formed status must be `Unsupported`, not
        // `MalformedResponse`.
        #[derive(Deserialize, Default)]
        #[serde(rename_all = "camelCase")]
        struct ResultBody {
            #[serde(default)]
            affected_group_ids: Option<Vec<String>>,
            target_device_id: Option<String>,
            membership_generation: Option<i64>,
            lease_id: Option<String>,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct RequestGroupBody {
            group_id: String,
            target_device_id: Option<String>,
            lease_id: Option<String>,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct RequestBody {
            // Present on the wire (the Worker's own fingerprint input
            // includes it) but unused here: this lookup is already scoped
            // to the caller's own account server-side, so there's nothing
            // left to compare it against locally.
            #[allow(dead_code)]
            user_id: String,
            action: String,
            removed_device_id: String,
            mode: String,
            groups: Vec<RequestGroupBody>,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Resp {
            operation_id: String,
            status: String,
            action: String,
            removed_device_id: String,
            request_fingerprint: String,
            request: RequestBody,
            result: Option<ResultBody>,
            rejection_code: Option<String>,
            rejection_detail: Option<String>,
        }
        let resp = client
            .get(format!("{addr}/devices/membership-operations/{operation_id}"))
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| RemoteQueryError {
                category: categorize_transport_error(&e),
                message: e.to_string(),
            })?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(MembershipOperationLookup::NotFound);
        }
        if !resp.status().is_success() {
            let status = resp.status();
            return Err(RemoteQueryError {
                category: categorize_error_status(status),
                message: format!("membership operation lookup returned HTTP {status}"),
            });
        }
        let parsed: Resp = resp.json().await.map_err(|e| RemoteQueryError {
            category: RemoteEvidenceErrorCategory::MalformedResponse,
            message: e.to_string(),
        })?;
        // Same endpoint-contract check as `query_enrollment_operation`'s own
        // -- see that function's identical comment.
        if parsed.operation_id != operation_id {
            return Err(RemoteQueryError {
                category: RemoteEvidenceErrorCategory::MalformedResponse,
                message: format!(
                    "operation id mismatch: requested {operation_id}, received {}",
                    parsed.operation_id
                ),
            });
        }
        let status = match parsed.status.as_str() {
            "committed" => MembershipRemoteStatus::Committed,
            "definitely-rejected" => MembershipRemoteStatus::DefinitelyRejected,
            other => {
                return Err(RemoteQueryError {
                    category: RemoteEvidenceErrorCategory::Unsupported,
                    message: format!("unsupported membership operation status: {other}"),
                });
            }
        };
        // The Worker's own `MembershipOperationAction`/`MembershipOperationMode`
        // wire types (`coordination-worker/src/db/types.ts`) are each a
        // closed two-value set -- an unrecognized value here means a newer
        // Worker deploy this build predates, `Unsupported`, not a shape
        // violation. Checked on both the top-level `action` and the nested
        // `request.action` since they are independently-decoded fields.
        for candidate in [parsed.action.as_str(), parsed.request.action.as_str()] {
            if candidate != "revoke" && candidate != "remove-device" {
                return Err(RemoteQueryError {
                    category: RemoteEvidenceErrorCategory::Unsupported,
                    message: format!("unsupported membership operation action: {candidate}"),
                });
            }
        }
        if parsed.request.mode != "guarded" && parsed.request.mode != "plain" {
            return Err(RemoteQueryError {
                category: RemoteEvidenceErrorCategory::Unsupported,
                message: format!("unsupported membership operation mode: {}", parsed.request.mode),
            });
        }
        // Two independently-decoded fields naming the same request
        // (top-level vs. `request.*`) disagreeing is not an unrecognized
        // value -- it is the response contradicting itself, which is
        // `MalformedResponse`, not `Unsupported`.
        if parsed.action != parsed.request.action {
            return Err(RemoteQueryError {
                category: RemoteEvidenceErrorCategory::MalformedResponse,
                message: format!(
                    "membership operation action mismatch: top-level {}, request {}",
                    parsed.action, parsed.request.action
                ),
            });
        }
        if parsed.removed_device_id != parsed.request.removed_device_id {
            return Err(RemoteQueryError {
                category: RemoteEvidenceErrorCategory::MalformedResponse,
                message: format!(
                    "membership operation removed device mismatch: top-level {}, request {}",
                    parsed.removed_device_id, parsed.request.removed_device_id
                ),
            });
        }
        let result = parsed.result.map(|r| MembershipRemoteResult {
            affected_group_ids: r.affected_group_ids,
            target_device_id: r.target_device_id,
            membership_generation: r.membership_generation,
            lease_id: r.lease_id,
        });
        let request = MembershipRemoteRequest {
            action: parsed.request.action,
            removed_device_id: parsed.request.removed_device_id,
            mode: parsed.request.mode,
            groups: parsed
                .request
                .groups
                .into_iter()
                .map(|group| MembershipRemoteRequestGroup {
                    group_id: group.group_id,
                    target_device_id: group.target_device_id,
                    lease_id: group.lease_id,
                })
                .collect(),
        };
        Ok(MembershipOperationLookup::Found(Box::new(MembershipOperationRecord {
            status,
            action: parsed.action,
            removed_device_id: parsed.removed_device_id,
            request_fingerprint: parsed.request_fingerprint,
            request,
            result,
            rejection_code: parsed.rejection_code,
            rejection_detail: parsed.rejection_detail,
        })))
    }

    /// Reads the coordination plane's own `enrollment_operations` ledger
    /// row by `operation_id`, scoped to this device's own account (the
    /// Worker route itself is `userId`-scoped). `Ok(None)` means a genuine
    /// HTTP 404 -- no durable operation record was returned for this
    /// operation id at lookup time. It does NOT prove that the request was
    /// definitely rejected, that no historical mutation occurred, or that
    /// treating this operation as resolved is safe -- see
    /// `RemoteEvidence`'s own doc comment for
    /// the same contract stated once, generally. Distinct from `Err`, which
    /// means the query itself could not be answered -- see
    /// [`RemoteEvidenceErrorCategory`]'s own doc comment for why these must
    /// never be conflated.
    pub async fn query_enrollment_operation(
        client: &reqwest::Client,
        addr: &str,
        access_token: &str,
        operation_id: &str,
    ) -> Result<Option<EnrollmentOperationRecord>, RemoteQueryError> {
        // `kind`/`status` are decoded as plain `String`, not a serde enum:
        // a serde enum fails the ENTIRE response parse on an unrecognized
        // variant, which this lookup would then report as
        // `MalformedResponse` -- indistinguishable from genuinely broken
        // JSON. Matched explicitly below instead, so an unrecognized-but
        // well-formed value (a newer Worker deploy adding a status this
        // build predates) is reported as `Unsupported`.
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct RequestBody {
            // Present on the wire (the fingerprint input includes it) but
            // unused here: this lookup is already scoped to the caller's
            // own account server-side.
            #[allow(dead_code)]
            user_id: String,
            #[serde(default)]
            group_name: Option<String>,
            #[serde(default)]
            group_id: Option<String>,
            device_id: String,
            #[serde(default)]
            storage_mode: Option<String>,
        }
        #[derive(Deserialize, Default)]
        struct ResultBody {
            #[serde(rename = "groupId")]
            group_id: Option<String>,
        }
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Resp {
            operation_id: String,
            kind: String,
            status: String,
            request_fingerprint: String,
            request: RequestBody,
            result: Option<ResultBody>,
        }
        let resp = client
            .get(format!("{addr}/devices/enrollment-operations/{operation_id}"))
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| RemoteQueryError {
                category: categorize_transport_error(&e),
                message: e.to_string(),
            })?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            let status = resp.status();
            return Err(RemoteQueryError {
                category: categorize_error_status(status),
                message: format!("enrollment operation lookup returned HTTP {status}"),
            });
        }
        let parsed: Resp = resp.json().await.map_err(|e| RemoteQueryError {
            category: RemoteEvidenceErrorCategory::MalformedResponse,
            message: e.to_string(),
        })?;
        // The endpoint's own contract is to answer for exactly the
        // requested operation_id -- a mismatch means the Worker response
        // itself broke that contract (not a local-vs-remote identity
        // question C2's diagnosis engine handles), so this is
        // `MalformedResponse`, not `Conflict` (which does not even exist
        // at this layer).
        if parsed.operation_id != operation_id {
            return Err(RemoteQueryError {
                category: RemoteEvidenceErrorCategory::MalformedResponse,
                message: format!(
                    "operation id mismatch: requested {operation_id}, received {}",
                    parsed.operation_id
                ),
            });
        }
        let status = match parsed.status.as_str() {
            "preparing" => EnrollmentRemoteStatus::Preparing,
            "prepared" => EnrollmentRemoteStatus::Prepared,
            "active" => EnrollmentRemoteStatus::Active,
            "cancelled" => EnrollmentRemoteStatus::Cancelled,
            other => {
                return Err(RemoteQueryError {
                    category: RemoteEvidenceErrorCategory::Unsupported,
                    message: format!("unsupported enrollment status: {other}"),
                });
            }
        };
        // `storage_mode` is a real wire field for `join`; for `create` it
        // is always `"eager"` by construction (see
        // `EnrollmentRemoteRequest`'s own doc comment) -- an absent field
        // there is expected, not a shape violation. A `join` response
        // missing it, or either kind missing its own required id field, IS
        // a shape this build doesn't recognize.
        let request = match parsed.kind.as_str() {
            "create" => {
                let Some(group_name) = parsed.request.group_name else {
                    return Err(RemoteQueryError {
                        category: RemoteEvidenceErrorCategory::Unsupported,
                        message: "create enrollment response missing groupName".to_string(),
                    });
                };
                EnrollmentRemoteRequest::Create {
                    group_name,
                    device_id: parsed.request.device_id,
                    storage_mode: "eager".to_string(),
                }
            }
            "join" => {
                let (Some(group_id), Some(storage_mode)) =
                    (parsed.request.group_id, parsed.request.storage_mode)
                else {
                    return Err(RemoteQueryError {
                        category: RemoteEvidenceErrorCategory::Unsupported,
                        message: "join enrollment response missing groupId/storageMode".to_string(),
                    });
                };
                if storage_mode != "eager" && storage_mode != "on-demand" {
                    return Err(RemoteQueryError {
                        category: RemoteEvidenceErrorCategory::Unsupported,
                        message: format!("unsupported join storage mode: {storage_mode}"),
                    });
                }
                EnrollmentRemoteRequest::Join {
                    group_id,
                    device_id: parsed.request.device_id,
                    storage_mode,
                }
            }
            other => {
                return Err(RemoteQueryError {
                    category: RemoteEvidenceErrorCategory::Unsupported,
                    message: format!("unsupported enrollment kind: {other}"),
                });
            }
        };
        Ok(Some(EnrollmentOperationRecord {
            status,
            request_fingerprint: parsed.request_fingerprint,
            request,
            result_group_id: parsed.result.and_then(|r| r.group_id),
        }))
    }

    /// Reads the coordination plane's `role_loss_operation_receipts` row by
    /// `operation_id` (Phase 2.1-C1) -- the receipt's mere existence IS the
    /// evidence that a role-loss commit landed; there is no separate
    /// status field the way enrollment/membership have one. `Ok(None)`
    /// means a genuine HTTP 404 -- no durable receipt was returned for this
    /// operation id at lookup time. It does NOT prove that the request was
    /// definitely rejected, that no historical mutation occurred (a commit
    /// made before generation 7, when this table did not exist, leaves no
    /// receipt either), or that treating this operation as resolved is
    /// safe -- see `RemoteEvidence`'s own doc
    /// comment for the same contract stated once, generally.
    pub async fn query_role_loss_operation(
        client: &reqwest::Client,
        addr: &str,
        access_token: &str,
        operation_id: &str,
    ) -> Result<Option<RoleLossOperationRecord>, RemoteQueryError> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Resp {
            operation_id: String,
            group_id: String,
            source_device_id: String,
            target_device_id: String,
            lease_id: Option<String>,
            action: String,
            membership_generation: Option<i64>,
            committed_at: i64,
        }
        let resp = client
            .get(format!("{addr}/devices/role-loss-operations/{operation_id}"))
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| RemoteQueryError {
                category: categorize_transport_error(&e),
                message: e.to_string(),
            })?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            let status = resp.status();
            return Err(RemoteQueryError {
                category: categorize_error_status(status),
                message: format!("role-loss operation lookup returned HTTP {status}"),
            });
        }
        let parsed: Resp = resp.json().await.map_err(|e| RemoteQueryError {
            category: RemoteEvidenceErrorCategory::MalformedResponse,
            message: e.to_string(),
        })?;
        // Same endpoint-contract check as `query_enrollment_operation`'s own
        // -- see that function's identical comment.
        if parsed.operation_id != operation_id {
            return Err(RemoteQueryError {
                category: RemoteEvidenceErrorCategory::MalformedResponse,
                message: format!(
                    "operation id mismatch: requested {operation_id}, received {}",
                    parsed.operation_id
                ),
            });
        }
        // `action` is well-formed JSON but has a closed, known set of legal
        // values on the Worker side (`"demote"`/`"revoke"` -- see
        // `commitHandoffRoleLoss`'s own doc comment) -- anything else is
        // `Unsupported`, not a shape violation.
        if parsed.action != "demote" && parsed.action != "revoke" {
            return Err(RemoteQueryError {
                category: RemoteEvidenceErrorCategory::Unsupported,
                message: format!("unsupported role-loss action: {}", parsed.action),
            });
        }
        // Generation 8's `role_loss_operation_receipts.membership_generation`
        // column is `NOT NULL` (see that table's own migration comment) --
        // a receipt with no generation at all is a shape this build does
        // not recognize, not a legitimately absent value; treating it as
        // generation 0 (an earlier version of this code did) would silently
        // fabricate a successful outcome from a malformed row.
        let Some(membership_generation) = parsed.membership_generation else {
            return Err(RemoteQueryError {
                category: RemoteEvidenceErrorCategory::Unsupported,
                message: "role-loss receipt missing membershipGeneration".to_string(),
            });
        };
        Ok(Some(RoleLossOperationRecord {
            group_id: parsed.group_id,
            source_device_id: parsed.source_device_id,
            target_device_id: parsed.target_device_id,
            lease_id: parsed.lease_id,
            action: parsed.action,
            membership_generation,
            committed_at_unix: parsed.committed_at,
        }))
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
