//! Phase 2.1-C1: read-only remote-evidence lookups the daemon uses to
//! diagnose a stuck local recovery-journal operation against the
//! coordination plane's own durable state.
//!
//! This module is strictly read-only, structurally: [`RecoveryEvidenceSource`]
//! carries no mutation method at all. A diagnosis engine (Phase 2.1-C2)
//! built only against this trait cannot retry, cancel, or otherwise change
//! coordination-plane state no matter what it concludes -- write-side
//! resolution (Phase 2.2) needs a separate capability entirely, not an
//! extension of this one.

use crate::coordination_client::{
    self, EnrollmentOperationRecord, MembershipOperationLookup, MembershipOperationRecord,
    RemoteEvidenceErrorCategory, RemoteQueryError, RoleLossOperationRecord,
};
use crate::recovery::RecoveryOperationKey;

/// The outcome of a single remote-evidence lookup.
///
/// `RecordNotFound` means ONLY that no durable operation record was
/// returned for this operation id at lookup time (a genuine HTTP 404). It
/// does NOT prove that:
/// - the request was definitely rejected;
/// - no historical mutation occurred (a role-loss commit made before
///   `role_loss_operation_receipts` existed leaves no receipt at all, and
///   even after that table exists, an enrollment/membership row whose own
///   endpoint never distinguishes "genuinely rejected" from "never
///   attempted" -- see each Worker route's own doc comment -- looks
///   identical here too);
/// - deleting the local journal, or otherwise treating this operation as
///   resolved, is safe.
///
/// Domain-specific diagnosis (Phase 2.1-C2) decides whether the same
/// request should be retried or whether additional evidence is required --
/// this type only reports what the lookup itself observed, nothing more.
///
/// The three-way split (as opposed to a plain `Option`) is what makes that
/// downstream diagnosis possible at all: a caller MUST be able to tell "the
/// coordination plane returned nothing for this id" (`RecordNotFound`)
/// apart from "the coordination plane could not be asked right now"
/// (`Unavailable`) -- collapsing the two, as an early draft of the
/// `role_loss_operation_receipts` write path itself briefly did in reverse
/// (treating a post-hoc state re-check as proof of success -- see that
/// fix's own doc comment in `coordination-worker/src/db/queries.ts`), is
/// exactly the class of bug this type exists to make impossible to write
/// by accident: nothing in this enum can be constructed by silently
/// downgrading `Unavailable` into `RecordNotFound`.
#[derive(Debug, Clone)]
pub enum RemoteEvidence<T> {
    Found(T),
    RecordNotFound,
    Unavailable { category: RemoteEvidenceErrorCategory },
}

fn from_lookup<T>(result: Result<Option<T>, RemoteQueryError>) -> RemoteEvidence<T> {
    match result {
        Ok(Some(value)) => RemoteEvidence::Found(value),
        Ok(None) => RemoteEvidence::RecordNotFound,
        Err(error) => RemoteEvidence::Unavailable { category: error.category },
    }
}

/// Read-only remote-evidence source for recovery diagnosis. See this
/// module's own doc comment for why it carries no mutation method.
pub trait RecoveryEvidenceSource {
    fn lookup_enrollment(
        &self,
        key: &RecoveryOperationKey,
    ) -> impl std::future::Future<Output = RemoteEvidence<EnrollmentOperationRecord>> + Send;

    fn lookup_membership(
        &self,
        key: &RecoveryOperationKey,
    ) -> impl std::future::Future<Output = RemoteEvidence<MembershipOperationRecord>> + Send;

    fn lookup_role_loss(
        &self,
        key: &RecoveryOperationKey,
    ) -> impl std::future::Future<Output = RemoteEvidence<RoleLossOperationRecord>> + Send;
}

/// The real [`RecoveryEvidenceSource`], backed by HTTP calls to the
/// coordination plane via `crate::coordination_client`. Holds its own
/// `reqwest::Client` (rather than each lookup building one internally) so
/// a test can inject a short-timeout client via
/// [`Self::with_timeout`] and exercise a genuine, real `Timeout`
/// classification end to end.
pub struct WorkerEvidenceSource<'a> {
    pub addr: &'a str,
    pub access_token: &'a str,
    client: reqwest::Client,
}

impl<'a> WorkerEvidenceSource<'a> {
    pub fn new(addr: &'a str, access_token: &'a str) -> Self {
        Self::with_timeout(addr, access_token, coordination_client::EVIDENCE_LOOKUP_TIMEOUT)
    }

    pub fn with_timeout(
        addr: &'a str,
        access_token: &'a str,
        timeout: std::time::Duration,
    ) -> Self {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .expect("building the recovery-evidence HTTP client");
        WorkerEvidenceSource { addr, access_token, client }
    }
}

impl RecoveryEvidenceSource for WorkerEvidenceSource<'_> {
    async fn lookup_enrollment(
        &self,
        key: &RecoveryOperationKey,
    ) -> RemoteEvidence<EnrollmentOperationRecord> {
        from_lookup(
            coordination_client::query_enrollment_operation(
                &self.client,
                self.addr,
                self.access_token,
                &key.operation_id,
            )
            .await,
        )
    }

    async fn lookup_membership(
        &self,
        key: &RecoveryOperationKey,
    ) -> RemoteEvidence<MembershipOperationRecord> {
        match coordination_client::query_membership_operation_categorized(
            &self.client,
            self.addr,
            self.access_token,
            &key.operation_id,
        )
        .await
        {
            Ok(MembershipOperationLookup::Found(record)) => RemoteEvidence::Found(*record),
            Ok(MembershipOperationLookup::NotFound) => RemoteEvidence::RecordNotFound,
            Err(error) => RemoteEvidence::Unavailable { category: error.category },
        }
    }

    async fn lookup_role_loss(
        &self,
        key: &RecoveryOperationKey,
    ) -> RemoteEvidence<RoleLossOperationRecord> {
        from_lookup(
            coordination_client::query_role_loss_operation(
                &self.client,
                self.addr,
                self.access_token,
                &key.operation_id,
            )
            .await,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    use yadorilink_replica_domain::recovery::RecoveryDomain;

    fn key(domain: RecoveryDomain, operation_id: &str) -> RecoveryOperationKey {
        RecoveryOperationKey { domain, operation_id: operation_id.to_string() }
    }

    /// A `RecoveryEvidenceSource` implementor, by construction, has no
    /// method that could mutate anything -- there is no "mutation call
    /// count" to even track for a fake built against this trait, since the
    /// trait itself has no such method to fake. This isn't asserted at
    /// runtime; it's a property of the trait's own shape, exercised here
    /// simply by implementing it with a fake that could not add a mutation
    /// method even if it wanted to influence a diagnosis result.
    struct FakeEvidenceSource;
    impl RecoveryEvidenceSource for FakeEvidenceSource {
        async fn lookup_enrollment(
            &self,
            _key: &RecoveryOperationKey,
        ) -> RemoteEvidence<EnrollmentOperationRecord> {
            RemoteEvidence::RecordNotFound
        }
        async fn lookup_membership(
            &self,
            _key: &RecoveryOperationKey,
        ) -> RemoteEvidence<MembershipOperationRecord> {
            RemoteEvidence::RecordNotFound
        }
        async fn lookup_role_loss(
            &self,
            _key: &RecoveryOperationKey,
        ) -> RemoteEvidence<RoleLossOperationRecord> {
            RemoteEvidence::RecordNotFound
        }
    }

    #[tokio::test]
    async fn fake_evidence_source_compiles_with_only_the_three_read_methods() {
        let fake = FakeEvidenceSource;
        assert!(matches!(
            fake.lookup_enrollment(&key(RecoveryDomain::Enrollment, "op-1")).await,
            RemoteEvidence::RecordNotFound
        ));
    }

    #[tokio::test]
    async fn enrollment_lookup_a_404_is_record_not_found() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/devices/enrollment-operations/op-1"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        let addr = server.uri();
        let source = WorkerEvidenceSource::new(&addr, "t");

        let evidence = source.lookup_enrollment(&key(RecoveryDomain::Enrollment, "op-1")).await;
        assert!(matches!(evidence, RemoteEvidence::RecordNotFound));
    }

    #[tokio::test]
    async fn enrollment_lookup_a_5xx_is_unavailable_server_error_never_absent() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/devices/enrollment-operations/op-1"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let addr = server.uri();
        let source = WorkerEvidenceSource::new(&addr, "t");

        let evidence = source.lookup_enrollment(&key(RecoveryDomain::Enrollment, "op-1")).await;
        assert!(matches!(
            evidence,
            RemoteEvidence::Unavailable { category: RemoteEvidenceErrorCategory::ServerError }
        ));
    }

    #[tokio::test]
    async fn enrollment_lookup_a_401_is_unavailable_unauthorized_never_absent() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/devices/enrollment-operations/op-1"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;
        let addr = server.uri();
        let source = WorkerEvidenceSource::new(&addr, "t");

        let evidence = source.lookup_enrollment(&key(RecoveryDomain::Enrollment, "op-1")).await;
        assert!(matches!(
            evidence,
            RemoteEvidence::Unavailable { category: RemoteEvidenceErrorCategory::Unauthorized }
        ));
    }

    #[tokio::test]
    async fn enrollment_lookup_a_403_is_also_unavailable_unauthorized() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/devices/enrollment-operations/op-1"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;
        let addr = server.uri();
        let source = WorkerEvidenceSource::new(&addr, "t");

        let evidence = source.lookup_enrollment(&key(RecoveryDomain::Enrollment, "op-1")).await;
        assert!(matches!(
            evidence,
            RemoteEvidence::Unavailable { category: RemoteEvidenceErrorCategory::Unauthorized }
        ));
    }

    #[tokio::test]
    async fn enrollment_lookup_a_malformed_2xx_body_is_unavailable_malformed_response() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/devices/enrollment-operations/op-1"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
            .mount(&server)
            .await;
        let addr = server.uri();
        let source = WorkerEvidenceSource::new(&addr, "t");

        let evidence = source.lookup_enrollment(&key(RecoveryDomain::Enrollment, "op-1")).await;
        assert!(matches!(
            evidence,
            RemoteEvidence::Unavailable {
                category: RemoteEvidenceErrorCategory::MalformedResponse
            }
        ));
    }

    /// A well-formed but unrecognized `status` (e.g. a newer Worker deploy
    /// this build predates) is `Unsupported`, NOT `MalformedResponse` --
    /// the JSON itself parses fine; only the semantic value is unknown.
    #[tokio::test]
    async fn enrollment_lookup_an_unknown_status_is_unavailable_unsupported_not_malformed() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/devices/enrollment-operations/op-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "operationId": "op-1",
                "kind": "create",
                "status": "from-the-future",
                "requestFingerprint": "fp-1",
                "request": { "userId": "user-1", "groupName": "photos", "deviceId": "device-a" },
                "result": null,
            })))
            .mount(&server)
            .await;
        let addr = server.uri();
        let source = WorkerEvidenceSource::new(&addr, "t");

        let evidence = source.lookup_enrollment(&key(RecoveryDomain::Enrollment, "op-1")).await;
        assert!(matches!(
            evidence,
            RemoteEvidence::Unavailable { category: RemoteEvidenceErrorCategory::Unsupported }
        ));
    }

    /// Same distinction for a well-formed but unrecognized role-loss
    /// `action`.
    #[tokio::test]
    async fn role_loss_lookup_an_unknown_action_is_unavailable_unsupported_not_malformed() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/devices/role-loss-operations/op-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "operationId": "op-1",
                "groupId": "group-1",
                "sourceDeviceId": "device-a",
                "targetDeviceId": "device-b",
                "leaseId": null,
                "action": "teleport",
                "membershipGeneration": 1,
                "committedAt": 1_700_000_000,
            })))
            .mount(&server)
            .await;
        let addr = server.uri();
        let source = WorkerEvidenceSource::new(&addr, "t");

        let evidence = source.lookup_role_loss(&key(RecoveryDomain::RoleLoss, "op-1")).await;
        assert!(matches!(
            evidence,
            RemoteEvidence::Unavailable { category: RemoteEvidenceErrorCategory::Unsupported }
        ));
    }

    #[tokio::test]
    async fn enrollment_lookup_a_network_error_is_unavailable_network_never_absent() {
        // No mock mounted, no server listening at this address at all --
        // the connection itself must fail, not merely 404.
        let source = WorkerEvidenceSource::new("http://127.0.0.1:1", "t");

        let evidence = source.lookup_enrollment(&key(RecoveryDomain::Enrollment, "op-1")).await;
        assert!(matches!(
            evidence,
            RemoteEvidence::Unavailable { category: RemoteEvidenceErrorCategory::Network }
        ));
    }

    #[tokio::test]
    async fn enrollment_lookup_a_timeout_is_unavailable_timeout_never_absent() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/devices/enrollment-operations/op-1"))
            .respond_with(
                ResponseTemplate::new(200).set_delay(std::time::Duration::from_secs(3600)),
            )
            .mount(&server)
            .await;
        // A short-timeout `WorkerEvidenceSource` stands in for `new()`'s own
        // 10s bound -- waiting the real 10s in a unit test is undesirable --
        // but this exercises the ACTUAL `lookup_enrollment` call end to end,
        // not just `categorize_transport_error` in isolation against a
        // hand-built `reqwest::Error`.
        let addr = server.uri();
        let source =
            WorkerEvidenceSource::with_timeout(&addr, "t", std::time::Duration::from_millis(50));

        let evidence = source.lookup_enrollment(&key(RecoveryDomain::Enrollment, "op-1")).await;
        assert!(matches!(
            evidence,
            RemoteEvidence::Unavailable { category: RemoteEvidenceErrorCategory::Timeout }
        ));
    }

    #[tokio::test]
    async fn enrollment_lookup_a_valid_create_record_is_found() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/devices/enrollment-operations/op-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "operationId": "op-1",
                "kind": "create",
                "status": "active",
                "requestFingerprint": "fp-1",
                "request": { "userId": "user-1", "groupName": "photos", "deviceId": "device-a" },
                "result": { "groupId": "group-1", "state": "active" },
            })))
            .mount(&server)
            .await;
        let addr = server.uri();
        let source = WorkerEvidenceSource::new(&addr, "t");

        let evidence = source.lookup_enrollment(&key(RecoveryDomain::Enrollment, "op-1")).await;
        let RemoteEvidence::Found(record) = evidence else {
            panic!("expected Found, got {evidence:?}");
        };
        assert_eq!(record.status, coordination_client::EnrollmentRemoteStatus::Active);
        assert_eq!(record.request_fingerprint, "fp-1");
        assert_eq!(
            record.request,
            coordination_client::EnrollmentRemoteRequest::Create {
                group_name: "photos".to_string(),
                device_id: "device-a".to_string(),
                storage_mode: "eager".to_string(),
            }
        );
        assert_eq!(record.result_group_id.as_deref(), Some("group-1"));
    }

    #[tokio::test]
    async fn enrollment_lookup_a_valid_join_record_reads_the_real_storage_mode() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/devices/enrollment-operations/op-2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "operationId": "op-2",
                "kind": "join",
                "status": "prepared",
                "requestFingerprint": "fp-2",
                "request": {
                    "userId": "user-1",
                    "groupId": "group-1",
                    "deviceId": "device-b",
                    "storageMode": "on-demand",
                },
                "result": null,
            })))
            .mount(&server)
            .await;
        let addr = server.uri();
        let source = WorkerEvidenceSource::new(&addr, "t");

        let evidence = source.lookup_enrollment(&key(RecoveryDomain::Enrollment, "op-2")).await;
        let RemoteEvidence::Found(record) = evidence else {
            panic!("expected Found, got {evidence:?}");
        };
        assert_eq!(record.status, coordination_client::EnrollmentRemoteStatus::Prepared);
        assert_eq!(
            record.request,
            coordination_client::EnrollmentRemoteRequest::Join {
                group_id: "group-1".to_string(),
                device_id: "device-b".to_string(),
                storage_mode: "on-demand".to_string(),
            }
        );
        assert_eq!(record.result_group_id, None);
    }

    #[tokio::test]
    async fn membership_lookup_a_404_is_record_not_found() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/devices/membership-operations/op-1"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        let addr = server.uri();
        let source = WorkerEvidenceSource::new(&addr, "t");

        let evidence = source.lookup_membership(&key(RecoveryDomain::Membership, "op-1")).await;
        assert!(matches!(evidence, RemoteEvidence::RecordNotFound));
    }

    #[tokio::test]
    async fn membership_lookup_a_5xx_is_unavailable_never_absent() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/devices/membership-operations/op-1"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;
        let addr = server.uri();
        let source = WorkerEvidenceSource::new(&addr, "t");

        let evidence = source.lookup_membership(&key(RecoveryDomain::Membership, "op-1")).await;
        assert!(matches!(
            evidence,
            RemoteEvidence::Unavailable { category: RemoteEvidenceErrorCategory::ServerError }
        ));
    }

    #[tokio::test]
    async fn membership_lookup_a_committed_revoke_is_found_with_its_full_request() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/devices/membership-operations/op-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "operationId": "op-1",
                "status": "committed",
                "action": "revoke",
                "removedDeviceId": "device-a",
                "requestFingerprint": "fp-1",
                "request": {
                    "userId": "user-1",
                    "action": "revoke",
                    "removedDeviceId": "device-a",
                    "mode": "guarded",
                    "groups": [{ "groupId": "group-1", "targetDeviceId": "device-b", "leaseId": "lease-1" }],
                },
                "result": { "targetDeviceId": "device-b", "membershipGeneration": 3, "leaseId": "lease-1" },
                "rejectionCode": null,
                "rejectionDetail": null,
            })))
            .mount(&server)
            .await;
        let addr = server.uri();
        let source = WorkerEvidenceSource::new(&addr, "t");

        let evidence = source.lookup_membership(&key(RecoveryDomain::Membership, "op-1")).await;
        let RemoteEvidence::Found(record) = evidence else {
            panic!("expected Found, got {evidence:?}");
        };
        assert_eq!(record.status, coordination_client::MembershipRemoteStatus::Committed);
        assert_eq!(record.request.groups.len(), 1);
        assert_eq!(record.request.groups[0].group_id, "group-1");
    }

    #[tokio::test]
    async fn role_loss_lookup_a_404_is_record_not_found() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/devices/role-loss-operations/op-1"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        let addr = server.uri();
        let source = WorkerEvidenceSource::new(&addr, "t");

        let evidence = source.lookup_role_loss(&key(RecoveryDomain::RoleLoss, "op-1")).await;
        assert!(matches!(evidence, RemoteEvidence::RecordNotFound));
    }

    #[tokio::test]
    async fn role_loss_lookup_a_5xx_is_unavailable_never_absent() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/devices/role-loss-operations/op-1"))
            .respond_with(ResponseTemplate::new(502))
            .mount(&server)
            .await;
        let addr = server.uri();
        let source = WorkerEvidenceSource::new(&addr, "t");

        let evidence = source.lookup_role_loss(&key(RecoveryDomain::RoleLoss, "op-1")).await;
        assert!(matches!(
            evidence,
            RemoteEvidence::Unavailable { category: RemoteEvidenceErrorCategory::ServerError }
        ));
    }

    #[tokio::test]
    async fn role_loss_lookup_a_valid_receipt_is_found() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/devices/role-loss-operations/op-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "operationId": "op-1",
                "groupId": "group-1",
                "sourceDeviceId": "device-a",
                "targetDeviceId": "device-b",
                "leaseId": "lease-1",
                "action": "demote",
                "membershipGeneration": 4,
                "committedAt": 1_700_000_000,
            })))
            .mount(&server)
            .await;
        let addr = server.uri();
        let source = WorkerEvidenceSource::new(&addr, "t");

        let evidence = source.lookup_role_loss(&key(RecoveryDomain::RoleLoss, "op-1")).await;
        let RemoteEvidence::Found(record) = evidence else {
            panic!("expected Found, got {evidence:?}");
        };
        assert_eq!(record.group_id, "group-1");
        assert_eq!(record.source_device_id, "device-a");
        assert_eq!(record.target_device_id, "device-b");
        assert_eq!(record.lease_id.as_deref(), Some("lease-1"));
        assert_eq!(record.action, "demote");
        assert_eq!(record.membership_generation, 4);
        assert_eq!(record.committed_at_unix, 1_700_000_000);
    }

    /// A response body naming a different operation id than the one
    /// requested breaks the endpoint's own contract -- this is
    /// `MalformedResponse`, not a local-vs-remote identity question C2's
    /// diagnosis engine handles.
    #[tokio::test]
    async fn enrollment_lookup_operation_id_mismatch_is_malformed_response() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/devices/enrollment-operations/op-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "operationId": "op-other",
                "kind": "create",
                "status": "active",
                "requestFingerprint": "fp-1",
                "request": { "userId": "user-1", "groupName": "photos", "deviceId": "device-a" },
                "result": { "groupId": "group-1", "state": "active" },
            })))
            .mount(&server)
            .await;
        let addr = server.uri();
        let source = WorkerEvidenceSource::new(&addr, "t");

        let evidence = source.lookup_enrollment(&key(RecoveryDomain::Enrollment, "op-1")).await;
        assert!(matches!(
            evidence,
            RemoteEvidence::Unavailable {
                category: RemoteEvidenceErrorCategory::MalformedResponse
            }
        ));
    }

    #[tokio::test]
    async fn membership_lookup_operation_id_mismatch_is_malformed_response() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/devices/membership-operations/op-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "operationId": "op-other",
                "status": "committed",
                "action": "revoke",
                "removedDeviceId": "device-a",
                "requestFingerprint": "fp-1",
                "request": {
                    "userId": "user-1",
                    "action": "revoke",
                    "removedDeviceId": "device-a",
                    "mode": "guarded",
                    "groups": [{ "groupId": "group-1", "targetDeviceId": "device-b", "leaseId": "lease-1" }],
                },
                "result": { "targetDeviceId": "device-b", "membershipGeneration": 3, "leaseId": "lease-1" },
                "rejectionCode": null,
                "rejectionDetail": null,
            })))
            .mount(&server)
            .await;
        let addr = server.uri();
        let source = WorkerEvidenceSource::new(&addr, "t");

        let evidence = source.lookup_membership(&key(RecoveryDomain::Membership, "op-1")).await;
        assert!(matches!(
            evidence,
            RemoteEvidence::Unavailable {
                category: RemoteEvidenceErrorCategory::MalformedResponse
            }
        ));
    }

    #[tokio::test]
    async fn role_loss_lookup_operation_id_mismatch_is_malformed_response() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/devices/role-loss-operations/op-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "operationId": "op-other",
                "groupId": "group-1",
                "sourceDeviceId": "device-a",
                "targetDeviceId": "device-b",
                "leaseId": "lease-1",
                "action": "demote",
                "membershipGeneration": 4,
                "committedAt": 1_700_000_000,
            })))
            .mount(&server)
            .await;
        let addr = server.uri();
        let source = WorkerEvidenceSource::new(&addr, "t");

        let evidence = source.lookup_role_loss(&key(RecoveryDomain::RoleLoss, "op-1")).await;
        assert!(matches!(
            evidence,
            RemoteEvidence::Unavailable {
                category: RemoteEvidenceErrorCategory::MalformedResponse
            }
        ));
    }

    /// A receipt whose `membershipGeneration` is NULL is a shape this build
    /// does not recognize -- generation 8's column is `NOT NULL`, so a NULL
    /// value here can only mean a pre-generation-8 row or a malformed
    /// deploy, never a legitimately absent generation. Must never be
    /// silently treated as generation 0.
    #[tokio::test]
    async fn role_loss_lookup_a_null_generation_is_unsupported_never_a_fabricated_zero() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/devices/role-loss-operations/op-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "operationId": "op-1",
                "groupId": "group-1",
                "sourceDeviceId": "device-a",
                "targetDeviceId": "device-b",
                "leaseId": null,
                "action": "demote",
                "membershipGeneration": null,
                "committedAt": 1_700_000_000,
            })))
            .mount(&server)
            .await;
        let addr = server.uri();
        let source = WorkerEvidenceSource::new(&addr, "t");

        let evidence = source.lookup_role_loss(&key(RecoveryDomain::RoleLoss, "op-1")).await;
        assert!(matches!(
            evidence,
            RemoteEvidence::Unavailable { category: RemoteEvidenceErrorCategory::Unsupported }
        ));
    }

    /// A `join` response naming a storage mode outside the known wire set
    /// (`"eager"`/`"on-demand"`) is `Unsupported`, not a shape violation.
    #[tokio::test]
    async fn enrollment_lookup_an_unknown_join_storage_mode_is_unsupported() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/devices/enrollment-operations/op-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "operationId": "op-1",
                "kind": "join",
                "status": "prepared",
                "requestFingerprint": "fp-1",
                "request": {
                    "userId": "user-1",
                    "groupId": "group-1",
                    "deviceId": "device-b",
                    "storageMode": "quantum",
                },
                "result": null,
            })))
            .mount(&server)
            .await;
        let addr = server.uri();
        let source = WorkerEvidenceSource::new(&addr, "t");

        let evidence = source.lookup_enrollment(&key(RecoveryDomain::Enrollment, "op-1")).await;
        assert!(matches!(
            evidence,
            RemoteEvidence::Unavailable { category: RemoteEvidenceErrorCategory::Unsupported }
        ));
    }

    /// An unrecognized `mode` value is `Unsupported`, checked independently
    /// of `action`.
    #[tokio::test]
    async fn membership_lookup_an_unknown_mode_is_unsupported() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/devices/membership-operations/op-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "operationId": "op-1",
                "status": "committed",
                "action": "revoke",
                "removedDeviceId": "device-a",
                "requestFingerprint": "fp-1",
                "request": {
                    "userId": "user-1",
                    "action": "revoke",
                    "removedDeviceId": "device-a",
                    "mode": "telepathic",
                    "groups": [{ "groupId": "group-1", "targetDeviceId": "device-b", "leaseId": "lease-1" }],
                },
                "result": { "targetDeviceId": "device-b", "membershipGeneration": 3, "leaseId": "lease-1" },
                "rejectionCode": null,
                "rejectionDetail": null,
            })))
            .mount(&server)
            .await;
        let addr = server.uri();
        let source = WorkerEvidenceSource::new(&addr, "t");

        let evidence = source.lookup_membership(&key(RecoveryDomain::Membership, "op-1")).await;
        assert!(matches!(
            evidence,
            RemoteEvidence::Unavailable { category: RemoteEvidenceErrorCategory::Unsupported }
        ));
    }

    /// The top-level `action` and `request.action` are independently
    /// decoded fields naming the same request -- disagreement between them
    /// is the response contradicting itself, `MalformedResponse`, not an
    /// unrecognized value.
    #[tokio::test]
    async fn membership_lookup_action_mismatch_between_top_level_and_request_is_malformed_response()
    {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/devices/membership-operations/op-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "operationId": "op-1",
                "status": "committed",
                "action": "revoke",
                "removedDeviceId": "device-a",
                "requestFingerprint": "fp-1",
                "request": {
                    "userId": "user-1",
                    "action": "remove-device",
                    "removedDeviceId": "device-a",
                    "mode": "guarded",
                    "groups": [{ "groupId": "group-1", "targetDeviceId": "device-b", "leaseId": "lease-1" }],
                },
                "result": { "targetDeviceId": "device-b", "membershipGeneration": 3, "leaseId": "lease-1" },
                "rejectionCode": null,
                "rejectionDetail": null,
            })))
            .mount(&server)
            .await;
        let addr = server.uri();
        let source = WorkerEvidenceSource::new(&addr, "t");

        let evidence = source.lookup_membership(&key(RecoveryDomain::Membership, "op-1")).await;
        assert!(matches!(
            evidence,
            RemoteEvidence::Unavailable {
                category: RemoteEvidenceErrorCategory::MalformedResponse
            }
        ));
    }

    #[tokio::test]
    async fn membership_lookup_removed_device_mismatch_between_top_level_and_request_is_malformed_response(
    ) {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/devices/membership-operations/op-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "operationId": "op-1",
                "status": "committed",
                "action": "revoke",
                "removedDeviceId": "device-a",
                "requestFingerprint": "fp-1",
                "request": {
                    "userId": "user-1",
                    "action": "revoke",
                    "removedDeviceId": "device-z",
                    "mode": "guarded",
                    "groups": [{ "groupId": "group-1", "targetDeviceId": "device-b", "leaseId": "lease-1" }],
                },
                "result": { "targetDeviceId": "device-b", "membershipGeneration": 3, "leaseId": "lease-1" },
                "rejectionCode": null,
                "rejectionDetail": null,
            })))
            .mount(&server)
            .await;
        let addr = server.uri();
        let source = WorkerEvidenceSource::new(&addr, "t");

        let evidence = source.lookup_membership(&key(RecoveryDomain::Membership, "op-1")).await;
        assert!(matches!(
            evidence,
            RemoteEvidence::Unavailable {
                category: RemoteEvidenceErrorCategory::MalformedResponse
            }
        ));
    }
}
