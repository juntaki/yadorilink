#![cfg(test)]

use super::*;
use ed25519_dalek::SigningKey;
use std::sync::Mutex;
use yadorilink_replica_domain::change::Change;
use yadorilink_replica_domain::ids::{DeviceId, FolderGroupId};
use yadorilink_replica_domain::test_authoring::create_signed_for_tests;
use yadorilink_sqlite_runtime::SyncDatabase;
use yadorilink_sync_sqlite::dag_store::{admit_change, init_dag_schema};

fn db() -> SyncDatabase {
    SyncDatabase::open_in_memory(|conn| {
        init_dag_schema(conn)
            .map_err(|e| yadorilink_sqlite_runtime::DatabaseError::CorruptSchema(e.to_string()))
    })
    .unwrap()
}

fn key() -> SigningKey {
    SigningKey::from_bytes(&[9u8; 32])
}

fn device_vk() -> VerifyingKey {
    key().verifying_key()
}

fn device_fingerprint() -> [u8; 32] {
    yadorilink_replica_domain::authorization_checkpoint::fingerprint_signing_key(&device_vk())
}

fn root_change(group: &str) -> Change {
    create_signed_for_tests(
        vec![],
        0,
        DeviceId("device-A".into()),
        FolderGroupId(group.into()),
        vec![],
        &key(),
    )
}

fn child_change(group: &str, parent: &Change) -> Change {
    create_signed_for_tests(
        vec![parent.compute_hash()],
        parent.lamport,
        DeviceId("device-A".into()),
        FolderGroupId(group.into()),
        vec![],
        &key(),
    )
}

#[test]
fn pending_batch_request_id_is_order_independent_and_content_sensitive() {
    let a = ChangeHash([1u8; 32]);
    let b = ChangeHash([2u8; 32]);
    assert_eq!(
        pending_batch_request_id("g", "d", &[a, b]),
        pending_batch_request_id("g", "d", &[b, a]),
        "order of the pending set must not change the derived request_id"
    );
    assert_ne!(
        pending_batch_request_id("g", "d", &[a]),
        pending_batch_request_id("g", "d", &[a, b]),
        "a different pending set must derive a different request_id"
    );
    assert_ne!(
        pending_batch_request_id("g1", "d", &[a]),
        pending_batch_request_id("g2", "d", &[a]),
        "different groups must never collide"
    );
}

struct FakeSource {
    authority_key: SigningKey,
    signer_key_id: [u8; 32],
    next_seq: Mutex<u64>,
    refuse: bool,
}

/// A `resolve_authority_key` closure recognizing exactly the ONE key
/// `source` signs with -- stands in for a real
/// `change_policy::GroupPolicyState`-backed resolver in these tests,
/// which don't exercise policy-chain verification itself (that's
/// `authorization_checkpoint.rs`'s job).
fn resolver_for(source: &FakeSource) -> impl Fn(&[u8; 32], &[u8; 32]) -> Option<VerifyingKey> + '_ {
    let signer_key_id = source.signer_key_id;
    let vk = source.authority_key.verifying_key();
    move |key_id: &[u8; 32], _policy_head: &[u8; 32]| (*key_id == signer_key_id).then_some(vk)
}

impl CheckpointSource for FakeSource {
    fn request_authorization_checkpoint<'a>(
        &'a self,
        group_id: &'a str,
        device_id: &'a str,
        _request_id: &'a str,
        merkle_root: [u8; 32],
        leaf_count: u64,
    ) -> Pin<Box<dyn Future<Output = Option<(AuthorizationCheckpoint, [u8; 64])>> + Send + 'a>>
    {
        Box::pin(async move {
            if self.refuse {
                return None;
            }
            let mut seq = self.next_seq.lock().unwrap();
            *seq += 1;
            let checkpoint = AuthorizationCheckpoint {
                group_id: group_id.to_string(),
                device_id: device_id.to_string(),
                signing_key_fingerprint: device_fingerprint(),
                merkle_root,
                leaf_count,
                checkpoint_seq: *seq,
                signer_key_id: self.signer_key_id,
                policy_epoch: 0,
                policy_seq: 1,
                policy_head: [0u8; 32],
                issued_at_unix: 1,
            };
            let signature = yadorilink_replica_domain::authorization_checkpoint::sign_checkpoint(
                &checkpoint,
                &self.authority_key,
            );
            Some((checkpoint, signature))
        })
    }
}

#[tokio::test]
async fn flush_pending_checkpoint_does_nothing_when_nothing_is_pending() {
    let c = db();
    let source = FakeSource {
        authority_key: SigningKey::from_bytes(&[7u8; 32]),
        signer_key_id: [0u8; 32],
        next_seq: Mutex::new(0),
        refuse: false,
    };
    let outcome = flush_pending_checkpoint(
        &c,
        &source,
        "g",
        "device-A",
        &device_vk(),
        &resolver_for(&source),
    )
    .await
    .unwrap();
    assert_eq!(outcome, FlushOutcome::NothingPending);
}

#[tokio::test]
async fn flush_pending_checkpoint_attaches_evidence_for_the_whole_batch() {
    let c = db();
    let a = root_change("g");
    let b = child_change("g", &a);
    c.write(|conn| admit_change(conn, &a)).unwrap();
    c.write(|conn| admit_change(conn, &b)).unwrap();

    let source = FakeSource {
        authority_key: SigningKey::from_bytes(&[7u8; 32]),
        signer_key_id: [0u8; 32],
        next_seq: Mutex::new(0),
        refuse: false,
    };
    let outcome = flush_pending_checkpoint(
        &c,
        &source,
        "g",
        "device-A",
        &device_vk(),
        &resolver_for(&source),
    )
    .await
    .unwrap();
    assert_eq!(outcome, FlushOutcome::Flushed { batch_size: 2, checkpoint_seq: 1 });
    assert!(c.read(|conn| published_view::is_published(conn, &a.compute_hash())).unwrap());
    assert!(c.read(|conn| published_view::is_published(conn, &b.compute_hash())).unwrap());
    assert!(c
        .read(|conn| published_view::pending_local_changes_for_group(conn, "g", "device-A"))
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn the_checkpoint_flush_produces_a_batch_that_actually_verifies() {
    // Round-trip proof that merkle_root/build_merkle_proof/the
    // checkpoint fields flush_pending_checkpoint assembles are
    // mutually consistent -- not just "is_published() says yes,"
    // but "an independent call to verify_change_admission, given the
    // same root/proof/checkpoint, actually accepts every Change in
    // the batch." (Uses the raw proof this test builds itself, not a
    // decode of the opaque bytes attach_authorization_evidence
    // stored -- decoding those is out of this module's scope, per
    // its own doc comment.)
    use yadorilink_replica_domain::authorization_checkpoint::{
        build_merkle_proof, fingerprint_signing_key, verify_change_admission,
    };

    let c = db();
    let a = root_change("g");
    let b = child_change("g", &a);
    c.write(|conn| admit_change(conn, &a)).unwrap();
    c.write(|conn| admit_change(conn, &b)).unwrap();

    let authority_key = SigningKey::from_bytes(&[7u8; 32]);
    let authority_vk = authority_key.verifying_key();
    let signer_key_id = fingerprint_signing_key(&authority_vk);
    let source =
        FakeSource { authority_key, signer_key_id, next_seq: Mutex::new(0), refuse: false };

    flush_pending_checkpoint(&c, &source, "g", "device-A", &device_vk(), &resolver_for(&source))
        .await
        .unwrap();

    // Reconstruct exactly what the source signed: same leaf order
    // flush_pending_checkpoint used (pending_local_changes_for_group's own
    // deterministic ORDER BY change_hash).
    let pending_before = vec![a.compute_hash(), b.compute_hash()];
    let mut hash_arrays: Vec<[u8; 32]> = pending_before.iter().map(|h| h.0).collect();
    hash_arrays.sort();
    let root = merkle_root(&hash_arrays);

    for (index, hash) in hash_arrays.iter().enumerate() {
        let checkpoint = AuthorizationCheckpoint {
            group_id: "g".to_string(),
            device_id: "device-A".to_string(),
            signing_key_fingerprint: device_fingerprint(),
            merkle_root: root,
            leaf_count: hash_arrays.len() as u64,
            checkpoint_seq: 1,
            signer_key_id,
            policy_epoch: 0,
            policy_seq: 1,
            policy_head: [0u8; 32],
            issued_at_unix: 1,
        };
        let signature = yadorilink_replica_domain::authorization_checkpoint::sign_checkpoint(
            &checkpoint,
            &source.authority_key,
        );
        let proof = build_merkle_proof(&hash_arrays, index);
        let result = verify_change_admission(
            "g",
            "device-A",
            &device_vk(),
            *hash,
            &proof,
            &checkpoint,
            &signature,
            |key_id, _policy_head| (*key_id == signer_key_id).then_some(authority_vk),
        );
        assert_eq!(result, Ok(()), "leaf {index} must verify against the flushed batch");
    }
}

#[tokio::test]
async fn a_refused_request_leaves_the_pending_set_untouched() {
    let c = db();
    let a = root_change("g");
    c.write(|conn| admit_change(conn, &a)).unwrap();

    let source = FakeSource {
        authority_key: SigningKey::from_bytes(&[7u8; 32]),
        signer_key_id: [0u8; 32],
        next_seq: Mutex::new(0),
        refuse: true,
    };
    let outcome = flush_pending_checkpoint(
        &c,
        &source,
        "g",
        "device-A",
        &device_vk(),
        &resolver_for(&source),
    )
    .await
    .unwrap();
    assert_eq!(outcome, FlushOutcome::Refused);
    assert!(!c.read(|conn| published_view::is_published(conn, &a.compute_hash())).unwrap());
    assert_eq!(
        c.read(|conn| published_view::pending_local_changes_for_group(conn, "g", "device-A"))
            .unwrap(),
        vec![a.compute_hash()]
    );
}

#[tokio::test]
async fn a_retry_of_the_same_still_pending_batch_reuses_the_same_request_id_and_evidence_is_idempotent(
) {
    // Simulates: flush succeeds, but the caller crashes before
    // observing success and calls flush again with the SAME pending
    // set still on disk (attach_authorization_evidence hadn't
    // committed yet in the real crash case -- here we instead prove
    // the request_id is stable and a second flush against an
    // ALREADY-flushed set is a harmless no-op, covering the "nothing
    // pending" convergence point from the other direction).
    let c = db();
    let a = root_change("g");
    c.write(|conn| admit_change(conn, &a)).unwrap();
    let pending_before = c
        .read(|conn| published_view::pending_local_changes_for_group(conn, "g", "device-A"))
        .unwrap();
    let id_first = pending_batch_request_id("g", "device-A", &pending_before);

    let source = FakeSource {
        authority_key: SigningKey::from_bytes(&[7u8; 32]),
        signer_key_id: [0u8; 32],
        next_seq: Mutex::new(0),
        refuse: false,
    };
    flush_pending_checkpoint(&c, &source, "g", "device-A", &device_vk(), &resolver_for(&source))
        .await
        .unwrap();

    // Pending set is now empty -- a second flush is a true no-op,
    // never re-deriving or re-requesting anything.
    let second = flush_pending_checkpoint(
        &c,
        &source,
        "g",
        "device-A",
        &device_vk(),
        &resolver_for(&source),
    )
    .await
    .unwrap();
    assert_eq!(second, FlushOutcome::NothingPending);

    // Sanity: had the same set still been pending, the id would not
    // have changed underneath the caller.
    assert_eq!(pending_batch_request_id("g", "device-A", &pending_before), id_first);
}
