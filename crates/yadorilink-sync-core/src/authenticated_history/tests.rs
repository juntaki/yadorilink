use std::collections::{BTreeMap, HashMap};

use ed25519_dalek::SigningKey;

use super::*;
use crate::change::{DeviceId, FolderGroupId, Op, SyncPath};

#[derive(Default)]
struct FakeSource {
    heads: Vec<ChangeHash>,
    changes: BTreeMap<ChangeHash, Change>,
    compacted_parent_auth: HashMap<(ChangeHash, ChangeHash), (u64, u64)>,
}

impl AuthenticatedHistorySource for FakeSource {
    fn retained_heads(&self, _group_id: &str) -> Result<Vec<ChangeHash>, SyncError> {
        Ok(self.heads.clone())
    }

    fn retained_change(&self, hash: &ChangeHash) -> Result<Option<Change>, SyncError> {
        Ok(self.changes.get(hash).cloned())
    }

    fn compacted_parent_auth(
        &self,
        _group_id: &str,
        child_hash: &ChangeHash,
        parent_hash: &ChangeHash,
    ) -> Result<Option<(u64, u64)>, SyncError> {
        Ok(self.compacted_parent_auth.get(&(*child_hash, *parent_hash)).copied())
    }
}

#[derive(Default)]
struct FakeTrust {
    keys: HashMap<String, [u8; 32]>,
    authorized: bool,
}

impl AuthenticatedHistoryTrust for FakeTrust {
    fn signing_key(&self, device_id: &str) -> Option<[u8; 32]> {
        self.keys.get(device_id).copied()
    }

    fn accepts_change_auth(
        &self,
        _device_id: &str,
        _group_id: &str,
        _signing_key_fingerprint: [u8; 32],
        _auth: ChangeAuth,
    ) -> bool {
        self.authorized
    }
}

fn signed_chain() -> (FakeSource, FakeTrust, ChangeHash, ChangeHash) {
    signed_chain_with_auth(ChangeAuth::PLACEHOLDER, ChangeAuth::PLACEHOLDER)
}

fn signed_chain_with_auth(
    root_auth: ChangeAuth,
    child_auth: ChangeAuth,
) -> (FakeSource, FakeTrust, ChangeHash, ChangeHash) {
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let root = Change::create_signed(
        vec![],
        0,
        root_auth,
        DeviceId("device-a".into()),
        FolderGroupId("g".into()),
        vec![Op::Delete { path: SyncPath("a.txt".into()) }],
        &key,
    );
    let root_hash = root.compute_hash();
    let child = Change::create_signed(
        vec![root_hash],
        root.lamport,
        child_auth,
        DeviceId("device-a".into()),
        FolderGroupId("g".into()),
        vec![Op::Delete { path: SyncPath("b.txt".into()) }],
        &key,
    );
    let child_hash = child.compute_hash();

    let mut source = FakeSource::default();
    source.heads = vec![child_hash];
    source.changes.insert(root_hash, root);
    source.changes.insert(child_hash, child);

    let mut trust = FakeTrust { authorized: true, ..Default::default() };
    trust.keys.insert("device-a".into(), key.verifying_key().to_bytes());
    (source, trust, root_hash, child_hash)
}

#[test]
fn validates_every_reachable_retained_change_once() {
    let (source, trust, _, _) = signed_chain();
    let report = validate_retained_group(&source, "g", &trust).unwrap();
    assert_eq!(report.verified_changes, 2);
}

#[test]
fn signature_only_corruption_is_detected_even_when_change_hash_is_unchanged() {
    let (mut source, trust, root_hash, _) = signed_chain();
    let root = source.changes.get_mut(&root_hash).unwrap();
    let original_hash = root.compute_hash();
    root.signature[0] ^= 0x80;
    assert_eq!(
        root.compute_hash(),
        original_hash,
        "signature is outside the hashed canonical body"
    );

    let error = validate_retained_group(&source, "g", &trust).unwrap_err();
    assert!(matches!(error, AuthenticatedHistoryError::InvalidHistory(_)));
}

#[test]
fn unavailable_author_key_defers_instead_of_misclassifying_history_as_corrupt() {
    let (source, mut trust, _, _) = signed_chain();
    trust.keys.clear();

    let error = validate_retained_group(&source, "g", &trust).unwrap_err();
    assert!(matches!(error, AuthenticatedHistoryError::TrustUnavailable { .. }));
}

#[test]
fn historical_authorization_rejection_is_a_hard_history_failure() {
    let (source, mut trust, _, _) = signed_chain();
    trust.authorized = false;

    let error = validate_retained_group(&source, "g", &trust).unwrap_err();
    assert!(matches!(error, AuthenticatedHistoryError::InvalidHistory(_)));
}

#[test]
fn retained_child_cannot_regress_auth_sequence_below_parent() {
    let root_auth = ChangeAuth { auth_seq: 10, auth_epoch: 3, policy_head_hash: [1u8; 32] };
    let child_auth = ChangeAuth { auth_seq: 9, auth_epoch: 3, policy_head_hash: [2u8; 32] };
    let (source, trust, _, _) = signed_chain_with_auth(root_auth, child_auth);

    let error = validate_retained_group(&source, "g", &trust).unwrap_err();
    assert!(matches!(error, AuthenticatedHistoryError::InvalidHistory(_)));
}

#[test]
fn retained_child_cannot_regress_auth_epoch_below_parent() {
    let root_auth = ChangeAuth { auth_seq: 10, auth_epoch: 4, policy_head_hash: [1u8; 32] };
    let child_auth = ChangeAuth { auth_seq: 10, auth_epoch: 3, policy_head_hash: [2u8; 32] };
    let (source, trust, _, _) = signed_chain_with_auth(root_auth, child_auth);

    let error = validate_retained_group(&source, "g", &trust).unwrap_err();
    assert!(matches!(error, AuthenticatedHistoryError::InvalidHistory(_)));
}

fn signed_child_with_missing_parent(
    auth: ChangeAuth,
    missing_parent: ChangeHash,
) -> (FakeSource, FakeTrust, ChangeHash) {
    let key = SigningKey::from_bytes(&[9u8; 32]);
    let child = Change::create_signed(
        vec![missing_parent],
        5,
        auth,
        DeviceId("device-a".into()),
        FolderGroupId("g".into()),
        vec![Op::Delete { path: SyncPath("c.txt".into()) }],
        &key,
    );
    let child_hash = child.compute_hash();
    let mut source = FakeSource::default();
    source.heads = vec![child_hash];
    source.changes.insert(child_hash, child);

    let mut trust = FakeTrust { authorized: true, ..Default::default() };
    trust.keys.insert("device-a".into(), key.verifying_key().to_bytes());
    (source, trust, child_hash)
}

/// A missing parent with no `compacted_parent_auth` proof is arbitrary
/// history loss, not a legitimate compaction boundary, and must fail closed
/// rather than being silently skipped.
#[test]
fn missing_parent_without_compacted_auth_proof_fails_closed() {
    let missing_parent = ChangeHash([0xAA; 32]);
    let auth = ChangeAuth { auth_seq: 5, auth_epoch: 2, policy_head_hash: [3u8; 32] };
    let (source, trust, _) = signed_child_with_missing_parent(auth, missing_parent);

    let error = validate_retained_group(&source, "g", &trust).unwrap_err();
    assert!(matches!(error, AuthenticatedHistoryError::InvalidHistory(_)));
}

/// A missing parent proven by `compacted_parent_auth` to be a legitimate
/// checkpoint-boundary parent is accepted, and the traversal does not try to
/// walk into it (there is nothing there to walk into).
#[test]
fn missing_parent_with_compacted_auth_proof_is_accepted() {
    let missing_parent = ChangeHash([0xAA; 32]);
    let auth = ChangeAuth { auth_seq: 5, auth_epoch: 2, policy_head_hash: [3u8; 32] };
    let (mut source, trust, child_hash) = signed_child_with_missing_parent(auth, missing_parent);
    source.compacted_parent_auth.insert((child_hash, missing_parent), (3, 1));

    let report = validate_retained_group(&source, "g", &trust).unwrap();
    assert_eq!(report.verified_changes, 1);
}

/// A `compacted_parent_auth` proof still must satisfy the same
/// auth-coordinate monotonicity rule a live parent body would enforce — the
/// boundary proof does not exempt the child from it.
#[test]
fn missing_parent_compacted_auth_proof_still_enforces_monotonicity() {
    let missing_parent = ChangeHash([0xAA; 32]);
    let auth = ChangeAuth { auth_seq: 2, auth_epoch: 1, policy_head_hash: [3u8; 32] };
    let (mut source, trust, child_hash) = signed_child_with_missing_parent(auth, missing_parent);
    // The compacted parent was authorized at a *higher* coordinate than the
    // child claims — a regression the child must not be allowed to commit.
    source.compacted_parent_auth.insert((child_hash, missing_parent), (10, 5));

    let error = validate_retained_group(&source, "g", &trust).unwrap_err();
    assert!(matches!(error, AuthenticatedHistoryError::InvalidHistory(_)));
}
