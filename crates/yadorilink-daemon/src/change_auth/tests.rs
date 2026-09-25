#![cfg(test)]

use std::sync::Arc;

use crate::replica_coordinator::ReplicaCoordinator;
use ed25519_dalek::SigningKey;
use yadorilink_local_storage::SegmentBlockStore;

use super::*;

fn test_state() -> Arc<DaemonState> {
    let store = Arc::new(SegmentBlockStore::new(tempfile::tempdir().unwrap().keep()).unwrap());
    let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    DaemonState::new("device-a".into(), sync_state, store)
}

#[tokio::test]
async fn resolve_authority_key_fails_closed_for_a_group_with_no_verified_policy() {
    let state = test_state();
    let authenticator = NetmapChangeAuthenticator::new(state);

    assert!(
        authenticator
            .resolve_authority_key("policy-invalid-group", &[0u8; 32], &[0u8; 32])
            .is_none(),
        "a group with no verified policy loaded must fail closed"
    );
}

#[tokio::test]
async fn signing_key_resolver_includes_this_devices_own_signing_identity() {
    let state = test_state();
    let key = SigningKey::from_bytes(&[9u8; 32]);
    state.set_device_signing_key(key.clone());
    let authenticator = NetmapChangeAuthenticator::new(state);

    assert_eq!(authenticator.signing_key("device-a"), Some(key.verifying_key().to_bytes()));
}

/// A cached `false` must be honored without re-resolving group policy --
/// a fresh (uncached) resolution of this never-touched bootstrap group
/// would say it is fine, so an empty result here can only come from the
/// cache actually being consulted.
#[tokio::test]
async fn effective_servable_groups_short_circuits_on_a_cached_result() {
    let state = test_state();
    let raw_groups: HashSet<String> = HashSet::from(["group-x".to_string()]);
    let cache: Mutex<HashMap<String, bool>> = Mutex::new(HashMap::new());
    cache.lock().unwrap().insert("group-x".to_string(), false);

    let result = NetmapChangeAuthenticator::effective_servable_groups(state, &raw_groups, &cache);
    assert!(result.is_empty());
}

/// A resolution miss populates the cache with its outcome, so a group
/// shared by many peers in one netmap-update pass is resolved once, not
/// once per peer sharing it.
#[tokio::test]
async fn effective_servable_groups_populates_the_validation_cache_on_a_miss() {
    let state = test_state();
    let raw_groups: HashSet<String> = HashSet::from(["group-y".to_string()]);
    let cache: Mutex<HashMap<String, bool>> = Mutex::new(HashMap::new());

    let result = NetmapChangeAuthenticator::effective_servable_groups(state, &raw_groups, &cache);
    assert_eq!(result, raw_groups);
    assert_eq!(cache.lock().unwrap().get("group-y").copied(), Some(true));
}

/// End-to-end integration proof (not just the underlying
/// `GroupPolicyState` primitive) that `NetmapChangeAuthenticator::
/// resolve_authority_key` -- the actual key resolution every peer-to-peer
/// checkpoint verification runs through -- resolves the group's real
/// authority key at a real historical policy point, and refuses when
/// the claimed `signer_key_id` does not match.
#[tokio::test]
async fn resolve_authority_key_matches_the_real_authority_key_and_rejects_a_wrong_fingerprint() {
    use crate::change_policy::policy_signing::grant_record;
    use crate::change_policy::{GroupPolicyLog, WriterRole};
    use sha2::Digest as _;

    let authority = SigningKey::from_bytes(&[7u8; 32]);
    let group_id = "shared-group";
    let device_fp = [42u8; 32];

    let grant =
        grant_record(&authority, group_id, 1, [0u8; 32], "device-b", device_fp, WriterRole::Editor);
    let head = grant.record_hash.clone();
    let log = GroupPolicyLog {
        group_id: group_id.to_string(),
        current_seq: 1,
        current_epoch: 0,
        policy_head: head.clone(),
        records: vec![grant],
    };
    let policy =
        crate::change_policy::verify_group_policy_log(&authority.verifying_key().to_bytes(), &log)
            .unwrap();

    let state = test_state();
    state.authority.replace_group_policy_states(HashMap::from([(group_id.to_string(), policy)]));
    let authenticator = NetmapChangeAuthenticator::new(state);

    let authority_fingerprint: [u8; 32] =
        sha2::Sha256::digest(authority.verifying_key().to_bytes()).into();
    let policy_head: [u8; 32] = head.as_slice().try_into().unwrap();

    assert_eq!(
        authenticator.resolve_authority_key(group_id, &authority_fingerprint, &policy_head),
        Some(authority.verifying_key()),
        "must resolve the real authority key at the real historical policy point"
    );

    assert!(
        authenticator.resolve_authority_key(group_id, &[1u8; 32], &policy_head).is_none(),
        "must refuse when the claimed signer_key_id does not match the real authority key"
    );
}
