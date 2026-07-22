use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::SigningKey;

use super::*;
use crate::change::DeviceId;
use crate::compaction::{CheckpointStore, CompactionDagStore, DeviceFrontierStore};

fn h(byte: u8) -> ChangeHash {
    ChangeHash([byte; 32])
}

#[derive(Default)]
struct FakeStore {
    heads: Vec<ChangeHash>,
    parents: BTreeMap<ChangeHash, Vec<ChangeHash>>,
    pruned: BTreeSet<ChangeHash>,
    checkpoint: RefCell<Option<Checkpoint>>,
    previous_checkpoint_hash: Cell<Option<[u8; 32]>>,
}

impl CompactionDagStore for FakeStore {
    fn heads(&self, _group: &FolderGroupId) -> Result<Vec<ChangeHash>, SyncError> {
        Ok(self.heads.clone())
    }

    fn parents(
        &self,
        _group: &FolderGroupId,
        change: &ChangeHash,
    ) -> Result<Vec<ChangeHash>, SyncError> {
        Ok(self.parents.get(change).cloned().unwrap_or_default())
    }

    fn contains_change(
        &self,
        _group: &FolderGroupId,
        change: &ChangeHash,
    ) -> Result<bool, SyncError> {
        Ok(self.parents.contains_key(change) && !self.pruned.contains(change))
    }

    fn was_pruned(&self, _group: &FolderGroupId, change: &ChangeHash) -> Result<bool, SyncError> {
        Ok(self.pruned.contains(change))
    }
}

impl DeviceFrontierStore for FakeStore {
    fn set_device_frontier(
        &self,
        _group: &FolderGroupId,
        _device: &DeviceId,
        _frontier: &[ChangeHash],
    ) -> Result<(), SyncError> {
        Ok(())
    }

    fn get_device_frontier(
        &self,
        _group: &FolderGroupId,
        _device: &DeviceId,
    ) -> Result<Vec<ChangeHash>, SyncError> {
        Ok(Vec::new())
    }

    fn remove_device_frontier(
        &self,
        _group: &FolderGroupId,
        _device: &DeviceId,
    ) -> Result<(), SyncError> {
        Ok(())
    }
}

impl CheckpointStore for FakeStore {
    fn latest_checkpoint(&self, _group: &FolderGroupId) -> Result<Option<Checkpoint>, SyncError> {
        Ok(self.checkpoint.borrow().clone())
    }

    fn commit_prune(
        &self,
        checkpoint: &Checkpoint,
        _pruned: &[ChangeHash],
    ) -> Result<(), SyncError> {
        *self.checkpoint.borrow_mut() = Some(checkpoint.clone());
        Ok(())
    }

    fn history_base_previous_checkpoint_hash(
        &self,
        _group: &FolderGroupId,
    ) -> Result<Option<[u8; 32]>, SyncError> {
        Ok(self.previous_checkpoint_hash.get())
    }
}

fn store_with_checkpoint() -> FakeStore {
    let group = FolderGroupId("g".into());
    let mut store = FakeStore { heads: vec![h(3)], ..Default::default() };
    store.parents.insert(h(2), vec![]);
    store.parents.insert(h(3), vec![h(2)]);
    store.pruned.insert(h(1));
    *store.checkpoint.borrow_mut() = Some(Checkpoint::new(group, vec![h(2)], [9u8; 32]));
    store
}

fn trust_for<'a>(device_id: &'a str, key: &'a SigningKey) -> impl RebootstrapTrust + 'a {
    let key_bytes = key.verifying_key().to_bytes();
    move |candidate: &str| (candidate == device_id).then_some(key_bytes)
}

#[test]
fn unknown_hash_never_produces_rebootstrap_required() {
    let store = store_with_checkpoint();
    let key = SigningKey::from_bytes(&[4u8; 32]);
    let response = prepare_rebootstrap_required(
        &store,
        &FolderGroupId("g".into()),
        &h(99),
        DeviceId("device-a".into()),
        &key,
    )
    .unwrap();
    assert!(response.is_none());
}

#[test]
fn exactly_pruned_hash_produces_signed_manifest_and_bound_response() {
    let store = store_with_checkpoint();
    let key = SigningKey::from_bytes(&[4u8; 32]);
    let response = prepare_rebootstrap_required(
        &store,
        &FolderGroupId("g".into()),
        &h(1),
        DeviceId("device-a".into()),
        &key,
    )
    .unwrap()
    .unwrap();

    response.verify(&trust_for("device-a", &key)).unwrap();
    assert_eq!(
        response.manifest.history_base,
        HistoryBase::from_checkpoint(&response.manifest.checkpoint)
    );
    assert_eq!(response.manifest.current_heads, vec![h(3)]);
}

#[test]
fn rebootstrap_required_survives_a_wire_encode_decode_round_trip() {
    let store = store_with_checkpoint();
    let key = SigningKey::from_bytes(&[4u8; 32]);
    let response = prepare_rebootstrap_required(
        &store,
        &FolderGroupId("g".into()),
        &h(1),
        DeviceId("device-a".into()),
        &key,
    )
    .unwrap()
    .unwrap();

    let decoded = RebootstrapRequired::decode(&response.canonical_encoding()).unwrap();
    assert_eq!(decoded, response);
    decoded.verify(&trust_for("device-a", &key)).unwrap();
}

/// The `Some` case of `previous_checkpoint_hash` must also round-trip --
/// the prior test only exercises `None` (a fresh `FakeStore`'s default).
#[test]
fn rebootstrap_required_with_a_previous_checkpoint_hash_survives_a_round_trip() {
    let store = store_with_checkpoint();
    store.previous_checkpoint_hash.set(Some([5u8; 32]));
    let key = SigningKey::from_bytes(&[4u8; 32]);
    let response = prepare_rebootstrap_required(
        &store,
        &FolderGroupId("g".into()),
        &h(1),
        DeviceId("device-a".into()),
        &key,
    )
    .unwrap()
    .unwrap();
    assert_eq!(response.manifest.previous_checkpoint_hash, Some([5u8; 32]));

    let decoded = RebootstrapRequired::decode(&response.canonical_encoding()).unwrap();
    assert_eq!(decoded, response);
}

#[test]
fn rebootstrap_required_decode_rejects_trailing_bytes() {
    let store = store_with_checkpoint();
    let key = SigningKey::from_bytes(&[4u8; 32]);
    let response = prepare_rebootstrap_required(
        &store,
        &FolderGroupId("g".into()),
        &h(1),
        DeviceId("device-a".into()),
        &key,
    )
    .unwrap()
    .unwrap();

    let mut bytes = response.canonical_encoding();
    bytes.push(0);
    assert!(RebootstrapRequired::decode(&bytes).is_err());
}

#[test]
fn response_cannot_be_replayed_as_proof_for_a_different_unknown_hash() {
    let store = store_with_checkpoint();
    let key = SigningKey::from_bytes(&[4u8; 32]);
    let mut response = prepare_rebootstrap_required(
        &store,
        &FolderGroupId("g".into()),
        &h(1),
        DeviceId("device-a".into()),
        &key,
    )
    .unwrap()
    .unwrap();
    response.requested_hash = h(99);

    assert!(response.verify(&trust_for("device-a", &key)).is_err());
}

#[test]
fn manifest_signer_identity_must_resolve_to_the_key_that_signed_it() {
    let store = store_with_checkpoint();
    let signing_key = SigningKey::from_bytes(&[4u8; 32]);
    let wrong_pinned_key = SigningKey::from_bytes(&[5u8; 32]);
    let response = prepare_rebootstrap_required(
        &store,
        &FolderGroupId("g".into()),
        &h(1),
        DeviceId("device-b".into()),
        &signing_key,
    )
    .unwrap()
    .unwrap();

    assert!(response.verify(&trust_for("device-b", &wrong_pinned_key)).is_err());
}

#[test]
fn unrelated_current_head_cannot_be_signed_under_checkpoint_history_base() {
    let mut store = store_with_checkpoint();
    store.heads = vec![h(9)];
    store.parents.insert(h(9), vec![]);
    let key = SigningKey::from_bytes(&[4u8; 32]);

    let error = prepare_rebootstrap_required(
        &store,
        &FolderGroupId("g".into()),
        &h(1),
        DeviceId("device-a".into()),
        &key,
    )
    .unwrap_err();
    assert!(matches!(error, SyncError::CorruptState(_)));
}

#[test]
fn checkpoint_for_another_group_cannot_be_signed_for_requested_group() {
    let store = store_with_checkpoint();
    *store.checkpoint.borrow_mut() =
        Some(Checkpoint::new(FolderGroupId("other-group".into()), vec![h(2)], [9u8; 32]));
    let key = SigningKey::from_bytes(&[4u8; 32]);

    let error = prepare_rebootstrap_required(
        &store,
        &FolderGroupId("g".into()),
        &h(1),
        DeviceId("device-a".into()),
        &key,
    )
    .unwrap_err();
    assert!(matches!(error, SyncError::CorruptState(_)));
}

#[derive(Default)]
struct RecordingInstaller {
    calls: Cell<usize>,
    installed_base: RefCell<Option<HistoryBase>>,
}

impl AtomicRebootstrapInstaller for RecordingInstaller {
    fn install_snapshot_and_switch_history_base(
        &self,
        manifest: &SnapshotManifest,
        _snapshot_bytes: &[u8],
    ) -> Result<(), SyncError> {
        self.calls.set(self.calls.get() + 1);
        *self.installed_base.borrow_mut() = Some(manifest.history_base);
        Ok(())
    }
}

#[test]
fn invalid_snapshot_content_never_reaches_atomic_installer() {
    let store = store_with_checkpoint();
    let key = SigningKey::from_bytes(&[4u8; 32]);
    let response = prepare_rebootstrap_required(
        &store,
        &FolderGroupId("g".into()),
        &h(1),
        DeviceId("device-a".into()),
        &key,
    )
    .unwrap()
    .unwrap();
    let installer = RecordingInstaller::default();

    let result = verify_and_install_rebootstrap(
        &installer,
        &response,
        &trust_for("device-a", &key),
        b"bad snapshot",
        |_manifest, _bytes| Err(SyncError::CorruptState("snapshot hash mismatch".into())),
    );
    assert!(result.is_err());
    assert_eq!(installer.calls.get(), 0);
}

#[test]
fn verified_response_and_snapshot_cross_the_atomic_installer_once() {
    let store = store_with_checkpoint();
    let key = SigningKey::from_bytes(&[4u8; 32]);
    let response = prepare_rebootstrap_required(
        &store,
        &FolderGroupId("g".into()),
        &h(1),
        DeviceId("device-a".into()),
        &key,
    )
    .unwrap()
    .unwrap();
    let installer = RecordingInstaller::default();

    verify_and_install_rebootstrap(
        &installer,
        &response,
        &trust_for("device-a", &key),
        b"snapshot bytes",
        |_manifest, bytes| {
            if bytes == b"snapshot bytes" {
                Ok(())
            } else {
                Err(SyncError::CorruptState("unexpected snapshot".into()))
            }
        },
    )
    .unwrap();

    assert_eq!(installer.calls.get(), 1);
    assert_eq!(*installer.installed_base.borrow(), Some(response.manifest.history_base));
}

#[test]
fn compaction_scheduling_remains_explicitly_gated_off() {
    const { assert!(!COMPACTION_SCHEDULING_READY) };
}
