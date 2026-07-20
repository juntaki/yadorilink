//! Daemon wiring for the R3.3 re-bootstrap protocol transported by
//! `PeerSyncSession`.
//!
//! Sync-core owns the signed protocol objects and atomic SQLite installer.  The
//! daemon supplies the process identity/signing key and a re-bootstrap-specific
//! trust resolver — deliberately NOT the same resolver ordinary retained-history
//! Change verification uses. See `trust_key`'s doc comment for why.

use std::sync::Arc;

use sha2::{Digest, Sha256};

use yadorilink_sync_core::change::{self, Change, ChangeAuth, ChangeHash, DeviceId, FolderGroupId};
use yadorilink_sync_core::dag_store::ChangeEmitter;
use yadorilink_sync_core::index::SyncState;
use yadorilink_sync_core::peer_session::{
    ChangeAuthenticator, PreparedRebootstrap, RebootstrapHandler,
};
use yadorilink_sync_core::rebootstrap::{
    prepare_rebootstrap_required, verify_and_install_rebootstrap, AtomicRebootstrapInstaller,
    RebootstrapRequired, RebootstrapTrust,
};
use yadorilink_sync_core::rebootstrap_snapshot::RebootstrapSnapshot;
use yadorilink_sync_core::SyncError;

use crate::daemon_state::{DaemonState, GroupPolicyResolution};

pub struct DaemonRebootstrapHandler {
    state: Arc<DaemonState>,
}

impl DaemonRebootstrapHandler {
    pub fn new(state: Arc<DaemonState>) -> Arc<Self> {
        Arc::new(Self { state })
    }

    /// Resolves a re-bootstrap control message's claimed signer to a LIVE
    /// key only — self, or a peer's *current* netmap-pinned signing key.
    ///
    /// This deliberately does NOT fall back to the historical pinned-key
    /// archive (`NetmapChangeAuthenticator::historical_pinned_signing_key`)
    /// the way ordinary retained-history Change verification does. That
    /// fallback exists to keep OLD, already-admitted Change signatures
    /// verifiable after their author is revoked — necessary, since history
    /// must remain checkable no matter who has since left. A re-bootstrap
    /// control message is different in kind: it is NOT verifying something
    /// already admitted, it is authorizing a BRAND NEW HistoryBase install
    /// going forward. If a device's private key were compromised or simply
    /// retained after revocation, the historical-pin fallback would let that
    /// key sign a new snapshot/checkpoint and have it accepted here — a
    /// revoked writer forging a new baseline. Restricting this resolver to
    /// live keys only closes that gap: a revoked device has no live key
    /// entry to resolve against.
    fn trust_key(&self, device_id: &str) -> Option<[u8; 32]> {
        if device_id == self.state.device_id {
            return self.state.device_signing_key().map(|key| key.verifying_key().to_bytes());
        }
        self.state.peer_signing_key(device_id)
    }

    /// Beyond signature validity (which only proves the manifest's signer
    /// key produced these exact bytes), a re-bootstrap manifest must also be
    /// authorized to introduce a NEW baseline for its specific group right
    /// now: the signer must be a device this policy currently recognizes as
    /// a writer, and — since a compaction snapshot materializes the group's
    /// *entire* retained history — a full replica of it. Neither of these is
    /// implied by a valid signature alone; `RebootstrapTrust::signing_key`
    /// has no group context to check them itself, so this runs as a second,
    /// explicit gate after signature verification, before either
    /// `verify_rebootstrap` or `install_rebootstrap` accepts the message.
    fn check_signer_authorized_for_group(
        &self,
        required: &RebootstrapRequired,
    ) -> Result<(), SyncError> {
        let group_id = required.manifest.group_id.as_str();
        let signer = required.manifest.signer_device_id.as_str();
        if signer == self.state.device_id {
            return Ok(());
        }
        if matches!(self.state.resolve_group_policy(group_id), GroupPolicyResolution::Withhold) {
            return Err(SyncError::CorruptState(format!(
                "cannot accept re-bootstrap manifest for group {group_id}: group policy is \
                 currently withheld"
            )));
        }
        if !self.state.peer_is_writer(signer, group_id) {
            return Err(SyncError::CorruptState(format!(
                "re-bootstrap manifest signer {signer} is not a current writer for group \
                 {group_id}; refusing to install a HistoryBase it is not authorized to introduce"
            )));
        }
        if !self.state.peer_group_is_full_replica(signer, group_id) {
            return Err(SyncError::CorruptState(format!(
                "re-bootstrap manifest signer {signer} is not a current full replica for group \
                 {group_id}; only a device holding the group's complete retained history can \
                 attest a compaction snapshot of it"
            )));
        }
        Ok(())
    }

    /// Trusting the outer `SnapshotManifest` signer only proves the snapshot
    /// bytes were not tampered with in transit (`snapshot_hash` equality) —
    /// it does NOT prove any individual `Change` embedded in
    /// `snapshot.frontier_changes` was itself legitimately authorized at the
    /// time it was created, which may be a DIFFERENT device's Change than
    /// the manifest signer. This independently re-verifies each embedded
    /// Change's own signature and historical authorization, the same
    /// signature/authentication boundary `authenticated_history::validate_retained_group`
    /// and live peer admission both already use, so a re-bootstrap install
    /// can never adopt a Change whose own authorization this device has not
    /// positively checked.
    fn verify_each_frontier_change(&self, snapshot: &RebootstrapSnapshot) -> Result<(), SyncError> {
        let authenticator = crate::change_auth::NetmapChangeAuthenticator::new(self.state.clone());
        for encoded in &snapshot.frontier_changes {
            let frontier_change = Change::from_wire_bytes(encoded).map_err(|error| {
                SyncError::CorruptState(format!(
                    "re-bootstrap snapshot contains an invalid frontier change: {error}"
                ))
            })?;
            let hash = frontier_change.compute_hash();
            let key_bytes =
                authenticator.signing_key(frontier_change.device_id.as_str()).ok_or_else(|| {
                    SyncError::CorruptState(format!(
                        "cannot verify re-bootstrap frontier change {}: no pinned signing key \
                         for author {}",
                        hash.to_hex(),
                        frontier_change.device_id.as_str()
                    ))
                })?;
            let verifying_key = change::verifying_key_from_bytes(&key_bytes).map_err(|error| {
                SyncError::CorruptState(format!(
                    "frontier change author {} has an invalid pinned signing key: {error}",
                    frontier_change.device_id.as_str()
                ))
            })?;
            let signing_key_fingerprint: [u8; 32] = Sha256::digest(key_bytes).into();
            let auth = ChangeAuth {
                auth_seq: frontier_change.auth_seq,
                auth_epoch: frontier_change.auth_epoch,
                policy_head_hash: frontier_change.policy_head_hash,
            };
            change::verify_change(
                &frontier_change,
                &hash,
                &verifying_key,
                |device_id, group_id| {
                    authenticator.accepts_change_auth(
                        device_id.as_str(),
                        group_id.as_str(),
                        signing_key_fingerprint,
                        auth,
                    )
                },
            )
            .map_err(|error| {
                SyncError::CorruptState(format!(
                    "re-bootstrap frontier change {} by {} failed signature/authorization \
                     verification: {error}",
                    hash.to_hex(),
                    frontier_change.device_id.as_str()
                ))
            })?;
        }
        Ok(())
    }
}

struct SyncStateRebootstrapInstaller {
    state: Arc<SyncState>,
    /// This device's own signing identity, used only if the incoming
    /// snapshot needs to squash and re-emit an offline-diverged local
    /// branch (see `SyncState::install_rebootstrap_snapshot`'s doc
    /// comment). `None` when this device has no signing key configured —
    /// an offline-diverged branch then falls back to the old fail-closed
    /// behavior rather than being silently dropped.
    local_emitter: Option<ChangeEmitter>,
}

impl AtomicRebootstrapInstaller for SyncStateRebootstrapInstaller {
    fn install_snapshot_and_switch_history_base(
        &self,
        manifest: &yadorilink_sync_core::rebootstrap::SnapshotManifest,
        snapshot_bytes: &[u8],
    ) -> Result<(), SyncError> {
        self.state.install_rebootstrap_snapshot(
            manifest,
            snapshot_bytes,
            self.local_emitter.as_ref(),
        )
    }
}

impl RebootstrapHandler for DaemonRebootstrapHandler {
    fn prepare_rebootstrap(
        &self,
        group_id: &str,
        requested_hash: ChangeHash,
    ) -> Result<Option<PreparedRebootstrap>, SyncError> {
        let Some(signing_key) = self.state.device_signing_key() else {
            return Ok(None);
        };
        let group = FolderGroupId::from(group_id);
        let required = prepare_rebootstrap_required(
            self.state.sync_state.as_ref(),
            &group,
            &requested_hash,
            DeviceId::from(self.state.device_id.as_str()),
            &signing_key,
        )?;
        let Some(required) = required else {
            return Ok(None);
        };
        let checkpoint_hash = required.manifest.checkpoint.checkpoint_hash();
        let snapshot_bytes = self
            .state
            .sync_state
            .checkpoint_snapshot(&checkpoint_hash)?
            .ok_or_else(|| {
                SyncError::CorruptState(format!(
                    "checkpoint {} can prove a prune but its re-bootstrap snapshot bytes are missing",
                    checkpoint_hash.to_hex()
                ))
            })?;
        let snapshot = RebootstrapSnapshot::decode(&snapshot_bytes)?;
        snapshot.validate_against_checkpoint(&required.manifest.checkpoint)?;
        Ok(Some(PreparedRebootstrap { required, snapshot_bytes }))
    }

    fn verify_rebootstrap(&self, required: &RebootstrapRequired) -> Result<(), SyncError> {
        struct Trust<'a>(&'a DaemonRebootstrapHandler);
        impl RebootstrapTrust for Trust<'_> {
            fn signing_key(&self, device_id: &str) -> Option<[u8; 32]> {
                self.0.trust_key(device_id)
            }
        }
        required.verify(&Trust(self))?;
        self.check_signer_authorized_for_group(required)
    }

    fn install_rebootstrap(
        &self,
        required: &RebootstrapRequired,
        snapshot_bytes: &[u8],
    ) -> Result<(), SyncError> {
        self.check_signer_authorized_for_group(required)?;
        struct Trust<'a>(&'a DaemonRebootstrapHandler);
        impl RebootstrapTrust for Trust<'_> {
            fn signing_key(&self, device_id: &str) -> Option<[u8; 32]> {
                self.0.trust_key(device_id)
            }
        }
        let local_emitter = self
            .state
            .device_signing_key()
            .map(|key| ChangeEmitter::new(self.state.device_id.clone(), key));
        let installer =
            SyncStateRebootstrapInstaller { state: self.state.sync_state.clone(), local_emitter };
        verify_and_install_rebootstrap(
            &installer,
            required,
            &Trust(self),
            snapshot_bytes,
            |manifest, bytes| {
                let snapshot = RebootstrapSnapshot::decode(bytes)?;
                snapshot.validate_against_checkpoint(&manifest.checkpoint)?;
                self.verify_each_frontier_change(&snapshot)
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use yadorilink_local_storage::FsBlockStore;
    use yadorilink_sync_core::compaction::Checkpoint;
    use yadorilink_sync_core::rebootstrap::SnapshotManifest;

    use super::*;

    fn test_state() -> Arc<DaemonState> {
        let store_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
        let sync_state = Arc::new(SyncState::open_in_memory().unwrap());
        DaemonState::new("device-a".into(), sync_state, store)
    }

    fn required_signed_by(group_id: &str, signer: &str, key: &SigningKey) -> RebootstrapRequired {
        let frontier = ChangeHash([9u8; 32]);
        let checkpoint = Checkpoint::new(FolderGroupId(group_id.into()), vec![frontier], [1u8; 32]);
        let manifest = SnapshotManifest::new_signed(
            checkpoint,
            vec![frontier],
            None,
            DeviceId(signer.into()),
            key,
        )
        .unwrap();
        RebootstrapRequired::new_signed(ChangeHash([2u8; 32]), manifest, key)
    }

    /// Issue A core fix: this device's own signing key resolves without
    /// touching anything peer-related.
    #[tokio::test]
    async fn trust_key_resolves_own_live_device_key() {
        let state = test_state();
        let key = SigningKey::from_bytes(&[7u8; 32]);
        state.set_device_signing_key(key.clone());
        let handler = DaemonRebootstrapHandler { state };
        assert_eq!(handler.trust_key("device-a"), Some(key.verifying_key().to_bytes()));
    }

    /// Issue A core fix: a peer's key resolves only from the LIVE netmap
    /// pin, and only after it has actually been recorded — there is no
    /// fallback of any kind (in particular no historical-pin-archive
    /// fallback) that could resolve a device this process has never seen
    /// pinned live.
    #[tokio::test]
    async fn trust_key_resolves_only_a_peers_live_pinned_key() {
        let state = test_state();
        let peer_key = SigningKey::from_bytes(&[8u8; 32]);
        let handler = DaemonRebootstrapHandler { state: state.clone() };
        assert_eq!(handler.trust_key("device-b"), None);
        state.record_peer_signing_key("device-b", peer_key.verifying_key().to_bytes());
        assert_eq!(handler.trust_key("device-b"), Some(peer_key.verifying_key().to_bytes()));
    }

    /// Issue A core fix: a signature-valid manifest is not enough on its
    /// own — the signer must also be a device this policy currently
    /// recognizes as a writer for the manifest's specific group. A signer
    /// for a group that was never introduced to this device at all (the
    /// same shape a revoked-and-since-forgotten device would present) must
    /// be rejected, not merely deferred.
    #[tokio::test]
    async fn a_signer_that_is_not_this_device_and_never_introduced_is_not_authorized() {
        let state = test_state();
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let handler = DaemonRebootstrapHandler { state };
        let required = required_signed_by("brand-new-group", "device-b", &key);
        let error = handler.check_signer_authorized_for_group(&required).unwrap_err();
        assert!(
            matches!(
                error,
                SyncError::CorruptState(ref message) if message.contains("is not a current writer")
            ),
            "unexpected error: {error:?}"
        );
    }

    /// A device is always authorized to sign a manifest for its own future
    /// HistoryBase install — no membership lookup needed or performed.
    #[tokio::test]
    async fn a_signer_that_is_this_device_is_trivially_authorized() {
        let state = test_state();
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let handler = DaemonRebootstrapHandler { state };
        let required = required_signed_by("g", "device-a", &key);
        handler.check_signer_authorized_for_group(&required).unwrap();
    }

    /// Issue D2: trusting the outer `SnapshotManifest` signer (verified
    /// separately, via `manifest_hash`/`snapshot_hash` binding) must not be
    /// conflated with trusting an individual embedded frontier `Change`'s
    /// own authorization. A frontier change from an author whose signing
    /// key this device has never pinned must be rejected independently,
    /// even though nothing here claims the outer manifest itself is invalid.
    #[tokio::test]
    async fn verify_each_frontier_change_rejects_a_change_with_no_pinned_author_key() {
        use yadorilink_sync_core::change::{Op, SyncPath};
        use yadorilink_sync_core::rebootstrap_snapshot::RebootstrapSnapshot;

        let state = test_state();
        let handler = DaemonRebootstrapHandler { state };
        let unpinned_author_key = SigningKey::from_bytes(&[42u8; 32]);
        let frontier_change = Change::create_signed(
            vec![],
            0,
            ChangeAuth::PLACEHOLDER,
            DeviceId("device-unknown".into()),
            FolderGroupId("g".into()),
            vec![Op::Delete { path: SyncPath("a.bin".into()) }],
            &unpinned_author_key,
        );
        let snapshot = RebootstrapSnapshot::new(
            FolderGroupId("g".into()),
            Vec::new(),
            vec![frontier_change.to_wire_bytes()],
            Vec::new(),
            Vec::new(),
        )
        .unwrap();

        let error = handler.verify_each_frontier_change(&snapshot).unwrap_err();
        assert!(
            matches!(
                error,
                SyncError::CorruptState(ref message) if message.contains("no pinned signing key")
            ),
            "unexpected error: {error:?}"
        );
    }
}
