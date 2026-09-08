//! Daemon wiring for the R3.3 re-bootstrap protocol transported by
//! `PeerSyncSession`.
//!
//! Sync-core owns the signed protocol objects and atomic SQLite installer.  The
//! daemon supplies the process identity/signing key and a re-bootstrap-specific
//! trust resolver — deliberately NOT the same resolver ordinary retained-history
//! Change verification uses. See `trust_key`'s doc comment for why.

use std::sync::Arc;

use sha2::{Digest, Sha256};

use crate::sync_error::SyncError;
use yadorilink_peer_session::peer_session::{
    ChangeAuthenticator, PreparedRebootstrap, RebootstrapHandler,
};
use yadorilink_peer_session::PeerSessionError;
use yadorilink_replica_domain::change;
use yadorilink_replica_domain::change::{Change, ChangeAuth};
use yadorilink_replica_domain::ids::{ChangeHash, DeviceId, FolderGroupId};
use yadorilink_replica_engine::error::ReplicaEngineError;
use yadorilink_replica_engine::rebootstrap::{
    prepare_rebootstrap_required, verify_and_install_rebootstrap, AtomicRebootstrapInstaller,
    RebootstrapRequired, RebootstrapTrust,
};
use yadorilink_replica_engine::rebootstrap_snapshot::RebootstrapSnapshot;
use yadorilink_sync_sqlite::dag_store::ChangeEmitter;

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
    /// a writer, the manifest's actual signing key must be the exact key the
    /// signed policy chain bound to that writer, and — since a compaction
    /// snapshot materializes the group's *entire* retained history — the
    /// signer must be a full replica of it. None of these is implied by a
    /// valid signature alone; `RebootstrapTrust::signing_key` has no group
    /// context to check them itself, so this runs as a second, explicit gate
    /// after signature verification, before either `verify_rebootstrap` or
    /// `install_rebootstrap` accepts the message.
    ///
    /// The writer-role-and-key-binding check (first two conditions above)
    /// now fully mirrors the pattern `NetmapChangeAuthenticator::
    /// accepts_change_auth` (`change_auth.rs`) uses for ordinary Change
    /// admission, via `GroupPolicyState::author_was_writer_at`: resolve the
    /// group's signed policy chain, check the signer's role against it (real,
    /// role-aware writer authorization -- NOT `state.peer_is_writer`, which
    /// is populated from plain netmap membership, every authorized group
    /// member including Viewer; see `replace_peer_netmap_metadata`), AND
    /// require the manifest's actual signer key (`self.trust_key(signer)`,
    /// the SAME key already used to verify the manifest's own signature) to
    /// hash to the exact `AuthorizedWriter::signing_key_fingerprint` the
    /// policy chain bound to that writer -- the same two-part test
    /// `author_was_writer_at` ends on (`role.is_writer() &&
    /// fingerprint_admits(...)`, `change_policy.rs`). Without this second
    /// half, the writer-role check would pass on `device_id` alone while
    /// still trusting whatever key the NETMAP currently has pinned for that
    /// device to have produced the signature actually verified above --
    /// exactly the weak trust root this whole check exists to stop relying
    /// on for write-authorization decisions. Unlike ordinary Change
    /// admission, this call site has no `ChangeAuth` policy-watermark stamp
    /// to check the signer against a specific historical seq -- it only has
    /// the bare signer device id -- so this checks `current_writers()`,
    /// `GroupPolicyState`'s existing "writer set as of the policy's own
    /// current/latest verified position" accessor, rather than a historical
    /// one.
    ///
    /// The full-replica check (the THIRD condition, `peer_group_is_full_
    /// replica` below) is intentionally and unavoidably netmap-derived only,
    /// with no signed-policy equivalent to bind against: `WriterRole`/the
    /// signed policy chain has no storage-mode/full-replica concept at all,
    /// so there is nothing in the policy chain for this to check the netmap
    /// claim against. Do not assume the fingerprint-binding fix above
    /// extends to this check too -- it does not, and cannot with the policy
    /// chain's current shape.
    fn check_signer_authorized_for_group(
        &self,
        required: &RebootstrapRequired,
    ) -> Result<(), SyncError> {
        let group_id = required.manifest.group_id.as_str();
        let signer = required.manifest.signer_device_id.as_str();
        if signer == self.state.device_id {
            return Ok(());
        }
        let is_writer = match self.state.resolve_group_policy(group_id) {
            GroupPolicyResolution::Verified(policy) => {
                // A verified policy whose `current_writers()` is empty -- a
                // genuinely empty signed log, or a chain where every past
                // writer has since been revoked or downgraded to Viewer --
                // is treated as "no authorized writer for this group, full
                // stop": `find` below returns `None` and `is_writer` resolves
                // to `false` unconditionally, with no netmap-derived
                // fallback of any kind. This is a deliberate, fail-closed
                // choice, and it differs on purpose from how the SAME
                // scenario is handled elsewhere in this codebase:
                //   - `local_change_auth_provider` (daemon_state.rs) falls
                //     through to `author_was_writer_at`'s own empty-log
                //     special case, which ALLOWS local emission (treats an
                //     empty verified log the same as the pre-policy
                //     Bootstrap window);
                //   - `repair_election_provider` (daemon_state.rs) falls
                //     back to the netmap's role-blind member set (see the
                //     TODO on that function for the follow-up needed to
                //     reconcile this).
                // Re-bootstrap is different in kind from both: it installs a
                // BRAND NEW HistoryBase for the group, wholesale replacing
                // retained history, on the strength of a single signer claim
                // with no group-wide quorum or merge to fall back on if that
                // signer turns out to be wrong. An empty verified writer set
                // gives this function no signed authority to point to at
                // all, so rejecting outright -- rather than guessing via
                // netmap membership, or treating "empty" as "still
                // bootstrapping" -- is the only answer that cannot be
                // exploited by a compromised or spoofed netmap entry. This
                // is a real behavior change from the pre-fix
                // membership-based version (which relied on
                // `peer_is_writer` and so would have allowed this); see
                // `check_signer_authorized_for_group_rejects_every_signer_when_the_verified_policy_names_no_writers`
                // below for regression coverage.
                policy
                    .current_writers()
                    .into_iter()
                    .find(|writer| writer.device_id == signer)
                    .is_some_and(|writer| {
                        // Fail closed if there is no LIVE netmap-pinned key
                        // to compare against (matches `trust_key`'s own
                        // fail-closed behavior for signature verification).
                        self.trust_key(signer)
                            .map(|signer_key| {
                                let presented_fingerprint: [u8; 32] =
                                    Sha256::digest(signer_key).into();
                                presented_fingerprint == writer.signing_key_fingerprint
                            })
                            .unwrap_or(false)
                    })
            }
            GroupPolicyResolution::Bootstrap => {
                // Genuine pre-policy bootstrap window: no signed policy
                // chain has ever existed for this group, so there is no
                // role data -- and so no signing-key binding either -- to
                // check against. Fall back to netmap membership, exactly
                // matching `local_change_auth_provider`'s and
                // `accepts_change_auth`'s own Bootstrap-arm behavior (both
                // documented as legitimate on this narrow pre-role window;
                // see their own comments).
                self.state.peer_is_writer(signer, group_id)
            }
            GroupPolicyResolution::Withhold => {
                return Err(SyncError::CorruptState(format!(
                    "cannot accept re-bootstrap manifest for group {group_id}: group policy is \
                     currently withheld"
                )));
            }
        };
        if !is_writer {
            return Err(SyncError::CorruptState(format!(
                "re-bootstrap manifest signer {signer} is not a current writer for group \
                 {group_id}, or its signing key does not match the key the signed policy chain \
                 bound to that writer; refusing to install a HistoryBase it is not authorized to \
                 introduce"
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
    state: Arc<crate::replica_coordinator::ReplicaCoordinator>,
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
        manifest: &yadorilink_replica_engine::rebootstrap::SnapshotManifest,
        snapshot_bytes: &[u8],
    ) -> Result<(), ReplicaEngineError> {
        // `SyncState::install_rebootstrap_snapshot` stays `SyncError`-returning
        // (it is sync-core's own SQLite-backed installer, not part of the
        // 7D-9D move) -- this trait's own error type is `ReplicaEngineError`
        // since `AtomicRebootstrapInstaller` moved to yadorilink-replica-engine,
        // so the boundary conversion happens here, same as every other
        // `SyncState`-backed replica-engine port adapter.
        self.state
            .install_rebootstrap_snapshot(manifest, snapshot_bytes, self.local_emitter.as_ref())
            .map_err(|e| ReplicaEngineError::Storage(e.to_string()))
    }
}

impl RebootstrapHandler for DaemonRebootstrapHandler {
    fn prepare_rebootstrap(
        &self,
        group_id: &str,
        requested_hash: ChangeHash,
    ) -> Result<Option<PreparedRebootstrap>, PeerSessionError> {
        let Some(signing_key) = self.state.device_signing_key() else {
            return Ok(None);
        };
        let group = FolderGroupId::from(group_id);
        let required = prepare_rebootstrap_required(
            self.state.replica_coordinator.as_ref(),
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
            .replica_coordinator
            .rebootstrap_store_repository()
            .checkpoint_snapshot(&checkpoint_hash)
            .map_err(SyncError::from)?
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

    fn verify_rebootstrap(&self, required: &RebootstrapRequired) -> Result<(), PeerSessionError> {
        struct Trust<'a>(&'a DaemonRebootstrapHandler);
        impl RebootstrapTrust for Trust<'_> {
            fn signing_key(&self, device_id: &str) -> Option<[u8; 32]> {
                self.0.trust_key(device_id)
            }
        }
        required.verify(&Trust(self))?;
        Ok(self.check_signer_authorized_for_group(required)?)
    }

    fn install_rebootstrap(
        &self,
        required: &RebootstrapRequired,
        snapshot_bytes: &[u8],
    ) -> Result<(), PeerSessionError> {
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
        let installer = SyncStateRebootstrapInstaller {
            state: self.state.replica_coordinator.clone(),
            local_emitter,
        };
        Ok(verify_and_install_rebootstrap(
            &installer,
            required,
            &Trust(self),
            snapshot_bytes,
            |manifest, bytes| {
                let snapshot = RebootstrapSnapshot::decode(bytes)?;
                snapshot.validate_against_checkpoint(&manifest.checkpoint)?;
                // `verify_each_frontier_change` stays `SyncError`-returning
                // (daemon-local signature/authorization verification, not
                // part of the 7D-9D move) -- the closure's own error type is
                // fixed to `ReplicaEngineError` by `verify_and_install_
                // rebootstrap`'s signature, so this boundary needs an
                // explicit conversion rather than a bare `?`.
                self.verify_each_frontier_change(&snapshot)
                    .map_err(|e| ReplicaEngineError::CorruptState(e.to_string()))
            },
        )?)
    }
}

#[cfg(test)]
mod tests {
    use crate::replica_coordinator::ReplicaCoordinator;
    use ed25519_dalek::SigningKey;
    use yadorilink_local_storage::FsBlockStore;
    use yadorilink_replica_engine::compaction::Checkpoint;
    use yadorilink_replica_engine::rebootstrap::SnapshotManifest;

    use super::*;

    fn test_state() -> Arc<DaemonState> {
        let store_dir = tempfile::tempdir().unwrap();
        let store = Arc::new(FsBlockStore::new(store_dir.path()).unwrap());
        let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
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

    /// Bug 2 regression: this function's own doc comment says the signer
    /// must be "a device this policy currently recognizes as a writer" --
    /// but the pre-fix code checked `state.peer_is_writer`, which is
    /// populated from plain netmap membership (every authorized group
    /// member, Viewer included; see `DaemonState::replace_peer_netmap_
    /// metadata`), not from the signed policy chain's Editor/Owner role
    /// data. That let a Viewer-role device's re-bootstrap manifest --
    /// installing a brand-new HistoryBase/compaction snapshot for the
    /// group -- be accepted as though it came from a real writer. This
    /// proves a Viewer-signed manifest is now rejected, and the identical
    /// manifest signed by the same device once re-granted Editor (and
    /// marked a full replica, the separate, unchanged full-replica check)
    /// is accepted.
    #[tokio::test]
    async fn check_signer_authorized_for_group_rejects_a_viewer_and_accepts_the_same_device_as_an_editor(
    ) {
        use crate::change_policy::policy_signing::grant_record;
        use crate::change_policy::{verify_group_policy_log, GroupPolicyLog, WriterRole};

        let authority = SigningKey::from_bytes(&[7u8; 32]);
        let group_id = "group-rebootstrap";
        let signer_key = SigningKey::from_bytes(&[13u8; 32]);
        let signer_fp: [u8; 32] = Sha256::digest(signer_key.verifying_key().to_bytes()).into();

        let viewer_grant = grant_record(
            &authority,
            group_id,
            1,
            [0u8; 32],
            "device-b",
            signer_fp,
            WriterRole::Viewer,
        );
        let viewer_head: [u8; 32] = viewer_grant.record_hash.as_slice().try_into().unwrap();
        let viewer_log = GroupPolicyLog {
            group_id: group_id.to_string(),
            current_seq: 1,
            current_epoch: 0,
            policy_head: viewer_head.to_vec(),
            records: vec![viewer_grant],
        };
        let viewer_policy =
            verify_group_policy_log(&authority.verifying_key().to_bytes(), &viewer_log).unwrap();

        let state = test_state();
        // device-b is a real netmap-authorized group member -- exactly what
        // a Viewer legitimately is (membership and write-role are separate
        // axes; see `WriterRole`'s own doc comment). This is what makes the
        // pre-fix check dangerous: `peer_is_writer` returns true here
        // (membership alone), which is precisely why this test needs the
        // real signed-policy role check instead.
        state.set_peer_group_writer("device-b", group_id, true);
        // Also already a full replica for the whole test, so the ONLY thing
        // that changes between the Viewer and Editor phases below is the
        // signed policy role -- isolating the writer-role check this test
        // targets from the separate, unchanged full-replica check.
        state.set_peer_group_full_replica("device-b", group_id, true);
        // The netmap-pinned key matches the policy-bound fingerprint for the
        // whole test (both derived from the same `signer_key`) -- fix 1's
        // added fingerprint-binding check is exercised elsewhere
        // (`..._rejects_a_manifest_signed_with_a_key_the_policy_never_bound_to_the_writer`);
        // this test isolates the writer-ROLE check only, so the fingerprint
        // half must trivially agree throughout.
        state.record_peer_signing_key("device-b", signer_key.verifying_key().to_bytes());
        state.replace_group_policy_states(std::collections::HashMap::from([(
            group_id.to_string(),
            viewer_policy,
        )]));
        let handler = DaemonRebootstrapHandler { state: state.clone() };
        let required = required_signed_by(group_id, "device-b", &signer_key);

        let error = handler.check_signer_authorized_for_group(&required).unwrap_err();
        assert!(
            matches!(
                error,
                SyncError::CorruptState(ref message) if message.contains("is not a current writer")
            ),
            "expected a Viewer-signed re-bootstrap manifest to be rejected as not-a-writer, got \
             {error:?}"
        );

        // Promote device-b to Editor at seq 2 -- membership and full-replica
        // status are unchanged from above, so this isolates the writer-role
        // check. The identical manifest must now be accepted.
        let editor_grant = grant_record(
            &authority,
            group_id,
            2,
            viewer_head,
            "device-b",
            signer_fp,
            WriterRole::Editor,
        );
        let editor_head: [u8; 32] = editor_grant.record_hash.as_slice().try_into().unwrap();
        let editor_log = GroupPolicyLog {
            group_id: group_id.to_string(),
            current_seq: 2,
            current_epoch: 0,
            policy_head: editor_head.to_vec(),
            records: vec![
                grant_record(
                    &authority,
                    group_id,
                    1,
                    [0u8; 32],
                    "device-b",
                    signer_fp,
                    WriterRole::Viewer,
                ),
                editor_grant,
            ],
        };
        let editor_policy =
            verify_group_policy_log(&authority.verifying_key().to_bytes(), &editor_log).unwrap();
        state.replace_group_policy_states(std::collections::HashMap::from([(
            group_id.to_string(),
            editor_policy,
        )]));

        handler.check_signer_authorized_for_group(&required).unwrap();
    }

    /// Signing-key fingerprint binding regression test: the writer-role
    /// check alone is not enough -- the manifest's ACTUAL signing key must
    /// also match the key the SIGNED POLICY CHAIN bound to that writer, not
    /// merely whatever key the
    /// (netmap-derived, weak) `trust_key` resolver currently has pinned for
    /// that device id. The policy binds device-b's Editor grant to key A's
    /// fingerprint; the netmap separately has a DIFFERENT key B pinned for
    /// device-b; the manifest is signed with key B. Before this fix,
    /// `check_signer_authorized_for_group` only checked `writer.device_id
    /// == signer` against `current_writers()` and never consulted
    /// `AuthorizedWriter::signing_key_fingerprint` at all, so this was
    /// wrongly accepted -- a manifest signed by a key the signed policy
    /// chain never actually authorized for that writer. The existing
    /// `check_signer_authorized_for_group_rejects_a_viewer_and_accepts_the_same_device_as_an_editor`
    /// test above can't catch this: it uses ONE key for both the Viewer and
    /// Editor phases, so `writer.device_id == signer` and a hypothetical
    /// fingerprint check would always agree there too. This test needs two
    /// DISTINCT keys to isolate the gap.
    #[tokio::test]
    async fn check_signer_authorized_for_group_rejects_a_manifest_signed_with_a_key_the_policy_never_bound_to_the_writer(
    ) {
        use crate::change_policy::policy_signing::grant_record;
        use crate::change_policy::{verify_group_policy_log, GroupPolicyLog, WriterRole};

        let authority = SigningKey::from_bytes(&[7u8; 32]);
        let group_id = "group-rebootstrap-fp-binding";
        // Key A: the key the signed policy chain binds device-b's Editor
        // grant to.
        let policy_bound_key = SigningKey::from_bytes(&[21u8; 32]);
        let policy_bound_fp: [u8; 32] =
            Sha256::digest(policy_bound_key.verifying_key().to_bytes()).into();
        // Key B: a DIFFERENT key, netmap-pinned for the SAME device id, and
        // the one the manifest is actually signed with -- the forged/wrong
        // key an attacker who controls the netmap pin (but not device-b's
        // real key A) would use.
        let netmap_pinned_key = SigningKey::from_bytes(&[22u8; 32]);
        assert_ne!(
            policy_bound_key.verifying_key().to_bytes(),
            netmap_pinned_key.verifying_key().to_bytes(),
            "test setup bug: the two keys must be distinct for this probe to mean anything"
        );

        let editor_grant = grant_record(
            &authority,
            group_id,
            1,
            [0u8; 32],
            "device-b",
            policy_bound_fp,
            WriterRole::Editor,
        );
        let editor_head: [u8; 32] = editor_grant.record_hash.as_slice().try_into().unwrap();
        let editor_log = GroupPolicyLog {
            group_id: group_id.to_string(),
            current_seq: 1,
            current_epoch: 0,
            policy_head: editor_head.to_vec(),
            records: vec![editor_grant],
        };
        let editor_policy =
            verify_group_policy_log(&authority.verifying_key().to_bytes(), &editor_log).unwrap();

        let state = test_state();
        state.set_peer_group_writer("device-b", group_id, true);
        state.set_peer_group_full_replica("device-b", group_id, true);
        // The attack: the netmap has key B pinned for device-b, NOT key A
        // the signed policy chain actually bound.
        state.record_peer_signing_key("device-b", netmap_pinned_key.verifying_key().to_bytes());
        state.replace_group_policy_states(std::collections::HashMap::from([(
            group_id.to_string(),
            editor_policy,
        )]));
        let handler = DaemonRebootstrapHandler { state: state.clone() };
        // Manifest claims signer "device-b" (a real Editor per the policy
        // chain) but is signed with key B, which the policy chain never
        // bound to device-b.
        let required = required_signed_by(group_id, "device-b", &netmap_pinned_key);

        let error = handler.check_signer_authorized_for_group(&required).unwrap_err();
        assert!(
            matches!(
                error,
                SyncError::CorruptState(ref message) if message.contains("is not a current writer")
            ),
            "expected a manifest signed with a key the signed policy chain never bound to this \
             writer to be rejected even though the same device id is a real Editor under a \
             DIFFERENT key, got {error:?}"
        );
    }

    /// Empty-verified-writer-set regression test: a signed policy
    /// chain that has been verified but currently names ZERO writers (a
    /// genuinely empty log here; a chain where every writer has since been
    /// revoked reaches the identical `current_writers().is_empty()` state)
    /// must reject every signer unconditionally -- no netmap-membership
    /// fallback of any kind, even for a device the netmap otherwise
    /// considers both a group member and a full replica. See this
    /// function's own doc comment (the paragraph on `current_writers()`
    /// being empty) for why this differs, on purpose, from how
    /// `local_change_auth_provider` and `repair_election_provider`
    /// (`daemon_state.rs`) each handle the identical scenario.
    #[tokio::test]
    async fn check_signer_authorized_for_group_rejects_every_signer_when_the_verified_policy_names_no_writers(
    ) {
        use crate::change_policy::{verify_group_policy_log, GroupPolicyLog};

        let authority = SigningKey::from_bytes(&[7u8; 32]);
        let group_id = "group-empty-writer-set";
        let empty_log = GroupPolicyLog {
            group_id: group_id.to_string(),
            current_seq: 0,
            current_epoch: 0,
            policy_head: vec![0u8; 32],
            records: vec![],
        };
        let empty_policy =
            verify_group_policy_log(&authority.verifying_key().to_bytes(), &empty_log).unwrap();
        assert!(
            empty_policy.current_writers().is_empty(),
            "test setup bug: this policy must have an empty writer set for the probe to mean \
             anything"
        );

        let state = test_state();
        let signer_key = SigningKey::from_bytes(&[31u8; 32]);
        // device-b looks like a fully legitimate signer by every
        // netmap-derived signal -- a real member, a real full replica, and
        // its real live key is pinned -- so the ONLY reason this must be
        // rejected is the empty verified writer set itself.
        state.set_peer_group_writer("device-b", group_id, true);
        state.set_peer_group_full_replica("device-b", group_id, true);
        state.record_peer_signing_key("device-b", signer_key.verifying_key().to_bytes());
        state.replace_group_policy_states(std::collections::HashMap::from([(
            group_id.to_string(),
            empty_policy,
        )]));
        let handler = DaemonRebootstrapHandler { state: state.clone() };
        let required = required_signed_by(group_id, "device-b", &signer_key);

        let error = handler.check_signer_authorized_for_group(&required).unwrap_err();
        assert!(
            matches!(
                error,
                SyncError::CorruptState(ref message) if message.contains("is not a current writer")
            ),
            "expected a verified-but-empty writer set to reject every signer unconditionally, \
             got {error:?}"
        );
    }

    /// Issue D2: trusting the outer `SnapshotManifest` signer (verified
    /// separately, via `manifest_hash`/`snapshot_hash` binding) must not be
    /// conflated with trusting an individual embedded frontier `Change`'s
    /// own authorization. A frontier change from an author whose signing
    /// key this device has never pinned must be rejected independently,
    /// even though nothing here claims the outer manifest itself is invalid.
    #[tokio::test]
    async fn verify_each_frontier_change_rejects_a_change_with_no_pinned_author_key() {
        use yadorilink_replica_domain::change::Op;
        use yadorilink_replica_domain::ids::SyncPath;
        use yadorilink_replica_engine::rebootstrap_snapshot::RebootstrapSnapshot;

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
