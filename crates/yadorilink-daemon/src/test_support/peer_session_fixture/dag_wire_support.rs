//! Reusable change-DAG producer support for over-the-wire integration
//! scenarios. The `tests/dst_support/` module is gated on the simulation
//! cfg, so a plain `cargo test` integration test cannot reuse it.
//! 1. [`pinned_authenticator`] — a `ChangeAuthenticator` that pins one or
//! more authors' Ed25519 verifying keys and treats each as a writer. It is
//! what `PeerSyncSession::set_change_authenticator` accepts and what makes
//! `handle_change_batch` admit those authors' signed changes. It mirrors
//! the daemon's `NetmapChangeAuthenticator` (`change_auth.rs`) minus the
//! netmap: that type answers `signing_key`/`is_writer` from
//! `DaemonState`'s mirrored netmap; here the same answers are pinned
//! directly. The permissive default `accepts_change_auth` (== `is_writer`,
//! from the trait) accepts `ChangeAuth::PLACEHOLDER`, which is exactly
//! what a bare `ReplicaCoordinator` emits (`local_emission_auth` returns
//! `PLACEHOLDER` when no policy provider is wired). 2. [`DagProducer`] — a
//! "commit a local edit into the DAG" routine that mirrors the daemon's
//! FS-edit -> signed-Change producer. Its [`DagProducer::commit_create`]
//! stores the content block and then calls
//! `ReplicaCoordinator::upsert_file_emitting_change` — the *exact*
//! function `LocalChangeProcessor::process_event` calls to sign a
//! `Change`, persist the referenced `FileVersion`, advance the group's DAG
//! head, and upsert the index row, all in one transaction. The caller then
//! drives `PeerSyncSession::announce_local_commit` (what the daemon's
//! `DaemonState::broadcast_change` does for a DAG-negotiated peer) so the
//! peer's heads-announce carries the new commit. Every API used here is
//! public `yadorilink_daemon::replica_coordinator`/
//! `yadorilink_replica_domain` surface. The daemon only adds the netmap
//! adapter and the broadcast wrapper on top, so the DAG producer is fully
//! exercisable directly against a `ReplicaCoordinator` — which is why this
//! support belongs at this layer and not inside the daemon crate itself.

#![allow(dead_code)] // reusable helper; not every scenario uses every method

use std::collections::HashMap;
use std::sync::Arc;

use crate::replica_coordinator::ReplicaCoordinator;
use ed25519_dalek::SigningKey;
use yadorilink_ipc_proto::sync as proto;
use yadorilink_peer_session::peer_session::{ChangeAuthenticator, RootCommitAuthorityProvider};
use yadorilink_replica_domain::change::{Op, PutOrigin};
use yadorilink_replica_domain::file::{BlockInfo, FileRecord, RecordKind};
use yadorilink_replica_domain::file::{FileMeta, FileVersion, VersionBlock};
use yadorilink_replica_domain::ids::{BlockHash, SyncPath};
use yadorilink_root_authority::root_commit::{RootCommitPermit, RootLease};
use yadorilink_sync_sqlite::dag_store::ChangeEmitter;

/// A `RootCommitAuthorityProvider` that always grants a lease, backed by one
/// process-lifetime `RootLease::for_tests()` per provider instance — the same
/// "no real link lifecycle" test lease `RootCommitPermit::for_tests` shares
/// process-wide, but scoped per device here so two devices in one process
/// (as this module's two-device wire scenarios construct) never share a
/// lease's admission counter.
///
/// `yadorilink_peer_session::peer_session::PeerSyncSessionDeps::standalone()` wires the deny-by-default
/// `DenyRootCommitAuthorityProvider` (mirroring the daemon-facing
/// `PeerSyncSessionOneTimeDeps::denied()`), which makes every `materialize`
/// call fail with "no live root-commit authority" — correct for a caller
/// that never established a link, but wrong for a test standing in for the
/// daemon's real per-link `RootLease` (installed by
/// `yadorilink-daemon`'s `DaemonState`, see `root_commit_authority.rs`,
/// once `start_link_watch` acquires the link's `SyncRootLock`). This mirrors
/// the crate-internal `AlwaysValidRootCommitAuthorityProvider` test default
/// (`peer_session.rs`), which is not part of this crate's public surface, so
/// integration tests need their own equivalent.
pub struct AlwaysValidRootCommitAuthorityProvider {
    lease: Arc<RootLease>,
}

impl AlwaysValidRootCommitAuthorityProvider {
    pub fn shared() -> Arc<dyn RootCommitAuthorityProvider> {
        Arc::new(Self { lease: Arc::new(RootLease::for_tests()) })
    }
}

impl RootCommitAuthorityProvider for AlwaysValidRootCommitAuthorityProvider {
    fn root_lease_for(&self, _group_id: &str) -> Option<Arc<RootLease>> {
        Some(self.lease.clone())
    }
}

/// A permissive `ChangeAuthenticator` that pins a fixed set of authors'
/// verifying keys and treats every pinned author as a writer for any group —
/// the trust material the daemon would inject from the coordination plane's
/// netmap. `accepts_change_auth` uses the trait default (== `is_writer`), so a
/// `PLACEHOLDER`-auth change signed by a pinned author is admitted.
struct PinnedKeysAuthenticator {
    keys: HashMap<String, [u8; 32]>,
}

impl ChangeAuthenticator for PinnedKeysAuthenticator {
    fn resolve_authority_key(
        &self,
        _group_id: &str,
        signer_key_id: &[u8; 32],
        _policy_head: &[u8; 32],
    ) -> Option<ed25519_dalek::VerifyingKey> {
        self.keys.values().find_map(|bytes| {
            let key = yadorilink_replica_domain::change::verifying_key_from_bytes(bytes).ok()?;
            (&yadorilink_replica_domain::authorization_checkpoint::fingerprint_signing_key(&key)
                == signer_key_id)
                .then_some(key)
        })
    }
}

/// Builds a `set_change_authenticator`-compatible authenticator that pins every
/// `(device_id, signing_key)` pair's verifying key. Wire this onto both sides of
/// a DAG session so each admits the other's signed changes.
pub fn pinned_authenticator(pairs: &[(&str, &SigningKey)]) -> Arc<dyn ChangeAuthenticator> {
    let keys =
        pairs.iter().map(|(id, key)| (id.to_string(), key.verifying_key().to_bytes())).collect();
    Arc::new(PinnedKeysAuthenticator { keys })
}

/// Builds a real, self-consistent `(checkpoints, published_changes)` pair
/// for `changes` (all authored by the SAME device), covering a
/// `proof-carrying-change` wire batch a real receiver accepts. `signing_key` signs the
/// checkpoint too, standing in for the coordination-plane authority: these
/// integration tests have no real authority/policy chain, and
/// `pinned_authenticator`'s `resolve_authority_key` accepts any key from its
/// pinned set regardless of whether it "really" issued the checkpoint, so a
/// device signing its own checkpoint is a faithful, minimal stand-in.
/// One self-signed checkpoint covering `changes` (all authored by the SAME
/// device), plus each change's own Merkle proof against it -- the raw pieces
/// both [`self_signed_checkpointed_batch`] (wire-frame proto shape, for
/// direct injection) and [`attach_self_signed_checkpoint`] (storage
/// attachment, for the real reconcile/heads-announce wire path) need. See
/// `self_signed_checkpointed_batch`'s own doc comment for why a device
/// signing its own checkpoint is a faithful, minimal stand-in for these
/// integration tests, which have no real coordination-plane authority.
struct SelfSignedCheckpoint {
    checkpoint_hash: [u8; 32],
    checkpoint_encoded: Vec<u8>,
    signature: Vec<u8>,
    author_signing_public_key: [u8; 32],
    group_id: String,
    device_id: String,
    checkpoint_seq: u64,
    proofs: Vec<yadorilink_replica_domain::authorization_checkpoint::MerkleProof>,
}

fn build_self_signed_checkpoint(
    signing_key: &SigningKey,
    changes: &[yadorilink_replica_domain::change::Change],
    checkpoint_seq: u64,
) -> SelfSignedCheckpoint {
    use yadorilink_replica_domain::authorization_checkpoint::{
        build_merkle_proof, canonical_signing_bytes, checkpoint_hash, fingerprint_signing_key,
        merkle_root, sign_checkpoint, AuthorizationCheckpoint,
    };

    assert!(!changes.is_empty(), "a checkpointed batch must cover at least one change");
    let group_id = changes[0].group_id.to_string();
    let device_id = changes[0].device_id.to_string();
    assert!(
        changes
            .iter()
            .all(|c| c.group_id.as_str() == group_id && c.device_id.as_str() == device_id),
        "a checkpointed batch covers a single (group, device) per checkpoint"
    );
    let author_fingerprint = fingerprint_signing_key(&signing_key.verifying_key());
    let hashes: Vec<[u8; 32]> = changes.iter().map(|c| c.compute_hash().0).collect();

    let checkpoint = AuthorizationCheckpoint {
        group_id: group_id.clone(),
        device_id: device_id.clone(),
        signing_key_fingerprint: author_fingerprint,
        merkle_root: merkle_root(&hashes),
        leaf_count: hashes.len() as u64,
        checkpoint_seq,
        signer_key_id: author_fingerprint,
        policy_epoch: 0,
        policy_seq: 0,
        policy_head: [0u8; 32],
        issued_at_unix: 0,
    };
    let encoded = canonical_signing_bytes(&checkpoint);
    let signature = sign_checkpoint(&checkpoint, signing_key);
    let hash = checkpoint_hash(&encoded, &signature);
    let proofs = (0..hashes.len()).map(|index| build_merkle_proof(&hashes, index)).collect();

    SelfSignedCheckpoint {
        checkpoint_hash: hash,
        checkpoint_encoded: encoded,
        signature: signature.to_vec(),
        author_signing_public_key: signing_key.verifying_key().to_bytes(),
        group_id,
        device_id,
        checkpoint_seq,
        proofs,
    }
}

pub fn self_signed_checkpointed_batch(
    signing_key: &SigningKey,
    changes: &[yadorilink_replica_domain::change::Change],
) -> (Vec<proto::AuthorizationCheckpointEnvelope>, Vec<proto::PublishedChange>) {
    let built = build_self_signed_checkpoint(signing_key, changes, 1);
    let envelope = proto::AuthorizationCheckpointEnvelope {
        checkpoint_hash: built.checkpoint_hash.to_vec(),
        checkpoint: built.checkpoint_encoded,
        signature: built.signature,
        author_signing_public_key: built.author_signing_public_key.to_vec(),
    };
    let published_changes = changes
        .iter()
        .zip(&built.proofs)
        .map(|(change, proof)| proto::PublishedChange {
            change: change.to_wire_bytes(),
            checkpoint_hash: built.checkpoint_hash.to_vec(),
            proof: Some(proto::AuthorizationMerkleProof {
                leaf_index: proof.leaf_index as u64,
                leaf_count: proof.leaf_count as u64,
                siblings: proof.siblings.iter().map(|s| s.to_vec()).collect(),
            }),
        })
        .collect();
    (vec![envelope], published_changes)
}

/// Publishes `changes` (all just committed by [`DagProducer::commit_create`]/
/// [`DagProducer::commit_create_empty`], all the SAME group+device) into
/// `state`'s own store by self-signing one covering checkpoint and attaching
/// it via `attach_authorization_evidence` -- exactly what the daemon's real
/// `flush_pending_checkpoint` does against a real coordination-plane
/// checkpoint, minus the network round trip. Local emission alone only ever
/// produces a Pending change;
/// only an evidence-attached (Published) change is eligible for
/// `send_change_batch` to pick up over the real reconcile/heads-announce
/// wire path `PeerSyncSession::announce_local_commit` drives, so a
/// two-session wire-convergence scenario needs this, not just
/// [`self_signed_checkpointed_batch`]'s direct-injection wire frames.
pub fn attach_self_signed_checkpoint(
    state: &ReplicaCoordinator,
    signing_key: &SigningKey,
    checkpoint_seq: u64,
    changes: &[yadorilink_replica_domain::change::Change],
) {
    use yadorilink_replica_domain::authorization_checkpoint::encode_merkle_proof;

    let built = build_self_signed_checkpoint(signing_key, changes, checkpoint_seq);
    let entries: Vec<(yadorilink_replica_domain::ids::ChangeHash, Vec<u8>)> = changes
        .iter()
        .zip(&built.proofs)
        .map(|(change, proof)| (change.compute_hash(), encode_merkle_proof(proof)))
        .collect();
    state
        .database()
        .write::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            yadorilink_sync_sqlite::dag_store::published_view::attach_authorization_evidence(
                conn,
                &built.checkpoint_hash,
                &built.group_id,
                &built.device_id,
                built.checkpoint_seq,
                &built.checkpoint_encoded,
                &built.signature,
                &built.author_signing_public_key,
                &entries,
            )
        })
        .expect("attach self-signed checkpoint evidence");
}

/// A device-local change-DAG producer over a real `ReplicaCoordinator` + block store,
/// mirroring the daemon's FS-edit -> signed-Change flow. Hold one per simulated
/// device; commits advance that device's own DAG head, and the owning
/// `PeerSyncSession` announces them with `announce_local_commit`.
pub struct DagProducer {
    state: Arc<ReplicaCoordinator>,
    store: Arc<dyn yadorilink_local_storage::BlockContentStore>,
    device_id: String,
    emitter: Arc<ChangeEmitter>,
    /// Every change committed since the last [`DagProducer::publish_pending`]
    /// call, keyed by group -- so a scenario touching more than one group
    /// still gets one checkpoint per group, never a cross-group batch
    /// (`build_self_signed_checkpoint` asserts a single group per
    /// checkpoint, matching real checkpoint issuance).
    pending: std::sync::Mutex<HashMap<String, Vec<yadorilink_replica_domain::ids::ChangeHash>>>,
    /// Next `checkpoint_seq` to self-sign with, per group -- real checkpoint
    /// issuance is a strictly increasing per-group sequence, and
    /// `attach_authorization_evidence`'s idempotency check would otherwise
    /// reject a second checkpoint reusing seq 1 for the same device.
    next_checkpoint_seq: std::sync::Mutex<HashMap<String, u64>>,
}

impl DagProducer {
    /// `signing_key` is this device's own Ed25519 key; the peer must pin its
    /// verifying key (see [`pinned_authenticator`]) to admit the changes it
    /// signs.
    pub fn new(
        state: Arc<ReplicaCoordinator>,
        store: Arc<dyn yadorilink_local_storage::BlockContentStore>,
        device_id: &str,
        signing_key: SigningKey,
    ) -> Self {
        let emitter = Arc::new(ChangeEmitter::new(device_id.to_string(), signing_key));
        Self {
            state,
            store,
            device_id: device_id.to_string(),
            emitter,
            pending: std::sync::Mutex::new(HashMap::new()),
            next_checkpoint_seq: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Commits a single-block file `Create` into the DAG exactly as the daemon
    /// producer would: store the content block, build the `FileVersion` the same
    /// way `LocalChangeProcessor::content_op` does (block hash + size + the given
    /// `mtime`), then emit the signed `Change` and upsert the index row via
    /// `ReplicaCoordinator::upsert_file_emitting_change`.
    ///
    /// `mtime_unix_nanos` is set explicitly so a scenario can invert mtime
    /// against lamport. Lamport is controlled by commit order: the emitter
    /// auto-parents from the group's current heads, so the first commit for a
    /// group is a DAG root (lamport 1) and each later commit descends from it
    /// (lamport N+1). Returns the committed `FileRecord`.
    pub fn commit_create(
        &self,
        group_id: &str,
        path: &str,
        content: &[u8],
        mtime_unix_nanos: i64,
    ) -> FileRecord {
        assert!(!content.is_empty(), "commit_create needs non-empty content to carry one block");
        let hash_hex = self.store.put(content).expect("store content block");
        let hash = hex::decode(&hash_hex).expect("block hash is hex");
        // Mirrors what `LocalChangeProcessor` does for a real local edit
        // (`record_group_block_provenance`'s doc comment): without this, a
        // peer session's block-serving/restore path refuses this block as
        // never having been obtained through the group.
        self.state
            .change_history_repository()
            .record_group_block_provenance(group_id, std::slice::from_ref(&hash))
            .unwrap();
        let size = content.len();

        let version = FileVersion::new(
            vec![VersionBlock { hash: BlockHash(hash.clone()), size: size as u32 }],
            size as u64,
            FileMeta {
                mtime_unix_nanos,
                unix_mode: None,
                symlink_target: None,
                record_kind: RecordKind::File,
                xattrs: Vec::new(),
            },
        );
        let op = Op::Put {
            path: SyncPath(path.to_string()),
            version: version.version_hash,
            origin: PutOrigin::Direct,
        };

        let record = FileRecord {
            path: path.to_string(),
            size: size as u64,
            mtime_unix_nanos,
            blocks: vec![BlockInfo { hash, offset: 0, size: size as u32 }],
            deleted: false,
        };

        let hash = self
            .state
            .upsert_file_emitting_change(
                group_id,
                &record,
                &self.device_id,
                yadorilink_replica_domain::session_state::ChangeContent {
                    ops: vec![op],
                    versions: std::slice::from_ref(&version),
                },
                None,
                None,
                crate::replica_coordinator::ReplicaChangeEmission {
                    emitter: &self.emitter,
                    permit: &RootCommitPermit::for_tests(),
                },
            )
            .expect("emit signed change and upsert index row");
        self.pending.lock().unwrap().entry(group_id.to_string()).or_default().push(hash);
        record
    }

    /// Commits an empty (zero-block) file `Create`. The receiving peer needs no
    /// block request to materialize it, so — unlike [`commit_create`] — this
    /// one never blocks on a block response. That makes it usable as an
    /// interleaved control signal: a message whose arrival at the index proves
    /// the receiver actually dequeued and handled it.
    pub fn commit_create_empty(
        &self,
        group_id: &str,
        path: &str,
        mtime_unix_nanos: i64,
    ) -> (FileRecord, FileVersion) {
        let version = FileVersion::new(
            vec![],
            0,
            FileMeta {
                mtime_unix_nanos,
                unix_mode: None,
                symlink_target: None,
                record_kind: RecordKind::File,
                xattrs: Vec::new(),
            },
        );
        let op = Op::Put {
            path: SyncPath(path.to_string()),
            version: version.version_hash,
            origin: PutOrigin::Direct,
        };
        let record = FileRecord {
            path: path.to_string(),
            size: 0,
            mtime_unix_nanos,
            blocks: vec![],
            deleted: false,
        };
        let hash = self
            .state
            .upsert_file_emitting_change(
                group_id,
                &record,
                &self.device_id,
                yadorilink_replica_domain::session_state::ChangeContent {
                    ops: vec![op],
                    versions: std::slice::from_ref(&version),
                },
                None,
                None,
                crate::replica_coordinator::ReplicaChangeEmission {
                    emitter: &self.emitter,
                    permit: &RootCommitPermit::for_tests(),
                },
            )
            .expect("emit signed change and upsert index row");
        self.pending.lock().unwrap().entry(group_id.to_string()).or_default().push(hash);
        (record, version)
    }

    /// [`commit_create`] plus the `FileVersion` it built, so a caller can hand
    /// the version to [`last_commit_as_wire_batch`]. Mirrors `commit_create`'s
    /// version construction exactly.
    pub fn commit_create_returning_version(
        &self,
        group_id: &str,
        path: &str,
        content: &[u8],
        mtime_unix_nanos: i64,
    ) -> (FileRecord, FileVersion) {
        let record = self.commit_create(group_id, path, content, mtime_unix_nanos);
        let hash = record.blocks[0].hash.clone();
        let version = FileVersion::new(
            vec![VersionBlock { hash: BlockHash(hash), size: content.len() as u32 }],
            content.len() as u64,
            FileMeta {
                mtime_unix_nanos,
                unix_mode: None,
                symlink_target: None,
                record_kind: RecordKind::File,
                xattrs: Vec::new(),
            },
        );
        (record, version)
    }

    /// Publishes every change committed for `group_id` since the last call
    /// (or since construction) -- see [`attach_self_signed_checkpoint`]'s
    /// own doc comment for why this is required before the real
    /// reconcile/heads-announce wire path (`PeerSyncSession::
    /// announce_local_commit`/`send_change_batch`) will ever pick a commit
    /// up. A no-op if nothing is pending for this group.
    pub fn publish_pending(&self, group_id: &str) {
        let hashes = self.pending.lock().unwrap().remove(group_id).unwrap_or_default();
        if hashes.is_empty() {
            return;
        }
        let changes: Vec<yadorilink_replica_domain::change::Change> = hashes
            .iter()
            .map(|hash| {
                self.state
                    .sqlite()
                    .dag_get_change(hash)
                    .expect("read back a just-committed change")
                    .expect("a just-committed change must be present")
            })
            .collect();
        let checkpoint_seq = {
            let mut next = self.next_checkpoint_seq.lock().unwrap();
            let seq = next.entry(group_id.to_string()).or_insert(1);
            let this_seq = *seq;
            *seq += 1;
            this_seq
        };
        attach_self_signed_checkpoint(
            &self.state,
            self.emitter.signing_key(),
            checkpoint_seq,
            &changes,
        );
    }
}
