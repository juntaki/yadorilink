//! Reusable change-DAG producer support for over-the-wire integration
//! scenarios.
//!
//! The `tests/dst_support/` module is `#![cfg(madsim)]`-gated, so a plain
//! (non-madsim) `cargo test` integration test cannot reuse it. This module is
//! the non-madsim counterpart: it supplies the two pieces a change-DAG
//! `PeerSyncSession` needs that the sync-core test harness otherwise only
//! receives from the daemon.
//!
//! 1. [`pinned_authenticator`] — a `ChangeAuthenticator` that pins one or more
//!    authors' Ed25519 verifying keys and treats each as a writer. It is what
//!    `PeerSyncSession::set_change_authenticator` accepts and what makes
//!    `handle_change_batch` admit those authors' signed changes. It mirrors the
//!    daemon's `NetmapChangeAuthenticator` (`change_auth.rs`) minus the netmap:
//!    that type answers `signing_key`/`is_writer` from
//!    `DaemonState`'s mirrored netmap; here the same answers are pinned
//!    directly. The permissive default `accepts_change_auth` (== `is_writer`,
//!    from the trait) accepts `ChangeAuth::PLACEHOLDER`, which is exactly what a
//!    bare `SyncState` emits (`local_emission_auth` returns `PLACEHOLDER` when
//!    no policy provider is wired).
//!
//! 2. [`DagProducer`] — a "commit a local edit into the DAG" routine that
//!    mirrors the daemon's FS-edit -> signed-Change producer. Its
//!    [`DagProducer::commit_create`] stores the content block and then calls
//!    `SyncState::upsert_file_emitting_change` — the *exact* function
//!    `LocalChangeProcessor::process_event` calls to sign a `Change`, persist
//!    the referenced `FileVersion`, advance the group's DAG head, and upsert the
//!    index row, all in one transaction. The caller then drives
//!    `PeerSyncSession::announce_local_commit` (what the daemon's
//!    `DaemonState::broadcast_change` does for a DAG-negotiated peer) so the
//!    peer's heads-announce carries the new commit.
//!
//! Every API used here is public `yadorilink_sync_core` surface. The daemon
//! only adds the netmap adapter and the broadcast wrapper on top, so the DAG
//! producer is fully exercisable at the sync-core layer — which is why this
//! support belongs at the sync-core layer and not at daemon level.

#![allow(dead_code)] // reusable helper; not every scenario uses every method

use std::collections::HashMap;
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use yadorilink_ipc_proto::sync as proto;
use yadorilink_local_storage::BlockStore;
use yadorilink_sync_core::change::{BlockHash, FileMeta, FileVersion, Op, SyncPath, VersionBlock};
use yadorilink_sync_core::dag_store::ChangeEmitter;
use yadorilink_sync_core::index::SyncState;
use yadorilink_sync_core::peer_session::ChangeAuthenticator;
use yadorilink_sync_core::types::{BlockInfo, FileRecord, RecordKind};
use yadorilink_sync_core::version_vector::VersionVector;

/// A permissive `ChangeAuthenticator` that pins a fixed set of authors'
/// verifying keys and treats every pinned author as a writer for any group —
/// the trust material the daemon would inject from the coordination plane's
/// netmap. `accepts_change_auth` uses the trait default (== `is_writer`), so a
/// `PLACEHOLDER`-auth change signed by a pinned author is admitted.
struct PinnedKeysAuthenticator {
    keys: HashMap<String, [u8; 32]>,
}

impl ChangeAuthenticator for PinnedKeysAuthenticator {
    fn signing_key(&self, device_id: &str) -> Option<[u8; 32]> {
        self.keys.get(device_id).copied()
    }
    fn is_writer(&self, _device_id: &str, _group_id: &str) -> bool {
        true
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

/// A device-local change-DAG producer over a real `SyncState` + block store,
/// mirroring the daemon's FS-edit -> signed-Change flow. Hold one per simulated
/// device; commits advance that device's own DAG head, and the owning
/// `PeerSyncSession` announces them with `announce_local_commit`.
pub struct DagProducer {
    state: Arc<SyncState>,
    store: Arc<dyn BlockStore + Send + Sync>,
    device_id: String,
    emitter: Arc<ChangeEmitter>,
}

impl DagProducer {
    /// `signing_key` is this device's own Ed25519 key; the peer must pin its
    /// verifying key (see [`pinned_authenticator`]) to admit the changes it
    /// signs.
    pub fn new(
        state: Arc<SyncState>,
        store: Arc<dyn BlockStore + Send + Sync>,
        device_id: &str,
        signing_key: SigningKey,
    ) -> Self {
        let emitter = Arc::new(ChangeEmitter::new(device_id.to_string(), signing_key));
        Self { state, store, device_id: device_id.to_string(), emitter }
    }

    /// Commits a single-block file `Create` into the DAG exactly as the daemon
    /// producer would: store the content block, build the `FileVersion` the same
    /// way `LocalChangeProcessor::content_op` does (block hash + size + the given
    /// `mtime`), then emit the signed `Change` and upsert the index row via
    /// `SyncState::upsert_file_emitting_change`.
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
        self.state.record_group_block_provenance(group_id, std::slice::from_ref(&hash)).unwrap();
        let size = content.len();

        let version = FileVersion::new(
            vec![VersionBlock { hash: BlockHash(hash.clone()), size: size as u32 }],
            size as u64,
            FileMeta {
                mtime_unix_nanos,
                exec_bit: false,
                symlink_target: None,
                record_kind: RecordKind::File,
            },
        );
        let op = Op::Create { path: SyncPath(path.to_string()), version: version.version_hash };

        let mut vv = VersionVector::new();
        vv.increment(&self.device_id);
        let record = FileRecord {
            path: path.to_string(),
            size: size as u64,
            mtime_unix_nanos,
            version: vv,
            blocks: vec![BlockInfo { hash, offset: 0, size: size as u32 }],
            deleted: false,
        };

        self.state
            .upsert_file_emitting_change(
                group_id,
                &record,
                &self.device_id,
                yadorilink_sync_core::index::ChangeContent {
                    ops: vec![op],
                    versions: std::slice::from_ref(&version),
                },
                // A plain single-block file carries no special local metadata
                // columns (kind=File, no symlink, exec-bit clear), so pass no
                // meta — matching the `dag_store` unit test's File-create call.
                None,
                &self.emitter,
            )
            .expect("emit signed change and upsert index row");
        record
    }

    /// Commits an empty (zero-block) file `Create`. The receiving peer needs no
    /// `BlockRequest` to materialize it, so — unlike [`commit_create`] — this
    /// one never blocks on a `BlockResponse`. That makes it usable as an
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
                exec_bit: false,
                symlink_target: None,
                record_kind: RecordKind::File,
            },
        );
        let op = Op::Create { path: SyncPath(path.to_string()), version: version.version_hash };
        let mut vv = VersionVector::new();
        vv.increment(&self.device_id);
        let record = FileRecord {
            path: path.to_string(),
            size: 0,
            mtime_unix_nanos,
            version: vv,
            blocks: vec![],
            deleted: false,
        };
        self.state
            .upsert_file_emitting_change(
                group_id,
                &record,
                &self.device_id,
                yadorilink_sync_core::index::ChangeContent {
                    ops: vec![op],
                    versions: std::slice::from_ref(&version),
                },
                None,
                &self.emitter,
            )
            .expect("emit signed change and upsert index row");
        (record, version)
    }

    /// The wire `ChangeBatch` carrying the single change [`commit_create`] just
    /// emitted, for a scenario that must inject changes into a peer *by hand*
    /// rather than through a `PeerSyncSession`'s own heads-announce loop —
    /// e.g. one that has to control exactly when (or whether) it answers the
    /// resulting `BlockRequest`s. Reads back the group's current head, which
    /// `commit_create` just advanced to the change it emitted.
    ///
    /// One batch per call, deliberately: a caller wanting N changes to occupy N
    /// separate receive permits needs N separate wire messages, since a single
    /// batch is processed under one permit no matter how many changes it holds.
    pub fn last_commit_as_wire_batch(
        &self,
        group_id: &str,
        version: &FileVersion,
    ) -> proto::ChangeBatch {
        let heads = self.state.dag_group_heads(group_id).expect("read group heads");
        assert_eq!(heads.len(), 1, "expected a single head right after a local commit");
        let change = self
            .state
            .dag_get_change(&heads[0])
            .expect("read the just-committed change")
            .expect("the just-committed change must be present");
        proto::ChangeBatch {
            folder_group_id: group_id.to_string(),
            changes: vec![change.to_wire_bytes()],
            compression: proto::Compression::None as i32,
            compressed_changes: Vec::new(),
            file_versions: vec![version.canonical_encoding()],
        }
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
                exec_bit: false,
                symlink_target: None,
                record_kind: RecordKind::File,
            },
        );
        (record, version)
    }
}
