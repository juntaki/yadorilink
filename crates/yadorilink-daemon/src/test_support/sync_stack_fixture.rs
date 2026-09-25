//! The two-device assembly every stack-level scenario starts from.
//!
//! A device here is the real thing: a `ReplicaCoordinator`, a
//! `SegmentBlockStore`, a `DaemonState`, a device signing key, and a netmap
//! entry pinning its peer. What the fixture stands in for is the *policy
//! chain* -- the verified group policy a real daemon would have received --
//! because reproducing one is a separate subject with its own tests, and
//! every group would otherwise resolve to `Withhold` the moment a netmap
//! named a writer for it.
//!
//! # Why this is not in `sync_adapter`
//!
//! It was, as `#[cfg(test)]` helpers beside the tests that first needed
//! them. `#[cfg(test)]` is crate-local: a test *binary* under `tests/`
//! compiles against this crate as an ordinary library, with `cfg(test)` off,
//! and so could not see them. That is why the stack-level partition scenario
//! had to live inside `src/` -- not because it belonged there, but because
//! its fixtures did.
//!
//! Gated `#[cfg(any(test, feature = "test-support"))]`, so this is not
//! production API: the only callers that can reach it are this crate's own
//! unit tests and a dependant that asked for the feature. This crate is
//! already its own dev-dependency with `test-support` on, so its integration
//! binaries get it without any further arrangement.
//!
//! # The authority key
//!
//! `authority_key` and `GROUP` live here rather than being borrowed from a
//! test module, because [`FixtureAuthenticator`] and
//! [`honest_bundle_carrying`] have to agree on both or nothing verifies.
//! Keeping the signer and the thing that accepts its signature in one file
//! is what makes that agreement checkable by reading.

use std::sync::Arc;

use ed25519_dalek::{SigningKey, VerifyingKey};
use yadorilink_lane_ports::sim_fault::EndpointId;
use yadorilink_local_storage::SegmentBlockStore;
use yadorilink_peer_session::peer_session::ChangeAuthenticator;
use yadorilink_replica_domain::authorization_checkpoint::{
    build_merkle_proof, encode_merkle_proof, fingerprint_signing_key, merkle_root, sign_checkpoint,
    AuthorizationCheckpoint,
};
use yadorilink_replica_domain::change::{Change, Op};
use yadorilink_replica_domain::file::{FileMeta, FileVersion, RecordKind, VersionBlock};
use yadorilink_replica_domain::ids::{BlockHash, ChangeHash, DeviceId, FolderGroupId, SyncPath};
use yadorilink_replica_domain::test_authoring::create_signed_for_tests;
use yadorilink_sync_sqlite::verified_change_store::{
    self, VerifiedChangeBundle, VerifiedCheckpoint,
};

use crate::daemon_state::DaemonState;
use crate::replica_coordinator::ReplicaCoordinator;

/// The one group every fixture device is a member of.
pub const GROUP: &str = "g";

/// The device id the fixture's Changes are authored under.
///
/// Distinct from the `DaemonState` device names a scenario picks: this is who
/// the Change says wrote it, and it is fixed so a bundle built on one device
/// verifies on another.
pub const DEVICE: &str = "device-A";

/// The key the fixture's Changes are signed with.
pub fn author_key() -> SigningKey {
    SigningKey::from_bytes(&[9u8; 32])
}

/// The key whose signature over a checkpoint makes a fixture bundle honest.
pub fn authority_key() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

/// Resolves the fixture authority key for the fixture group, and nothing else.
///
/// Deliberately not `NetmapChangeAuthenticator`: resolving a real signer
/// requires a verified group-policy chain, which has its own tests and is not
/// what a stack-level scenario is about. Production uses the real one.
#[derive(Debug)]
pub struct FixtureAuthenticator;

impl ChangeAuthenticator for FixtureAuthenticator {
    fn resolve_authority_key(
        &self,
        group_id: &str,
        signer_key_id: &[u8; 32],
        _policy_head: &[u8; 32],
    ) -> Option<VerifyingKey> {
        let authority = authority_key().verifying_key();
        let expected = fingerprint_signing_key(&authority);
        (group_id == GROUP && *signer_key_id == expected).then_some(authority)
    }
}

/// A real device: coordinator, block store, state, signing key, policy
/// bootstrap.
///
/// The returned `TempDir` is the block store's, and dropping it takes the
/// store's files with it -- so a caller has to hold it for as long as the
/// device is expected to work.
pub fn device(name: &str, key_byte: u8) -> (Arc<DaemonState>, tempfile::TempDir) {
    let store_dir = tempfile::tempdir().unwrap();
    let store = Arc::new(SegmentBlockStore::new(store_dir.path()).unwrap());
    let coordinator = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    let state = DaemonState::new(name.into(), coordinator, store);
    state.set_device_signing_key(SigningKey::from_bytes(&[key_byte; 32]));
    // Disclosure needs a group this device may serve at all, not just a peer
    // it may serve to. A real daemon gets that from a verified policy chain;
    // here the fixture stands in for one. Without it every group resolves to
    // `Withhold` the moment a netmap names a writer for it, which is correct
    // production behaviour.
    state.authority.install_test_group_policy_bootstrap(GROUP);
    (state, store_dir)
}

/// The endpoint identity a device built with `key_byte` will have.
///
/// `SyncStack::spawn` hands the device signing key straight to the substrate
/// node, so a device's endpoint id *is* the public half of its signing key.
/// Written that way rather than by asking iroh to derive it, because the
/// equality is the fact worth stating: it is what lets a scenario declare a
/// partition against a device that has not started yet.
pub fn endpoint_of(key_byte: u8) -> EndpointId {
    let public = SigningKey::from_bytes(&[key_byte; 32]).verifying_key().to_bytes();
    EndpointId::from_bytes(&public).expect("an ed25519 public key is a valid endpoint id")
}

/// Pin `peer` in `local`'s netmap and authorize it for the group, exactly as
/// an authenticated netmap entry would.
pub fn pin(local: &DaemonState, peer_name: &str, peer_key: u8) {
    let key = SigningKey::from_bytes(&[peer_key; 32]).verifying_key().to_bytes();
    local.record_peer_signing_key(peer_name, key);
    local.replace_peer_netmap_metadata(
        peer_name,
        Some(key),
        &std::iter::once(GROUP.to_string()).collect(),
        &Default::default(),
    );
}

/// The Changes this device can serve for `group` -- what "it has it" means.
pub fn possessed(state: &DaemonState, group: &FolderGroupId) -> Vec<ChangeHash> {
    state
        .replica_coordinator
        .database()
        .read::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            verified_change_store::servable_change_hashes(conn, group)
        })
        .unwrap()
}

pub fn init_staging_schema(state: &DaemonState) {
    state
        .replica_coordinator
        .database()
        .write::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            verified_change_store::init_verified_change_schema(conn)
        })
        .unwrap();
}

/// Stages a verified bundle on `state`, as an admitted Change.
///
/// `seq` is the staging sequence the caller is responsible for advancing;
/// two bundles staged under one `seq` is a fixture bug, not a product one.
pub fn stage(state: &DaemonState, bundle: VerifiedChangeBundle, seq: i64) {
    state
        .replica_coordinator
        .database()
        .write_immediate::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            verified_change_store::stage_verified_bundles(conn, std::slice::from_ref(&bundle), seq)
        })
        .unwrap();
}

pub fn change_touching(paths: &[&str]) -> Change {
    create_signed_for_tests(
        vec![],
        0,
        DeviceId(DEVICE.into()),
        FolderGroupId(GROUP.into()),
        paths.iter().map(|path| Op::Delete { path: SyncPath((*path).into()) }).collect(),
        &author_key(),
    )
}

/// A real, structurally valid file version of `size` bytes in one block.
///
/// The version hash is derived from the content, as it is everywhere else --
/// these fixtures never invent an identity, because a version whose hash does
/// not describe its bytes is exactly what the receiving side is supposed to
/// reject.
pub fn file_version(size: u32, seed: u8) -> FileVersion {
    FileVersion::new(
        vec![VersionBlock { hash: BlockHash(vec![seed; 32]), size }],
        size as u64,
        FileMeta {
            mtime_unix_nanos: 1,
            unix_mode: Some(0o644),
            symlink_target: None,
            record_kind: RecordKind::File,
            xattrs: Vec::new(),
        },
    )
}

/// A Change that writes content, and so refers to a file version.
///
/// Most fixtures here use `Op::Delete`, which refers to nothing -- which is
/// exactly why a bundle missing its versions once passed every test and only
/// surfaced in a scale run.
pub fn change_putting(path: &str, version: &FileVersion) -> Change {
    create_signed_for_tests(
        vec![],
        0,
        DeviceId(DEVICE.into()),
        FolderGroupId(GROUP.into()),
        vec![Op::Put {
            path: SyncPath(path.into()),
            version: version.version_hash,
            origin: yadorilink_replica_domain::change::PutOrigin::Direct,
        }],
        &author_key(),
    )
}

/// A genuinely signed, genuinely provable bundle -- the same construction an
/// honest peer would produce.
pub fn honest_bundle(change: Change) -> VerifiedChangeBundle {
    honest_bundle_carrying(change, Vec::new())
}

/// The same, for a Change that refers to file versions. The caller passes
/// exactly the set the Change refers to; anything else is what the contract
/// under test rejects.
pub fn honest_bundle_carrying(change: Change, versions: Vec<FileVersion>) -> VerifiedChangeBundle {
    let hash = change.compute_hash();
    let leaves = vec![hash.0];
    let authority = authority_key();

    let checkpoint = AuthorizationCheckpoint {
        group_id: GROUP.to_string(),
        device_id: DEVICE.to_string(),
        signing_key_fingerprint: fingerprint_signing_key(&author_key().verifying_key()),
        merkle_root: merkle_root(&leaves),
        leaf_count: 1,
        checkpoint_seq: 1,
        signer_key_id: fingerprint_signing_key(&authority.verifying_key()),
        policy_epoch: 0,
        policy_seq: 1,
        policy_head: [0u8; 32],
        issued_at_unix: 1,
    };
    let signature = sign_checkpoint(&checkpoint, &authority);
    let encoded_checkpoint =
        yadorilink_replica_domain::authorization_checkpoint::canonical_signing_bytes(&checkpoint);
    let checkpoint_hash = yadorilink_replica_domain::authorization_checkpoint::checkpoint_hash(
        &encoded_checkpoint,
        &signature,
    );

    VerifiedChangeBundle {
        encoded: change.to_wire_bytes(),
        change,
        checkpoint: VerifiedCheckpoint {
            checkpoint_hash,
            group_id: FolderGroupId(GROUP.into()),
            device_id: DEVICE.into(),
            checkpoint_seq: 1,
            encoded: encoded_checkpoint,
            signature: signature.to_vec(),
            author_signing_public_key: author_key().verifying_key().to_bytes(),
        },
        merkle_proof: encode_merkle_proof(&build_merkle_proof(&leaves, 0)),
        versions,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The agreement the whole module depends on: what the bundle builder
    /// signs, the authenticator accepts -- checked through the real verifier,
    /// not by comparing the two constants. Split across two modules this
    /// held by coincidence; here it holds by test.
    #[test]
    fn a_bundle_this_module_builds_verifies_under_the_authenticator_it_ships_with() {
        let bundle = honest_bundle(change_touching(&["a.txt"]));

        let verified =
            crate::sync_adapter::verify::verify_bundle(&bundle, GROUP, &|key_id, head| {
                FixtureAuthenticator.resolve_authority_key(GROUP, key_id, head)
            });

        assert_eq!(
            verified.expect("the fixture's own bundle must verify under its own authenticator"),
            bundle.change.compute_hash()
        );
    }

    /// And rejects anything else, so a scenario cannot pass on a bundle no
    /// real policy chain would have authorized.
    #[test]
    fn the_authenticator_rejects_another_group_and_another_signer() {
        let expected = fingerprint_signing_key(&authority_key().verifying_key());

        assert_eq!(
            FixtureAuthenticator.resolve_authority_key("another-group", &expected, &[0u8; 32]),
            None
        );
        assert_eq!(
            FixtureAuthenticator.resolve_authority_key(GROUP, &[0xAA; 32], &[0u8; 32]),
            None
        );
    }

    /// A device starts with nothing servable, so a scenario asserting that a
    /// Change arrived is not reading a row the fixture planted.
    // `device` builds a real `DaemonState`, which supervises tasks.
    #[tokio::test]
    async fn a_fresh_device_possesses_nothing() {
        let (state, _dir) = device("device-fresh", 1);
        init_staging_schema(&state);

        assert!(possessed(&state, &FolderGroupId(GROUP.into())).is_empty());
    }

    /// Staging is what makes a Change servable, and the fixture's own
    /// staging path is the one every scenario authors through.
    // `device` builds a real `DaemonState`, which supervises tasks.
    #[tokio::test]
    async fn a_staged_bundle_becomes_servable() {
        let (state, _dir) = device("device-author", 2);
        init_staging_schema(&state);
        let group = FolderGroupId(GROUP.into());

        let version = file_version(4096, 0x11);
        let change = change_putting("a.bin", &version);
        let hash = change.compute_hash();
        stage(&state, honest_bundle_carrying(change, vec![version]), 1);

        assert!(possessed(&state, &group).contains(&hash));
    }

    /// The endpoint a scenario partitions is the endpoint the device will
    /// actually have. If these ever diverge, a partition would be declared
    /// against nothing, every network fault would silently do nothing, and
    /// the scenario would pass by never being cut.
    // `device` builds a real `DaemonState`, which supervises tasks.
    #[tokio::test]
    async fn the_predicted_endpoint_is_the_one_the_device_key_yields() {
        let key_byte = 11u8;
        let (state, _dir) = device("device-endpoint", key_byte);

        let signing = state.device_signing_key().expect("the fixture set one");
        assert_eq!(
            endpoint_of(key_byte).as_bytes(),
            &signing.verifying_key().to_bytes(),
            "the endpoint a scenario cuts is not the one this device will bind"
        );
    }
}

// ---------------------------------------------------------------------------
// Local capture: what a device writes to disk, as a Change it signed itself.
// ---------------------------------------------------------------------------
//
// Everything above builds a Change on the caller's behalf and stages it as
// already-verified. That is enough to ask whether the stack carries a Change,
// and not enough to ask whether the product notices a file. A `Case`'s `Op`
// is filesystem-level, so running one means running the pipeline production
// runs:
//
// ```text
// filesystem event
//   -> LocalChangeProcessor + ChangeEmitter   (a Change this device signed)
//   -> Pending
//   -> flush_pending_checkpoint               (Pending -> Published)
//   -> note_local_commit_for_group
//   -> ReconciliationDriver -> SyncStack -> RBSR
// ```
//
// The `Pending` step is not a formality: a Pending Change is not servable
// over RBSR, so a scenario that captures a local write and stops there has
// built something the peer can never receive.

use std::future::Future;
use std::pin::Pin;
use std::sync::Mutex;

use yadorilink_local_capture::LocalChangeProcessor;
use yadorilink_sync_sqlite::dag_store::ChangeEmitter;

use crate::checkpoint_source::{flush_pending_checkpoint, CheckpointSource, FlushOutcome};

/// This device's own local-capture processor, signing with the device key
/// `DaemonState` already holds.
///
/// Derived from `state.device_signing_key()` rather than from a parallel
/// generator. A device's signing key is also its substrate endpoint identity
/// (see [`endpoint_of`]), so a fixture that minted a second key for change
/// authoring would give one device two identities and make a partition
/// declared against one of them miss the other.
pub fn local_capture(state: &Arc<DaemonState>) -> Arc<LocalChangeProcessor> {
    let signing = state.device_signing_key().expect("the fixture's device has a signing key");
    Arc::new(
        LocalChangeProcessor::new(
            state.replica_coordinator.clone(),
            Arc::new(crate::adapters::block_store_ports::BlockStorePortsAdapter::new(
                state.block_store.clone(),
            )),
            state.device_id.clone(),
            Arc::new(yadorilink_root_authority::root_commit::RootLease::for_tests()),
        )
        .with_change_emitter(Arc::new(ChangeEmitter::new(state.device_id.clone(), signing))),
    )
}

/// A coordination plane that issues checkpoints signed by [`authority_key`].
///
/// A fake source rather than a fake flush: `flush_pending_checkpoint` is the
/// production primitive that turns Pending into Published, and it verifies
/// every leaf against the checkpoint before attaching anything. Reaching
/// Published by calling that with a stand-in issuer exercises the primitive;
/// attaching evidence directly would skip the thing under test.
///
/// The one key it signs with is [`authority_key`], which is what
/// [`FixtureAuthenticator`] resolves -- so a Change published here verifies
/// on the peer without any second arrangement.
pub struct FixtureCheckpointSource {
    device_signing_public_key: VerifyingKey,
    next_seq: Mutex<u64>,
}

impl FixtureCheckpointSource {
    /// `state` is the device whose Changes this source will authorize: a
    /// checkpoint names the signing key of the device it covers, and a real
    /// coordination plane knows it because the device enrolled with it.
    pub fn for_device(state: &DaemonState) -> Self {
        Self {
            device_signing_public_key: state
                .device_signing_key()
                .expect("the fixture's device has a signing key")
                .verifying_key(),
            next_seq: Mutex::new(0),
        }
    }
}

impl CheckpointSource for FixtureCheckpointSource {
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
            let seq = {
                let mut next = self.next_seq.lock().expect("checkpoint seq lock");
                *next += 1;
                *next
            };
            let authority = authority_key();
            let checkpoint = AuthorizationCheckpoint {
                group_id: group_id.to_string(),
                device_id: device_id.to_string(),
                signing_key_fingerprint: fingerprint_signing_key(&self.device_signing_public_key),
                merkle_root,
                leaf_count,
                checkpoint_seq: seq,
                signer_key_id: fingerprint_signing_key(&authority.verifying_key()),
                policy_epoch: 0,
                policy_seq: 1,
                policy_head: [0u8; 32],
                issued_at_unix: 1,
            };
            let signature = sign_checkpoint(&checkpoint, &authority);
            Some((checkpoint, signature))
        })
    }
}

/// Moves this device's Pending Changes for `group` to Published, through the
/// production primitive.
///
/// Named as a step a scenario takes rather than folded into `author`, because
/// it is a step production takes too -- `broadcast_change` flushes the
/// pending checkpoint before raising the local commit -- and a scenario that
/// skips it has Changes RBSR will not serve.
pub async fn publish_local_pending(
    state: &Arc<DaemonState>,
    source: &dyn CheckpointSource,
    group: &str,
) -> FlushOutcome {
    let signing = state.device_signing_key().expect("the fixture's device has a signing key");
    let authority = authority_key().verifying_key();
    let expected = fingerprint_signing_key(&authority);
    flush_pending_checkpoint(
        &state.replica_coordinator.database(),
        source,
        group,
        &state.device_id,
        &signing.verifying_key(),
        &move |key_id: &[u8; 32], _policy_head: &[u8; 32]| {
            (*key_id == expected).then_some(authority)
        },
    )
    .await
    .expect("the fixture's own checkpoint must verify against its own authority")
}

/// Links `root` as this device's folder for [`GROUP`], the way linking it
/// would.
///
/// Three things, none optional, each one a state the daemon cannot be in
/// without it:
///
/// * The link row. A session's sync roots are derived from the link table, so
///   a device holding a root with no link row is a state production cannot
///   produce, and the apply path refuses to write for it.
/// * `VerifiedRoot::open`, which adopts the root token. Without it the local
///   capture refuses the root outright -- "the link has no previously-adopted
///   root token" -- and indexes nothing, which is correct: an unadopted root
///   might be a different folder that happens to sit at the same path.
/// * A completed startup. A daemon never leaves a live link without a
///   readiness gate, and peer apply defers for a live link that has none, so
///   a link made with a bare `add_link` silently defers everything for the
///   whole test budget.
/// * A live `RootCommitAuthority`. Production gets this from the `RootLease`
///   the link runtime creates in `start_link_watch`; a device without one
///   cannot commit a projection for the group, so it holds and serves
///   Changes and writes nothing -- which looks exactly like a broken
///   projection path and is not one.
///
/// The same three steps as `peer_session_fixture::link_with_completed_startup`,
/// for this fixture's own group. Not shared, because that one hard-codes its
/// own `GROUP` and the two fixtures name different groups; what is worth
/// sharing is the reasoning above, and it is written down in both places.
/// Returns the path the link was actually made under, which is `root`
/// canonicalised.
///
/// Returned rather than discarded because the difference bites. The link row,
/// the adopted root token and the readiness gate are all keyed by the
/// canonical path, while the local capture resolves an event against whatever
/// root its caller hands it -- so a caller that keeps its own uncanonical
/// path and passes that to `process_event` is describing a folder the daemon
/// has no link for, and captures nothing. On Linux a `tempfile::tempdir()`
/// under `/tmp` is already canonical and the two coincide; on macOS it is
/// `/var/folders/...`, a symlink to `/private/var/folders/...`, and they
/// never do. Taking the return value is how a caller stops holding the wrong
/// one.
#[must_use = "the link was made under the canonical path; using the original \
              path instead is what makes the capture find no link"]
pub fn link_folder(state: &DaemonState, root: &std::path::Path) -> std::path::PathBuf {
    let canonical = root.canonicalize().expect("the linked folder exists");
    let coordinator = &state.replica_coordinator;
    coordinator.link_repository().add_link(&canonical.to_string_lossy(), GROUP).unwrap();
    yadorilink_root_authority::root_identity::VerifiedRoot::open(
        &canonical,
        GROUP,
        coordinator.as_ref(),
    )
    .expect("adopt a root token for the linked folder");
    let generation = coordinator.startup_readiness().begin_group_startup(GROUP);
    coordinator.startup_readiness().mark_group_ready(GROUP, generation);
    state.install_test_root_commit_authority(GROUP);
    canonical
}

/// A linked folder with the production watcher-to-capture pipeline behind it.
///
/// The whole point is that a scenario writes a file and does nothing else.
/// Everything between the write and the peer is production code:
///
/// ```text
/// std::fs::write
///   -> FsChangeEvent            (what the OS watcher would have produced)
///   -> debounce::run_debouncer  (real quiet period, real coalescing)
///   -> LocalChangeProcessor::process_flush
///   -> Pending
///   -> flush_pending_checkpoint -> Published
///   -> ReconciliationDriver::note_local_change
/// ```
///
/// The last two steps are what `DaemonState::broadcast_change` does in
/// production, in that order, and they are here rather than in the scenario
/// because a scenario that forgot either would produce a Change RBSR cannot
/// serve and a failure that reads like a network problem.
///
/// The simulated watch source rather than a real OS watcher: a test that
/// waited for inotify would be measuring the kernel, and on macOS or Windows
/// it would be measuring something else again. What is under test is the
/// debounce boundary and everything after it, and `SimulatedFolderWatchSource`
/// is the seam production itself uses to stand in for the OS.
pub struct WatchedFolder {
    /// Owned for its lifetime only, and `None` when the caller supplied the
    /// directory. Every path this type hands out or reports comes from
    /// `canonical` instead -- see [`WatchedFolder::path`].
    _root: Option<tempfile::TempDir>,
    canonical: std::path::PathBuf,
    events: tokio::sync::mpsc::Sender<yadorilink_filesystem_sync::watcher::FsChangeEvent>,
    /// What the registered link runtime's flush handle reaches the daemon
    /// through, held here because the handle only holds it weakly. `None`
    /// unless the folder was made by [`watch_folder_with_pending_flush`].
    _flush_dependencies: Option<Arc<crate::link_runtime::dependencies::LinkRuntimeDependencies>>,
}

impl WatchedFolder {
    /// The folder, by the name the capture pipeline knows it under.
    ///
    /// Canonical, and that is not a detail. `process_flush` is given the
    /// canonical root, and it resolves each event's path *relative to that
    /// root*; an event naming the same file by an uncanonical path is outside
    /// the root as far as the capture is concerned, and is dropped. The device
    /// then produces no Change at all, which reads exactly like a broken
    /// capture pipeline.
    ///
    /// On Linux a `tempfile::tempdir()` under `/tmp` is already canonical and
    /// the distinction never shows. On macOS the same call returns
    /// `/var/folders/...`, which is a symlink to `/private/var/folders/...`,
    /// so the two differ on every single event: four tests that pass here fail
    /// there, deterministically, with "the local capture did not produce a
    /// Change". Reported by the macOS lane rather than found locally, which is
    /// the only way this class gets found.
    ///
    /// So the uncanonical path is not exposed at all -- the `TempDir` is kept
    /// private and only for its lifetime. A caller cannot reach the wrong path
    /// to pass it back in.
    pub fn path(&self) -> &std::path::Path {
        &self.canonical
    }

    /// Reports a path to the watcher, exactly as the OS would have.
    ///
    /// Separate from the write so a caller that already performed the
    /// filesystem change -- `dst_support::op_applier::apply_op`, which is
    /// what turns a `Case`'s `Op` into disk state -- can report it without
    /// this type having to know what a `Case` is.
    ///
    /// Always called after the change, never before: the capture re-stats
    /// the path, so an event that arrives first describes a file that is not
    /// there yet and is correctly ignored.
    pub async fn notify(
        &self,
        path: std::path::PathBuf,
        kind: yadorilink_filesystem_sync::watcher::FsChangeKind,
    ) {
        self.events
            .send(yadorilink_filesystem_sync::watcher::FsChangeEvent { path, kind })
            .await
            .expect("the watcher channel outlives the folder");
    }

    /// Writes `contents` at `relative` and tells the watcher.
    pub async fn write(&self, relative: &str, contents: &[u8]) {
        use yadorilink_filesystem_sync::watcher::FsChangeKind;
        let path = self.path().join(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("the file's parent directory");
        }
        std::fs::write(&path, contents).expect("write the file the device should notice");
        self.notify(path, FsChangeKind::CreatedOrModified).await;
    }

    /// Deletes `relative` and tells the watcher.
    pub async fn remove(&self, relative: &str) {
        use yadorilink_filesystem_sync::watcher::FsChangeKind;
        let path = self.path().join(relative);
        std::fs::remove_file(&path).expect("remove the file the device should notice");
        self.notify(path, FsChangeKind::Removed).await;
    }
}

/// Links a fresh folder for `state` and starts the capture pipeline over it.
///
/// `driver` is this device's own reconciliation driver: the executor raises
/// the local-commit event on it after publishing, which is the one push
/// production makes. Nothing in the returned handle calls `sync_with`.
pub fn watch_folder(
    state: &Arc<DaemonState>,
    driver: &Arc<crate::sync_adapter::ReconciliationDriver>,
) -> WatchedFolder {
    watch_folder_over(state, driver, own_temp_dir(), false)
}

/// [`watch_folder`], with the folder also registered as the group's link
/// runtime, so the pending-change flush production runs before projecting
/// over a path -- `PendingLocalChangeFlush` on `DaemonState` -- reaches this
/// folder's debouncer.
///
/// A change that flush forces through capture is announced the way
/// production announces it, and `broadcast_change` finds no coordination
/// plane here to publish it with: it stays Pending until the caller
/// publishes it (`publish_local_pending`).
pub fn watch_folder_with_pending_flush(
    state: &Arc<DaemonState>,
    driver: &Arc<crate::sync_adapter::ReconciliationDriver>,
) -> WatchedFolder {
    watch_folder_over(state, driver, own_temp_dir(), true)
}

/// [`watch_folder`], over a directory the caller already has.
///
/// For the cases where *which* directory it is matters -- a root reached
/// through a symlink, a folder that has to outlive the handle, or a second
/// handle onto an existing one.
pub fn watch_folder_at(
    state: &Arc<DaemonState>,
    driver: &Arc<crate::sync_adapter::ReconciliationDriver>,
    root: &std::path::Path,
) -> WatchedFolder {
    watch_folder_over(state, driver, (None, root.to_path_buf()), false)
}

/// A fresh directory and the path to reach it by, separately, because the
/// path has to outlive the move of the `TempDir` into the handle.
fn own_temp_dir() -> (Option<tempfile::TempDir>, std::path::PathBuf) {
    let root = tempfile::tempdir().expect("a linked folder");
    let path = root.path().to_path_buf();
    (Some(root), path)
}

fn watch_folder_over(
    state: &Arc<DaemonState>,
    driver: &Arc<crate::sync_adapter::ReconciliationDriver>,
    (owned_root, root): (Option<tempfile::TempDir>, std::path::PathBuf),
    register_pending_flush: bool,
) -> WatchedFolder {
    let root = root.as_path();
    use yadorilink_filesystem_sync::debounce::{self, DebounceConfig};
    use yadorilink_filesystem_sync::watcher::{FolderWatchSource, SimulatedFolderWatchSource};

    let canonical = link_folder(state, root);

    let (watch_source, events) = SimulatedFolderWatchSource::new(32);
    let ignore_set =
        Arc::new(yadorilink_root_authority::ignore_patterns::EffectiveIgnoreSet::defaults_only());
    let watcher = watch_source.watch(&canonical, ignore_set).expect("watch the linked folder");
    let (events_rx, overflowed, guard) = watcher.split();
    // The guard keeps the watch alive; the folder outlives it by construction
    // because `WatchedFolder` owns the TempDir the watch is over.
    Box::leak(Box::new(guard));

    let (flush_tx, mut flush_rx) =
        tokio::sync::mpsc::channel(debounce::DEFAULT_EXECUTOR_CHANNEL_CAPACITY);
    let (flush_request_tx, flush_request_rx) = tokio::sync::mpsc::channel(4);
    let (flush_all_request_tx, flush_all_request_rx) = tokio::sync::mpsc::channel(4);
    tokio::spawn(debounce::run_debouncer(
        DebounceConfig::default(),
        events_rx,
        flush_tx,
        overflowed,
        flush_request_rx,
        flush_all_request_rx,
    ));

    let processor = local_capture(state);
    let flush_dependencies = register_pending_flush.then(|| {
        let dependencies = state.link_runtime_dependencies();
        let local_path = canonical.to_string_lossy().to_string();
        let root_lease = Arc::new(yadorilink_root_authority::root_commit::RootLease::for_tests());
        let flush_handle =
            crate::link_runtime::operations::capture_local_change::LinkFlushHandle::new(
                &dependencies,
                flush_request_tx.clone(),
                flush_all_request_tx.clone(),
                processor.clone(),
                canonical.clone(),
                local_path.clone(),
                root_lease.clone(),
            );
        crate::link_registry::LinkRegistry::reserve_starting(&state.links, local_path)
            .expect("nothing else runs this folder")
            .publish(Arc::new(crate::link_runtime::LinkRuntime::new(
                Vec::new(),
                Arc::new(flush_handle),
                root_lease,
            )));
        dependencies
    });
    drop((flush_request_tx, flush_all_request_tx));
    let source = FixtureCheckpointSource::for_device(state);
    let (executor_state, executor_driver) = (state.clone(), driver.clone());
    let capture_root = canonical.clone();
    tokio::spawn(async move {
        let group = yadorilink_replica_domain::ids::FolderGroupId(GROUP.into());
        while let Some(flush) = flush_rx.recv().await {
            let Ok(outcome) = processor.process_flush(GROUP, &capture_root, flush).await else {
                continue;
            };
            if outcome.records.is_empty() {
                continue;
            }
            // Exactly what `broadcast_change` does, in this order. Publishing
            // first is not a nicety: a Pending Change is not servable, so
            // raising the commit before the flush would wake a driver that
            // has nothing to offer.
            publish_local_pending(&executor_state, &source, GROUP).await;
            executor_driver.note_local_change(&group);
        }
    });

    WatchedFolder { _root: owned_root, canonical, events, _flush_dependencies: flush_dependencies }
}
