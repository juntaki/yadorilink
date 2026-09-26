//! The receive path end to end: encode, decode, verify, stage.

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use yadorilink_rbsr::ItemId;
use yadorilink_replica_domain::authorization_checkpoint::{
    build_merkle_proof, encode_merkle_proof, fingerprint_signing_key, merkle_root, sign_checkpoint,
    AuthorizationCheckpoint,
};
use yadorilink_replica_domain::change::{Change, Op};
use yadorilink_replica_domain::file::FileVersion;
use yadorilink_replica_domain::ids::{DeviceId, FolderGroupId, SyncPath};
use yadorilink_replica_domain::test_authoring::create_signed_for_tests;
use yadorilink_sqlite_runtime::SyncDatabase;
use yadorilink_sync_protocol::ports::{GroupId, PeerKey, ReplicaPort};
use yadorilink_sync_protocol::wire::OpaqueBundle;
use yadorilink_sync_sqlite::verified_change_store::{VerifiedChangeBundle, VerifiedCheckpoint};

use super::bundle_codec;
use super::replica_port::{AuthorityResolver, SqliteReplicaPort};
use super::verify::{verify_bundle, BundleVerifyError};
use yadorilink_lane_ports::StaticPeerDirectory;
use yadorilink_replica_domain::proof_carrying::ProofVerificationError;

// The group, the two keys and the Change/bundle builders now live in
// `test_support::sync_stack_fixture`, so a scenario under `tests/` can reach
// them -- `#[cfg(test)]` is crate-local and a test binary compiles against
// this crate as a library. Re-exported rather than rewritten at ~200 call
// sites in this file.
pub(super) use crate::test_support::sync_stack_fixture::{
    author_key, authority_key, change_putting, change_touching, file_version, honest_bundle,
    honest_bundle_carrying, DEVICE, GROUP,
};

const PEER_ENDPOINT: [u8; 32] = [0xE1; 32];

fn resolver() -> AuthorityResolver {
    let authority = authority_key().verifying_key();
    let signer_key_id = fingerprint_signing_key(&authority);
    Arc::new(move |group: &str, key_id: &[u8; 32], _policy_head: &[u8; 32]| {
        (group == GROUP && *key_id == signer_key_id).then_some(authority)
    })
}

fn verify(
    bundle: &VerifiedChangeBundle,
) -> Result<yadorilink_replica_domain::ids::ChangeHash, BundleVerifyError> {
    let resolver = resolver();
    verify_bundle(bundle, GROUP, &move |key_id, head| resolver(GROUP, key_id, head))
}

// --- codec -----------------------------------------------------------------

#[test]
fn a_bundle_round_trips_through_the_codec() {
    let bundle = honest_bundle(change_touching(&["a.txt"]));
    let encoded = bundle_codec::encode(&bundle).unwrap();
    let decoded = bundle_codec::decode(&encoded).unwrap();

    assert_eq!(decoded.encoded, bundle.encoded);
    assert_eq!(decoded.checkpoint, bundle.checkpoint);
    assert_eq!(decoded.merkle_proof, bundle.merkle_proof);
    assert_eq!(decoded.change_hash(), bundle.change_hash());
}

/// Bytes arrive from a peer that may be adversarial, so a declared length is a
/// claim and never an instruction. Cutting the frame anywhere must be refused
/// rather than partially decoded.
#[test]
fn a_truncated_bundle_is_rejected_at_every_offset() {
    let encoded = bundle_codec::encode(&honest_bundle(change_touching(&["a.txt"]))).unwrap();
    for cut in 0..encoded.len() {
        assert!(
            bundle_codec::decode(&encoded[..cut]).is_err(),
            "a bundle cut to {cut} bytes must not decode"
        );
    }
}

#[test]
fn trailing_bytes_after_a_bundle_are_rejected() {
    let mut encoded = bundle_codec::encode(&honest_bundle(change_touching(&["a.txt"]))).unwrap();
    encoded.push(0);
    assert!(matches!(
        bundle_codec::decode(&encoded),
        Err(bundle_codec::BundleCodecError::TrailingBytes(1))
    ));
}

// --- verification ----------------------------------------------------------

#[test]
fn an_honest_bundle_verifies() {
    let bundle = honest_bundle(change_touching(&["a.txt"]));
    assert_eq!(verify(&bundle).unwrap(), bundle.change.compute_hash());
}

/// Nothing about the connection is an input to verification, so the same
/// bundle verifies identically no matter which peer handed it over. This is
/// what makes carrier choice provably irrelevant to acceptance.
#[test]
fn verification_does_not_depend_on_who_delivered_the_bundle() {
    let bundle = honest_bundle(change_touching(&["a.txt"]));
    let first = verify(&bundle).unwrap();
    let second = verify(&bundle).unwrap();
    assert_eq!(first, second);
}

#[test]
fn a_bundle_for_another_group_is_refused() {
    let bundle = honest_bundle(change_touching(&["a.txt"]));
    let resolver = resolver();
    let result =
        verify_bundle(&bundle, "another-group", &move |key_id, head| resolver(GROUP, key_id, head));
    assert!(matches!(
        result,
        Err(BundleVerifyError::Proof(ProofVerificationError::GroupMismatch { .. }))
    ));
}

#[test]
fn a_bundle_whose_change_bytes_were_altered_is_refused() {
    // The Change codec is strict — it rejects trailing bytes — so altered
    // bytes are refused at the decode, before anything else examines them.
    let mut appended = honest_bundle(change_touching(&["a.txt"]));
    appended.encoded.push(0);
    assert!(matches!(
        verify(&appended),
        Err(BundleVerifyError::Proof(ProofVerificationError::UndecodableChange(_)))
    ));

    let mut truncated = honest_bundle(change_touching(&["a.txt"]));
    truncated.encoded.pop();
    assert!(matches!(
        verify(&truncated),
        Err(BundleVerifyError::Proof(ProofVerificationError::UndecodableChange(_)))
    ));

    let mut flipped = honest_bundle(change_touching(&["a.txt"]));
    let last = flipped.encoded.len() - 1;
    flipped.encoded[last] ^= 0xFF;
    assert!(verify(&flipped).is_err(), "a flipped byte must not verify");
}

/// The canonical-encoding guard is defence in depth, not a path reachable
/// today: this codec is strict enough that anything which decodes re-encodes
/// to the same bytes, so the check costs one re-encode and never fires. It is
/// kept because a future codec change admitting a second encoding of the same
/// Change would otherwise let a peer store — and re-serve — bytes differing
/// from the ones the Change's hash covers.
#[test]
fn the_canonical_encoding_guard_holds_for_a_genuine_encoding() {
    let bundle = honest_bundle(change_touching(&["a.txt"]));
    assert_eq!(bundle.change.to_wire_bytes(), bundle.encoded);
    assert!(verify(&bundle).is_ok());
}

#[test]
fn a_bundle_whose_checkpoint_signature_was_altered_is_refused() {
    let mut bundle = honest_bundle(change_touching(&["a.txt"]));
    bundle.checkpoint.signature[0] ^= 0xFF;
    assert!(matches!(
        verify(&bundle),
        Err(BundleVerifyError::Proof(ProofVerificationError::CheckpointHashMismatch))
    ));
}

/// The fields carried beside the envelope are what this node would index the
/// checkpoint under. If they could disagree with the signed content, the index
/// would describe something the authority never vouched for.
#[test]
fn a_bundle_whose_carried_fields_disagree_with_the_signed_checkpoint_is_refused() {
    let mut bundle = honest_bundle(change_touching(&["a.txt"]));
    bundle.checkpoint.device_id = "device-Z".into();
    assert!(matches!(
        verify(&bundle),
        Err(BundleVerifyError::EnvelopeDisagreement { field: "device id" })
    ));

    let mut bundle = honest_bundle(change_touching(&["a.txt"]));
    bundle.checkpoint.checkpoint_seq = 99;
    assert!(matches!(
        verify(&bundle),
        Err(BundleVerifyError::EnvelopeDisagreement { field: "checkpoint sequence" })
    ));
}

#[test]
fn a_checkpoint_signed_by_a_key_the_policy_chain_does_not_know_is_refused() {
    let bundle = honest_bundle(change_touching(&["a.txt"]));
    let result = verify_bundle(&bundle, GROUP, &|_key_id, _head| None);
    assert!(matches!(
        result,
        Err(BundleVerifyError::Proof(ProofVerificationError::NotAdmissible(_)))
    ));
}

#[test]
fn a_bundle_carrying_someone_elses_proof_is_refused() {
    let mut bundle = honest_bundle(change_touching(&["a.txt"]));
    let other = honest_bundle(change_touching(&["b.txt"]));
    bundle.merkle_proof = other.merkle_proof;
    bundle.checkpoint = other.checkpoint;
    assert!(matches!(
        verify(&bundle),
        Err(BundleVerifyError::Proof(ProofVerificationError::NotAdmissible(_)))
    ));
}

// --- the port --------------------------------------------------------------

/// The DAG tables first, then `yadorilink_sqlite_runtime::init_schema` (which
/// assumes `changes` exists), then the staging tables — the daemon's own
/// bootstrap order. `local_dirty_paths`, the local capture barrier, comes from
/// the middle step.
fn db() -> Arc<SyncDatabase> {
    Arc::new(
        SyncDatabase::open_in_memory(|conn| {
            yadorilink_sync_sqlite::dag_store::init_dag_schema(conn).map_err(|e| {
                yadorilink_sqlite_runtime::DatabaseError::CorruptSchema(e.to_string())
            })?;
            yadorilink_sqlite_runtime::init_schema(conn)?;
            yadorilink_sync_sqlite::materialized_generation::init_materialized_generation_schema(
                conn,
            )
            .map_err(|e| yadorilink_sqlite_runtime::DatabaseError::CorruptSchema(e.to_string()))?;
            yadorilink_sync_sqlite::verified_change_store::init_verified_change_schema(conn)
                .map_err(|e| yadorilink_sqlite_runtime::DatabaseError::CorruptSchema(e.to_string()))
        })
        .unwrap(),
    )
}

/// The same schema, on a file, so a test can close a database and reopen it.
fn db_at(path: &std::path::Path) -> Arc<SyncDatabase> {
    Arc::new(
        SyncDatabase::open(path, |conn| {
            yadorilink_sync_sqlite::dag_store::init_dag_schema(conn).map_err(|e| {
                yadorilink_sqlite_runtime::DatabaseError::CorruptSchema(e.to_string())
            })?;
            yadorilink_sqlite_runtime::init_schema(conn)?;
            yadorilink_sync_sqlite::materialized_generation::init_materialized_generation_schema(
                conn,
            )
            .map_err(|e| yadorilink_sqlite_runtime::DatabaseError::CorruptSchema(e.to_string()))?;
            yadorilink_sync_sqlite::verified_change_store::init_verified_change_schema(conn)
                .map_err(|e| yadorilink_sqlite_runtime::DatabaseError::CorruptSchema(e.to_string()))
        })
        .unwrap(),
    )
}

fn port(entitled: bool) -> SqliteReplicaPort<StaticPeerDirectory> {
    port_on(db(), entitled)
}

fn store_on(db: Arc<SyncDatabase>) -> super::async_store::AsyncReplicaStore {
    super::async_store::AsyncReplicaStore::new(db, super::async_store::StoreLimits::default())
}

fn port_on(db: Arc<SyncDatabase>, entitled: bool) -> SqliteReplicaPort<StaticPeerDirectory> {
    let mut directory = StaticPeerDirectory::new();
    if entitled {
        directory.bind_endpoint(PEER_ENDPOINT, "device-B");
        directory.authorize("device-B", GROUP);
    }
    SqliteReplicaPort::new(store_on(db), Arc::new(directory), resolver())
}

pub(super) fn frame(bundle: &VerifiedChangeBundle) -> OpaqueBundle {
    OpaqueBundle {
        change_hash: ItemId::from_bytes(bundle.change_hash().0),
        payload: bundle_codec::encode(bundle).unwrap(),
    }
}

fn group() -> GroupId {
    GroupId(GROUP.into())
}

/// An endpoint the coordination plane has not bound to a device is told
/// nothing. Being on the other end of the connection is not evidence of who
/// you are — that is exactly the thing being checked.
#[tokio::test]
async fn an_unbound_endpoint_is_told_nothing() {
    let port = port(false);
    let peer = PeerKey(PEER_ENDPOINT);

    assert!(!port.may_disclose(peer, group()).await.unwrap());
    assert!(port.servable(peer, group()).await.unwrap().is_empty());
    assert!(port.load_bundles(peer, group(), vec![ItemId::MIN]).await.unwrap().is_empty());
}

#[tokio::test]
async fn a_verified_bundle_is_staged_and_becomes_servable() {
    let port = port(true);
    let peer = PeerKey(PEER_ENDPOINT);
    let bundle = honest_bundle(change_touching(&["a.txt"]));
    let hash = ItemId::from_bytes(bundle.change_hash().0);

    let staged = port.stage_bundles(peer, group(), vec![frame(&bundle)]).await.unwrap();
    assert_eq!(staged, vec![hash]);
    assert_eq!(port.servable(peer, group()).await.unwrap(), vec![hash]);

    // And it can be served straight back out: possession is possession,
    // whichever side of promotion it is on.
    let served = port.load_bundles(peer, group(), vec![hash]).await.unwrap();
    assert_eq!(served.len(), 1);
    assert_eq!(served[0].change_hash, hash);
}

#[tokio::test]
async fn redelivering_a_staged_bundle_does_no_work() {
    let port = port(true);
    let peer = PeerKey(PEER_ENDPOINT);
    let bundle = honest_bundle(change_touching(&["a.txt"]));

    assert_eq!(port.stage_bundles(peer, group(), vec![frame(&bundle)]).await.unwrap().len(), 1);
    for _ in 0..5 {
        assert!(port.stage_bundles(peer, group(), vec![frame(&bundle)]).await.unwrap().is_empty());
    }
    assert_eq!(port.servable(peer, group()).await.unwrap().len(), 1);
}

/// A peer must not get the front of a delivery accepted by putting something
/// unverifiable behind it.
#[tokio::test]
async fn a_delivery_with_one_bad_bundle_stages_none_of_itself() {
    let port = port(true);
    let peer = PeerKey(PEER_ENDPOINT);

    let good = honest_bundle(change_touching(&["a.txt"]));
    let mut bad = frame(&honest_bundle(change_touching(&["b.txt"])));
    // Corrupt the payload so verification cannot succeed.
    let last = bad.payload.len() - 1;
    bad.payload[last] ^= 0xFF;

    let result = port.stage_bundles(peer, group(), vec![frame(&good), bad]).await;

    assert!(result.is_err(), "the delivery must be refused");
    assert!(
        port.servable(peer, group()).await.unwrap().is_empty(),
        "the verifiable bundle ahead of the bad one must not have been staged"
    );
}

/// The frame's claim about which Change it carries must match what the
/// verified bytes hash to. Otherwise the requester's "is this what I asked
/// for?" check would be checking a label rather than the content.
#[tokio::test]
async fn a_frame_that_mislabels_its_payload_is_refused() {
    let port = port(true);
    let peer = PeerKey(PEER_ENDPOINT);

    let mut mislabelled = frame(&honest_bundle(change_touching(&["a.txt"])));
    mislabelled.change_hash = ItemId::from_bytes([0xAB; 32]);

    assert!(port.stage_bundles(peer, group(), vec![mislabelled]).await.is_err());
    assert!(port.servable(peer, group()).await.unwrap().is_empty());
}

/// The carrier is not an input to admission, so a bundle that fails
/// verification fails identically whichever peer handed it over — and leaves
/// nothing behind either way.
///
/// The primitive takes no carrier parameter, so this holds by construction for
/// the same input. What this pins is the surrounding path: that the adapter
/// does not reach a different verdict, or a different amount of durable state,
/// depending on who it is talking to.
#[tokio::test]
async fn a_bad_bundle_is_refused_identically_whichever_carrier_delivered_it() {
    const OTHER_ENDPOINT: [u8; 32] = [0xE2; 32];

    let mut directory = StaticPeerDirectory::new();
    directory.bind_endpoint(PEER_ENDPOINT, "device-B");
    directory.bind_endpoint(OTHER_ENDPOINT, "device-C");
    directory.authorize("device-B", GROUP);
    directory.authorize("device-C", GROUP);

    let db = db();
    let port = SqliteReplicaPort::new(store_on(db.clone()), Arc::new(directory), resolver());

    // A forged checkpoint signature, and a proof that belongs to a different
    // Change. Both are refusals the primitive makes with no reference to who
    // delivered them.
    let mut forged_signature = honest_bundle(change_touching(&["a.txt"]));
    forged_signature.checkpoint.signature[0] ^= 0xFF;

    let mut wrong_proof = honest_bundle(change_touching(&["b.txt"]));
    let other = honest_bundle(change_touching(&["c.txt"]));
    wrong_proof.merkle_proof = other.merkle_proof.clone();
    wrong_proof.checkpoint = other.checkpoint.clone();

    for bad in [&forged_signature, &wrong_proof] {
        let mut verdicts = Vec::new();
        for endpoint in [PEER_ENDPOINT, OTHER_ENDPOINT] {
            let peer = PeerKey(endpoint);
            let result = port.stage_bundles(peer, group(), vec![frame(bad)]).await;
            verdicts.push(result.is_err());

            assert!(
                port.servable(peer, group()).await.unwrap().is_empty(),
                "a refused bundle must leave nothing durable behind"
            );
        }
        assert_eq!(
            verdicts,
            vec![true, true],
            "the same bad bundle must be refused by every carrier, not just one"
        );
    }

    assert!(
        port.servable(PeerKey(PEER_ENDPOINT), group()).await.unwrap().is_empty(),
        "no bad bundle may have left anything behind"
    );
}

/// Admission rests on the proof a bundle carries and nothing else. An
/// unverifiable Change is refused even from an entitled peer.
#[tokio::test]
async fn entitlement_does_not_make_an_unverifiable_change_admissible() {
    let port = port(true);
    let peer = PeerKey(PEER_ENDPOINT);

    let mut forged = honest_bundle(change_touching(&["a.txt"]));
    forged.change = change_touching(&["b.txt"]);

    assert!(port.stage_bundles(peer, group(), vec![frame(&forged)]).await.is_err());
    assert!(port.servable(peer, group()).await.unwrap().is_empty());
}

#[tokio::test]
async fn a_key_the_policy_chain_rejects_makes_every_bundle_inadmissible() {
    let mut directory = StaticPeerDirectory::new();
    directory.bind_endpoint(PEER_ENDPOINT, "device-B");
    directory.authorize("device-B", GROUP);

    let port = SqliteReplicaPort::new(
        store_on(db()),
        Arc::new(directory),
        Arc::new(|_group: &str, _key_id: &[u8; 32], _head: &[u8; 32]| None),
    );

    let bundle = honest_bundle(change_touching(&["a.txt"]));
    assert!(port
        .stage_bundles(PeerKey(PEER_ENDPOINT), group(), vec![frame(&bundle)])
        .await
        .is_err());
}

// --- admission liveness ----------------------------------------------------
//
// Two properties, both with every timer and every periodic sweep switched off.
// Nothing in these tests ticks: the only things that happen are a staging, a
// local state change, and a wake.

use super::admission::AdmissionCoordinator;

fn child_of(parent: &Change, paths: &[&str]) -> Change {
    create_signed_for_tests(
        vec![parent.compute_hash()],
        parent.lamport,
        DeviceId(DEVICE.into()),
        FolderGroupId(GROUP.into()),
        paths.iter().map(|path| Op::Delete { path: SyncPath((*path).into()) }).collect(),
        &author_key(),
    )
}

/// A bundle for `change` proved under a checkpoint covering both `change` and
/// its parent, so a parent/child pair can both be honestly staged.
fn honest_pair(parent: &Change, child: &Change) -> (VerifiedChangeBundle, VerifiedChangeBundle) {
    honest_pair_carrying(parent, child, Vec::new())
}

/// The same, where the parent refers to file versions and so must carry them.
fn honest_pair_carrying(
    parent: &Change,
    child: &Change,
    parent_versions: Vec<FileVersion>,
) -> (VerifiedChangeBundle, VerifiedChangeBundle) {
    let mut leaves = vec![parent.compute_hash().0, child.compute_hash().0];
    leaves.sort();
    let authority = authority_key();

    let checkpoint = AuthorizationCheckpoint {
        group_id: GROUP.to_string(),
        device_id: DEVICE.to_string(),
        signing_key_fingerprint: fingerprint_signing_key(&author_key().verifying_key()),
        merkle_root: merkle_root(&leaves),
        leaf_count: leaves.len() as u64,
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

    let build = |change: &Change| {
        let index = leaves.iter().position(|leaf| *leaf == change.compute_hash().0).unwrap();
        VerifiedChangeBundle {
            encoded: change.to_wire_bytes(),
            change: change.clone(),
            checkpoint: VerifiedCheckpoint {
                checkpoint_hash,
                group_id: FolderGroupId(GROUP.into()),
                device_id: DEVICE.into(),
                checkpoint_seq: 1,
                encoded: encoded_checkpoint.clone(),
                signature: signature.to_vec(),
                author_signing_public_key: author_key().verifying_key().to_bytes(),
            },
            merkle_proof: encode_merkle_proof(&build_merkle_proof(&leaves, index)),
            versions: if change.compute_hash() == parent.compute_hash() {
                parent_versions.clone()
            } else {
                Vec::new()
            },
        }
    };

    (build(parent), build(child))
}

fn folder() -> FolderGroupId {
    FolderGroupId(GROUP.into())
}

pub(super) fn is_canonical(db: &SyncDatabase, change: &Change) -> bool {
    let hash = change.compute_hash();
    db.read(|conn| yadorilink_sync_sqlite::dag_store::published_view::is_published(conn, &hash))
        .unwrap()
}

pub(super) fn set_barrier(db: &SyncDatabase, path: &str, open: bool) {
    db.write(|conn| {
        if open {
            conn.execute(
                "INSERT OR REPLACE INTO local_dirty_paths \
                 (group_id, path, change_kind, first_seen_unix_nanos, observed_at_unix_nanos, \
                  attempts) \
                 VALUES (?1, ?2, 'modified', 1, 1, 0)",
                rusqlite::params![GROUP, path],
            )?;
        } else {
            conn.execute(
                "DELETE FROM local_dirty_paths WHERE group_id = ?1 AND path = ?2",
                rusqlite::params![GROUP, path],
            )?;
        }
        Ok::<_, yadorilink_sync_sqlite::SyncSqliteError>(())
    })
    .unwrap();
}

/// Gate: a staged child whose parent is absent promotes when the parent lands,
/// with the network stopped and no periodic maintenance running.
///
/// The delivery side and the admission side have separate liveness: RBSR makes
/// sure nothing delivered stays undiscovered, and this coordinator makes sure
/// nothing promotable stays unpromoted. Neither is a timer.
#[tokio::test]
async fn a_staged_child_promotes_when_its_parent_lands_with_no_network_and_no_timer() {
    let db = db();
    let port = port_on(db.clone(), true);
    let peer = PeerKey(PEER_ENDPOINT);
    let coordinator = AdmissionCoordinator::new(store_on(db.clone()));

    let parent = change_touching(&["a.txt"]);
    let child = child_of(&parent, &["b.txt"]);
    let (parent_bundle, child_bundle) = honest_pair(&parent, &child);

    // Only the child is delivered. Its parent is nowhere.
    port.stage_bundles(peer, group(), vec![frame(&child_bundle)]).await.unwrap();
    coordinator.mark_stale(&folder());

    let first = coordinator.drain(&folder()).await.unwrap().unwrap();
    assert!(first.promoted.is_empty(), "a child with no parent must not be promoted");
    assert!(!is_canonical(&db, &child));

    // The parent arrives. From here on nothing else happens on the network,
    // and no timer fires — only the wake that staging raises.
    port.stage_bundles(peer, group(), vec![frame(&parent_bundle)]).await.unwrap();
    coordinator.mark_stale(&folder());

    let second = coordinator.drain(&folder()).await.unwrap().unwrap();

    assert!(
        is_canonical(&db, &parent) && is_canonical(&db, &child),
        "the parent landing must carry the child through as well"
    );
    assert_eq!(second.promoted.len(), 2);
    assert!(
        second.passes >= 2,
        "the child can only have been promoted by a pass after the parent's, got {} pass(es)",
        second.passes
    );
}

/// Gate: a staged Change blocked by an open local capture barrier promotes
/// when the barrier settles — with the network stopped and no timer.
///
/// An open barrier means a local edit has been observed but not yet turned
/// into a Change. Promoting across it would order the remote Change after
/// content this device has not expressed as history.
#[tokio::test]
async fn a_staged_change_promotes_when_its_capture_barrier_settles_with_no_network_and_no_timer() {
    let db = db();
    let port = port_on(db.clone(), true);
    let peer = PeerKey(PEER_ENDPOINT);
    let coordinator = AdmissionCoordinator::new(store_on(db.clone()));

    let change = change_touching(&["a.txt"]);
    let bundle = honest_bundle(change.clone());

    // A local edit to the same path is outstanding before the Change arrives.
    set_barrier(&db, "a.txt", true);

    port.stage_bundles(peer, group(), vec![frame(&bundle)]).await.unwrap();
    coordinator.mark_stale(&folder());

    let blocked = coordinator.drain(&folder()).await.unwrap().unwrap();
    assert!(blocked.promoted.is_empty(), "an open capture barrier must block promotion");
    assert_eq!(blocked.still_blocked, 1);
    assert!(!is_canonical(&db, &change));

    // Delivery is already complete and stays complete: the peer must not be
    // asked for this Change again while it waits.
    assert_eq!(
        port.servable(peer, group()).await.unwrap(),
        vec![ItemId::from_bytes(change.compute_hash().0)]
    );

    // The barrier settles. Nothing arrives from the network; no timer fires.
    set_barrier(&db, "a.txt", false);
    coordinator.mark_stale(&folder());

    let settled = coordinator.drain(&folder()).await.unwrap().unwrap();
    assert_eq!(settled.promoted, vec![change.compute_hash()]);
    assert!(is_canonical(&db, &change));
}

/// Wait for a spawned drain to reach `predicate`, by yielding rather than
/// sleeping — no timer is involved, only the runtime running the task that
/// `schedule` handed it.
pub(super) async fn settles(mut predicate: impl FnMut() -> bool) -> bool {
    for _ in 0..1000 {
        if predicate() {
            return true;
        }
        tokio::task::yield_now().await;
    }
    predicate()
}

/// Staging must be enough on its own.
///
/// Becoming promotable and being re-evaluated are different events. If marking
/// the group stale and starting a drain were two operations, every call site
/// would carry the contract "and then start a drain" — and the one that forgot
/// would leave a Change promotable forever with nothing to notice.
#[tokio::test]
async fn staging_alone_promotes_with_no_explicit_drain_call() {
    let db = db();
    let coordinator = Arc::new(AdmissionCoordinator::new(store_on(db.clone())));
    let port = port_on(db.clone(), true).waking(coordinator.clone());
    let peer = PeerKey(PEER_ENDPOINT);

    let change = change_touching(&["a.txt"]);
    port.stage_bundles(peer, group(), vec![frame(&honest_bundle(change.clone()))]).await.unwrap();

    // Nothing below asks for a drain. The staging is the only event.
    assert!(settles(|| is_canonical(&db, &change)).await, "staging must schedule its own drain");
}

/// The same for a transition the port does not raise: a barrier settling is
/// somebody else's event, and scheduling it must be enough.
#[tokio::test]
async fn scheduling_after_a_barrier_settles_promotes_with_no_explicit_drain_call() {
    let db = db();
    let coordinator = Arc::new(AdmissionCoordinator::new(store_on(db.clone())));
    let port = port_on(db.clone(), true).waking(coordinator.clone());
    let peer = PeerKey(PEER_ENDPOINT);

    let change = change_touching(&["a.txt"]);
    set_barrier(&db, "a.txt", true);
    port.stage_bundles(peer, group(), vec![frame(&honest_bundle(change.clone()))]).await.unwrap();

    assert!(
        !settles(|| is_canonical(&db, &change)).await,
        "an open barrier must block promotion however many drains run"
    );

    set_barrier(&db, "a.txt", false);
    coordinator.schedule(&folder());

    assert!(
        settles(|| is_canonical(&db, &change)).await,
        "scheduling after the barrier settled must promote it"
    );
}

/// A drain that runs while another is in flight is coalesced, not started
/// alongside it.
#[tokio::test]
async fn a_drain_runs_when_nothing_else_holds_the_group() {
    let db = db();
    let coordinator = Arc::new(AdmissionCoordinator::new(store_on(db.clone())));

    let first = coordinator.drain(&folder()).await.unwrap();
    assert!(first.is_some(), "the only drain must actually run");
}

/// One Change that cannot be promoted must not stop every other Change in
/// its group from being promoted.
///
/// Scenario on the reconciliation path: a delivered Change referenced a
/// file version this device did not hold, and `commit_admission` returns
/// that as an error. If that error ended the drain — on every pass —
/// nothing else in the group would ever move either: every device would
/// sit holding verified Changes it could have admitted, held back by one
/// member.
///
/// The cause of that particular failure is now impossible: a bundle carries
/// the versions its Change refers to, and staging refuses one that does not.
/// So this test reaches past the contract on purpose, writing a staged row by
/// hand that today's staging path would never produce.
///
/// That is deliberate rather than lazy. The drain's robustness must not
/// depend on the staging contract being perfect, because the rows it reads
/// are durable and outlive the code that wrote them — a row staged by an
/// older build, or by a future path with a gap of its own, must cost its own
/// promotion and nothing else's.
#[tokio::test]
async fn one_unpromotable_change_does_not_hold_back_the_rest_of_its_group() {
    let db = db();
    let port = port_on(db.clone(), true);
    let peer = PeerKey(PEER_ENDPOINT);
    let coordinator = AdmissionCoordinator::new(store_on(db.clone()));

    // Both are this one author's own changes, so they are built in the
    // order their author chain expects: the one that must promote takes the
    // author's first sequence. The broken one never installs at all — its
    // missing version is refused before the chain is consulted — so the
    // sequence it holds is never reached.
    let ordinary = change_touching(&["fine.txt"]);
    // Refers to a version that will not be staged with it.
    let unpromotable = change_putting("needs-content.bin", &file_version(64, 0x5a));

    port.stage_bundles(peer, group(), vec![frame(&honest_bundle(ordinary.clone()))]).await.unwrap();

    // By hand, past the contract: the object row without its versions.
    let broken = honest_bundle(unpromotable.clone());
    db.write::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
        conn.execute(
            "INSERT OR IGNORE INTO verified_checkpoints (checkpoint_hash, group_id, device_id, \
                 checkpoint_seq, encoded, signature, author_signing_public_key) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                &broken.checkpoint.checkpoint_hash[..],
                GROUP,
                DEVICE,
                broken.checkpoint.checkpoint_seq as i64,
                &broken.checkpoint.encoded,
                &broken.checkpoint.signature,
                &broken.checkpoint.author_signing_public_key[..],
            ],
        )?;
        conn.execute(
            "INSERT INTO verified_change_objects (change_hash, group_id, encoded, \
                 checkpoint_hash, merkle_proof, verified_at_unix_nanos) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                &unpromotable.compute_hash().0[..],
                GROUP,
                &broken.encoded,
                &broken.checkpoint.checkpoint_hash[..],
                &broken.merkle_proof,
                1i64,
            ],
        )?;
        Ok(())
    })
    .unwrap();

    coordinator.mark_stale(&folder());
    let outcome = coordinator.drain(&folder()).await.unwrap().unwrap();

    assert!(
        is_canonical(&db, &ordinary),
        "a Change with nothing wrong with it must promote regardless of what else is staged"
    );
    assert!(!is_canonical(&db, &unpromotable));
    assert_eq!(outcome.promoted, vec![ordinary.compute_hash()]);
    assert!(
        outcome.still_blocked >= 1,
        "the Change that could not be promoted must be reported as still blocked, not lost"
    );
}

/// A bundle whose Change writes content carries the version metadata that
/// content needs, and lands as one thing: possessed and admissible together.
///
/// This is the whole boundary in one test. Before it, a Change could be
/// delivered, verified, staged and advertised as possessed while remaining
/// permanently un-admittable, because the metadata admission needs travelled
/// on no path at all. That state was unrecoverable rather than merely slow:
/// possession is what tells a peer not to send it again.
#[tokio::test]
async fn a_change_that_writes_content_arrives_admissible() {
    let db = db();
    let port = port_on(db.clone(), true);
    let peer = PeerKey(PEER_ENDPOINT);
    let coordinator = AdmissionCoordinator::new(store_on(db.clone()));

    let version = file_version(4096, 0x11);
    let change = change_putting("photo.jpg", &version);
    let bundle = honest_bundle_carrying(change.clone(), vec![version.clone()]);

    let staged = port.stage_bundles(peer, group(), vec![frame(&bundle)]).await.unwrap();
    assert_eq!(staged.len(), 1);

    let outcome = coordinator.drain(&folder()).await.unwrap().unwrap();
    assert_eq!(outcome.promoted, vec![change.compute_hash()]);
    assert!(is_canonical(&db, &change));

    // The version is canonical now too, not left behind in staging.
    let installed = db
        .read::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            yadorilink_sync_sqlite::dag_store::get_file_version(conn, GROUP, &version.version_hash)
        })
        .unwrap();
    assert_eq!(installed.map(|v| v.version_hash), Some(version.version_hash));

    // Block-serving authorization, which is a separate thing from holding
    // the version. `change_file_versions` is the security index that says
    // "this group's published history references this version" -- an extra
    // row in it would manufacture a serving right, so it must be derived
    // from admitted history and nothing else. Promotion goes through the
    // same `append_change` body the legacy path used, so it is; this asserts
    // that rather than trusting the call graph.
    let authorized = db
        .read::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            let n: i64 = conn.query_row(
                "SELECT COUNT(*) FROM change_file_versions \
                  WHERE group_id = ?1 AND change_hash = ?2 AND version_hash = ?3",
                rusqlite::params![GROUP, &change.compute_hash().0[..], &version.version_hash.0[..]],
                |row| row.get(0),
            )?;
            Ok(n)
        })
        .unwrap();
    assert_eq!(
        authorized, 1,
        "promoting a Change through reconciliation must establish this group's \
         block-serving authorization for the version it refers to"
    );

    // And what this device serves onward is self-contained in turn: a
    // promoted Change is still served with its versions, from the canonical
    // side of the union.
    let served = port
        .load_bundles(peer, group(), vec![ItemId::from_bytes(change.compute_hash().0)])
        .await
        .unwrap();
    let decoded = bundle_codec::decode(&served[0].payload).unwrap();
    assert_eq!(
        decoded.versions.iter().map(|v| v.version_hash).collect::<Vec<_>>(),
        vec![version.version_hash],
        "a Change promoted here must still be servable in full to the next peer"
    );
}

/// Every way a bundle's carried versions can fail to be exactly the set its
/// Change refers to. All of them reject the bundle whole; none of them stage
/// anything.
///
/// Whole-bundle rejection matters as much as the checks themselves. A partial
/// accept would leave the Change possessed and unadmittable, which is the
/// state this entire boundary exists to make unreachable.
#[tokio::test]
async fn a_bundle_whose_carried_versions_are_not_exactly_right_is_refused_whole() {
    let version = file_version(4096, 0x11);
    let unrelated = file_version(2048, 0x22);
    let change = change_putting("photo.jpg", &version);

    let mut tampered = version.clone();
    tampered.blocks[0].size += 1;

    let cases: Vec<(&str, Vec<FileVersion>)> = vec![
        ("a required version omitted", vec![]),
        ("an unrelated version added", vec![version.clone(), unrelated.clone()]),
        ("the same version carried twice", vec![version.clone(), version.clone()]),
        ("the version's bytes altered", vec![tampered]),
        ("only an unrelated version", vec![unrelated]),
    ];

    for (what, versions) in cases {
        let db = db();
        let port = port_on(db.clone(), true);
        let peer = PeerKey(PEER_ENDPOINT);

        let bundle = honest_bundle_carrying(change.clone(), versions);
        let result = port.stage_bundles(peer, group(), vec![frame(&bundle)]).await;

        assert!(result.is_err(), "{what}: must be refused");
        assert!(
            port.servable(peer, group()).await.unwrap().is_empty(),
            "{what}: nothing may be staged by a refused bundle"
        );
    }
}

/// Receiving the same bundle repeatedly costs one of everything.
///
/// The counting includes the versions now: a bundle redelivered ten times
/// must not accumulate ten rows, ten verifications' worth of canonical state,
/// or ten admissions.
#[tokio::test]
async fn redelivering_a_bundle_with_versions_ten_times_stores_one_of_each() {
    let db = db();
    let port = port_on(db.clone(), true);
    let peer = PeerKey(PEER_ENDPOINT);
    let coordinator = AdmissionCoordinator::new(store_on(db.clone()));

    let version = file_version(4096, 0x11);
    let change = change_putting("photo.jpg", &version);
    let bundle = honest_bundle_carrying(change.clone(), vec![version.clone()]);

    let mut staged_reports = 0usize;
    let mut promoted = 0usize;
    for _ in 0..10 {
        staged_reports +=
            port.stage_bundles(peer, group(), vec![frame(&bundle)]).await.unwrap().len();
        if let Some(outcome) = coordinator.drain(&folder()).await.unwrap() {
            promoted += outcome.promoted.len();
        }
    }

    assert_eq!(staged_reports, 1, "only the first delivery is new");
    assert_eq!(promoted, 1, "the Change is admitted exactly once");

    let (versions, objects) = db
        .read::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            let versions: i64 = conn.query_row(
                "SELECT COUNT(*) FROM file_versions WHERE group_id = ?1",
                rusqlite::params![GROUP],
                |row| row.get(0),
            )?;
            let objects: i64 = conn.query_row(
                "SELECT COUNT(*) FROM verified_change_objects WHERE group_id = ?1",
                rusqlite::params![GROUP],
                |row| row.get(0),
            )?;
            Ok((versions, objects))
        })
        .unwrap();
    assert_eq!(versions, 1);
    assert_eq!(objects, 0, "the staged copy is gone once the Change is canonical");
}

/// A staged bundle's versions survive a restart, and the Change promotes
/// afterwards with no network at all.
///
/// This is what "durable staging is the linearization point of possession"
/// has to mean in practice. The peer has been told we hold this Change and
/// will not send it again; if a restart could lose the metadata admission
/// needs, possession would be a claim this device could not honour.
#[tokio::test]
async fn a_staged_bundle_promotes_after_a_restart_with_no_network() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("replica.sqlite3");

    let version = file_version(4096, 0x11);
    let change = change_putting("photo.jpg", &version);
    let child = child_of(&change, &["after.txt"]);

    {
        let db = db_at(&path);
        let port = port_on(db.clone(), true);
        // The child arrives first, so nothing can promote yet: the parent is
        // missing. Both are staged, versions and all.
        let (parent_bundle, child_bundle) =
            honest_pair_carrying(&change, &child, vec![version.clone()]);
        port.stage_bundles(PeerKey(PEER_ENDPOINT), group(), vec![frame(&child_bundle)])
            .await
            .unwrap();
        port.stage_bundles(PeerKey(PEER_ENDPOINT), group(), vec![frame(&parent_bundle)])
            .await
            .unwrap();
    }

    // A fresh process. Nothing is connected to anything.
    let db = db_at(&path);
    let coordinator = AdmissionCoordinator::new(store_on(db.clone()));
    let outcome = coordinator.drain(&folder()).await.unwrap().unwrap();

    assert_eq!(outcome.promoted.len(), 2, "both must promote from durable state alone");
    assert!(is_canonical(&db, &change) && is_canonical(&db, &child));
}

/// The codec must not be the thing that decides what history is expressible.
///
/// Two separate claims, because they fail differently.
///
/// The first is arithmetic and absolute: the bundle's own ceilings are
/// derived from the domain's, so no domain-valid Change can be refused by
/// this encoder for referring to more versions, or larger ones, than it will
/// carry. A hand-picked constant here would be a second opinion about what
/// the domain allows, and the two would drift.
///
/// The second is the honest limit and is deliberately stated rather than
/// asserted away. One bundle is one frame, and `MAX_BUNDLE_BYTES` caps a
/// frame. The domain's theoretical maximum — `MAX_OPS` distinct versions of
/// `MAX_BLOCKS` blocks each — is orders of magnitude past any frame and
/// always will be; what matters is that the frame comfortably holds a Change
/// referring to a realistically large file, and that anything beyond it is
/// refused with a size error rather than truncated. That is a known ceiling,
/// not a silent one.
#[test]
fn the_bundle_encoding_is_never_tighter_than_the_domain() {
    use yadorilink_replica_domain::limits::{MAX_BLOCKS, MAX_BLOCK_SIZE_BYTES, MAX_OPS};

    // Claim 1: the per-field ceilings are the domain's own.
    assert!(
        super::bundle_codec::max_versions() >= MAX_OPS,
        "a Change refers to at most one version per op, so refusing fewer than MAX_OPS \
         versions would make this encoder the limit on valid history"
    );
    assert!(
        super::bundle_codec::max_version_bytes() >= MAX_BLOCKS * (4 + 32 + 4),
        "the largest domain-valid version's block list must fit"
    );

    // Claim 2: one frame holds a Change referring to a realistically large
    // file, with room to spare for the proof and the checkpoint.
    let one_block_entry = 4 + 32 + 4;
    let largest_file_in_one_frame =
        (yadorilink_sync_protocol::wire::MAX_BUNDLE_BYTES / 2 / one_block_entry) as u64
            * MAX_BLOCK_SIZE_BYTES as u64;
    assert!(
        largest_file_in_one_frame >= 1 << 40,
        "one bundle frame must carry the metadata for at least a 1 TiB file; it carries \
         {largest_file_in_one_frame} bytes' worth"
    );
}

/// A bundle larger than one frame is refused with a size error, at the
/// encoder, rather than being truncated into something a peer would reject
/// for the wrong reason.
#[test]
fn a_version_larger_than_the_encoding_allows_is_refused_at_the_encoder() {
    let oversized = vec![0u8; super::bundle_codec::max_version_bytes() + 1];
    assert!(matches!(
        super::bundle_codec::check_version_size(oversized.len()),
        Err(super::bundle_codec::BundleCodecError::FieldTooLarge { .. })
    ));
}

/// A staged-but-unpromoted Change grants no block-serving authorization.
///
/// The other half of the same boundary. Possession is not a serving right:
/// until a Change is canonical and carries its evidence, this device has no
/// published history referencing that version, and an entry in the serving
/// index would be manufacturing one.
#[tokio::test]
async fn a_staged_change_grants_no_block_serving_authorization_until_it_is_promoted() {
    let db = db();
    let port = port_on(db.clone(), true);
    let peer = PeerKey(PEER_ENDPOINT);
    let coordinator = AdmissionCoordinator::new(store_on(db.clone()));

    let version = file_version(4096, 0x77);
    let parent = change_putting("blocked.bin", &version);
    let child = child_of(&parent, &["later.txt"]);

    // Only the child is delivered, so nothing can promote: its parent is
    // missing. It is possessed, and possession is all it is.
    let (_parent_bundle, child_bundle) =
        honest_pair_carrying(&parent, &child, vec![version.clone()]);
    port.stage_bundles(peer, group(), vec![frame(&child_bundle)]).await.unwrap();
    coordinator.drain(&folder()).await.unwrap();

    assert!(!is_canonical(&db, &child));
    let rows = db
        .read::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            let n: i64 = conn.query_row(
                "SELECT COUNT(*) FROM change_file_versions WHERE group_id = ?1",
                rusqlite::params![GROUP],
                |row| row.get(0),
            )?;
            Ok(n)
        })
        .unwrap();
    assert_eq!(
        rows, 0,
        "a Change this device holds but has not admitted must grant no serving right"
    );
}

// ---------------------------------------------------------------------------
// The capture barrier settles through the LIVE watcher executor.
//
// `a_staged_change_promotes_when_its_capture_barrier_settles_with_no_network_
// and_no_timer` above proves the admission half: given `local_dirty_paths:
// present -> absent` AND a wake, the staged Change promotes. It clears the
// barrier by writing the table directly and raises the wake by hand, so it
// cannot see whether the code that really clears that row in production also
// raises that wake.
//
// It did not. The executor's live flush loop clears the dirty rows that ARE
// the barrier, and it can do that while authoring nothing --
// `announce_local_change` returns at `records.is_empty()` before reaching
// anything that re-asks admission. A remote Change held behind that path then
// stays staged with no network event, no timer, and no local edit left to
// notice: delivery complete, promotion never reached.
//
// So this test drives the real `spawn_executor_task` and never calls
// `note_capture_settled` itself. The only thing it does is put a flush on the
// executor's own channel.
// ---------------------------------------------------------------------------

/// Everything `spawn_executor_task` needs, wired the way the daemon wires it:
/// one `ReplicaCoordinator` and one `AdmissionCoordinator` over one database.
/// `note_capture_settled` does what `DaemonState`'s own impl does -- schedule
/// an admission drain -- and counts, so a failure can tell "the executor never
/// notified" apart from "the drain ran and decided not to promote".
struct ExecutorHost {
    admission: Arc<AdmissionCoordinator>,
    capture_settled: Arc<std::sync::atomic::AtomicUsize>,
    broadcasts: Arc<std::sync::atomic::AtomicUsize>,
}

impl crate::link_runtime::dependencies::LinkRuntimeHostPort for ExecutorHost {
    fn broadcast_change<'a>(
        &'a self,
        _group_id: &'a str,
        _records: Vec<yadorilink_replica_domain::file::FileRecord>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        self.broadcasts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Box::pin(async {})
    }

    fn begin_write_activity(&self) -> Box<dyn Send + '_> {
        Box::new(())
    }

    fn device_signing_key(&self) -> Option<SigningKey> {
        Some(author_key())
    }

    fn note_capture_settled(&self, group_id: &str) {
        self.capture_settled.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.admission.schedule(&FolderGroupId(group_id.to_string()));
    }
}

/// Gate: a staged Change blocked by an open capture barrier promotes when the
/// LIVE executor's own flush clears that barrier -- with no network, no timer,
/// and no hand-raised wake.
///
/// The flush authors nothing (its `records` are empty, so nothing is
/// broadcast). That is the whole point: the settlement is real, the
/// announcement is not, and a mechanism that only re-asks admission when there
/// was something to announce never re-asks here.
// Multi-thread: the executor's live flush loop uses `block_in_place`, which
// panics outright on a current-thread runtime -- as production runs on the
// daemon's multi-thread runtime, a current-thread harness would be testing a
// path that does not exist.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_live_executor_flush_that_authors_nothing_still_settles_the_capture_barrier() {
    use std::sync::atomic::Ordering::SeqCst;
    use yadorilink_filesystem_sync::debounce::DebounceFlush;
    use yadorilink_filesystem_sync::watcher::FsChangeKind;

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    std::fs::create_dir_all(&root).unwrap();

    let db = db_at(&tmp.path().join("sync.db"));
    let replica_coordinator =
        Arc::new(crate::replica_coordinator::ReplicaCoordinator::from_database(
            db.clone(),
            Arc::new(crate::sync_runtime::path_locks::PathLockRegistry::new()),
            Arc::new(crate::sync_runtime::startup_readiness::StartupReadinessRegistry::new()),
        ));

    // A real link row and an adopted root token: `VerifiedRoot::verify` (which
    // every flush after the first goes through) requires the persisted token,
    // and an `UPDATE ... WHERE group_id = ?` cannot persist it without a row.
    replica_coordinator.link_repository().add_link(&root.display().to_string(), GROUP).unwrap();
    yadorilink_root_authority::root_identity::VerifiedRoot::open(
        &root,
        GROUP,
        replica_coordinator.as_ref(),
    )
    .unwrap();

    let admission = Arc::new(AdmissionCoordinator::new(store_on(db.clone())));
    let capture_settled = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let broadcasts = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    let block_store = Arc::new(
        yadorilink_local_storage::SegmentBlockStore::new(tmp.path().join("blocks")).unwrap(),
    );
    let (status_tx, _status_rx) = tokio::sync::broadcast::channel(16);
    let deps = Arc::new(crate::link_runtime::dependencies::LinkRuntimeDependencies {
        replica_coordinator: replica_coordinator.clone(),
        block_store: block_store.clone(),
        telemetry: Arc::new(crate::runtime_telemetry::RuntimeTelemetry::new(status_tx)),
        device_id: "device-LOCAL".to_string(),
        host: Arc::new(ExecutorHost {
            admission: admission.clone(),
            capture_settled: capture_settled.clone(),
            broadcasts: broadcasts.clone(),
        }),
    });

    // A processor with no change emitter: this test is about the dirty-path
    // barrier, which the index layer owns, not about what an emitter authors.
    let processor = Arc::new(yadorilink_local_capture::LocalChangeProcessor::new(
        replica_coordinator.clone(),
        Arc::new(crate::adapters::block_store_ports::BlockStorePortsAdapter::new(
            block_store.clone(),
        )),
        "device-LOCAL".to_string(),
        Arc::new(yadorilink_root_authority::root_commit::RootLease::for_tests()),
    ));

    // The executor does real disk and SQLite work on another worker thread, so
    // `settles`' yield-only spin (written for tasks that only need the runtime
    // to poll them) can complete before the flush has run at all. This waits
    // on the same condition with a real, generous ceiling -- an observation
    // budget in a test, not a mechanism the daemon relies on: nothing here
    // retries, re-sends, or re-drives, and every assertion below still fails
    // if the state never arrives.
    async fn eventually(mut predicate: impl FnMut() -> bool) -> bool {
        for _ in 0..3000 {
            if predicate() {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        predicate()
    }

    let generation = replica_coordinator.startup_readiness().begin_group_startup(GROUP);
    let guard = crate::link_runtime::startup::GroupStartupReadyGuard::new(
        deps.clone(),
        GROUP.to_string(),
        generation,
    );
    let (flush_tx, flush_rx) = tokio::sync::mpsc::channel(4);
    let _executor = crate::link_runtime::tasks::spawn_executor_task(
        deps.clone(),
        root.display().to_string(),
        GROUP.to_string(),
        processor.clone(),
        root.clone(),
        Arc::new(yadorilink_root_authority::ignore_patterns::EffectiveIgnoreSet::defaults_only()),
        true,
        guard,
        flush_rx,
    );

    // The executor's startup (initial scan, then the dirty-journal redrive)
    // has to be complete before anything below touches the barrier: that
    // redrive clears every dirty row it finds, so a barrier opened while it is
    // still running would be swept away by setup rather than by the flush this
    // test is about. Waiting also keeps the root empty for the scan, so it
    // authors nothing.
    assert!(
        eventually(|| !replica_coordinator.startup_readiness().group_startup_in_progress(GROUP))
            .await,
        "setup: the executor's startup must complete"
    );

    // Setup, not the property under test: get `shared.bin` into the index
    // through the executor's own path, so the flush that matters later is a
    // genuine no-op rather than an unindexed path being skipped.
    let file = root.join("shared.bin");
    std::fs::write(&file, b"shared content").unwrap();
    flush_tx
        .send(DebounceFlush::Paths(vec![(file.clone(), FsChangeKind::CreatedOrModified, 1)]))
        .await
        .unwrap();
    let indexed = || {
        db.read::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            let n: i64 = conn.query_row(
                "SELECT COUNT(*) FROM files WHERE group_id = ?1 AND path = 'shared.bin'",
                rusqlite::params![GROUP],
                |row| row.get(0),
            )?;
            Ok(n)
        })
        .unwrap()
            > 0
    };
    let dirty = || {
        db.read::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
            let n: i64 = conn.query_row(
                "SELECT COUNT(*) FROM local_dirty_paths \
                 WHERE group_id = ?1 AND path = 'shared.bin'",
                rusqlite::params![GROUP],
                |row| row.get(0),
            )?;
            Ok(n)
        })
        .unwrap()
            > 0
    };
    // Wait for that first flush to have fully finished -- indexed, its own
    // dirty row cleared, AND its broadcast delivered. Opening the barrier
    // below while that clear is still in flight would let it delete the very
    // row this test is about.
    //
    // The broadcast is part of "finished" for a reason that is easy to miss.
    // The dirty row clears before the broadcast is emitted, so waiting only
    // for the row leaves a window: the counters are reset, the setup flush's
    // own broadcast then lands, and the assertion below attributes it to the
    // flush under test. That reads as "the settling flush authored
    // something" -- a failure describing the opposite of what happened, and
    // one that appears only under enough load to separate the two steps.
    assert!(
        eventually(|| indexed() && !dirty() && broadcasts.load(SeqCst) >= 1).await,
        "setup: the executor must index the file it is given, clear its own dirty row, \
         and announce what it authored"
    );

    capture_settled.store(0, SeqCst);
    broadcasts.store(0, SeqCst);

    // A local edit to that same path is observed but not yet captured, and a
    // remote Change touching it arrives while the barrier is open.
    set_barrier(&db, "shared.bin", true);
    let change = change_touching(&["shared.bin"]);
    let port = port_on(db.clone(), true);
    port.stage_bundles(
        PeerKey(PEER_ENDPOINT),
        group(),
        vec![frame(&honest_bundle(change.clone()))],
    )
    .await
    .unwrap();

    let blocked = admission.drain(&folder()).await.unwrap().unwrap();
    assert_eq!(
        blocked.still_blocked,
        1,
        "an open capture barrier must block promotion; promoted={:?} passes={} dirty={} \
         canonical={}",
        blocked.promoted,
        blocked.passes,
        dirty(),
        is_canonical(&db, &change)
    );
    assert!(!is_canonical(&db, &change));

    // The one event. The file on disk is unchanged since it was indexed, so
    // this flush clears the dirty row and authors nothing.
    flush_tx
        .send(DebounceFlush::Paths(vec![(file.clone(), FsChangeKind::CreatedOrModified, 2)]))
        .await
        .unwrap();

    if !eventually(|| !dirty()).await {
        let rows: Vec<String> = db
            .read::<_, yadorilink_sync_sqlite::SyncSqliteError>(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT path, change_kind, observed_at_unix_nanos, attempts, \
                     COALESCE(last_error, '') FROM local_dirty_paths WHERE group_id = ?1",
                )?;
                let out = stmt
                    .query_map(rusqlite::params![GROUP], |r| {
                        Ok(format!(
                            "{} kind={} observed_at={} attempts={} last_error={}",
                            r.get::<_, String>(0)?,
                            r.get::<_, String>(1)?,
                            r.get::<_, i64>(2)?,
                            r.get::<_, i64>(3)?,
                            r.get::<_, String>(4)?
                        ))
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(out)
            })
            .unwrap();
        panic!("the flush must clear the dirty row it processed; rows={rows:?}");
    }

    // Read here, where the dirty row has just cleared and the flush under
    // test is therefore done, rather than after the wait below. The periodic
    // redrive is free to run during that wait and author something of its
    // own; counting afterwards would attribute its broadcast to this flush
    // and fail a test about settlement for a reason that has nothing to do
    // with settlement. Observed as roughly a one-in-three failure under full
    // suite parallelism, and never in isolation.
    let authored_by_the_flush = broadcasts.load(SeqCst);

    assert!(
        eventually(|| is_canonical(&db, &change)).await,
        "the executor's own flush settled the barrier; nothing else was going to notice"
    );
    assert_eq!(
        authored_by_the_flush, 0,
        "the settling flush must have authored nothing -- otherwise this test is proving \
         the announce path, not the settlement path"
    );
    assert_eq!(
        capture_settled.load(SeqCst),
        1,
        "the live flush loop must report the settlement exactly once"
    );
}

// --- base negotiation: a refusal drops the peer's earlier claim ---------------

/// A refused negotiation is the latest word on a peer and names no base for
/// it, so whatever the peer claimed before must not outlive it as
/// merge-required state -- whichever way the negotiation was refused: an
/// advertisement that does not decode, one for another group, or one the
/// session could not judge at all. (A summary contradiction over one base
/// is covered end to end in `base_negotiation_tests`.)
#[tokio::test]
async fn a_refused_negotiation_drops_the_peers_earlier_claim() {
    use yadorilink_replica_domain::base_negotiation::{
        AdvertisedBase, BaseAdvertisement, SummaryIdentity,
    };
    use yadorilink_replica_domain::rebootstrap::{Checkpoint, HistoryEpoch};
    use yadorilink_sync_protocol::ports::BaseVerdict;

    let port = port(true);
    let peer = PeerKey(PEER_ENDPOINT);
    let folder = FolderGroupId(GROUP.into());
    let advertise = |group: &str, base: AdvertisedBase| {
        BaseAdvertisement::new(FolderGroupId(group.into()), base, Vec::new()).unwrap().encode()
    };
    let ours = advertise(GROUP, AdvertisedBase::Genesis);
    let elsewhere = |group: &str| {
        advertise(
            group,
            AdvertisedBase::Installed {
                checkpoint: Box::new(Checkpoint::new(
                    FolderGroupId(group.into()),
                    Vec::new(),
                    [7; 32],
                )),
                summary: SummaryIdentity([8; 32]),
            },
        )
    };
    let claimed = || port.foreign_bases().merge_required(&folder, HistoryEpoch::Genesis);

    enum Refusal {
        Undecodable,
        OtherGroup,
        Unjudgeable,
    }
    for refusal in [Refusal::Undecodable, Refusal::OtherGroup, Refusal::Unjudgeable] {
        let verdict =
            port.negotiate_base(peer, group(), ours.clone(), elsewhere(GROUP)).await.unwrap();
        assert!(matches!(verdict, BaseVerdict::MergeRequired), "{verdict:?}");
        assert_eq!(claimed().len(), 1);

        match refusal {
            Refusal::Undecodable => {
                let verdict =
                    port.negotiate_base(peer, group(), ours.clone(), vec![0xFF; 3]).await.unwrap();
                assert!(matches!(verdict, BaseVerdict::Refused(_)), "{verdict:?}");
            }
            Refusal::OtherGroup => {
                let verdict = port
                    .negotiate_base(peer, group(), ours.clone(), elsewhere("another-group"))
                    .await
                    .unwrap();
                assert!(matches!(verdict, BaseVerdict::Refused(_)), "{verdict:?}");
            }
            Refusal::Unjudgeable => {
                port.base_unjudgeable(peer, group(), "unreadable".into()).await.unwrap();
            }
        }
        assert!(claimed().is_empty(), "a refused peer is not someone to merge with");
    }
}
