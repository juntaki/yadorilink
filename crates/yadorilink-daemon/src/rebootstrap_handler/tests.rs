#![cfg(test)]

use crate::replica_coordinator::ReplicaCoordinator;
use ed25519_dalek::SigningKey;
use yadorilink_local_storage::SegmentBlockStore;
use yadorilink_replica_domain::ids::{DeviceId, FolderGroupId};
use yadorilink_replica_domain::test_authoring::create_signed_for_tests;
use yadorilink_replica_engine::compaction::Checkpoint;
use yadorilink_replica_engine::rebootstrap::SnapshotManifest;

use super::*;

fn test_state() -> Arc<DaemonState> {
    let store = Arc::new(SegmentBlockStore::new(tempfile::tempdir().unwrap().keep()).unwrap());
    let sync_state = Arc::new(ReplicaCoordinator::open_in_memory().unwrap());
    DaemonState::new("device-a".into(), sync_state, store)
}

/// Whether `signer` may found a base of `group_id`, asked about the key
/// this device would verify its manifest's signature under.
fn authorize(
    handler: &DaemonRebootstrapHandler,
    group_id: &str,
    signer: &str,
) -> Result<(), SyncError> {
    handler.authorize_base_signer(group_id, signer, handler.trust_key(signer).as_ref())
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
    let handler = DaemonRebootstrapHandler { state };
    let error = authorize(&handler, "brand-new-group", "device-b").unwrap_err();
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
    let handler = DaemonRebootstrapHandler { state };
    authorize(&handler, "g", "device-a").unwrap();
}

/// Bug 2 regression: this function's own doc comment says the signer
/// must be "a device this policy currently recognizes as a writer" --
/// but the pre-fix code checked `state.authority.peer_is_writer`, which is
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
async fn authorize_base_signer_rejects_a_viewer_and_accepts_the_same_device_as_an_editor() {
    use crate::change_policy::policy_signing::grant_record;
    use crate::change_policy::{verify_group_policy_log, GroupPolicyLog, WriterRole};

    let authority = SigningKey::from_bytes(&[7u8; 32]);
    let group_id = "group-rebootstrap";
    let signer_key = SigningKey::from_bytes(&[13u8; 32]);
    let signer_fp: [u8; 32] = Sha256::digest(signer_key.verifying_key().to_bytes()).into();

    let viewer_grant =
        grant_record(&authority, group_id, 1, [0u8; 32], "device-b", signer_fp, WriterRole::Viewer);
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
    state.authority.set_peer_group_full_replica("device-b", group_id, true);
    // The netmap-pinned key matches the policy-bound fingerprint for the
    // whole test (both derived from the same `signer_key`) -- fix 1's
    // added fingerprint-binding check is exercised elsewhere
    // (`..._rejects_a_manifest_signed_with_a_key_the_policy_never_bound_to_the_writer`);
    // this test isolates the writer-ROLE check only, so the fingerprint
    // half must trivially agree throughout.
    state.record_peer_signing_key("device-b", signer_key.verifying_key().to_bytes());
    state.authority.replace_group_policy_states(std::collections::HashMap::from([(
        group_id.to_string(),
        viewer_policy,
    )]));
    let handler = DaemonRebootstrapHandler { state: state.clone() };

    let error = authorize(&handler, group_id, "device-b").unwrap_err();
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
    state.authority.replace_group_policy_states(std::collections::HashMap::from([(
        group_id.to_string(),
        editor_policy,
    )]));

    authorize(&handler, group_id, "device-b").unwrap();
}

/// Signing-key fingerprint binding regression test: the writer-role
/// check alone is not enough -- the manifest's ACTUAL signing key must
/// also match the key the SIGNED POLICY CHAIN bound to that writer, not
/// merely whatever key the
/// (netmap-derived, weak) `trust_key` resolver currently has pinned for
/// that device id. The policy binds device-b's Editor grant to key A's
/// fingerprint; the netmap separately has a DIFFERENT key B pinned for
/// device-b; the manifest is signed with key B. Before this fix,
/// `authorize_base_signer` only checked `writer.device_id
/// == signer` against `current_writers()` and never consulted
/// `AuthorizedWriter::signing_key_fingerprint` at all, so this was
/// wrongly accepted -- a manifest signed by a key the signed policy
/// chain never actually authorized for that writer. The existing
/// `authorize_base_signer_rejects_a_viewer_and_accepts_the_same_device_as_an_editor`
/// test above can't catch this: it uses ONE key for both the Viewer and
/// Editor phases, so `writer.device_id == signer` and a hypothetical
/// fingerprint check would always agree there too. This test needs two
/// DISTINCT keys to isolate the gap.
#[tokio::test]
async fn authorize_base_signer_rejects_a_manifest_signed_with_a_key_the_policy_never_bound_to_the_writer(
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
    state.authority.set_peer_group_full_replica("device-b", group_id, true);
    // The attack: the netmap has key B pinned for device-b, NOT key A
    // the signed policy chain actually bound.
    state.record_peer_signing_key("device-b", netmap_pinned_key.verifying_key().to_bytes());
    state.authority.replace_group_policy_states(std::collections::HashMap::from([(
        group_id.to_string(),
        editor_policy,
    )]));
    let handler = DaemonRebootstrapHandler { state: state.clone() };
    // Manifest claims signer "device-b" (a real Editor per the policy
    // chain) but is signed with key B, which the policy chain never
    // bound to device-b.
    let error = authorize(&handler, group_id, "device-b").unwrap_err();
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
async fn authorize_base_signer_rejects_every_signer_when_the_verified_policy_names_no_writers() {
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
    state.authority.set_peer_group_full_replica("device-b", group_id, true);
    state.record_peer_signing_key("device-b", signer_key.verifying_key().to_bytes());
    state.authority.replace_group_policy_states(std::collections::HashMap::from([(
        group_id.to_string(),
        empty_policy,
    )]));
    let handler = DaemonRebootstrapHandler { state: state.clone() };

    let error = authorize(&handler, group_id, "device-b").unwrap_err();
    assert!(
        matches!(
            error,
            SyncError::CorruptState(ref message) if message.contains("is not a current writer")
        ),
        "expected a verified-but-empty writer set to reject every signer unconditionally, \
         got {error:?}"
    );
}

/// Trusting the outer `SnapshotManifest` signer (verified
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
    let frontier_change = create_signed_for_tests(
        vec![],
        0,
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
        Vec::new(),
        // A snapshot must say where each author it carries history for
        // stands; this one carries exactly the frontier change above.
        vec![yadorilink_replica_engine::rebootstrap_snapshot::SnapshotAuthorState {
            device_id: "device-unknown".into(),
            watermark: frontier_change.author_seq,
            tip_change_hash: frontier_change.compute_hash(),
        }],
        Vec::new(),
        frontier_change.lamport,
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

/// A base a peer offers to merge is founded under the same authority as a
/// re-bootstrap manifest, asked about the key its signature verified
/// under: a writer the signed policy bound to that exact key, and a full
/// replica. A key the policy never bound to the writer, or a writer that
/// is not a full replica, founds nothing.
#[tokio::test]
async fn the_base_signer_authority_holds_a_merged_base_to_the_rebootstrap_conditions() {
    use crate::change_policy::policy_signing::grant_record;
    use crate::change_policy::{verify_group_policy_log, GroupPolicyLog, WriterRole};
    use yadorilink_sync_sqlite::rebootstrap_store::BaseSignerAuthority;

    let authority = SigningKey::from_bytes(&[7u8; 32]);
    let group_id = "group-merge-authority";
    let bound = SigningKey::from_bytes(&[31u8; 32]).verifying_key().to_bytes();
    let unbound = SigningKey::from_bytes(&[32u8; 32]).verifying_key().to_bytes();
    let grant = grant_record(
        &authority,
        group_id,
        1,
        [0u8; 32],
        "device-b",
        Sha256::digest(bound).into(),
        WriterRole::Editor,
    );
    let head: [u8; 32] = grant.record_hash.as_slice().try_into().unwrap();
    let log = GroupPolicyLog {
        group_id: group_id.to_string(),
        current_seq: 1,
        current_epoch: 0,
        policy_head: head.to_vec(),
        records: vec![grant],
    };
    let policy = verify_group_policy_log(&authority.verifying_key().to_bytes(), &log).unwrap();
    let state = test_state();
    state.set_peer_group_writer("device-b", group_id, true);
    state.authority.replace_group_policy_states(std::collections::HashMap::from([(
        group_id.to_string(),
        policy,
    )]));
    let handler = DaemonRebootstrapHandler { state: state.clone() };

    assert!(
        !handler.may_found_base(group_id, "device-b", &bound),
        "not a full replica of the group"
    );
    state.authority.set_peer_group_full_replica("device-b", group_id, true);
    assert!(handler.may_found_base(group_id, "device-b", &bound));
    assert!(
        !handler.may_found_base(group_id, "device-b", &unbound),
        "a key the policy never bound"
    );
    assert!(!handler.may_found_base(group_id, "device-c", &bound), "not a writer at all");
}

/// A handler whose group lets `device-b` found a base with `signer_key`,
/// under a policy the authority `[7; 32]` signed; and the policy head the
/// grant produced.
fn handler_where_b_founds_bases(
    group_id: &str,
    signer_key: &SigningKey,
) -> (DaemonRebootstrapHandler, [u8; 32]) {
    use crate::change_policy::policy_signing::grant_record;
    use crate::change_policy::{verify_group_policy_log, GroupPolicyLog, WriterRole};

    let authority = SigningKey::from_bytes(&[7u8; 32]);
    let bound = signer_key.verifying_key().to_bytes();
    let grant = grant_record(
        &authority,
        group_id,
        1,
        [0u8; 32],
        "device-b",
        Sha256::digest(bound).into(),
        WriterRole::Editor,
    );
    let head: [u8; 32] = grant.record_hash.as_slice().try_into().unwrap();
    let log = GroupPolicyLog {
        group_id: group_id.to_string(),
        current_seq: 1,
        current_epoch: 0,
        policy_head: head.to_vec(),
        records: vec![grant],
    };
    let policy = verify_group_policy_log(&authority.verifying_key().to_bytes(), &log).unwrap();
    let state = test_state();
    state.set_peer_group_writer("device-b", group_id, true);
    state.authority.set_peer_group_full_replica("device-b", group_id, true);
    state.record_peer_signing_key("device-b", bound);
    state.authority.replace_group_policy_states(std::collections::HashMap::from([(
        group_id.to_string(),
        policy,
    )]));
    (DaemonRebootstrapHandler { state }, head)
}

/// Evidence that `change` by `device-c` was published, in a checkpoint
/// `checkpoint_signer` signed at `policy_head`.
fn witness_signed_by(
    group_id: &str,
    change: ChangeHash,
    policy_head: [u8; 32],
    checkpoint_signer: &SigningKey,
) -> yadorilink_replica_engine::rebootstrap_snapshot::PublishedChangeWitness {
    use yadorilink_replica_domain::authorization_checkpoint::{
        build_merkle_proof, canonical_signing_bytes, checkpoint_hash, encode_merkle_proof,
        fingerprint_signing_key, merkle_root, sign_checkpoint, AuthorizationCheckpoint,
    };
    let author = SigningKey::from_bytes(&[41u8; 32]).verifying_key();
    let authority = SigningKey::from_bytes(&[7u8; 32]).verifying_key();
    let checkpoint = AuthorizationCheckpoint {
        group_id: group_id.to_string(),
        device_id: "device-c".to_string(),
        signing_key_fingerprint: fingerprint_signing_key(&author),
        merkle_root: merkle_root(&[change.0]),
        leaf_count: 1,
        checkpoint_seq: 1,
        signer_key_id: Sha256::digest(authority.to_bytes()).into(),
        policy_epoch: 0,
        policy_seq: 1,
        policy_head,
        issued_at_unix: 0,
    };
    let encoded = canonical_signing_bytes(&checkpoint);
    let signature = sign_checkpoint(&checkpoint, checkpoint_signer);
    yadorilink_replica_engine::rebootstrap_snapshot::PublishedChangeWitness {
        change_hash: change,
        checkpoint_hash: checkpoint_hash(&encoded, &signature),
        checkpoint_encoded: encoded,
        checkpoint_signature: signature.to_vec(),
        author_signing_public_key: author.to_bytes(),
        merkle_proof_encoded: encode_merkle_proof(&build_merkle_proof(&[change.0], 0)),
    }
}

/// A base holding one file `f`, written by `change` of `writer` and
/// served on the strength of `witness`, signed by `device-b` as a merged
/// base is offered.
fn offered_base(
    group_id: &str,
    change: ChangeHash,
    witness: yadorilink_replica_engine::rebootstrap_snapshot::PublishedChangeWitness,
    signer_key: &SigningKey,
    writer: &str,
) -> (SnapshotManifest, Vec<u8>) {
    use yadorilink_replica_domain::file::{FileRecord, FileVersion, RecordKind};
    use yadorilink_replica_domain::ids::{AuthorSeq, VersionHash};
    use yadorilink_replica_engine::rebootstrap_snapshot::{
        SnapshotAuthorState, SnapshotFile, SnapshotPathHead, SnapshotVersionState,
    };
    let version =
        FileVersion::from_index_row(Vec::new(), 0, 1_000, RecordKind::File, None, None, Vec::new());
    let file = SnapshotFile {
        record: FileRecord {
            path: "f".to_string(),
            size: 0,
            mtime_unix_nanos: 1_000,
            blocks: Vec::new(),
            deleted: false,
        },
        version_seq: 1,
        state: SnapshotVersionState::Current,
        origin_device_id: Some(writer.to_string()),
        record_kind: RecordKind::File,
        symlink_target: None,
        symlink_out_of_root: false,
        unix_mode: None,
        xattrs: Vec::new(),
        authoring_change_hash: Some(change),
    };
    let head = SnapshotPathHead {
        path: "f".to_string(),
        change_hash: change,
        device_id: writer.to_string(),
        author_seq: AuthorSeq(1),
        lamport: 1,
        version_hash: VersionHash(version.version_hash.0),
        naming_device_id: writer.to_string(),
    };
    let snapshot = RebootstrapSnapshot::new(
        FolderGroupId(group_id.into()),
        vec![file],
        Vec::new(),
        vec![version.canonical_encoding()],
        vec![witness],
        Vec::new(),
        vec![SnapshotAuthorState {
            device_id: writer.to_string(),
            watermark: AuthorSeq(1),
            tip_change_hash: change,
        }],
        vec![head],
        1,
    )
    .unwrap();
    let checkpoint =
        Checkpoint::new(FolderGroupId(group_id.into()), Vec::new(), snapshot.snapshot_hash());
    let manifest = SnapshotManifest::new_signed(
        checkpoint,
        Vec::new(),
        None,
        DeviceId("device-b".into()),
        signer_key,
    )
    .unwrap();
    (manifest, snapshot.canonical_encoding())
}

/// A base a peer offers to merge keeps no frontier body behind: every row
/// it carries is served on the strength of its witness alone, so each
/// witness is verified as a received change's evidence is -- a checkpoint
/// the group's authority signed, naming that change. One signed by any
/// other key is refused, though the base itself is signed by a signer the
/// group lets found one.
#[tokio::test]
async fn a_foreign_base_whose_witness_the_group_authority_never_signed_is_refused() {
    let group_id = "group-merge-witness";
    let signer_key = SigningKey::from_bytes(&[31u8; 32]);
    let (handler, head) = handler_where_b_founds_bases(group_id, &signer_key);
    let change = ChangeHash([0x55; 32]);

    let genuine = witness_signed_by(group_id, change, head, &SigningKey::from_bytes(&[7u8; 32]));
    let (manifest, bytes) = offered_base(group_id, change, genuine, &signer_key, "device-c");
    handler.verify_foreign_base(group_id, &manifest, &bytes).expect("genuine evidence verifies");

    let forged = witness_signed_by(group_id, change, head, &SigningKey::from_bytes(&[99u8; 32]));
    let (manifest, bytes) = offered_base(group_id, change, forged, &signer_key, "device-c");
    let error = handler
        .verify_foreign_base(group_id, &manifest, &bytes)
        .expect_err("evidence the authority never signed is refused");
    assert!(
        matches!(error, ForeignBaseMergeError::WitnessUnverified { change: refused, .. } if refused == change),
        "got {error:?}"
    );
}

/// Genuine evidence that `device-c` published a change does not vouch for
/// that change as another author's write: the summary's author for a
/// change is its position, and the evidence has to name the same one.
#[tokio::test]
async fn a_witness_published_by_another_author_than_the_summary_names_is_refused() {
    let group_id = "group-merge-witness-author";
    let signer_key = SigningKey::from_bytes(&[31u8; 32]);
    let (handler, head) = handler_where_b_founds_bases(group_id, &signer_key);
    let change = ChangeHash([0x56; 32]);
    let genuine = witness_signed_by(group_id, change, head, &SigningKey::from_bytes(&[7u8; 32]));

    let (manifest, bytes) = offered_base(group_id, change, genuine, &signer_key, "device-d");
    let error = handler
        .verify_foreign_base(group_id, &manifest, &bytes)
        .expect_err("evidence for another author is refused");

    assert!(
        matches!(error, ForeignBaseMergeError::WitnessUnverified { change: refused, .. } if refused == change),
        "got {error:?}"
    );
}
