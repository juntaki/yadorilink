#![cfg(test)]
//! Installing a base with the atomic epoch reset
//! ([`install_base_for_tests`], the install [`commit_foreign_merge`]
//! commits): the fixtures other install tests build on, and what the
//! reset itself guarantees about the authors and rows it installs.

use super::*;
use ed25519_dalek::SigningKey;
use yadorilink_replica_domain::authorization_checkpoint::{
    build_merkle_proof, canonical_signing_bytes, checkpoint_hash, encode_merkle_proof,
    fingerprint_signing_key, merkle_root, sign_checkpoint, AuthorizationCheckpoint,
};
use yadorilink_replica_domain::file::{FileRecord, RecordKind};
use yadorilink_replica_domain::ids::{DeviceId, FolderGroupId, SyncPath};
use yadorilink_replica_domain::rebootstrap::HistoryBase;
use yadorilink_replica_domain::test_authoring::create_signed_for_tests;
use yadorilink_replica_engine::rebootstrap_snapshot::PublishedChangeWitness;

/// Full production schema in the production order (`yadorilink_sqlite_
/// runtime::init_schema` assumes `changes`/`pruned_changes` already
/// exist, per its own doc comment).
pub(super) fn open() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    crate::dag_store::init_dag_schema(&conn).unwrap();
    yadorilink_sqlite_runtime::init_schema(&conn).unwrap();
    conn
}

/// The author positions a snapshot carries for authors these tests do
/// not otherwise exercise. The device id is deliberately one no test
/// emits under, so restoring it can never collide with a local author's
/// real state.
pub(super) fn base_author_state() -> Vec<SnapshotAuthorState> {
    vec![SnapshotAuthorState {
        device_id: "device-base-author".to_string(),
        watermark: yadorilink_replica_domain::ids::AuthorSeq(1),
        tip_change_hash: ChangeHash([0x11; 32]),
    }]
}

pub(super) fn snapshot_row(
    path: &str,
    version_seq: i64,
    state: SnapshotVersionState,
    deleted: bool,
    size: u64,
) -> SnapshotFile {
    SnapshotFile {
        record: FileRecord {
            path: path.to_string(),
            size,
            mtime_unix_nanos: 0,
            blocks: vec![],
            deleted,
        },
        version_seq,
        state,
        origin_device_id: Some("device-a".to_string()),
        record_kind: RecordKind::File,
        symlink_target: None,
        symlink_out_of_root: false,
        unix_mode: None,
        xattrs: Vec::new(),
        authoring_change_hash: None,
    }
}

/// The change a test base names as the author of its rows.
///
/// A base's current rows each carry the change that authored them, and a
/// group with a base refuses a current row that names none -- so a test
/// base that is not about authorship still needs one. It is written by the
/// author [`base_author_state`] names, which no test emits under, touching
/// a path no test uses.
pub(super) fn base_author_change(group_id: &str) -> Change {
    create_signed_for_tests(
        Vec::new(),
        0,
        DeviceId("device-base-author".to_string()),
        FolderGroupId(group_id.to_string()),
        vec![Op::Delete { path: SyncPath("base-author-marker".to_string()) }],
        &SigningKey::from_bytes(&[13u8; 32]),
    )
}

/// Evidence that `change` was published, as a base carries it for a row
/// that change authored. The install stores it without verifying it; the
/// verification belongs to whoever accepted the base.
pub(super) fn witness_for(group_id: &str, change: &Change) -> PublishedChangeWitness {
    let hash = change.compute_hash();
    let author = SigningKey::from_bytes(&[13u8; 32]).verifying_key();
    let checkpoint = AuthorizationCheckpoint {
        group_id: group_id.to_string(),
        device_id: change.device_id.as_str().to_string(),
        signing_key_fingerprint: fingerprint_signing_key(&author),
        merkle_root: merkle_root(&[hash.0]),
        leaf_count: 1,
        checkpoint_seq: 1,
        signer_key_id: [2; 32],
        policy_epoch: 0,
        policy_seq: 1,
        policy_head: [3; 32],
        issued_at_unix: 0,
    };
    let encoded = canonical_signing_bytes(&checkpoint);
    let signature = sign_checkpoint(&checkpoint, &SigningKey::from_bytes(&[42; 32]));
    PublishedChangeWitness {
        change_hash: hash,
        checkpoint_hash: checkpoint_hash(&encoded, &signature),
        checkpoint_encoded: encoded,
        checkpoint_signature: signature.to_vec(),
        author_signing_public_key: author.to_bytes(),
        merkle_proof_encoded: encode_merkle_proof(&build_merkle_proof(&[hash.0], 0)),
    }
}

/// A minimal but genuinely valid install: real `files` rows, each
/// authored by [`base_author_change`], whose evidence the base carries.
pub(super) fn install(conn: &mut Connection, group_id: &str, files: Vec<SnapshotFile>) {
    install_authored_by(conn, &base_author_change(group_id), files).unwrap();
}

/// Installs a base whose one author is `author`, carrying `files`, each
/// authored by `author` and witnessed. Returns the installed checkpoint.
fn install_authored_by(
    conn: &mut Connection,
    author: &Change,
    mut files: Vec<SnapshotFile>,
) -> Result<Checkpoint, ForeignMergeError> {
    let group_id = author.group_id.as_str().to_string();
    let author_hash = author.compute_hash();
    for file in &mut files {
        file.authoring_change_hash = Some(author_hash);
    }
    let witnesses =
        if files.is_empty() { Vec::new() } else { vec![witness_for(&group_id, author)] };
    let snapshot = RebootstrapSnapshot::new(
        author.group_id.clone(),
        files,
        Vec::new(),
        Vec::new(),
        witnesses,
        Vec::new(),
        vec![SnapshotAuthorState {
            device_id: author.device_id.as_str().to_string(),
            watermark: author.author_seq,
            tip_change_hash: author_hash,
        }],
        Vec::new(),
        author.lamport,
    )
    .unwrap();
    let checkpoint = Checkpoint::new(author.group_id.clone(), Vec::new(), snapshot.snapshot_hash());
    let tx = conn.transaction().unwrap();
    install_base_for_tests(&tx, &checkpoint, &snapshot)?;
    tx.commit().unwrap();
    Ok(checkpoint)
}

/// An install retires every change of the history it replaces, and with
/// them every materialized basis that named one. A path's basis naming one
/// of them must not outlive the install as if it were current: the
/// device's next edit of that path would be parented on a change this
/// group no longer holds, which its own emission then refuses, and every
/// peer would too.
#[test]
fn an_install_retires_the_materialized_bases_of_the_history_it_replaces() {
    use yadorilink_replica_domain::admission::ChangeEmitter;
    use yadorilink_replica_domain::change::PutOrigin;
    use yadorilink_replica_domain::file::{FileMeta, FileVersion, VersionBlock};

    const GROUP: &str = "group-basis-install";
    let conn = open();
    let emitter = ChangeEmitter::new("device-a", SigningKey::from_bytes(&[11u8; 32]));
    let version = FileVersion::new(
        Vec::<VersionBlock>::new(),
        0,
        FileMeta {
            mtime_unix_nanos: 7,
            unix_mode: None,
            symlink_target: None,
            record_kind: RecordKind::File,
            xattrs: Vec::new(),
        },
    );
    crate::dag_store::put_file_version(&conn, GROUP, &version).unwrap();
    let put = |path: &str| Op::Put {
        path: SyncPath(path.to_string()),
        version: version.version_hash,
        origin: PutOrigin::Direct,
    };

    // The path as last placed, under a basis naming the change that put it
    // there; then a later change the incoming base carries the author at.
    let placed =
        crate::dag_store::emit_local_change(&conn, GROUP, vec![put("kept.txt")], &emitter).unwrap();
    crate::materialized_generation::record_materialized_generation(
        &conn,
        GROUP,
        "kept.txt",
        &[placed.compute_hash()],
        crate::materialized_generation::MaterializedObjectKind::RegularFile,
        Some(&version.version_hash),
        None,
        0,
    )
    .unwrap();
    let sealed = crate::dag_store::emit_local_change(
        &conn,
        GROUP,
        vec![Op::Delete { path: SyncPath("other.txt".to_string()) }],
        &emitter,
    )
    .unwrap();
    let sealed_hash = sealed.compute_hash();

    let group = FolderGroupId(GROUP.to_string());
    let snapshot = RebootstrapSnapshot::new(
        group.clone(),
        Vec::new(),
        vec![sealed.to_wire_bytes()],
        Vec::new(),
        Vec::new(),
        Vec::new(),
        vec![SnapshotAuthorState {
            device_id: "device-a".to_string(),
            watermark: sealed.author_seq,
            tip_change_hash: sealed_hash,
        }],
        Vec::new(),
        sealed.lamport,
    )
    .unwrap();
    let checkpoint = Checkpoint::new(group, vec![sealed_hash], snapshot.snapshot_hash());
    // A writer that read kept.txt's fence before the install and publishes
    // after it.
    let in_flight_epoch =
        crate::materialized_generation::snapshot_mutation_fence(&conn, GROUP, "kept.txt").unwrap();
    {
        let tx = conn.unchecked_transaction().unwrap();
        install_base_for_tests(&tx, &checkpoint, &snapshot).unwrap();
        tx.commit().unwrap();
    }
    assert!(
        !crate::dag_store::has_change(&conn, &placed.compute_hash()).unwrap(),
        "the install must actually drop the placing change for this to test anything"
    );
    assert!(
        crate::materialized_generation::lookup_materialized_generation_diagnostic(
            &conn, GROUP, "kept.txt"
        )
        .unwrap()
        .is_none(),
        "the install must delete the basis row, not only make it unreadable"
    );
    assert!(
        crate::materialized_generation::publish_materialized_generation_if_fence_current(
            &conn,
            GROUP,
            "kept.txt",
            &[placed.compute_hash()],
            crate::materialized_generation::MaterializedObjectKind::RegularFile,
            Some(&version.version_hash),
            None,
            in_flight_epoch,
            0,
        )
        .unwrap()
        .is_none(),
        "a writer that read the fence before the install must not republish a replaced basis"
    );
}

/// Installs an empty base carrying `author_state`.
fn install_carrying(
    conn: &mut Connection,
    group_id: &str,
    author_state: Vec<SnapshotAuthorState>,
) -> Result<Checkpoint, ForeignMergeError> {
    let group = FolderGroupId(group_id.to_string());
    let snapshot = RebootstrapSnapshot::new(
        group.clone(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        author_state,
        Vec::new(),
        0,
    )
    .unwrap();
    let checkpoint = Checkpoint::new(group, Vec::new(), snapshot.snapshot_hash());
    let tx = conn.transaction().unwrap();
    install_base_for_tests(&tx, &checkpoint, &snapshot)?;
    tx.commit().unwrap();
    Ok(checkpoint)
}

fn idle_author(watermark: u64, tip: u8) -> SnapshotAuthorState {
    SnapshotAuthorState {
        device_id: "device-idle".to_string(),
        watermark: yadorilink_replica_domain::ids::AuthorSeq(watermark),
        tip_change_hash: ChangeHash([tip; 32]),
    }
}

fn does_not_carry(error: &ForeignMergeError) -> Option<&str> {
    match error {
        ForeignMergeError::Store(SyncSqliteError::HistoryBaseInstallDoesNotCarryAuthor {
            device_id,
            ..
        }) => Some(device_id.as_str()),
        _ => None,
    }
}

/// A base must carry every author this replica holds a position for at
/// least as far as this replica holds it. One that omits an idle author
/// leaves that author anchored on the history being replaced -- unable to
/// emit here -- while a replica installing the base fresh restarts it at
/// its first position: the two would never agree on that author again.
#[test]
fn a_base_that_omits_an_author_held_here_is_refused() {
    const GROUP: &str = "group-omitted-author";
    let mut conn = open();
    let h1 = install_carrying(
        &mut conn,
        GROUP,
        vec![base_author_state().remove(0), idle_author(3, 0x33)],
    )
    .unwrap();

    let error = install_carrying(&mut conn, GROUP, base_author_state()).unwrap_err();
    assert_eq!(does_not_carry(&error), Some("device-idle"), "unexpected: {error}");
    assert_eq!(
        read_history_base(&conn, GROUP).unwrap(),
        Some(HistoryBase::from_checkpoint(&h1)),
        "the refused base is not installed"
    );
}

/// The same for a base that carries the author, but behind the position
/// held here: replicas holding the later change and replicas installing
/// the base fresh would anchor the author differently and admit
/// differently from then on.
#[test]
fn a_base_that_carries_an_author_behind_its_position_here_is_refused() {
    const GROUP: &str = "group-author-behind";
    let mut conn = open();
    install_carrying(&mut conn, GROUP, vec![base_author_state().remove(0), idle_author(3, 0x33)])
        .unwrap();

    let error = install_carrying(
        &mut conn,
        GROUP,
        vec![base_author_state().remove(0), idle_author(2, 0x22)],
    )
    .unwrap_err();
    assert!(
        does_not_carry(&error).is_some(),
        "a base carrying the author at an earlier position must be refused, got {error}"
    );
}

/// A base carrying every author at or beyond its position here installs.
#[test]
fn a_base_carrying_every_author_held_here_installs() {
    const GROUP: &str = "group-author-carried";
    let mut conn = open();
    install_carrying(&mut conn, GROUP, vec![base_author_state().remove(0), idle_author(3, 0x33)])
        .unwrap();
    install_carrying(&mut conn, GROUP, vec![base_author_state().remove(0), idle_author(4, 0x44)])
        .expect("a base carrying the author further than this replica holds it");
}

/// An installed base's rows keep the change that authored them.
///
/// A group with history accepts a current row only when it names an
/// author that history vouches for, and an installed base is that
/// history. A row installed without its author is one the database
/// refuses: the next install aborts on it, and reopening the database
/// refuses the whole group.
#[test]
fn an_installed_bases_rows_keep_their_authors_across_a_reopen_and_the_next_install() {
    const GROUP: &str = "group-authored-rows";
    let mut conn = open();
    let first_author = base_author_change(GROUP);
    let row = |size| snapshot_row("doc.txt", 7, SnapshotVersionState::Current, false, size);

    install_authored_by(&mut conn, &first_author, vec![row(10)]).expect("the first base installs");
    let stored: Option<Vec<u8>> = conn
        .query_row(
            "SELECT authoring_change_hash FROM files WHERE group_id = ?1 AND path = 'doc.txt'",
            [GROUP],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        stored.as_deref(),
        Some(&first_author.compute_hash().0[..]),
        "the row lost its author"
    );
    yadorilink_sqlite_runtime::init_schema(&conn)
        .expect("reopening refuses the rows the install wrote");

    install_authored_by(&mut conn, &first_author, vec![row(20)])
        .expect("the next base over the installed one installs");
    yadorilink_sqlite_runtime::init_schema(&conn)
        .expect("reopening refuses the rows the second install wrote");
}

/// A group a base was installed into must report real per-path rewind
/// values. Before the install stamped `admitted_at_unix_nanos`,
/// every path in the group came back `Unavailable` for every target
/// time until the next local write to that path -- a blanket "this
/// device cannot answer" about a folder whose contents it plainly
/// holds. This also exercises the reader's `version_seq DESC`
/// tie-break through the real write path: an install stamps a path's
/// whole retained history with one instant, so every multi-version path
/// here is a genuine tie.
#[test]
fn a_rebootstrapped_groups_rewind_plan_reports_real_values_not_unavailable() {
    let mut conn = open();
    let before_install = crate::file_index::now_unix_nanos_checked().unwrap();
    install(
        &mut conn,
        "group-1",
        vec![
            // A compacted path: real history behind it, starting above
            // version 1, and all three rows stamped with the install's
            // single instant -- so every one of them is a tie.
            snapshot_row("kept.txt", 4, SnapshotVersionState::Current, false, 40),
            snapshot_row("kept.txt", 3, SnapshotVersionState::Superseded, false, 30),
            snapshot_row("kept.txt", 2, SnapshotVersionState::Superseded, false, 20),
            // A path whose whole history the snapshot carries.
            snapshot_row("fresh.txt", 1, SnapshotVersionState::Current, false, 10),
            // A path the snapshot itself carries as deleted.
            snapshot_row("gone.txt", 1, SnapshotVersionState::Current, true, 0),
        ],
    );
    let after_install = crate::file_index::now_unix_nanos_checked().unwrap();

    let plan = crate::rewind_plan::compute_rewind_plan(&conn, "group-1", after_install).unwrap();
    let counts = plan.action_counts();
    assert_eq!(counts.unavailable, 0, "a rebootstrapped group must be answerable, got {plan:?}");
    assert_eq!(
        counts.unchanged, 3,
        "nothing happened between the install and the target, so nothing would change"
    );
    // Specifically: the multi-version path resolved to its CURRENT row,
    // not to one of the superseded rows sharing the same stamp -- that
    // would have reported a rollback that never happened.
    assert!(
        plan.entries.iter().all(|entry| matches!(
            entry.action,
            yadorilink_replica_domain::rewind::RewindPathAction::Unchanged
        )),
        "expected every path unchanged, got {plan:?}"
    );

    // The honest remaining limit, asserted so it stays honest. A target
    // BEFORE the install is before this device's own history for the
    // group exists at all: the install emptied `files` and reinstalled
    // the SOURCE device's rows, complete with the source's `version_seq`
    // numbering. So EVERY path is unanswerable that early, including the
    // ones whose reinstalled history starts at version 1 -- for those,
    // "version 1" means "never edited since the source device created
    // it", which says nothing about when this device first saw the path
    // and must not be read as "created after the target".
    use yadorilink_replica_domain::rewind::RewindPathAction;
    let earlier =
        crate::rewind_plan::compute_rewind_plan(&conn, "group-1", before_install).unwrap();
    let action = |path: &str| {
        earlier.entries.iter().find(|entry| entry.path == path).unwrap().action.clone()
    };
    for path in ["kept.txt", "fresh.txt", "gone.txt"] {
        match action(path) {
            RewindPathAction::Unavailable { reason } => {
                assert!(
                    reason.contains("re-bootstrap"),
                    "the reason must name the real cause for {path}: {reason}"
                );
                assert!(
                    !reason.contains("retention"),
                    "retention cannot be the cause below the install instant, and naming it \
                     for {path} would be a confident wrong explanation: {reason}"
                );
            }
            other => {
                panic!("expected Unavailable before the install for {path}, got {other:?}")
            }
        }
    }
    assert_eq!(earlier.action_counts().unavailable, 3);
    assert_eq!(
        earlier.action_counts().delete,
        0,
        "reporting a never-edited pre-install file as 'created after the target' would \
         invent history this device never observed"
    );
}

/// The exact inversion the group's local history floor exists to
/// prevent, and the boundary it must NOT over-apply, both through the
/// real install path.
///
/// A file the source device created long ago and never edited since
/// arrives in the snapshot as `version_seq = 1`. Read from `files`
/// alone that is indistinguishable from a path this device itself first
/// indexed after the rewind target -- which would report `Delete`,
/// claiming the file was created recently, for the never-modified
/// majority of an ordinary folder. The install records its own instant
/// as the floor precisely so that reading is suspended below it.
#[test]
fn an_unmodified_file_from_before_an_install_is_unavailable_below_the_floor() {
    let mut conn = open();
    let before_install = crate::file_index::now_unix_nanos_checked().unwrap();
    install(
        &mut conn,
        "group-1",
        vec![snapshot_row("unmodified.txt", 1, SnapshotVersionState::Current, false, 10)],
    );

    let floor: i64 = conn
        .query_row(
            "SELECT floor_unix_nanos FROM group_local_history_floor WHERE group_id = ?1",
            ["group-1"],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        floor >= before_install,
        "the install must record its own instant as this group's local history floor"
    );

    // An ordinary local write after the install, at a chosen instant so
    // the second target below can sit strictly between the two. Direct
    // SQL for the same reason `rewind_plan`'s own tests use it: the
    // production writer stamps the wall clock and offers no way to pick
    // the instant (`stamps_the_local_admission_clock_at_the_write_
    // chokepoint` covers that writer separately).
    //
    // The group has history from the install on, so the row needs an
    // authoring change this device knows; a pruned change's stub stands in
    // for the local change that would have authored it.
    let author = [0x5Bu8; 32];
    conn.execute(
        "INSERT INTO pruned_changes \
         (group_id, change_hash, checkpoint_hash, lamport, encoding_version) \
         VALUES ('group-1', ?1, ?2, 1, 1)",
        params![&author[..], &[0x5Au8; 32][..]],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO files (group_id, path, version_seq, state, deleted, size, \
                            mtime_unix_nanos, blocks_json, admitted_at_unix_nanos, \
                            authoring_change_hash) \
         VALUES ('group-1', 'typed-later.txt', 1, 'current', 0, 20, 0, '[]', ?1, ?2)",
        params![floor + 2, &author[..]],
    )
    .unwrap();

    let action = |at: i64, path: &str| {
        crate::rewind_plan::compute_rewind_plan(&conn, "group-1", at)
            .unwrap()
            .entries
            .iter()
            .find(|entry| entry.path == path)
            .unwrap()
            .action
            .clone()
    };
    use yadorilink_replica_domain::rewind::RewindPathAction;

    // Below the floor: this device has no history of its own that early,
    // so neither path can be classified -- least of all as `Delete`.
    for path in ["unmodified.txt", "typed-later.txt"] {
        assert!(
            matches!(action(before_install, path), RewindPathAction::Unavailable { .. }),
            "{path} must be unanswerable below the floor, got {:?}",
            action(before_install, path)
        );
    }

    // At or above it, the group's local history is this device's own
    // unbroken record again and ordinary classification resumes --
    // including the "first version admitted after the target" reading
    // the floor suspends below itself.
    assert_eq!(action(floor + 1, "unmodified.txt"), RewindPathAction::Unchanged);
    assert_eq!(action(floor + 1, "typed-later.txt"), RewindPathAction::Delete);
}

/// A base that carries no author positions while claiming heads or a
/// non-zero Lamport ceiling cannot say where its own authors stand, and
/// the summary reader refuses exactly that shape as damage. Installing it
/// would leave every later read of the group's summary failing, so the
/// install refuses it before writing anything. An honest seal never
/// produces it: a ceiling above zero means some author wrote a change.
#[test]
fn a_base_with_no_author_positions_but_a_nonzero_ceiling_is_refused() {
    const GROUP: &str = "group-no-authors";
    let mut conn = open();
    let group = FolderGroupId(GROUP.to_string());
    let snapshot = RebootstrapSnapshot::new(
        group.clone(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        5,
    )
    .expect("the snapshot shape itself is accepted; the install is what must refuse it");
    let checkpoint = Checkpoint::new(group, Vec::new(), snapshot.snapshot_hash());
    let tx = conn.transaction().unwrap();
    let error = install_base_for_tests(&tx, &checkpoint, &snapshot).unwrap_err();
    assert!(
        matches!(error, ForeignMergeError::Refused(ForeignMergeRefusal::SnapshotInvalid { .. })),
        "expected the install to refuse the authorless base, got {error}"
    );
    drop(tx);
    assert_eq!(read_history_base(&conn, GROUP).unwrap(), None, "nothing was installed");
    assert!(history_base_summary(&conn, GROUP).unwrap().is_none());
}

/// The one authorless base that is genuine: sealed over a history with
/// nothing in it -- no authors, no heads, a ceiling of zero. It installs,
/// and its summary reads back as empty rather than as damage.
#[test]
fn an_empty_base_with_no_authors_installs_and_reads_back_empty() {
    const GROUP: &str = "group-empty-base";
    let mut conn = open();
    install_carrying(&mut conn, GROUP, Vec::new()).expect("an empty base installs");
    let summary = history_base_summary(&conn, GROUP).unwrap();
    assert!(
        summary.as_ref().is_some_and(|summary| summary.author_state.is_empty()
            && summary.path_heads.is_empty()
            && summary.lamport_ceiling == 0),
        "expected an empty summary, got {summary:?}"
    );
}
