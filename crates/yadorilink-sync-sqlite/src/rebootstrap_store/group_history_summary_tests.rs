#![cfg(test)]
//! What `build_group_history_summary` answers, below and above an
//! installed base.
//!
//! The summary is read out of derived state the store already maintains:
//! the author-chain rows, the live path frontier, and the installed base's
//! own summary. On a device that has crossed a compaction boundary the path
//! frontier describes only what is retained -- pruning a change forgets its
//! frontier rows -- so the heads of a path the current epoch has not
//! touched come from the base.

use super::base_install_tests::open;
use super::*;
use ed25519_dalek::SigningKey;
use yadorilink_replica_domain::admission::ChangeEmitter;
use yadorilink_replica_domain::change::{Op, PutOrigin};
use yadorilink_replica_domain::file::{FileMeta, FileVersion, RecordKind, VersionBlock};
use yadorilink_replica_domain::ids::{FolderGroupId, SyncPath};

fn version(seed: u8) -> FileVersion {
    FileVersion::new(
        Vec::<VersionBlock>::new(),
        0,
        FileMeta {
            mtime_unix_nanos: 1_000 + seed as i64,
            unix_mode: None,
            symlink_target: None,
            record_kind: RecordKind::File,
            xattrs: Vec::new(),
        },
    )
}

/// Seals `summary` as this group's installed history base, the way a
/// local compaction commits one, and returns the checkpoint it was sealed
/// at so the caller can prune against it.
fn seal_base(
    conn: &Connection,
    group_id: &str,
    summary: &GroupHistorySummary,
    frontier: Vec<ChangeHash>,
) -> Checkpoint {
    let group = FolderGroupId(group_id.to_string());
    let snapshot = RebootstrapSnapshot::new(
        group.clone(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        summary.author_state.clone(),
        summary.path_heads.clone(),
        summary.lamport_ceiling,
    )
    .unwrap();
    let checkpoint = Checkpoint::new(group, frontier, snapshot.snapshot_hash());
    persist_history_base(conn, &checkpoint, &snapshot, None).unwrap();
    checkpoint
}

/// A group that already holds an installed history base is summarized over
/// its whole history, not only over the epoch above the base.
///
/// The scenario is the one a second compaction walks into. `A1` writes
/// `p.txt` and `A2`, an unrelated edit on `q.txt`, descends it. A base is
/// sealed over both and the `A1` prefix is pruned, which is what makes the
/// base worth anything -- and pruning `A1` forgets its path-frontier rows.
/// The base still carries `p.txt -> A1`; the live frontier does not. The
/// summary takes a path the current epoch has not touched from the base,
/// and a path it has touched from the current epoch alone: every change on
/// the current epoch descends from the base as a whole.
#[test]
fn a_group_that_already_holds_an_installed_base_is_summarized_over_its_whole_history() {
    const GROUP: &str = "group-summary-over-installed-base";
    let conn = open();
    let emitter = ChangeEmitter::new("device-a", SigningKey::from_bytes(&[23u8; 32]));
    let v1 = version(1);
    let v2 = version(2);
    for version in [&v1, &v2] {
        crate::dag_store::put_file_version(&conn, GROUP, version).unwrap();
    }
    let put = |path: &str, version: &FileVersion| Op::Put {
        path: SyncPath(path.to_string()),
        version: version.version_hash,
        origin: PutOrigin::Direct,
    };

    let a1 = crate::dag_store::emit_local_change(&conn, GROUP, vec![put("p.txt", &v1)], &emitter)
        .unwrap()
        .compute_hash();
    let a2 = crate::dag_store::emit_local_change(&conn, GROUP, vec![put("q.txt", &v2)], &emitter)
        .unwrap()
        .compute_hash();

    // The summary of the whole history, while all of it is still here.
    let before = build_group_history_summary(&conn, GROUP).unwrap();
    assert!(
        before.path_heads.iter().any(|head| head.path == "p.txt" && head.change_hash == a1),
        "the un-compacted history has p.txt at A1: {before:?}"
    );

    // Seal a base over it and prune the A1 prefix, exactly as a
    // compaction does: the base carries the summary, the pruned change
    // loses its frontier rows.
    let checkpoint = seal_base(&conn, GROUP, &before, vec![a2]);
    crate::dag_store::commit_prune(&conn, &checkpoint, &[a1]).unwrap();

    // The base still carries the head. The live frontier cannot.
    let base = history_base_summary(&conn, GROUP).unwrap().expect("a base is installed");
    assert!(
        base.path_heads.iter().any(|head| head.path == "p.txt" && head.change_hash == a1),
        "the installed base carries p.txt -> A1: {base:?}"
    );
    let live = crate::dag_store::path_frontier::live_content_heads_for_group(&conn, GROUP).unwrap();
    assert!(
        !live.iter().any(|head| head.path == "p.txt"),
        "pruning A1 forgot its frontier rows: {live:?}"
    );

    let sorted = |mut summary: GroupHistorySummary| {
        summary.author_state.sort();
        summary.path_heads.sort();
        summary
    };
    assert_eq!(
        sorted(build_group_history_summary(&conn, GROUP).unwrap()),
        sorted(before),
        "nothing has been written above the base, so the summary is the base's own"
    );

    // Rewriting p.txt above the base replaces the head the base carried
    // for it; q.txt, untouched, keeps the base's.
    let v3 = version(3);
    crate::dag_store::put_file_version(&conn, GROUP, &v3).unwrap();
    let a3 = crate::dag_store::emit_local_change(&conn, GROUP, vec![put("p.txt", &v3)], &emitter)
        .unwrap();
    let after = build_group_history_summary(&conn, GROUP).unwrap();
    let heads_of = |path: &str| -> Vec<ChangeHash> {
        after
            .path_heads
            .iter()
            .filter(|head| head.path == path)
            .map(|head| head.change_hash)
            .collect()
    };
    assert_eq!(heads_of("p.txt"), vec![a3.compute_hash()]);
    assert_eq!(heads_of("q.txt"), vec![a2]);
    assert_eq!(after.lamport_ceiling, a3.lamport);
    assert_eq!(after.author_watermark("device-a"), Some(a3.author_seq));
}

/// A group that has never crossed a boundary is summarized from its live
/// frontier alone.
#[test]
fn a_group_with_no_installed_base_is_summarized_from_live_state() {
    const GROUP: &str = "group-summary-genesis";
    let conn = open();
    let emitter = ChangeEmitter::new("device-a", SigningKey::from_bytes(&[24u8; 32]));
    let v1 = version(1);
    crate::dag_store::put_file_version(&conn, GROUP, &v1).unwrap();
    let a1 = crate::dag_store::emit_local_change(
        &conn,
        GROUP,
        vec![Op::Put {
            path: SyncPath("p.txt".to_string()),
            version: v1.version_hash,
            origin: PutOrigin::Direct,
        }],
        &emitter,
    )
    .unwrap()
    .compute_hash();

    let summary = build_group_history_summary(&conn, GROUP).unwrap();
    assert!(summary.path_heads.iter().any(|head| head.change_hash == a1), "{summary:?}");
}

/// Builds a small history and seals a base over it, leaving the group
/// with a persisted summary to read back.
fn group_with_a_sealed_base(conn: &Connection, group_id: &str, key: u8) -> GroupHistorySummary {
    let emitter = ChangeEmitter::new("device-a", SigningKey::from_bytes(&[key; 32]));
    let v1 = version(1);
    crate::dag_store::put_file_version(conn, group_id, &v1).unwrap();
    let a1 = crate::dag_store::emit_local_change(
        conn,
        group_id,
        vec![Op::Put {
            path: SyncPath("p.txt".to_string()),
            version: v1.version_hash,
            origin: PutOrigin::Direct,
        }],
        &emitter,
    )
    .unwrap()
    .compute_hash();
    let summary = build_group_history_summary(conn, group_id).unwrap();
    seal_base(conn, group_id, &summary, vec![a1]);
    summary
}

/// A base with no stored Lamport ceiling is damage, and is reported as
/// damage rather than answered with zero.
///
/// The ceiling is written in the same transaction as the base itself, so
/// its absence cannot mean "this history reached Lamport 0". Answering
/// zero would be the worse of the two outcomes: the Lamport anchor
/// resumes from the ceiling, so a zeroed one silently changes the order
/// two replicas resolve a path into while every row still looks plausible.
#[test]
fn an_installed_base_with_no_stored_lamport_ceiling_is_damage_not_a_ceiling_of_zero() {
    const GROUP: &str = "group-base-missing-meta";
    let conn = open();
    let summary = group_with_a_sealed_base(&conn, GROUP, 31);
    assert!(summary.lamport_ceiling > 0, "the sealed history reached a real Lamport");
    assert_eq!(
        history_base_summary(&conn, GROUP).unwrap().unwrap().lamport_ceiling,
        summary.lamport_ceiling
    );

    conn.execute("DELETE FROM history_base_meta WHERE group_id = ?1", [GROUP]).unwrap();

    let error = history_base_summary(&conn, GROUP)
        .expect_err("a base with no ceiling row is a damaged database");
    assert!(matches!(error, SyncSqliteError::CorruptState(_)), "got {error:?}");
}

/// A base that claims heads but carries no author positions is damage
/// too. A base is not installable without them, so no rows here cannot
/// mean an empty history.
#[test]
fn an_installed_base_with_heads_but_no_author_positions_is_damage() {
    const GROUP: &str = "group-base-missing-author-state";
    let conn = open();
    let summary = group_with_a_sealed_base(&conn, GROUP, 32);
    assert!(!summary.path_heads.is_empty() && !summary.author_state.is_empty());

    conn.execute("DELETE FROM history_base_author_state WHERE group_id = ?1", [GROUP]).unwrap();

    let error = history_base_summary(&conn, GROUP)
        .expect_err("a base cannot carry heads by authors it has no position for");
    assert!(matches!(error, SyncSqliteError::CorruptState(_)), "got {error:?}");
}

/// The one state that genuinely reads as empty stays readable: a base
/// sealed over a history that had nothing in it. No authors, no heads, a
/// ceiling of zero -- and a stored ceiling row saying so, which is what
/// separates it from the damaged case above.
#[test]
fn a_base_sealed_over_an_empty_history_still_reads_as_an_empty_summary() {
    const GROUP: &str = "group-base-over-empty-history";
    let conn = open();
    let empty = GroupHistorySummary {
        author_state: Vec::new(),
        path_heads: Vec::new(),
        lamport_ceiling: 0,
    };
    seal_base(&conn, GROUP, &empty, Vec::new());

    let read = history_base_summary(&conn, GROUP).unwrap().expect("a base is installed");
    assert_eq!(read, empty, "an empty history's base is empty, not corrupt");
}
