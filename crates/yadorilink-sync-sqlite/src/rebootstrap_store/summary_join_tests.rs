//! The causal join of two summaries of one group's history.
//!
//! Pure: no store, no transaction, no history. What is under test is the
//! definition of merging two histories -- watermarks by maximum, head sets
//! by union minus what the other side's watermark already covers, Lamport
//! ceiling by maximum -- because that definition is what a re-bootstrap
//! install now uses in place of rewriting one side into the other.

use super::*;

fn hash(byte: u8) -> ChangeHash {
    ChangeHash([byte; 32])
}

fn version(byte: u8) -> VersionHash {
    VersionHash([byte; 32])
}

fn author(device_id: &str, watermark: u64, tip: u8) -> SnapshotAuthorState {
    SnapshotAuthorState {
        device_id: device_id.to_string(),
        watermark: AuthorSeq(watermark),
        tip_change_hash: hash(tip),
    }
}

fn head(path: &str, change: u8, device_id: &str, seq: u64, content: u8) -> SnapshotPathHead {
    SnapshotPathHead {
        path: path.to_string(),
        change_hash: hash(change),
        device_id: device_id.to_string(),
        author_seq: AuthorSeq(seq),
        lamport: seq,
        version_hash: version(content),
        naming_device_id: device_id.to_string(),
    }
}

fn summary(
    author_state: Vec<SnapshotAuthorState>,
    path_heads: Vec<SnapshotPathHead>,
    lamport_ceiling: u64,
) -> GroupHistorySummary {
    GroupHistorySummary { author_state, path_heads, lamport_ceiling }
}

/// A head both sides name must be described the same way on both. Were the
/// join to keep whichever description came second, `A.join(B)` and
/// `B.join(A)` would differ, and so would the identity of the joined summary
/// and the base minted over it: two replicas merging from opposite sides
/// would part ways.
#[test]
fn a_head_the_two_sides_describe_differently_is_refused_in_either_order() {
    let authors = vec![author("a", 2, 0x12), author("c", 1, 0x31)];
    let left = summary(authors.clone(), vec![head("z", 0x31, "c", 1, 0x40)], 2);
    let mut right = summary(authors, vec![head("z", 0x31, "c", 1, 0x41)], 2);

    for (first, second) in [(&left, &right), (&right, &left)] {
        let error = first.join(second).expect_err("one head, two descriptions");
        assert!(matches!(error, SyncSqliteError::CorruptState(_)), "got {error:?}");
    }

    // Described the same way, the head joins, whichever side is asked.
    right.path_heads[0].version_hash = version(0x40);
    let joined = left.join(&right).unwrap();
    assert_eq!(joined, right.join(&left).unwrap());
    assert_eq!(joined.path_heads, vec![head("z", 0x31, "c", 1, 0x40)]);
}

/// A watermark is a prefix of one author's chain, so the higher of two
/// contains the lower -- and the tip travels with the watermark it was
/// attested alongside, never pairing a number with a change that did not
/// stand at it.
#[test]
fn watermarks_join_by_maximum_and_keep_their_own_tip() {
    let left = summary(vec![author("a", 5, 0x50), author("b", 2, 0x20)], Vec::new(), 9);
    let right = summary(vec![author("a", 3, 0x30), author("c", 7, 0x70)], Vec::new(), 4);

    let joined = left.join(&right).unwrap();

    assert_eq!(
        joined.author_state,
        vec![author("a", 5, 0x50), author("b", 2, 0x20), author("c", 7, 0x70)]
    );
    assert_eq!(joined.lamport_ceiling, 9, "the ceiling is the greater of the two");
    assert_eq!(
        left.join(&right).unwrap(),
        right.join(&left).unwrap(),
        "a join does not depend on which side is asked"
    );
}

/// One position naming two different changes is equivocation, which is
/// outside the merge domain: the watermark stops deciding membership the
/// moment one number can name two changes, so there is nothing to join.
#[test]
fn one_position_naming_two_changes_is_refused_rather_than_joined() {
    let left = summary(vec![author("a", 4, 0x40)], Vec::new(), 4);
    let right = summary(vec![author("a", 4, 0x41)], Vec::new(), 4);

    let error = left.join(&right).expect_err("equivocation has no join");
    assert!(matches!(error, SyncSqliteError::CorruptState(_)), "got {error:?}");
}

/// The union rule, in its three cases at once. A head both sides hold
/// survives. A head only one side holds survives when the other side has
/// not seen that author that far. A head only one side holds is dropped
/// when the other side HAS seen that author past it and does not list it:
/// that side has seen what superseded it, and carrying it forward would
/// resurrect content a later write removed.
#[test]
fn a_head_survives_unless_the_other_sides_watermark_already_covers_it() {
    let shared = head("both.txt", 0x01, "a", 1, 0xaa);
    let ahead = head("ahead.txt", 0x02, "b", 4, 0xbb);
    let superseded = head("gone.txt", 0x03, "c", 2, 0xcc);

    let left = summary(
        vec![author("a", 1, 0x01), author("b", 4, 0x02), author("c", 2, 0x03)],
        vec![shared.clone(), ahead.clone(), superseded.clone()],
        4,
    );
    // The right side has seen c up to sequence 5 and lists no head of
    // `gone.txt`, and has seen b only up to sequence 1.
    let right = summary(
        vec![author("a", 1, 0x01), author("b", 1, 0x09), author("c", 5, 0x05)],
        vec![shared.clone()],
        5,
    );

    let joined = left.join(&right).unwrap();
    let paths: Vec<&str> = joined.path_heads.iter().map(|h| h.path.as_str()).collect();
    assert_eq!(
        paths,
        vec!["ahead.txt", "both.txt"],
        "the superseded head is the only one the join drops"
    );
    assert!(joined.path_heads.contains(&shared));
    assert!(joined.path_heads.contains(&ahead));
    assert!(!joined.path_heads.contains(&superseded));
}

/// An author the other side has no position for at all covers nothing. Not
/// having heard of an author is not evidence about what that author wrote.
#[test]
fn a_side_that_never_heard_of_an_author_covers_none_of_its_heads() {
    let only = head("only.txt", 0x07, "stranger", 3, 0x77);
    let left = summary(vec![author("stranger", 3, 0x07)], vec![only.clone()], 3);
    let right = summary(vec![author("a", 9, 0x90)], Vec::new(), 9);

    assert_eq!(left.join(&right).unwrap().path_heads, vec![only]);
}

/// Two devices that wrote the same bytes concurrently produced two writes,
/// and a later delete descending from only one of them removes only that
/// one. A join that collapsed them by content could not say the other
/// survives, and the content would be lost.
#[test]
fn concurrent_heads_that_landed_the_same_content_stay_two_heads() {
    let by_a = head("same.txt", 0x11, "a", 1, 0xff);
    let by_b = head("same.txt", 0x12, "b", 1, 0xff);
    assert_eq!(by_a.version_hash, by_b.version_hash);

    let left = summary(vec![author("a", 1, 0x11)], vec![by_a.clone()], 1);
    let right = summary(vec![author("b", 1, 0x12)], vec![by_b.clone()], 1);

    let joined = left.join(&right).unwrap();
    assert_eq!(joined.path_heads, vec![by_a, by_b], "identical content is not one head");
}

/// An author's second write to a path descends its first -- the edit is
/// made against that path's materialized basis and takes it as its parents
/// -- so the earlier write cannot still be maximal. Two heads of one path
/// by one author is corrupt state on some side, and the join says so
/// rather than picking one.
#[test]
fn two_heads_of_one_path_by_one_author_is_corrupt_state() {
    let earlier = head("p.txt", 0x21, "a", 1, 0x01);
    let later = head("p.txt", 0x22, "a", 2, 0x02);
    // Neither side's watermark covers the other's head, so both reach the
    // bound check.
    let left = summary(vec![author("a", 1, 0x21)], vec![earlier], 1);
    let right = summary(vec![author("b", 1, 0x99)], vec![later], 2);

    let error = left.join(&right).expect_err("one author cannot hold two heads of one path");
    assert!(matches!(error, SyncSqliteError::CorruptState(_)), "got {error:?}");
}

/// The seam a merged base is built on: the join of two
/// summaries is explicit state, and its namespace projection is what the
/// merged base's rows must hold. `A` holds a file `a`, `B` holds `a/x`;
/// neither side alone has a conflict, the join does, and projecting it
/// makes `a` a structural directory with the file relocated beside it.
#[test]
fn summary_join_then_project_yields_structural_container() {
    use yadorilink_replica_domain::file::RecordKind;
    use yadorilink_replica_engine::namespace::{DirectoryNode, PhysicalNode, Placement};

    let left = summary(vec![author("a", 1, 1)], vec![head("a", 1, "a", 1, 1)], 1);
    let right = summary(vec![author("b", 1, 2)], vec![head("a/x", 2, "b", 1, 2)], 1);
    let joined = left.join(&right).unwrap();

    let projection = joined.project(|_| Some(RecordKind::File)).unwrap();

    assert_eq!(projection.get("a"), Some(&PhysicalNode::Directory(DirectoryNode::Structural)));
    let entries: Vec<(&str, &str, Placement)> = projection
        .nodes()
        .iter()
        .filter_map(|(name, node)| match node {
            PhysicalNode::Entry(entry) => {
                Some((name.as_str(), entry.source.as_str(), entry.placement))
            }
            PhysicalNode::Directory(_) => None,
        })
        .collect();
    assert_eq!(entries.len(), 2, "{entries:?}");
    assert!(entries.contains(&("a/x", "a/x", Placement::AtPath)));
    assert!(entries.iter().any(|(name, source, placement)| *source == "a"
        && *placement == Placement::Relocated
        && name.starts_with("a (")));
}
