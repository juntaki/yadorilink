//! Conflict-copy names are physical; the state they stand for is logical.
//!
//! Two replicas holding the very same native state may project a loser at
//! different physical names: a copy keeps the name it was first given, so a
//! replica that learned of an ordinary file at the first derived name before
//! the conflict names the copy one step later, while a replica that named the
//! copy first keeps it there and moves the ordinary file aside. Both disks
//! then show the same logical state under different names, and the very same
//! physical name can be the ordinary file on one replica and the loser's copy
//! on the other. This module pins that the difference stays physical:
//!
//! * a user edit or delete of the copy is authored against the loser's head
//!   (found through the row's native identity, never through its name), so
//!   the delta is the same whichever replica made it and carries no name;
//! * an edit or delete of the ordinary file is an edit of that file's own
//!   logical path and never touches the loser, wherever its replica shows it;
//! * after both replicas apply every delta their states are equal and the
//!   set of (source path, version) pairs the projections stand for is the
//!   same although the names differ;
//! * a directory rename that carries the copy keeps the loser a loser of
//!   the same logical source on both replicas.
//!
//! What local capture does with a physical path is reproduced by
//! [`capture`]: the entry the path is a copy of is found by
//! `write_through_source`, and the operation is authored at that source.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::SigningKey;
use rusqlite::Connection;

use yadorilink_replica_domain::author::{AuthorId, IncarnationId};
use yadorilink_replica_domain::file::{FileMeta, FileRecord, FileVersion, RecordKind};
use yadorilink_replica_domain::ids::{AuthorSeq, DeviceId, FolderGroupId, SyncPath, VersionHash};
use yadorilink_replica_domain::local_op::Op;
use yadorilink_replica_domain::native_plan::NativeRowIdentity;
use yadorilink_replica_domain::native_resolver::numbered_copy_name;
use yadorilink_replica_domain::native_state::{resolve_winner, Dot, LiveHead};
use yadorilink_replica_domain::recursive_operation::RecursiveOperationKind;
use yadorilink_replica_domain::session_state::{LocalFileMetaColumns, PreparedLocalMutation};
use yadorilink_replica_domain::signed_delta::{DeltaOp, DeltaPut, NativeDelta};

use crate::local_author::LocalAuthor;
use yadorilink_replica_domain::native_plan::NativePlannedNode;

use crate::native_desired_state::native_plan_level;
use crate::{native_authoring, native_store};

const GROUP: &str = "g1";

fn group() -> FolderGroupId {
    FolderGroupId(GROUP.into())
}

fn author_id(name: &str) -> AuthorId {
    AuthorId { device: DeviceId(name.into()), incarnation: IncarnationId([1u8; 16]) }
}

fn key_of(name: &str) -> SigningKey {
    let mut seed = [0u8; 32];
    for (slot, byte) in seed.iter_mut().zip(name.bytes().cycle()) {
        *slot = byte;
    }
    SigningKey::from_bytes(&seed)
}

fn version(mtime: i64) -> FileVersion {
    FileVersion::new(
        Vec::new(),
        0,
        FileMeta {
            mtime_unix_nanos: mtime,
            unix_mode: Some(0o644),
            symlink_target: None,
            record_kind: RecordKind::File,
            xattrs: Vec::new(),
        },
    )
}

/// Every content version the scenarios use.
struct Versions {
    winner: FileVersion,
    loser: FileVersion,
    ordinary: FileVersion,
    edit: FileVersion,
    ordinary_edit: FileVersion,
}

impl Versions {
    fn all(&self) -> [&FileVersion; 5] {
        [&self.winner, &self.loser, &self.ordinary, &self.edit, &self.ordinary_edit]
    }

    fn by_hash(&self, hash: [u8; 32]) -> &FileVersion {
        self.all().into_iter().find(|v| v.version_hash.0 == hash).expect("a known content version")
    }
}

fn versions() -> Versions {
    Versions {
        winner: version(1_000),
        loser: version(2_000),
        ordinary: version(3_000),
        edit: version(4_000),
        ordinary_edit: version(5_000),
    }
}

fn put(path: &str, v: &FileVersion) -> Op {
    Op::Put { path: SyncPath(path.into()), version: v.version_hash }
}

fn delete(path: &str) -> Op {
    Op::Delete { path: SyncPath(path.into()) }
}

fn heads_at(c: &Connection, path: &str) -> Vec<LiveHead> {
    native_store::native_heads_at(c, &group(), &SyncPath(path.into())).unwrap()
}

type LogicalPath = (BTreeSet<[u8; 32]>, Option<[u8; 32]>);

/// What the logical state says at `paths`: per path, every live head's
/// version and the winner's. Dots are left out so states built from
/// different authors can be compared; equality of dots is asserted where the
/// same delta was applied.
fn logical(c: &Connection, paths: &[&str]) -> BTreeMap<String, LogicalPath> {
    paths
        .iter()
        .map(|path| {
            let heads = heads_at(c, path);
            let versions = heads.iter().map(|h| h.payload.version.0).collect();
            let winner = resolve_winner(heads.iter()).map(|h| h.payload.version.0);
            ((*path).to_owned(), (versions, winner))
        })
        .collect()
}

/// The deltas an author signed, oldest first.
fn deltas_of(c: &Connection, author: &AuthorId) -> Vec<NativeDelta> {
    let seq = native_store::frontier_entry_get(c, &group(), author)
        .unwrap()
        .map_or(0, |entry| entry.seq.get());
    (1..=seq)
        .map(|n| {
            let body = native_store::fetch_delta_body(c, &group(), author, AuthorSeq(n))
                .unwrap()
                .expect("a signed delta has a stored body");
            NativeDelta::from_wire_bytes(&body).unwrap()
        })
        .collect()
}

/// A first delta of `name` putting `version` at `path`, observing nothing:
/// every replica that installs it holds the same head.
fn install_first_put(c: &Connection, name: &str, path: &str, version: &FileVersion) {
    let key = key_of(name);
    let mut delta = NativeDelta {
        recursive_part: None,
        group_id: group(),
        author: author_id(name),
        seq: AuthorSeq::FIRST,
        prev: None,
        ops: vec![DeltaOp {
            path: SyncPath(path.into()),
            removes: vec![],
            put: Some(DeltaPut { version: version.version_hash }),
            keeps: Vec::new(),
            keep_put: false,
        }],
        signature: [0u8; 64],
    };
    delta.sign(&key);
    native_store::install_verified_delta(c, &group(), &delta, &key.verifying_key()).unwrap();
}

/// The row a materializer leaves at `path` for `identity`: showing `version`
/// and carrying the native head it was produced from.
fn write_row(c: &Connection, path: &str, version: &FileVersion, identity: &NativeRowIdentity) {
    let tx = c.unchecked_transaction().unwrap();
    crate::file_index::upsert_file_with_authoring_in_tx(
        &tx,
        GROUP,
        &FileRecord {
            path: path.to_string(),
            size: version.size,
            mtime_unix_nanos: version.meta.mtime_unix_nanos,
            blocks: Vec::new(),
            deleted: false,
        },
        "device-x",
        Some(identity),
    )
    .unwrap();
    crate::file_index::apply_local_meta_columns_in_tx(
        &tx,
        GROUP,
        path,
        &LocalFileMetaColumns {
            record_kind: version.meta.record_kind,
            symlink_target: None,
            symlink_out_of_root: false,
            unix_mode: version.meta.unix_mode,
            xattrs: Vec::new(),
        },
    )
    .unwrap();
    tx.commit().unwrap();
}

/// Which the replica learns first: the ordinary file at the loser's first
/// derived name, or the conflict.
#[derive(Clone, Copy)]
enum Learns {
    OrdinaryFirst,
    ConflictFirst,
}

/// One replica: its own database, projected on its own disk.
struct Replica {
    conn: Connection,
    /// The directory the contested path lives in (`""` for the root).
    parent: String,
    /// The contested logical path.
    source: String,
    /// The logical path of the ordinary file: the loser's first derived name.
    ordinary: String,
}

type Projection = BTreeMap<String, (String, [u8; 32])>;

fn projection_of(c: &Connection, parent: &str) -> Projection {
    native_plan_level(c, GROUP, parent)
        .unwrap()
        .nodes
        .into_iter()
        .filter_map(|(path, node)| match node {
            NativePlannedNode::Entry { head, .. } => Some((
                path.as_str().to_owned(),
                (head.source_path.as_str().to_owned(), head.version().0),
            )),
            _ => None,
        })
        .collect()
}

impl Replica {
    /// Plans the level, then writes the row of every planned file as the
    /// materializer would. A row already showing the planned head stays.
    fn settle(&self) {
        let plan = native_plan_level(&self.conn, GROUP, &self.parent).unwrap();
        for (path, node) in &plan.nodes {
            let NativePlannedNode::Entry { head, .. } = node else { continue };
            let shown = crate::store::read_canonical_current_row(&self.conn, GROUP, path.as_str())
                .unwrap()
                .filter(|row| !row.snapshot.deleted)
                .map(|row| row.version_hash());
            if shown == Some(head.version()) {
                continue;
            }
            let content = versions().by_hash(head.version().0).clone();
            write_row(&self.conn, path.as_str(), &content, &NativeRowIdentity::of(head));
        }
    }

    /// The physical path -> (source path, version) every planned file stands
    /// for, as the plan of the contested level shows it.
    fn projection(&self) -> Projection {
        projection_of(&self.conn, &self.parent)
    }

    /// The (source path, version) pairs the projection stands for.
    fn pairs(&self) -> BTreeSet<(String, [u8; 32])> {
        self.projection().into_values().collect()
    }

    /// Where this replica's disk shows `version` of `source`.
    fn name_of(&self, source: &str, version: &FileVersion) -> String {
        self.projection()
            .into_iter()
            .find(|(_, (s, v))| s == source && *v == version.version_hash.0)
            .unwrap_or_else(|| panic!("no file shows {source} at that version"))
            .0
    }

    fn state(&self) -> yadorilink_replica_domain::native_state::NativeState {
        native_store::load_state(&self.conn, &group()).unwrap()
    }

    fn loser_dot(&self) -> Dot {
        heads_at(&self.conn, &self.source)
            .into_iter()
            .find(|h| h.payload.version == versions().loser.version_hash)
            .expect("the loser is live")
            .dot
    }

    fn paths(&self) -> [&str; 2] {
        [self.source.as_str(), self.ordinary.as_str()]
    }
}

/// A replica holding the state
///
/// ```text
/// <source>        winner (device-w) | loser (device-l)
/// <first name>    an ordinary file (device-o)
/// ```
///
/// reached in the given order, so the two orders end in the same native
/// state with different projections.
fn replica(parent: &str, learns: Learns) -> Replica {
    let v = versions();
    let c = Connection::open_in_memory().unwrap();
    crate::replica_tables::init(&c).unwrap();
    for version in v.all() {
        crate::dag_store::put_file_version(&c, GROUP, version).unwrap();
    }
    let source = if parent.is_empty() { "x".to_owned() } else { format!("{parent}/x") };
    let ordinary = numbered_copy_name(&source, v.loser.version_hash.0, 1);
    let r = Replica { conn: c, parent: parent.to_owned(), source: source.clone(), ordinary };
    match learns {
        Learns::OrdinaryFirst => {
            install_first_put(&r.conn, "device-o", &r.ordinary, &v.ordinary);
            r.settle();
            install_first_put(&r.conn, "device-w", &source, &v.winner);
            install_first_put(&r.conn, "device-l", &source, &v.loser);
            r.settle();
        }
        Learns::ConflictFirst => {
            install_first_put(&r.conn, "device-w", &source, &v.winner);
            install_first_put(&r.conn, "device-l", &source, &v.loser);
            r.settle();
            install_first_put(&r.conn, "device-o", &r.ordinary, &v.ordinary);
            r.settle();
        }
    }
    r
}

/// The two replicas of every scenario: `a` learned of the ordinary file
/// first, `b` of the conflict.
fn pair(parent: &str) -> (Replica, Replica) {
    let (a, b) = (replica(parent, Learns::OrdinaryFirst), replica(parent, Learns::ConflictFirst));
    assert_premise(&a, &b);
    (a, b)
}

/// The premise every test relies on: the very same native state, projected
/// differently, with one physical name meaning two different entries.
fn assert_premise(a: &Replica, b: &Replica) {
    let v = versions();
    assert_eq!(a.state(), b.state(), "the replicas hold the very same native state");
    assert_eq!(a.pairs(), b.pairs(), "and show the same (source, version) pairs");
    let (a_loser, b_loser) = (a.name_of(&a.source, &v.loser), b.name_of(&b.source, &v.loser));
    assert_ne!(a_loser, b_loser, "under different names for the loser");
    assert_eq!(b_loser, a.ordinary, "the name B gives the loser is the ordinary file's own on A");
    assert_eq!(a.name_of(&a.ordinary, &v.ordinary), a.ordinary, "A shows the ordinary file there");
    assert_ne!(
        b.name_of(&b.ordinary, &v.ordinary),
        a.ordinary,
        "B had to put the ordinary file elsewhere"
    );
}

/// What local capture does with the user's change of the file at the physical
/// path `physical`: the entry the file is a copy of is found by
/// `write_through_source`, and the operation is authored at that source.
fn capture(
    r: &Replica,
    name: &str,
    physical: &str,
    new_content: Option<&FileVersion>,
) -> NativeDelta {
    let source = crate::write_through::write_through_source(&r.conn, GROUP, physical)
        .unwrap()
        .unwrap_or_else(|| physical.to_owned());
    let op = match new_content {
        Some(v) => put(&source, v),
        None => delete(&source),
    };
    let key = key_of(name);
    let local = LocalAuthor { author: author_id(name), signing_key: &key, capture: None };
    native_authoring::author_op(&r.conn, &group(), &local, &op, &SyncPath(physical.into()))
        .unwrap();
    deltas_of(&r.conn, &author_id(name))
        .pop()
        .expect("the operation authored no delta: it acted on nothing")
}

fn admit(r: &Replica, name: &str, delta: &NativeDelta) {
    native_store::install_verified_delta(&r.conn, &group(), delta, &key_of(name).verifying_key())
        .unwrap();
}

type Effect = (SyncPath, Vec<Dot>, Option<VersionHash>);

/// The edits a delta carries, with the author left out: path, the dots it
/// supersedes, and what it puts.
fn effect(delta: &NativeDelta) -> Vec<Effect> {
    let mut out: Vec<Effect> = delta
        .ops
        .iter()
        .map(|op| {
            (
                op.path.clone(),
                op.removes.iter().map(|r| r.dot.clone()).collect(),
                op.put.as_ref().map(|p| p.version),
            )
        })
        .collect();
    out.sort();
    out
}

/// No physical name rides in `delta` unless it is also the logical path of
/// one of its edits (the ordinary file's own name is).
fn assert_no_physical_name(delta: &NativeDelta, names: &[&str]) {
    let wire = delta.to_wire_bytes();
    let has = |needle: &[u8]| wire.windows(needle.len()).any(|w| w == needle);
    for name in names {
        let logical = delta.ops.iter().any(|op| op.path.as_str() == *name);
        assert!(
            logical || !has(name.as_bytes()),
            "an authored delta carries the physical name {name}"
        );
    }
}

// --- (a) a user edit or delete of the conflict copy -------------------------------

#[test]
fn editing_the_copy_is_authored_against_the_loser_identity_and_means_the_same_on_either_replica() {
    let v = versions();
    let (a, b) = pair("");
    let (a_copy, b_copy) = (a.name_of("x", &v.loser), b.name_of("x", &v.loser));
    let b_twin = replica("", Learns::ConflictFirst);
    let loser_dot = a.loser_dot();

    // A edits the copy it shows at one name; B edits the copy it shows at
    // another, which is the ordinary file's own name on A.
    let from_a = capture(&a, "device-a", &a_copy, Some(&v.edit));
    let from_b = capture(&b_twin, "device-b", &b_copy, Some(&v.edit));

    assert_eq!(
        effect(&from_a),
        effect(&from_b),
        "the delta names the loser's head at the logical source, not the physical name"
    );
    assert_eq!(
        effect(&from_a),
        vec![(SyncPath("x".into()), vec![loser_dot], Some(v.edit.version_hash))]
    );
    assert_no_physical_name(&from_a, &[&a_copy, &b_copy]);

    // The same delta means the same thing on B as on A.
    admit(&b, "device-a", &from_a);
    assert_eq!(a.state(), b.state(), "an admitted copy edit yields the author's own state");
    // And the edit B would have made itself yields the same logical state.
    assert_eq!(logical(&b.conn, &a.paths()), logical(&b_twin.conn, &a.paths()));
    assert_eq!(
        logical(&b.conn, &a.paths())["x"].0,
        BTreeSet::from([v.winner.version_hash.0, v.edit.version_hash.0]),
        "the winner stays and the edit sits beside it; the shown loser is gone"
    );
}

#[test]
fn deleting_the_copy_is_authored_against_the_loser_identity_and_means_the_same_on_either_replica() {
    let v = versions();
    let (a, b) = pair("");
    let (a_copy, b_copy) = (a.name_of("x", &v.loser), b.name_of("x", &v.loser));
    let b_twin = replica("", Learns::ConflictFirst);
    let loser_dot = a.loser_dot();

    let from_a = capture(&a, "device-a", &a_copy, None);
    let from_b = capture(&b_twin, "device-b", &b_copy, None);

    assert_eq!(effect(&from_a), effect(&from_b));
    assert_eq!(effect(&from_a), vec![(SyncPath("x".into()), vec![loser_dot], None)]);
    assert_no_physical_name(&from_a, &[&a_copy, &b_copy]);

    admit(&b, "device-a", &from_a);
    assert_eq!(a.state(), b.state());
    assert_eq!(logical(&b.conn, &a.paths()), logical(&b_twin.conn, &a.paths()));
    assert_eq!(
        logical(&b.conn, &a.paths())["x"],
        (BTreeSet::from([v.winner.version_hash.0]), Some(v.winner.version_hash.0))
    );
}

// --- (b) the ordinary file that occupies the name ---------------------------------

#[test]
fn editing_the_ordinary_file_is_an_edit_of_its_own_path_and_never_touches_the_loser() {
    let v = versions();
    let (a, b) = pair("");
    let a_file = a.name_of(&a.ordinary, &v.ordinary);
    let b_file = b.name_of(&b.ordinary, &v.ordinary);
    assert_ne!(a_file, b_file, "the replicas keep the ordinary file under different names");
    let b_twin = replica("", Learns::ConflictFirst);
    let loser_before = logical(&b.conn, &["x"]);

    let ordinary_dot = heads_at(&a.conn, &a.ordinary).remove(0).dot;
    let from_a = capture(&a, "device-a", &a_file, Some(&v.ordinary_edit));
    let from_b = capture(&b_twin, "device-b", &b_file, Some(&v.ordinary_edit));

    let expected = vec![(
        SyncPath(a.ordinary.clone()),
        vec![ordinary_dot],
        Some(v.ordinary_edit.version_hash),
    )];
    assert_eq!(effect(&from_a), expected, "its own logical path");
    assert_eq!(effect(&from_b), expected, "whichever name the replica keeps the file under");
    assert_no_physical_name(&from_b, &[&b_file]);

    admit(&b, "device-a", &from_a);
    assert_eq!(a.state(), b.state());
    for r in [&a, &b] {
        assert_eq!(logical(&r.conn, &["x"]), loser_before, "x's heads are untouched");
    }
    assert_eq!(logical(&b.conn, &a.paths()), logical(&b_twin.conn, &a.paths()));
}

#[test]
fn deleting_the_ordinary_file_is_a_delete_of_its_own_path_and_never_touches_the_loser() {
    let v = versions();
    let (a, b) = pair("");
    let a_file = a.name_of(&a.ordinary, &v.ordinary);
    let b_file = b.name_of(&b.ordinary, &v.ordinary);
    let b_twin = replica("", Learns::ConflictFirst);
    let loser_before = logical(&b.conn, &["x"]);

    let ordinary_dot = heads_at(&a.conn, &a.ordinary).remove(0).dot;
    let from_a = capture(&a, "device-a", &a_file, None);
    let from_b = capture(&b_twin, "device-b", &b_file, None);

    let expected = vec![(SyncPath(a.ordinary.clone()), vec![ordinary_dot], None)];
    assert_eq!(effect(&from_a), expected);
    assert_eq!(effect(&from_b), expected);

    admit(&b, "device-a", &from_a);
    for r in [&a, &b] {
        assert_eq!(logical(&r.conn, &["x"]), loser_before, "x's heads are untouched");
        assert!(heads_at(&r.conn, &r.ordinary).is_empty(), "the file is gone");
    }
}

// --- (c) both replicas apply everything ------------------------------------------

#[test]
fn after_every_delta_is_applied_the_replicas_agree_although_their_names_differ() {
    let v = versions();
    let (a, b) = pair("");
    let (a_file, b_copy) = (a.name_of(&a.ordinary, &v.ordinary), b.name_of("x", &v.loser));
    assert_eq!(a_file, b_copy, "one physical name: the ordinary file on A, the loser's copy on B");
    let names_before = (a.projection().into_keys().collect::<Vec<_>>(), {
        b.projection().into_keys().collect::<Vec<_>>()
    });

    // Each edits what it sees at that name, concurrently.
    let on_a = capture(&a, "device-a", &a_file, Some(&v.ordinary_edit));
    let on_b = capture(&b, "device-b", &b_copy, Some(&v.edit));
    assert_eq!(effect(&on_a)[0].0, SyncPath(a.ordinary.clone()), "A edited the ordinary file");
    assert_eq!(effect(&on_b)[0].0, SyncPath("x".into()), "B edited the loser");

    admit(&a, "device-b", &on_b);
    admit(&b, "device-a", &on_a);

    assert_eq!(a.state(), b.state(), "the same deltas give the same native state");
    assert_eq!(logical(&a.conn, &a.paths()), logical(&b.conn, &a.paths()));
    a.settle();
    b.settle();
    assert_eq!(a.pairs(), b.pairs(), "the set of (logical source path, version) pairs agrees");
    assert_eq!(
        a.pairs(),
        BTreeSet::from([
            ("x".to_owned(), v.winner.version_hash.0),
            ("x".to_owned(), v.edit.version_hash.0),
            (a.ordinary.clone(), v.ordinary_edit.version_hash.0),
        ])
    );
    let winners = |r: &Replica| {
        (logical(&r.conn, &["x"])["x"].1, logical(&r.conn, &[&r.ordinary])[&r.ordinary].1)
    };
    assert_eq!(winners(&a), winners(&b), "and so does the winner of each path");
    assert_ne!(names_before.0, names_before.1, "the replicas showed different names throughout");
}

// --- (d) a directory rename that carries the copy ---------------------------------

fn moved(path: &str) -> String {
    format!("q/{}", path.strip_prefix("p/").expect("under p"))
}

fn delete_mutation(path: &str) -> PreparedLocalMutation {
    PreparedLocalMutation::Delete {
        record: FileRecord {
            path: path.into(),
            size: 0,
            mtime_unix_nanos: 1,
            blocks: Vec::new(),
            deleted: true,
        },
        op: delete(path),
        native_witness: None,
    }
}

fn upsert_mutation(path: &str, version: &FileVersion) -> PreparedLocalMutation {
    PreparedLocalMutation::Upsert {
        record: FileRecord {
            path: path.into(),
            size: version.size,
            mtime_unix_nanos: version.meta.mtime_unix_nanos,
            blocks: Vec::new(),
            deleted: false,
        },
        op: put(path, version),
        version: version.clone(),
        meta: None,
        native_witness: None,
    }
}

/// `mv p q` as capture sees it on `r`: every file under `p` disappears and
/// reappears under `q` under the same name.
fn rename_directory(r: &Replica, name: &str) -> Vec<NativeDelta> {
    let v = versions();
    let mut mutations = Vec::new();
    for (physical, (_, version)) in r.projection() {
        mutations.push(delete_mutation(&physical));
        mutations.push(upsert_mutation(&moved(&physical), v.by_hash(version)));
    }
    let kind =
        RecursiveOperationKind::RenameTree { from: SyncPath("p".into()), to: SyncPath("q".into()) };
    let written =
        crate::write_through::write_recursive_operation_through(&r.conn, GROUP, &kind, &mutations)
            .unwrap();
    let pairs: Vec<(Op, SyncPath)> = written
        .iter()
        .map(|w| (w.mutation.op().clone(), SyncPath(w.mutation.record().path.clone())))
        .collect();
    let witnesses = vec![None; pairs.len()];
    let key = key_of(name);
    let local = LocalAuthor { author: author_id(name), signing_key: &key, capture: None };
    native_authoring::author_recursive_part_tagged(
        &r.conn,
        &group(),
        &local,
        &pairs,
        &witnesses,
        None,
    )
    .unwrap();
    deltas_of(&r.conn, &author_id(name))
}

#[test]
fn renaming_the_directory_that_holds_the_copy_keeps_the_loser_a_loser_of_the_same_source() {
    let v = versions();
    let (a, b) = pair("p");
    let b_twin = replica("p", Learns::ConflictFirst);

    let chain_a = rename_directory(&a, "device-a");
    let chain_b = rename_directory(&b_twin, "device-b");

    // The same rename is the same chain whichever replica made it, and no
    // delta names a copy.
    let flat = |chain: &[NativeDelta]| {
        let mut out: Vec<Effect> = chain.iter().flat_map(effect).collect();
        out.sort();
        out
    };
    assert_eq!(flat(&chain_a), flat(&chain_b), "the rename is one chain on both replicas");
    let names: Vec<String> = a.projection().into_keys().chain(b.projection().into_keys()).collect();
    let names: Vec<&str> = names.iter().map(String::as_str).collect();
    for delta in chain_a.iter().chain(&chain_b) {
        assert_no_physical_name(delta, &names);
    }

    // B admits A's chain whole and ends where A is.
    for delta in &chain_a {
        admit(&b, "device-a", delta);
    }
    assert_eq!(a.state(), b.state(), "an admitted directory rename yields the author's own state");
    for r in [&a, &b] {
        assert!(heads_at(&r.conn, "p/x").is_empty(), "nothing is left at the source");
        assert_eq!(
            logical(&r.conn, &["q/x"])["q/x"].0,
            BTreeSet::from([v.winner.version_hash.0, v.loser.version_hash.0]),
            "both heads of the contested path moved"
        );
    }

    // Each replica then plans the moved level against its own state: the
    // loser is a loser of `q/x` on both, and the ordinary file moved as its
    // own path.
    let (qa, qb) = (projection_of(&a.conn, "q"), projection_of(&b.conn, "q"));
    assert_eq!(
        qa.values().collect::<BTreeSet<_>>(),
        qb.values().collect::<BTreeSet<_>>(),
        "the same (source, version) pairs under q"
    );
    assert!(
        qa.values().any(|(source, version)| source == "q/x" && *version == v.loser.version_hash.0),
        "the loser is a loser of q/x"
    );
    assert!(
        qa.values().any(|(source, version)| *source == moved(&a.ordinary)
            && *version == v.ordinary.version_hash.0),
        "the ordinary file moved as its own path"
    );
}
