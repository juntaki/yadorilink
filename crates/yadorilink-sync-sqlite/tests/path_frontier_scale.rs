//! What resolving a path is allowed to cost.
//!
//! The point of the path frontier is not that resolving a path got
//! faster. It is that resolving a path stopped depending on how much
//! history the group has -- no change decoded, no ancestry walked, the
//! same work for a path in a group of ten changes as in a group of ten
//! thousand. A timing test cannot establish that; a faster wrong
//! implementation passes one.
//!
//! So the two structural claims are tested by removing what they claim
//! not to need. Resolution must survive every encoded change body being
//! replaced with garbage, which it cannot if it decodes one. It must
//! survive every parent edge being deleted, which it cannot if it walks
//! ancestry. Both are exact, and neither can pass by accident.
//!
//! Timing appears only where the claim is genuinely about growth: that
//! admitting the ten-thousandth change into a group costs about what
//! admitting the hundredth did. That one is deliberately loose, because
//! its job is to catch a reintroduced history-length walk -- which shows
//! up as orders of magnitude, not percentages -- and not to police
//! ordinary variation.
//!
//! # What this looked like on real devices
//!
//! Two enrolled devices, two daemons, a 10,000-file folder synced
//! end to end. Each daemon reports per-attempt DAG-resolution counters;
//! summed over the whole run, with 10,000 paths resolved on each side:
//!
//! ```text
//!                                 before        after
//!   dag_get_change per path       ~11,494           0     (receiver)
//!   dag_get_change per path       ~10,192           0     (sender)
//!   dag_is_ancestor calls           large           0
//!   parent edges traversed          large           0
//!   change ops scanned              large           0
//! ```
//!
//! The "before" figures are the ones that opened this investigation:
//! ~91,949 and ~81,533 change decodes per eight-path reconcile batch.
//! Scaled to the 10,000 paths each side actually resolved, the receiver
//! would have decoded and op-scanned on the order of 10^8 changes. It
//! decoded none.
//!
//! Both devices ended with identical live frontiers (10,000 rows, equal
//! row for row), no live head missing its effect row, no group head
//! absent from a path it touches, no duplicate admission ordinal, and
//! every synced file byte-identical on both sides.

use std::time::Instant;

use ed25519_dalek::SigningKey;
use rusqlite::Connection;
use yadorilink_replica_domain::change::{Change, Op, PutOrigin};
use yadorilink_replica_domain::file::{FileMeta, FileVersion, RecordKind, VersionBlock};
use yadorilink_replica_domain::ids::{ChangeHash, DeviceId, FolderGroupId, SyncPath};
use yadorilink_replica_domain::test_authoring::create_signed_for_tests;
use yadorilink_sync_sqlite::dag_store::{
    admit_change, init_conflict_copy_provenance_schema, init_dag_schema, live_path_heads,
    put_file_version,
};

const GROUP: &str = "group-scale";

fn open() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    init_dag_schema(&conn).unwrap();
    // Admitting onto a frontier with more than one head makes admission
    // derive the conflict copies that change owes, which reads this
    // table. A catch-up scenario is exactly that shape.
    init_conflict_copy_provenance_schema(&conn).unwrap();
    conn
}

fn version() -> FileVersion {
    FileVersion::new(
        Vec::<VersionBlock>::new(),
        0,
        FileMeta {
            mtime_unix_nanos: 1_000,
            unix_mode: None,
            symlink_target: None,
            record_kind: RecordKind::File,
            xattrs: Vec::new(),
        },
    )
}

/// One change per file, chained onto the previous one -- the shape a
/// folder import produces, and the shape that made the old walk cost the
/// whole group's history to resolve a single path.
fn seed_chain(conn: &Connection, n: usize) -> Vec<ChangeHash> {
    // Each call seeds a store of its own, and a store of its own is a
    // history of its own: its first change must be its author's first.
    // Without this the second store in a test inherits the first's
    // numbering and refuses everything it is given.
    yadorilink_replica_domain::test_authoring::reset_author_sequences();
    let v = version();
    put_file_version(conn, GROUP, &v).unwrap();
    let signing_key = SigningKey::from_bytes(&[7u8; 32]);

    let mut hashes = Vec::with_capacity(n);
    let mut parents: Vec<ChangeHash> = Vec::new();
    let mut parent_lamport = 0u64;
    for i in 0..n {
        let change = create_signed_for_tests(
            parents.clone(),
            parent_lamport,
            DeviceId("device-a".to_string()),
            FolderGroupId(GROUP.to_string()),
            vec![Op::Put {
                path: SyncPath(format!("f{i:07}.bin")),
                version: v.version_hash,
                origin: PutOrigin::Direct,
            }],
            &signing_key,
        );
        admit_change(conn, &change).unwrap();
        let hash = change.compute_hash();
        parent_lamport = change.lamport;
        parents = vec![hash];
        hashes.push(hash);
    }
    hashes
}

/// Resolution must not decode a change. Proven by making every encoded
/// change body unreadable and resolving anyway: a resolution that
/// decoded one could not return the right answer, and would not return
/// an answer at all.
#[test]
fn resolving_a_path_does_not_read_any_encoded_change() {
    let conn = open();
    let hashes = seed_chain(&conn, 200);

    let before = live_path_heads(&conn, GROUP, "f0000000.bin").unwrap();
    assert_eq!(before.len(), 1, "sanity: the path must resolve before anything is broken");
    assert_eq!(before[0].change_hash, hashes[0].0);

    // Not a subtle corruption: every encoded body becomes a single zero
    // byte, which no decoder can turn back into a change.
    let replaced =
        conn.execute("UPDATE changes SET encoded = x'00' WHERE group_id = ?1", [GROUP]).unwrap();
    assert_eq!(replaced, 200, "sanity: every change body must have been replaced");

    let after = live_path_heads(&conn, GROUP, "f0000000.bin").unwrap();
    assert_eq!(
        after.len(),
        1,
        "resolving a path must not depend on any encoded change being readable"
    );
    assert_eq!(after[0].change_hash, before[0].change_hash);
    assert_eq!(after[0].lamport, before[0].lamport);
    assert_eq!(after[0].device_id, before[0].device_id);
    assert_eq!(
        after[0].content.as_ref().map(|c| c.version_hash),
        before[0].content.as_ref().map(|c| c.version_hash)
    );
}

/// Resolution must not walk ancestry. Proven by deleting every parent
/// edge in the database and resolving anyway: a resolution that walked
/// the DAG would have nothing left to walk.
#[test]
fn resolving_a_path_does_not_traverse_parent_edges() {
    let conn = open();
    let hashes = seed_chain(&conn, 200);

    let before = live_path_heads(&conn, GROUP, "f0000100.bin").unwrap();
    assert_eq!(before.len(), 1);
    assert_eq!(before[0].change_hash, hashes[100].0);

    let removed = conn.execute("DELETE FROM change_parents", []).unwrap();
    assert!(removed > 0, "sanity: there must have been edges to delete");

    let after = live_path_heads(&conn, GROUP, "f0000100.bin").unwrap();
    assert_eq!(
        after.len(),
        1,
        "resolving a path must not depend on the DAG's parent edges being present"
    );
    assert_eq!(after[0].change_hash, before[0].change_hash);
}

/// Every path in a long history resolves to the one change that wrote
/// it, and a path nothing ever wrote resolves to nothing. Cheap to state,
/// but it is the property a subtly wrong frontier update breaks, and it
/// breaks it silently.
#[test]
fn every_path_in_a_long_history_resolves_to_its_own_writer() {
    let conn = open();
    let hashes = seed_chain(&conn, 2_000);

    for i in (0..2_000).step_by(97) {
        let heads = live_path_heads(&conn, GROUP, &format!("f{i:07}.bin")).unwrap();
        assert_eq!(heads.len(), 1, "f{i:07}.bin must have exactly one live head");
        assert_eq!(heads[0].change_hash, hashes[i].0, "f{i:07}.bin must resolve to its writer");
    }
    assert!(
        live_path_heads(&conn, GROUP, "never-written.bin").unwrap().is_empty(),
        "a path nothing ever wrote must resolve to nothing"
    );
}

/// Admitting a change must not get more expensive as the group's history
/// grows.
///
/// This is the claim that matters most and is easiest to lose: the read
/// path only got cheap because the supersession decision moved to write
/// time, and a write-time decision that walks history has not removed the
/// cost, only relocated it. A single-headed chain is the case where a
/// reintroduced walk would be most expensive and least visible, since
/// every admission would have the whole prior history to walk.
///
/// When this test was first written it failed, and it was right to. The
/// cost it found was not in the frontier maintenance it was written to
/// guard -- disabling that maintenance entirely changed nothing -- but in
/// admission's own conflict-copy derivation, which resolved each touched
/// path by walking the frontier-reachable DAG. Per 500 admissions into a
/// single-headed chain, measured here: 487ms for the first 500, 19,913ms
/// for the 500 after 9,500 -- 41x, still climbing. Letting that
/// derivation read the path frontier when it recognizes the frontier as
/// the current one gives 75ms and 92ms for the same two points.
///
/// The threshold is deliberately far above any plausible constant-factor
/// variation. A history-length walk over a chain of this length is
/// hundreds of times slower by the end, not tens of percent.
#[test]
fn admission_cost_does_not_grow_with_history_length() {
    const CHUNK: usize = 500;
    const CHUNKS: usize = 20;

    let conn = open();
    let v = version();
    put_file_version(&conn, GROUP, &v).unwrap();
    let signing_key = SigningKey::from_bytes(&[7u8; 32]);

    let mut parents: Vec<ChangeHash> = Vec::new();
    let mut parent_lamport = 0u64;
    let mut chunk_times = Vec::with_capacity(CHUNKS);

    for chunk in 0..CHUNKS {
        let started = Instant::now();
        for i in 0..CHUNK {
            let change = create_signed_for_tests(
                parents.clone(),
                parent_lamport,
                DeviceId("device-a".to_string()),
                FolderGroupId(GROUP.to_string()),
                vec![Op::Put {
                    path: SyncPath(format!("f{:07}.bin", chunk * CHUNK + i)),
                    version: v.version_hash,
                    origin: PutOrigin::Direct,
                }],
                &signing_key,
            );
            admit_change(&conn, &change).unwrap();
            parent_lamport = change.lamport;
            parents = vec![change.compute_hash()];
        }
        chunk_times.push(started.elapsed());
    }

    let first = chunk_times[0];
    let last = chunk_times[CHUNKS - 1];
    assert!(
        last.as_secs_f64() < first.as_secs_f64() * 10.0 + 0.5,
        "admitting into a group of {} changes took {last:?} per {CHUNK}, against {first:?} for \
         the first {CHUNK} -- admission cost is tracking history length, which means a walk over \
         it has come back",
        CHUNK * (CHUNKS - 1),
    );
}

/// Catching up an offline branch must not get more expensive the further
/// into the branch it gets.
///
/// This is the shape peer-to-peer sync exists to handle, and it is not
/// the shape the other tests here measure. A device that forked long ago
/// comes back with a run of changes whose parents are its own, not this
/// device's heads:
///
/// ```text
///   A0 -- A1 -- ... -- An          <- this device's frontier
///     \
///      B1 -- B2 -- ... -- Bm       <- what the returning device brings
/// ```
///
/// Every one of those admissions lands on a frontier that is not the
/// current one -- `An` stays a head throughout, so the group is
/// two-headed for the whole catch-up and the current-frontier shortcut
/// never fires. Whatever admission falls back to therefore runs `m`
/// times, and if it walks the branch it is building, the catch-up is
/// quadratic in the branch's own length on top of being linear in how
/// long ago the fork was.
///
/// The numbers printed on failure are the measurement, not decoration:
/// the question is whether admitting the last hundred of the branch costs
/// what admitting the first hundred did.
#[test]
fn catching_up_an_offline_branch_does_not_get_more_expensive_as_it_goes() {
    const BASE: usize = 1_000;
    const FORK_AT: usize = 200;
    const MAINLINE_AFTER_FORK: usize = 1_000;
    const BRANCH: usize = 2_000;
    const SAMPLE: usize = 100;

    let conn = open();
    let v = version();
    put_file_version(&conn, GROUP, &v).unwrap();
    let signing_key = SigningKey::from_bytes(&[7u8; 32]);

    let put = |path: String| Op::Put {
        path: SyncPath(path),
        version: v.version_hash,
        origin: PutOrigin::Direct,
    };
    let sign = |parents: Vec<ChangeHash>, parent_lamport: u64, device: &str, path: String| {
        create_signed_for_tests(
            parents,
            parent_lamport,
            DeviceId(device.to_string()),
            FolderGroupId(GROUP.to_string()),
            vec![put(path)],
            &signing_key,
        )
    };

    // The shared history both devices had before the fork, and then some
    // more that only this device has.
    let mut parents: Vec<ChangeHash> = Vec::new();
    let mut parent_lamport = 0u64;
    let mut fork_point: Option<(ChangeHash, u64)> = None;
    for i in 0..(BASE + MAINLINE_AFTER_FORK) {
        let change = sign(parents.clone(), parent_lamport, "device-a", format!("a{i:07}.bin"));
        admit_change(&conn, &change).unwrap();
        parent_lamport = change.lamport;
        parents = vec![change.compute_hash()];
        if i == FORK_AT {
            fork_point = Some((change.compute_hash(), change.lamport));
        }
    }
    let (fork_hash, fork_lamport) = fork_point.expect("the fork point must have been recorded");

    // What the returning device brings: a run off the old fork point,
    // each change touching a path this device has never seen.
    let mut branch: Vec<Change> = Vec::with_capacity(BRANCH);
    let mut b_parents = vec![fork_hash];
    let mut b_lamport = fork_lamport;
    for i in 0..BRANCH {
        let change = sign(b_parents.clone(), b_lamport, "device-b", format!("offline/b{i:07}.bin"));
        b_lamport = change.lamport;
        b_parents = vec![change.compute_hash()];
        branch.push(change);
    }

    let mut first = std::time::Duration::ZERO;
    let mut last = std::time::Duration::ZERO;
    for (i, change) in branch.iter().enumerate() {
        let started = Instant::now();
        admit_change(&conn, change).unwrap();
        let elapsed = started.elapsed();
        if i < SAMPLE {
            first += elapsed;
        }
        if i >= BRANCH - SAMPLE {
            last += elapsed;
        }
    }

    // Sanity: the catch-up really did land on a two-headed frontier the
    // whole way, or this measured nothing.
    let heads = yadorilink_sync_sqlite::dag_store::group_heads(&conn, GROUP).unwrap();
    assert_eq!(heads.len(), 2, "the branch must have left the group genuinely two-headed");
    for i in [0usize, BRANCH / 2, BRANCH - 1] {
        let path = format!("offline/b{i:07}.bin");
        let live = live_path_heads(&conn, GROUP, &path).unwrap();
        assert_eq!(live.len(), 1, "{path} must resolve to exactly the change that wrote it");
        assert_eq!(live[0].change_hash, branch[i].compute_hash().0);
    }

    eprintln!(
        "OFFLINE first{SAMPLE}={first:?} last{SAMPLE}={last:?} ratio={:.2}",
        last.as_secs_f64() / first.as_secs_f64().max(1e-9)
    );
    assert!(
        last.as_secs_f64() < first.as_secs_f64() * 3.0 + 0.10,
        "catching up an offline branch is getting more expensive as it goes: the last {SAMPLE} \
         of a {BRANCH}-change branch took {last:?}, against {first:?} for the first {SAMPLE}. \
         Admission cost is tracking position within the branch, which makes a catch-up \
         quadratic in the branch's own length",
    );
}

/// The catch-up that actually happens: an offline device editing files
/// that already existed before it forked.
///
/// The companion test above has the returning device carry only paths
/// this device has never seen, which is the case a "was this path ever
/// touched" lookup answers outright. Real catch-up is mostly the other
/// case -- someone worked offline on the files that were already there --
/// and for those the lookup says "yes, somewhere" and settles nothing.
/// Resolving them by walking back through the branch and then through
/// shared history until the path's previous touch turns up is what this
/// guards against. That admission no longer walks at all is proven
/// structurally, in `catch_up_admission_structure.rs`; this test keeps the
/// absolute cost on the record.
///
/// ```text
///   P0 .. Pn  --  (fork)  --  unrelated mainline work
///                    \
///                     edit P0, edit P1, ... edit Pn
/// ```
///
/// Reports absolute per-admission cost as well as the first-versus-last
/// ratio, because the two failure shapes are different and the ratio
/// alone hides one of them: editing the files in creation order makes the
/// walk roughly constant-length rather than growing, so a purely
/// proportional check can read as flat while every single admission is
/// still walking thousands of changes.
#[test]
fn catching_up_an_offline_branch_of_edits_to_existing_files_stays_bounded() {
    const FILES: usize = 1_000;
    const MAINLINE_AFTER_FORK: usize = 500;
    const SAMPLE: usize = 100;

    let conn = open();
    let v = version();
    put_file_version(&conn, GROUP, &v).unwrap();
    let signing_key = SigningKey::from_bytes(&[7u8; 32]);

    let sign = |parents: Vec<ChangeHash>, parent_lamport: u64, device: &str, path: String| {
        create_signed_for_tests(
            parents,
            parent_lamport,
            DeviceId(device.to_string()),
            FolderGroupId(GROUP.to_string()),
            vec![Op::Put {
                path: SyncPath(path),
                version: v.version_hash,
                origin: PutOrigin::Direct,
            }],
            &signing_key,
        )
    };

    // Shared history: every file exists before the fork.
    let mut parents: Vec<ChangeHash> = Vec::new();
    let mut parent_lamport = 0u64;
    for i in 0..FILES {
        let change = sign(parents.clone(), parent_lamport, "device-a", format!("p{i:07}.bin"));
        admit_change(&conn, &change).unwrap();
        parent_lamport = change.lamport;
        parents = vec![change.compute_hash()];
    }
    let fork_hash = parents[0];
    let fork_lamport = parent_lamport;

    // This device keeps working on unrelated things after the fork.
    for i in 0..MAINLINE_AFTER_FORK {
        let change =
            sign(parents.clone(), parent_lamport, "device-a", format!("mainline{i:07}.bin"));
        admit_change(&conn, &change).unwrap();
        parent_lamport = change.lamport;
        parents = vec![change.compute_hash()];
    }

    // The returning device edited every pre-existing file once.
    let mut branch: Vec<Change> = Vec::with_capacity(FILES);
    let mut b_parents = vec![fork_hash];
    let mut b_lamport = fork_lamport;
    for i in 0..FILES {
        let change = sign(b_parents.clone(), b_lamport, "device-b", format!("p{i:07}.bin"));
        b_lamport = change.lamport;
        b_parents = vec![change.compute_hash()];
        branch.push(change);
    }

    let mut first = std::time::Duration::ZERO;
    let mut last = std::time::Duration::ZERO;
    let whole = Instant::now();
    for (i, change) in branch.iter().enumerate() {
        let started = Instant::now();
        admit_change(&conn, change).unwrap();
        let elapsed = started.elapsed();
        if i < SAMPLE {
            first += elapsed;
        }
        if i >= FILES - SAMPLE {
            last += elapsed;
        }
    }
    let whole = whole.elapsed();
    let per_admission_us = whole.as_secs_f64() * 1e6 / FILES as f64;
    eprintln!(
        "EXISTING first{SAMPLE}={first:?} last{SAMPLE}={last:?} ratio={:.2}          whole={whole:?} per_admission={per_admission_us:.0}us",
        last.as_secs_f64() / first.as_secs_f64().max(1e-9)
    );

    // Both edits of a file are real, and the later one wins.
    for i in [0usize, FILES / 2, FILES - 1] {
        let path = format!("p{i:07}.bin");
        let live = live_path_heads(&conn, GROUP, &path).unwrap();
        assert_eq!(live.len(), 1, "{path} must resolve to exactly one head");
        assert_eq!(
            live[0].change_hash,
            branch[i].compute_hash().0,
            "{path} must resolve to the offline edit, which supersedes the original"
        );
    }

    assert!(
        last.as_secs_f64() < first.as_secs_f64() * 3.0 + 0.10,
        "catching up edits to existing files is getting more expensive as it goes: the last \
         {SAMPLE} took {last:?} against {first:?} for the first {SAMPLE}",
    );
    assert!(
        per_admission_us < 600.0,
        "catching up an edit to an existing file costs {per_admission_us:.0}us per admission \
         over {FILES} files. A cost that is flat but this high is what a walk through shared \
         history looks like here, since editing files in creation order keeps the walk a \
         constant length; it measured 3,780us when admission still walked",
    );
}

/// What verifying the effect projection costs at startup.
///
/// Startup already decodes every retained change to re-verify it against
/// its own signed bytes, so checking that its stored path effects still
/// say what its ops say adds one indexed lookup and one op scan per
/// change -- not a second decode pass, so verifying effect contents at
/// startup does not mean decoding every change again.
///
/// Reports the absolute times so the numbers are on the record, and asserts
/// on the SHAPE, as this file's header says a timing test here must: the
/// claim is one lookup and one op scan per change, so quadrupling the history
/// must quadruple the total and leave the per-change cost alone. A
/// reintroduced history-length walk turns that 1.0x into ~4.0x.
///
/// A tight absolute per-change bound (e.g. `< 250us`) would police the
/// host's codegen, not the code: debug builds on ordinary hardware land
/// just around such a figure. The absolute kept below is the 600us its
/// sibling `catching_up_an_offline_branch_of_edits_to_existing_files_stays_
/// bounded` already uses, which catches an order of magnitude without
/// pretending to know how fast anyone's debug build is.
#[test]
fn verifying_the_effect_projection_at_startup_stays_cheap() {
    const CHANGES: usize = 10_000;
    const QUARTER: usize = CHANGES / 4;

    let small = open();
    seed_chain(&small, QUARTER);
    let started = Instant::now();
    init_dag_schema(&small).unwrap();
    let small_elapsed = started.elapsed();
    let small_per_change_us = small_elapsed.as_secs_f64() * 1e6 / QUARTER as f64;

    let conn = open();
    seed_chain(&conn, CHANGES);

    let started = Instant::now();
    init_dag_schema(&conn).unwrap();
    let elapsed = started.elapsed();
    let per_change_us = elapsed.as_secs_f64() * 1e6 / CHANGES as f64;
    eprintln!(
        "STARTUP schema init: {QUARTER} changes {small_elapsed:?} \
         ({small_per_change_us:.1}us/change), {CHANGES} changes {elapsed:?} \
         ({per_change_us:.1}us/change), growth {:.2}x",
        per_change_us / small_per_change_us
    );

    // Nothing was wrong, so nothing should have been rebuilt: the index
    // must still answer, and answer the same thing.
    let heads = live_path_heads(&conn, GROUP, "f0005000.bin").unwrap();
    assert_eq!(heads.len(), 1, "a healthy index must survive its own verification untouched");

    assert!(
        per_change_us < small_per_change_us * 1.5,
        "verifying the effect projection costs {per_change_us:.1}us per change over {CHANGES} \
         changes against {small_per_change_us:.1}us over {QUARTER}. Per-change cost that grows \
         with the history is the walk this projection exists to remove coming back; a walk \
         would show ~4x here, and measured drift on flat work is a couple of percent",
    );
    assert!(
        per_change_us < 600.0,
        "verifying the effect projection costs {per_change_us:.1}us per change over {CHANGES} \
         changes ({elapsed:?} total), which is more than a lookup and an op scan should be",
    );
}
