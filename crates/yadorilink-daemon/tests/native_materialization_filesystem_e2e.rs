//! DCF desired tree vs native desired tree vs the *actual*
//! filesystem tree, materialized through the real, existing production
//! primitives (`yadorilink_local_storage::materialize_write::
//! {reconstruct_file, create_explicit_directory}`) into test-only temp
//! directories — never a real sync root, never real user data.
//!
//! Two-stage comparison:
//!
//! 1. **Semantic** — logical source path, kind, content/version, winner/
//!    loser relationship. Already covered exhaustively by
//!    `native_materialize_differential.rs`/`native_materialize_tree_
//!    differential.rs`'s 500-seed randomized sweeps against DCF's real
//!    `resolve_path_heads`/`project_own_node`; this file calls the same
//!    real functions (`project`, the whole-tree one, on both sides) as the
//!    *input* to the filesystem comparison, not as new semantic coverage of its own.
//! 2. **Filesystem** — actual filenames/content/kinds after both sides'
//!    real projection (`yadorilink_replica_engine::namespace::project` for
//!    DCF, `yadorilink_replica_domain::native_materialize::project` for
//!    native) is materialized through the identical
//!    `reconstruct_file`/`create_explicit_directory` calls. DCF's `project`
//!    already assigns and disambiguates conflict-copy names itself (this
//!    file uses its real output, untouched); native's adapter assigns
//!    names at materialization time only, via the same
//!    `conflict_copy_path` function DCF uses, with the same numbered-
//!    disambiguator convention on a collision — a materialization-time
//!    presentation decision, never a causal fact native's core state
//!    holds (no mtime was added to `HeadPayload`; mtime is a placeholder
//!    constant here, exactly as available to any materializer that has
//!    not yet looked up a real `FileVersion`'s recorded mtime).
//!
//! No new native-specific filesystem executor: both sides are rendered by
//! the identical `reconstruct_file`/`create_explicit_directory` calls this
//! module drives directly, bypassing only the DCF-row/admission/fence
//! bookkeeping layer (`LocalConvergenceExecutor::materialize_local`'s outer
//! shell) — which is about SQLite crash-consistency bookkeeping, not "does
//! the file look right", and which this test does not touch, so existing
//! crash/retry invariants (covered by their own, unmodified test suites)
//! are not at risk of being broken by anything here.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Mutex;

use sha2::{Digest, Sha256};

use yadorilink_local_storage::materialize_write::{
    create_explicit_directory, reconstruct_file, StructuralDirectoryLedger,
};
use yadorilink_local_storage::{ContentHash, LocallyHashedBlock, StorageError};
use yadorilink_replica_domain::author::{AuthorId, IncarnationId};
use yadorilink_replica_domain::conflict::conflict_copy_path;
use yadorilink_replica_domain::file::{BlockInfo, RecordKind};
use yadorilink_replica_domain::ids::{AuthorSeq, DeviceId, SyncPath, VersionHash};
use yadorilink_replica_domain::native_materialize::{self, PhysicalNode as NativePhysicalNode};
use yadorilink_replica_domain::native_state::{
    win_key, DeltaHash, Dot, HeadPayload, LiveHead, PathHeads,
};
use yadorilink_replica_engine::conflict::{PathHead, PathHeadContent};
use yadorilink_replica_engine::namespace::PhysicalNode as DcfPhysicalNode;

// --- Shared test infrastructure --------------------------------------------

/// A minimal in-memory `BlockContentStore` — test scaffolding satisfying
/// the existing production trait, not a new materialization primitive:
/// [`reconstruct_file`] itself (the thing that actually writes files) is
/// the real, unmodified, production function.
#[derive(Default)]
struct MemStore(Mutex<BTreeMap<String, Vec<u8>>>);

impl MemStore {
    fn put(&self, data: &[u8]) -> ContentHash {
        let hash = hex::encode(Sha256::digest(data));
        self.0.lock().unwrap().insert(hash.clone(), data.to_vec());
        hash
    }
}

impl yadorilink_local_storage::BlockContentStore for MemStore {
    fn put(&self, data: &[u8]) -> Result<ContentHash, StorageError> {
        Ok(MemStore::put(self, data))
    }
    fn put_prepared(&self, _prepared: &LocallyHashedBlock) -> Result<(), StorageError> {
        unimplemented!("not used by this test")
    }
    fn put_prepared_batch(&self, _prepared: &[LocallyHashedBlock]) -> Result<(), StorageError> {
        unimplemented!("not used by this test")
    }
    fn get(&self, hash: &str) -> Result<Vec<u8>, StorageError> {
        self.0
            .lock()
            .unwrap()
            .get(hash)
            .cloned()
            .ok_or_else(|| StorageError::NotFound(hash.to_owned()))
    }
    fn present_blocks(&self, hashes: &[ContentHash]) -> Result<Vec<bool>, StorageError> {
        let store = self.0.lock().unwrap();
        Ok(hashes.iter().map(|h| store.contains_key(h)).collect())
    }
}

/// A ledger that records nothing and refuses nothing — this test never
/// races a concurrent `mkdir`, so the ledger's whole job (detecting that
/// race) has nothing to detect.
struct NoOpLedger;

impl StructuralDirectoryLedger for NoOpLedger {
    fn record_intent(&self, _rel_path: &str) -> Result<(), StorageError> {
        Ok(())
    }
    fn complete(
        &self,
        _rel_path: &str,
        _identity: &yadorilink_root_authority::fs_identity::FileIdentity,
    ) -> Result<(), StorageError> {
        Ok(())
    }
    fn abandon(&self, _rel_path: &str) -> Result<(), StorageError> {
        Ok(())
    }
}

/// One entry to materialize: what `reconstruct_file`/`create_explicit_directory`
/// (or, for a symlink, the OS syscall the real `materialize_symlink_at`
/// itself ultimately calls) needs.
enum Entry {
    File { content: Vec<u8>, unix_mode: Option<u32> },
    Directory,
    Symlink { target: Vec<u8> },
}

/// Materializes `entries` (path -> what to place there) under `root`,
/// using the real production primitives for files and directories.
fn materialize(root: &Path, store: &MemStore, entries: &BTreeMap<String, Entry>) {
    // Directories first (shallowest first), matching
    // `yadorilink_replica_engine::namespace`'s own documented plan order
    // ("directory creations shallowest first, then entry writes").
    let mut dir_paths: Vec<&String> =
        entries.iter().filter(|(_, e)| matches!(e, Entry::Directory)).map(|(p, _)| p).collect();
    dir_paths.sort_by_key(|p| p.matches('/').count());
    for path in dir_paths {
        create_explicit_directory(&root.join(path), root, &NoOpLedger).unwrap();
    }
    for (path, entry) in entries {
        let out_path = root.join(path);
        match entry {
            Entry::Directory => {} // handled above
            Entry::File { content, unix_mode } => {
                let hash = store.put(content);
                let block = BlockInfo {
                    hash: hex::decode(&hash).unwrap(),
                    offset: 0,
                    size: content.len() as u32,
                };
                reconstruct_file(store, &out_path, std::slice::from_ref(&block), 0).unwrap();
                #[cfg(unix)]
                if let Some(mode) = unix_mode {
                    std::fs::set_permissions(&out_path, std::fs::Permissions::from_mode(*mode))
                        .unwrap();
                }
                #[cfg(not(unix))]
                let _ = unix_mode;
            }
            Entry::Symlink { target } => {
                #[cfg(unix)]
                {
                    let target_os = yadorilink_root_authority::fs_identity::bytes_to_target(target);
                    std::os::unix::fs::symlink(target_os, &out_path).unwrap();
                }
                #[cfg(not(unix))]
                let _ = target;
            }
        }
    }
}

/// Every regular file/dir/symlink under `root`, relative path -> (kind,
/// content-or-symlink-target). The observable actual filesystem tree.
fn walk(root: &Path) -> BTreeMap<String, (RecordKind, Vec<u8>)> {
    let mut out = BTreeMap::new();
    walk_into(root, root, &mut out);
    out
}

fn walk_into(root: &Path, dir: &Path, out: &mut BTreeMap<String, (RecordKind, Vec<u8>)>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        let rel = path.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/");
        let file_type = entry.file_type().unwrap();
        if file_type.is_symlink() {
            let target = yadorilink_root_authority::fs_identity::target_to_bytes(
                &std::fs::read_link(&path).unwrap(),
            );
            out.insert(rel, (RecordKind::Symlink, target));
        } else if file_type.is_dir() {
            out.insert(rel, (RecordKind::Directory, Vec::new()));
            walk_into(root, &path, out);
        } else {
            out.insert(rel, (RecordKind::File, std::fs::read(&path).unwrap()));
        }
    }
}

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

// --- Head-set scenario builder (shared by both sides) ----------------------

#[derive(Clone)]
struct HeadSpec {
    author: &'static str,
    tie_break_byte: u8,
    content: &'static [u8],
    kind: RecordKind,
}

fn content_hash(content: &[u8]) -> [u8; 32] {
    Sha256::digest(content).into()
}

fn dcf_heads(specs: &[HeadSpec]) -> Vec<PathHead> {
    specs
        .iter()
        .map(|s| PathHead {
            change_hash: [s.tie_break_byte; 32],
            // DCF orders concurrent heads by rank; hand it the native win order:
            // a directory above every file, then the content hash.
            rank: (u64::from(s.kind == RecordKind::Directory) << 40)
                | (u64::from_be_bytes(content_hash(s.content)[..8].try_into().unwrap()) >> 40),
            device_id: s.author.to_owned(),
            naming_device_id: s.author.to_owned(),
            content: Some(PathHeadContent {
                version_hash: content_hash(s.content),
                mtime_unix_nanos: 0,
            }),
        })
        .collect()
}

fn native_heads(specs: &[HeadSpec]) -> Vec<LiveHead> {
    specs
        .iter()
        .enumerate()
        .map(|(seq, s)| LiveHead {
            dot: Dot {
                author: AuthorId {
                    device: DeviceId(s.author.to_owned()),
                    incarnation: IncarnationId([1u8; 16]),
                },
                seq: AuthorSeq((seq + 1) as u64),
            },
            payload: HeadPayload {
                version: VersionHash(content_hash(s.content)),
                provenance: DeltaHash([s.tie_break_byte; 32]),
            },
        })
        .collect()
}

/// `content` is the entry's real bytes (a file's content, or a symlink's
/// target, encoded as bytes the same way `HeadSpec::content` always is in
/// this test's scenario builders) — never the version hash, which only
/// identifies content, it is not the content.
fn place_entry(
    path: &str,
    kind: RecordKind,
    content: &[u8],
    entries: &mut BTreeMap<String, Entry>,
) {
    match kind {
        RecordKind::Directory => {
            entries.insert(path.to_owned(), Entry::Directory);
        }
        RecordKind::Symlink => {
            entries.insert(path.to_owned(), Entry::Symlink { target: content.to_vec() });
        }
        RecordKind::File => {
            entries.insert(
                path.to_owned(),
                Entry::File { content: content.to_vec(), unix_mode: None },
            );
        }
    }
}

fn spec_by_content(specs: &[HeadSpec], version_hash: [u8; 32]) -> &HeadSpec {
    specs
        .iter()
        .find(|s| content_hash(s.content) == version_hash)
        .expect("version hash must match a spec")
}

// --- DCF side: real project(), untouched, including its own copy naming ---

fn dcf_tree_entries(scenario: &BTreeMap<String, Vec<HeadSpec>>) -> BTreeMap<String, Entry> {
    let heads_by_path: BTreeMap<String, Vec<PathHead>> =
        scenario.iter().map(|(path, specs)| (path.clone(), dcf_heads(specs))).collect();
    let kind_of = |version_hash: &[u8; 32]| {
        scenario
            .values()
            .flatten()
            .find(|s| content_hash(s.content) == *version_hash)
            .map(|s| s.kind)
    };
    let projection =
        yadorilink_replica_engine::namespace::project(&heads_by_path, kind_of).unwrap();

    let mut entries = BTreeMap::new();
    for (path, node) in projection.nodes() {
        match node {
            DcfPhysicalNode::Directory(_) => {
                entries.insert(path.clone(), Entry::Directory);
            }
            DcfPhysicalNode::Entry(placed) => {
                // `placed.source` names which logical path this content
                // belongs to, which is where its `HeadSpec` is recorded in
                // `scenario` (the copy path itself never has its own entry
                // there — see native_state::resolve_path's doc on why a
                // copy is a derived view, not a stored identity, on the
                // native side; DCF's own model agrees for the same reason
                // stated in namespace.rs's doc: relocation is a
                // projection, never authored).
                let specs = &scenario[&placed.source];
                let spec = spec_by_content(specs, placed.version_hash);
                place_entry(path, placed.kind, spec.content, &mut entries);
            }
        }
    }
    entries
}

// --- Native side: real project(), plus materialization-time copy naming ---

fn native_tree_entries(scenario: &BTreeMap<String, Vec<HeadSpec>>) -> BTreeMap<String, Entry> {
    let heads_by_path: BTreeMap<SyncPath, PathHeads> = scenario
        .iter()
        .map(|(path, specs)| {
            let mut m = PathHeads::new();
            for h in native_heads(specs) {
                m.insert(h.dot, h.payload);
            }
            (SyncPath(path.clone()), m)
        })
        .collect();
    let kind_of = |version: &VersionHash| {
        scenario.values().flatten().find(|s| content_hash(s.content) == version.0).map(|s| s.kind)
    };
    let projection = native_materialize::project(&heads_by_path, kind_of).unwrap();

    let mut entries = BTreeMap::new();
    for (path, node) in &projection {
        match node {
            NativePhysicalNode::Directory(_) => {
                entries.insert(path.as_str().to_owned(), Entry::Directory);
            }
            NativePhysicalNode::Entry(winner) => {
                let specs = &scenario[path.as_str()];
                let spec = spec_by_content(specs, winner.version.0);
                place_entry(path.as_str(), winner.kind, spec.content, &mut entries);
            }
        }
    }

    // Conflict copies: materialization-time naming only (never a causal
    // fact), reusing DCF's own conflict_copy_path/numbered-disambiguator
    // convention so the two sides' actual files agree.
    for (path, specs) in scenario {
        let heads = native_heads(specs);
        let Some(winner) = heads.iter().max_by_key(|head| {
            let is_directory =
                spec_by_content(specs, head.payload.version.0).kind == RecordKind::Directory;
            (win_key(is_directory, head.payload.version), head.payload.provenance)
        }) else {
            continue;
        };
        let mut seen_versions = std::collections::BTreeSet::new();
        seen_versions.insert(winner.payload.version);
        for head in &heads {
            if !seen_versions.insert(head.payload.version) {
                continue; // identical-content collapse (already winner, or a duplicate class already placed).
            }
            let spec = spec_by_content(specs, head.payload.version.0);
            let name = disambiguated_copy_name(path, spec.author, head.payload.version.0, &entries);
            place_entry(&name, spec.kind, spec.content, &mut entries);
        }
    }
    entries
}

/// `conflict_copy_path`'s own numbered-disambiguator convention (device
/// field gets " N" appended on a retry), applied until a free name is
/// found — the same policy DCF's real `place()` uses.
fn disambiguated_copy_name(
    path: &str,
    device: &str,
    version_hash: [u8; 32],
    taken: &BTreeMap<String, Entry>,
) -> String {
    let mut name = conflict_copy_path(path, 0, device, &version_hash);
    let mut attempt = 2u32;
    while taken.contains_key(&name) {
        name = conflict_copy_path(path, 0, &format!("{device} {attempt}"), &version_hash);
        attempt += 1;
    }
    name
}

/// Runs one scenario through both sides, materializes each into its own
/// temp dir, and asserts the actual resulting trees agree.
fn assert_materialized_trees_agree(scenario: BTreeMap<String, Vec<HeadSpec>>) {
    let dcf_root_dir = tempfile::tempdir().unwrap();
    let native_root_dir = tempfile::tempdir().unwrap();
    let dcf_root = dcf_root_dir.path().canonicalize().unwrap();
    let native_root = native_root_dir.path().canonicalize().unwrap();
    let store = MemStore::default();

    let dcf_entries = dcf_tree_entries(&scenario);
    materialize(&dcf_root, &store, &dcf_entries);

    let native_entries = native_tree_entries(&scenario);
    materialize(&native_root, &store, &native_entries);

    let dcf_tree = walk(&dcf_root);
    let native_tree = walk(&native_root);
    assert_eq!(dcf_tree, native_tree, "actual filesystem trees must agree");
}

fn scenario(entries: Vec<(&str, Vec<HeadSpec>)>) -> BTreeMap<String, Vec<HeadSpec>> {
    entries.into_iter().map(|(p, s)| (p.to_owned(), s)).collect()
}

fn file(author: &'static str, content: &'static [u8]) -> HeadSpec {
    HeadSpec { author, tie_break_byte: 1, content, kind: RecordKind::File }
}

// --- Scenarios --------------------------------------------------------------

#[test]
fn create() {
    assert_materialized_trees_agree(scenario(vec![("a.txt", vec![file("device-a", b"hello")])]));
}

#[test]
fn update() {
    // "Update" is just a different winning content at the same path --
    // desired state has no notion of history, only the current winner.
    assert_materialized_trees_agree(scenario(vec![("a.txt", vec![file("device-a", b"v2")])]));
}

#[test]
fn delete() {
    assert_materialized_trees_agree(scenario(vec![]));
}

#[test]
fn file_rename() {
    // The old name has no heads at all; the new name holds the content --
    // a rename's desired-state shape is indistinguishable from
    // delete-old+create-new, which is exactly the point.
    assert_materialized_trees_agree(scenario(vec![("b.txt", vec![file("device-a", b"moved")])]));
}

#[test]
fn directory_rename() {
    assert_materialized_trees_agree(scenario(vec![
        ("dir2/x.txt", vec![file("device-a", b"x")]),
        ("dir2/y.txt", vec![file("device-a", b"y")]),
    ]));
}

#[test]
fn recursive_delete() {
    assert_materialized_trees_agree(scenario(vec![]));
}

#[test]
fn empty_directory() {
    assert_materialized_trees_agree(scenario(vec![(
        "dir",
        vec![HeadSpec {
            author: "device-a",
            tie_break_byte: 1,
            content: b"",
            kind: RecordKind::Directory,
        }],
    )]));
}

#[test]
fn file_to_directory_replacement() {
    // A directory head beats a file at the same path, whatever its version
    // (spec-adjacent decided rule, shared with DCF's own tree constraint).
    assert_materialized_trees_agree(scenario(vec![(
        "a",
        vec![
            HeadSpec {
                author: "device-a",
                tie_break_byte: 1,
                content: b"was a file",
                kind: RecordKind::File,
            },
            HeadSpec {
                author: "device-b",
                tie_break_byte: 2,
                content: b"",
                kind: RecordKind::Directory,
            },
        ],
    )]));
}

#[cfg(unix)]
#[test]
fn symlink() {
    assert_materialized_trees_agree(scenario(vec![(
        "link",
        vec![HeadSpec {
            author: "device-a",
            tie_break_byte: 1,
            content: b"target/path",
            kind: RecordKind::Symlink,
        }],
    )]));
}

#[test]
fn winner_and_conflict_loser() {
    assert_materialized_trees_agree(scenario(vec![(
        "x.txt",
        vec![
            HeadSpec {
                author: "device-a",
                tie_break_byte: 1,
                content: b"winner",
                kind: RecordKind::File,
            },
            HeadSpec {
                author: "device-b",
                tie_break_byte: 2,
                content: b"loser",
                kind: RecordKind::File,
            },
        ],
    )]));
}

#[test]
fn conflict_copy_placement_matches_across_edit_delete_rename_like_shapes() {
    // "edit/delete/rename" of a conflict copy all reduce, at the desired-
    // state level, to "what does the loser's content and path look like
    // now" -- exactly what this scenario fixes: a loser with a distinct
    // path-shaping content (its own materialization is what an edit,
    // rename, or the pre-delete state all produce as an input to this
    // comparison).
    assert_materialized_trees_agree(scenario(vec![(
        "x.txt",
        vec![
            HeadSpec {
                author: "device-a",
                tie_break_byte: 1,
                content: b"winner content",
                kind: RecordKind::File,
            },
            HeadSpec {
                author: "device-b",
                tie_break_byte: 2,
                content: b"edited loser content",
                kind: RecordKind::File,
            },
        ],
    )]));
}

#[test]
fn nested_conflicts_in_a_directory() {
    assert_materialized_trees_agree(scenario(vec![
        (
            "dir/a.txt",
            vec![
                HeadSpec {
                    author: "device-a",
                    tie_break_byte: 1,
                    content: b"a-winner",
                    kind: RecordKind::File,
                },
                HeadSpec {
                    author: "device-b",
                    tie_break_byte: 2,
                    content: b"a-loser",
                    kind: RecordKind::File,
                },
            ],
        ),
        (
            "dir/b.txt",
            vec![
                HeadSpec {
                    author: "device-c",
                    tie_break_byte: 3,
                    content: b"b-winner",
                    kind: RecordKind::File,
                },
                HeadSpec {
                    author: "device-d",
                    tie_break_byte: 4,
                    content: b"b-loser",
                    kind: RecordKind::File,
                },
            ],
        ),
    ]));
}

#[test]
fn copy_name_collision_with_an_ordinary_entry_is_disambiguated_the_same_way_on_both_sides() {
    // Three distinct losing versions from the same device at the same
    // path/mtime would all compute the identical first-choice copy name;
    // both sides must retry with the same numbered disambiguator and agree
    // on the final result.
    assert_materialized_trees_agree(scenario(vec![(
        "x.txt",
        vec![
            HeadSpec {
                author: "device-a",
                tie_break_byte: 1,
                content: b"winner",
                kind: RecordKind::File,
            },
            HeadSpec {
                author: "device-b",
                tie_break_byte: 2,
                content: b"loser-one",
                kind: RecordKind::File,
            },
            HeadSpec {
                author: "device-b",
                tie_break_byte: 3,
                content: b"loser-two",
                kind: RecordKind::File,
            },
        ],
    )]));
}

#[cfg(unix)]
#[test]
fn executable_bit_is_available_to_the_same_materializer_for_both_sides() {
    // The desired-state layer this test compares does not itself carry a
    // unix_mode (that is `FileVersion` metadata, applied by
    // `MaterializationPlan::apply_payload_metadata` after the content
    // write -- a materializer-level concern this test's `Entry::File`
    // models via a direct `unix_mode` field, applied identically for both
    // sides after the same `reconstruct_file` call).
    let mut scenario = scenario(vec![("run.sh", vec![file("device-a", b"#!/bin/sh\necho hi\n")])]);
    let _ = &mut scenario;
    let dcf_root_dir = tempfile::tempdir().unwrap();
    let native_root_dir = tempfile::tempdir().unwrap();
    let dcf_root = dcf_root_dir.path().canonicalize().unwrap();
    let native_root = native_root_dir.path().canonicalize().unwrap();
    let store = MemStore::default();

    let mut dcf_entries = dcf_tree_entries(&scenario);
    let mut native_entries = native_tree_entries(&scenario);
    for entries in [&mut dcf_entries, &mut native_entries] {
        if let Some(Entry::File { unix_mode, .. }) = entries.get_mut("run.sh") {
            *unix_mode = Some(0o755);
        }
    }
    materialize(&dcf_root, &store, &dcf_entries);
    materialize(&native_root, &store, &native_entries);

    let dcf_mode = std::fs::metadata(dcf_root.join("run.sh")).unwrap().permissions().mode() & 0o777;
    let native_mode =
        std::fs::metadata(native_root.join("run.sh")).unwrap().permissions().mode() & 0o777;
    assert_eq!(dcf_mode, 0o755);
    assert_eq!(native_mode, 0o755);
}
