//! The self-
//! healing lifecycle hook.
//!
//! A bare-`PeerSyncSession` DST scenario never runs the periodic sweeps a
//! real daemon runs (`repair_interrupted_materializations` +
//! `cleanup_stale_temp_files`, driven by `link_manager.rs`), so a state the
//! production daemon would have repaired on its next sweep -- an interrupted
//! eager materialize's live-but-fileless index row plus an orphaned
//! `.yadorilink-tmp.*` file -- surfaced as `StructuralIndexDiskMismatch` /
//! `Corruption` violations that were pure harness artifacts (the
//! canonical inline account is in `dst_two_device_chaos.rs` /
//! `dst_network_fault_chaos.rs`, seed 3298840595's finding).
//!
//! `run_self_healing` invokes the exact same production sweep code at each
//! quiescent point and before the terminal oracle checks. Every repair it
//! performs is returned as an *informational* `RepairedBySweep` finding:
//! a sweep that fixes a state keeps the signal about how
//! often the repair path is exercised visible rather than swallowed, while
//! a sweep that *fails* to reach a consistent state leaves a hard
//! structural/corruption violation for the terminal oracles that run after
//! it -- masking nothing, since the sweep runs production code and
//! exercising it more is coverage, not suppression.
//!
//! `#![cfg(madsim)]`-gated like every DST scenario file.

use std::path::Path;

use yadorilink_local_storage::BlockStore;
use yadorilink_sync_core::index::SyncState;
use yadorilink_sync_core::materialization::{
    cleanup_stale_temp_files, repair_interrupted_materializations,
};

use super::oracle::{Violation, ViolationKind};

/// Runs the production self-healing sweeps against one device's state,
/// block store, and synced root, returning one informational
/// `RepairedBySweep` finding per repair actually performed (a
/// reconstructed file, a demote-to-placeholder, or a removed stale temp
/// file). An empty result means the sweep found nothing to repair.
///
/// The sweep's own errors are best-effort-swallowed exactly as the
/// scenarios' inline call sites did (`let _ = repair_...`): a sweep that
/// cannot run is not itself a product violation, and any inconsistency it
/// therefore leaves behind is caught by the terminal structural/corruption
/// oracles run afterward.
pub fn run_self_healing(
    state: &SyncState,
    store: &dyn BlockStore,
    root: &Path,
    group_id: &str,
) -> Vec<Violation> {
    let mut findings = Vec::new();

    if let Ok(report) = repair_interrupted_materializations(state, store, root, group_id) {
        for path in report.reconstructed {
            findings.push(repaired(path, "reconstructed an interrupted eager materialize"));
        }
        for path in report.demoted_to_placeholder {
            findings.push(repaired(
                path,
                "demoted an unrecoverable interrupted materialize to a placeholder",
            ));
        }
    }

    for removed in cleanup_stale_temp_files(root) {
        findings.push(repaired(
            removed.to_string_lossy().into_owned(),
            "removed an orphaned .yadorilink-tmp.* file",
        ));
    }

    findings
}

fn repaired(path: String, what: &str) -> Violation {
    Violation {
        kind: ViolationKind::RepairedBySweep,
        path: Some(path),
        content_ids: Vec::new(),
        devices: Vec::new(),
        detail: format!(
            "self-healing sweep {what} (informational -- the same repair a production daemon's \
             periodic sweep performs; not a failure)"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::super::oracle::GlobalOracle;
    use super::*;
    use yadorilink_local_storage::FsBlockStore;
    use yadorilink_sync_core::types::{BlockInfo, FileRecord, MaterializationState};
    use yadorilink_sync_core::version_vector::VersionVector;

    const GROUP_ID: &str = "sweep-test-group";

    fn setup() -> (SyncState, tempfile::TempDir, FsBlockStore, tempfile::TempDir) {
        let root = tempfile::tempdir().unwrap();
        let store_dir = tempfile::tempdir().unwrap();
        let state = SyncState::open_in_memory().unwrap();
        state.add_link(&root.path().to_string_lossy(), GROUP_ID).unwrap();
        let store = FsBlockStore::new(store_dir.path().to_path_buf()).unwrap();
        (state, root, store, store_dir)
    }

    /// The exact PF-investigation shape (interrupted eager materialize:
    /// live Hydrated row, only a partial file on disk, blocks still present
    /// in the store, plus an orphaned temp file) -- the sweep must repair
    /// it and leave the terminal structural oracle clean, and it must
    /// report the repair rather than swallowing it.
    #[test]
    fn sweep_repairs_an_interrupted_materialization_and_records_it() {
        let (state, root, store, _store_dir) = setup();
        // Establish this root's identity marker up front, the way a real
        // daemon does at initial link setup, long before any later crash.
        // Without it, `repair_interrupted_materializations`'s internal
        // `VerifiedRoot::open` sees an unmarked root and falls back to
        // corroboration-based adoption -- which the partial on-disk file
        // written below (the interrupted-materialize scenario itself) can
        // never satisfy, since a partial write is definitionally a mismatch
        // against the index. That is not a bug in root-identity: it is this
        // fixture skipping the boot-time adoption a running install already
        // completed before any crash could interrupt a materialize.
        yadorilink_sync_core::root_identity::VerifiedRoot::readopt(root.path(), GROUP_ID, &state)
            .unwrap();
        let content = b"pre-crash acknowledged content".repeat(8);
        let hash_hex = store.put(&content).unwrap();
        let record = FileRecord {
            path: "pre-crash.bin".to_string(),
            size: content.len() as u64,
            mtime_unix_nanos: 1,
            version: {
                let mut vv = VersionVector::new();
                vv.increment("device-a");
                vv
            },
            blocks: vec![BlockInfo {
                hash: hex::decode(hash_hex).unwrap(),
                offset: 0,
                size: content.len() as u32,
            }],
            deleted: false,
        };
        state.upsert_file(GROUP_ID, &record).unwrap();
        state
            .set_materialization_state(GROUP_ID, "pre-crash.bin", MaterializationState::Hydrated)
            .unwrap();
        // Only a partial file on disk + an orphaned temp file: the
        // interrupted-materialize window. The orphan is left by a *previous*
        // (crashed) process, so its pid segment is deliberately a foreign
        // constant, not this live process's id: `chunker::unique_tmp_path`
        // stamps its own temps with the current pid plus a process-global
        // atomic counter, so a same-pid orphan can collide with this run's own
        // reconstruction temp once a concurrently-running test has advanced
        // that shared counter past 0 — the reconstruction would then rename the
        // orphan away as its own write target and the cleanup finding would
        // vanish. A foreign pid can never collide, while
        // `cleanup_stale_temp_files` still recognizes it (any `<digits>.<digits>`
        // suffix matches).
        std::fs::write(root.path().join("pre-crash.bin"), &content[..content.len() / 3]).unwrap();
        std::fs::write(
            root.path().join("pre-crash.bin.yadorilink-tmp.4242.1"),
            b"interrupted materialize temp",
        )
        .unwrap();

        let findings = run_self_healing(&state, &store, root.path(), GROUP_ID);

        // The full content is now on disk, and the sweep reported both the
        // reconstruction and the temp-file cleanup.
        assert_eq!(std::fs::read(root.path().join("pre-crash.bin")).unwrap(), content);
        assert!(
            findings.iter().all(|f| f.kind == ViolationKind::RepairedBySweep),
            "all findings must be informational: {findings:?}"
        );
        assert!(
            findings.iter().any(|f| f.detail.contains("reconstructed")),
            "expected a reconstruction finding: {findings:?}"
        );
        assert!(
            findings.iter().any(|f| f.detail.contains("orphaned")),
            "expected a temp-file cleanup finding: {findings:?}"
        );

        // Terminal structural oracle is clean after the sweep.
        let oracle = GlobalOracle::new();
        let violations = oracle.check_structural(GROUP_ID, &[(root.path(), &state)]);
        assert!(violations.is_empty(), "sweep should leave a consistent state: {violations:?}");
    }

    /// The sweep must not mask a genuinely inconsistent row it cannot
    /// repair: a live index row with no blocks to reconstruct from and no
    /// file on disk is unrepairable, so the sweep does nothing and the
    /// terminal structural oracle still hard-flags it (a
    /// sweep that fails to produce a consistent state still yields a hard
    /// violation).
    #[test]
    fn sweep_does_not_mask_a_genuinely_inconsistent_row() {
        let (state, root, store, _store_dir) = setup();
        state
            .upsert_file(
                GROUP_ID,
                &FileRecord {
                    path: "ghost.bin".to_string(),
                    size: 0,
                    mtime_unix_nanos: 0,
                    version: VersionVector::new(),
                    blocks: Vec::new(), // nothing to reconstruct from
                    deleted: false,
                },
            )
            .unwrap();

        let findings = run_self_healing(&state, &store, root.path(), GROUP_ID);
        assert!(findings.is_empty(), "nothing was repairable: {findings:?}");

        let oracle = GlobalOracle::new();
        let violations = oracle.check_structural(GROUP_ID, &[(root.path(), &state)]);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].kind, ViolationKind::StructuralIndexDiskMismatch);
    }
}
