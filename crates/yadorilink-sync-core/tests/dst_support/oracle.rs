//! dst-full-stack-heat-run-framework P0 task 0.2: the multi-device oracle
//! library — convergence, global no-loss, no-corruption, conflict-copy
//! accounting, and structural invariants — that a `Case`-IR-driven DST
//! scenario checks its final (or, where cheap, incremental) state against.
//!
//! Deliberately a *new*, separate mechanism from this module's sibling
//! `WriteOracle`/`check_no_silent_data_loss` (`dst_support/mod.rs`), not a
//! rewrite of it: that checker is single-device-scoped, already used and
//! tested by other `dst_*.rs` scenarios, and its own doc comment already
//! marks multi-device generalization as future work with `causal_evidence`
//! as the intended extension point. This module *is* that extension,
//! built from scratch against the real, multi-device shape rather than
//! retrofitted onto the single-device one, so existing callers are
//! unaffected. `content_hash` is re-used from the sibling module for
//! consistency (same hash for the same bytes everywhere in `dst_support`).
//!
//! Design-review notes this module encodes (agmsg review, 2026-07-08):
//! - **No-loss is causal-supersession-aware, not "every value survives."**
//!   A write legitimately, correctly disappears when a causally-*later*
//!   write or delete (by version vector) superseded it — requiring literal
//!   survival of every `content_id` would false-positive on every ordinary
//!   last-writer-wins overwrite. `GlobalOracle::record` takes the real
//!   `VersionVector` the write/delete carried at the moment it was durably
//!   applied; `check_no_loss` only requires survival of an entry that
//!   nothing else recorded for that path causally dominates.
//! - **`content_table` must be a complete source of truth.** Every op that
//!   produces disk content (`Write` *and* `Edit`) must register its bytes
//!   at issue time; the empty/placeholder/tombstone-materialization content
//!   an `OnDemand` policy or a delete can legitimately leave behind is
//!   deliberately out of this P0 check's scope (Eager materialization only
//!   — every P0 scenario uses it), so it never has to distinguish
//!   "legitimately no bytes" from "a third, corrupt value" yet.
//! - **`Violation` is structured for P4's triage/dedup**, not a bare
//!   string: `kind` + machine-readable `path`/`content_ids`/`devices`, with
//!   `detail` only for the human-readable remainder.
//! - **History legality (the oracle's 4th invariant) is intentionally not a
//!   separate general linearizability checker in P0.** Its two components
//!   that actually matter for what P0's scenarios produce — "no write is
//!   lost without a causally-later write/delete explaining its absence"
//!   and "every genuine concurrent-edit pair keeps both copies" — are
//!   covered by `check_no_loss` and `check_conflict_copy_accounting`
//!   respectively. A dedicated, more general legality oracle is deferred:
//!   grow it from real triaged cases, don't let a from-scratch perfect
//!   checker block P0.

#![cfg(madsim)]
#![allow(dead_code)] // not every check has a caller in P0's single retrofitted scenario yet

use std::collections::{HashMap, HashSet};
use std::path::Path;

use yadorilink_sync_core::index::SyncState;
use yadorilink_sync_core::version_vector::{VersionVector, VvOrdering};

use super::case_ir::ContentTable;
use super::content_hash;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ViolationKind {
    Convergence,
    NoLoss,
    Corruption,
    ConflictCopyAccounting,
    StructuralIndexDiskMismatch,
    StructuralOrphanIndexRow,
    /// PF (fidelity/artifact-reduction) promptness tracking, agmsg
    /// investigation 2026-07-09: a per-round convergence check took
    /// longer than a realistic SLA to settle. Deliberately *not* a hard
    /// per-round failure -- production has no "N seconds or fail" gate,
    /// only eventual consistency -- but a genuine, measured cost (the
    /// self-echo re-index churn's ~30s hydration-timeout cycle, confirmed
    /// production-real by investigation) that must stay *visible* rather
    /// than being hidden by simply loosening the round-progression gate
    /// that tolerates it.
    SlowConvergence,
}

/// One oracle failure, structured so P4's triage/dedup can group by
/// `(kind, path)` (or a coarser signature) without re-parsing prose.
#[derive(Debug, Clone)]
pub struct Violation {
    pub kind: ViolationKind,
    pub path: Option<String>,
    pub content_ids: Vec<u64>,
    pub devices: Vec<usize>,
    pub detail: String,
}

impl std::fmt::Display for Violation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{:?}]", self.kind)?;
        if let Some(path) = &self.path {
            write!(f, " path={path}")?;
        }
        if !self.devices.is_empty() {
            write!(f, " devices={:?}", self.devices)?;
        }
        if !self.content_ids.is_empty() {
            write!(f, " content_ids={:?}", self.content_ids)?;
        }
        write!(f, ": {}", self.detail)
    }
}

pub fn format_violations(seed: u64, violations: &[Violation]) -> String {
    let lines: Vec<String> = violations.iter().map(|v| format!("  - {v}")).collect();
    format!("seed {seed}: {} oracle violation(s):\n{}", violations.len(), lines.join("\n"))
}

/// One recorded write or delete, with the real version vector it carried
/// at the moment it was durably applied — the causal evidence
/// `check_no_loss` compares entries against to decide whether an absent
/// write was legitimately superseded.
#[derive(Debug, Clone)]
struct HistoryEntry {
    device_idx: usize,
    /// `None` for a delete.
    content_id: Option<u64>,
    version: VersionVector,
}

/// Multi-device history + the checks run against it at the end of a run
/// (or, for the cheap ones, incrementally). One instance per `Case` run.
#[derive(Default)]
pub struct GlobalOracle {
    // path -> every write/delete recorded for it, in recording order.
    history: HashMap<String, Vec<HistoryEntry>>,
    // PF promptness tracking: (path, elapsed) for every per-round
    // convergence check the harness ran, regardless of whether it stayed
    // within a realistic SLA -- see `check_convergence_promptness`.
    convergence_latencies: Vec<(String, std::time::Duration)>,
}

impl GlobalOracle {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records how long one per-round convergence check took to settle,
    /// for `check_convergence_promptness` to later flag against an SLA.
    /// Called regardless of outcome (fast or slow) -- the promptness
    /// check itself decides what's notable, this is just the raw log.
    pub fn record_round_convergence_latency(&mut self, path: &str, elapsed: std::time::Duration) {
        self.convergence_latencies.push((path.to_string(), elapsed));
    }

    /// PF (fidelity/artifact-reduction) promptness oracle, agmsg
    /// investigation 2026-07-09: flags any per-round convergence that
    /// took longer than `sla` to settle, without itself gating round
    /// progression (that's `converge_path`'s own, deliberately generous,
    /// bound in the harness). Keeps a real, measured cost (self-echo
    /// re-index churn's ~30s hydration-timeout cycle -- confirmed
    /// production-real, not a harness/madsim artifact, by investigation)
    /// visible in the oracle's own findings rather than silently
    /// tolerated just because the round-progression gate is loose enough
    /// to not fail on it.
    pub fn check_convergence_promptness(&self, sla: std::time::Duration) -> Vec<Violation> {
        self.convergence_latencies
            .iter()
            .filter(|(_, elapsed)| *elapsed > sla)
            .map(|(path, elapsed)| Violation {
                kind: ViolationKind::SlowConvergence,
                path: Some(path.clone()),
                content_ids: Vec::new(),
                devices: Vec::new(),
                detail: format!(
                    "convergence took {elapsed:?}, exceeding the {sla:?} promptness SLA -- likely \
                     self-echo re-index churn driving a hydration-timeout cycle, not itself a \
                     correctness bug (round progression still succeeded)"
                ),
            })
            .collect()
    }

    /// Records a durably-applied write, with the version vector the
    /// resulting `FileRecord` carried at that moment (read the real record
    /// back after applying the op — don't fabricate one).
    pub fn record_write(
        &mut self,
        path: &str,
        device_idx: usize,
        content_id: u64,
        version: VersionVector,
    ) {
        self.history.entry(path.to_string()).or_default().push(HistoryEntry {
            device_idx,
            content_id: Some(content_id),
            version,
        });
    }

    /// Records a durably-applied delete (tombstone), with its version
    /// vector.
    pub fn record_delete(&mut self, path: &str, device_idx: usize, version: VersionVector) {
        self.history.entry(path.to_string()).or_default().push(HistoryEntry {
            device_idx,
            content_id: None,
            version,
        });
    }

    /// **No-loss (causal-supersession-aware).** A recorded entry needs to
    /// survive (as the live file, or as a `(conflicted copy...)` sibling)
    /// unless some *other* recorded entry for the same path has a version
    /// vector that strictly dominates it (`VvOrdering::After` from the
    /// other entry's perspective) — i.e. was genuinely superseded by a
    /// causally-later write or delete. Two genuinely concurrent entries
    /// (`VvOrdering::Concurrent`) both need to survive *unless* one is a
    /// delete that lost the conflict to the other's content (COR-3's
    /// documented delete-vs-write outcome: the losing tombstone is
    /// dropped outright, never conflict-copied) — a losing delete is
    /// therefore never required to "survive" as a deletion once a
    /// concurrent write outright wins; only a losing *write* against a
    /// concurrent delete is required to survive as a conflict copy.
    pub fn check_no_loss(
        &self,
        content_table: &ContentTable,
        devices: &[(&Path, &SyncState)],
    ) -> Vec<Violation> {
        let mut violations = Vec::new();

        for (path, entries) in &self.history {
            for (i, entry) in entries.iter().enumerate() {
                let superseded = entries.iter().enumerate().any(|(j, other)| {
                    if i == j {
                        return false;
                    }
                    other.version.compare(&entry.version) == VvOrdering::After
                });
                if superseded {
                    continue; // legitimately overwritten; no survival required
                }

                let Some(content_id) = entry.content_id else {
                    // A non-superseded delete: nothing further to check
                    // here (delete_survives-style checks belong to
                    // structural/no-corruption, since "survives" isn't
                    // meaningful for a tombstone the same way it is for
                    // content).
                    continue;
                };

                // A losing write against a concurrent delete (COR-3) is
                // still required to survive as a conflict copy -- COR-3
                // only exempts the *delete* side, never the write side.
                // So every non-superseded write entry, concurrent or not,
                // must have its content_id's bytes present somewhere.
                let Some(expected_bytes) = content_table.get(content_id) else {
                    violations.push(Violation {
                        kind: ViolationKind::NoLoss,
                        path: Some(path.clone()),
                        content_ids: vec![content_id],
                        devices: vec![entry.device_idx],
                        detail: format!(
                            "content_id {content_id} recorded for a write with no corresponding \
                             content_table entry -- scenario bug, not a product violation"
                        ),
                    });
                    continue;
                };

                let survives = devices
                    .iter()
                    .any(|(root, _state)| write_survives_anywhere(root, path, expected_bytes));
                if !survives {
                    violations.push(Violation {
                        kind: ViolationKind::NoLoss,
                        path: Some(path.clone()),
                        content_ids: vec![content_id],
                        devices: vec![entry.device_idx],
                        detail: format!(
                            "device {}'s write (content_id {content_id}) was never causally \
                             superseded but its content is not present, live or as a conflict \
                             copy, on any device",
                            entry.device_idx
                        ),
                    });
                }
            }
        }

        violations
    }

    /// **Conflict-copy accounting.** For every path with two or more
    /// *mutually concurrent, non-superseded* write entries (a genuine
    /// race, not one that later got superseded by something else
    /// entirely), each such entry's content must appear exactly once
    /// across all devices combined (no duplicate conflict copies for the
    /// same divergent writer, no missing one).
    pub fn check_conflict_copy_accounting(
        &self,
        content_table: &ContentTable,
        devices: &[(&Path, &SyncState)],
        _group_id: &str,
    ) -> Vec<Violation> {
        let mut violations = Vec::new();

        for (path, entries) in &self.history {
            let racing: Vec<&HistoryEntry> = entries
                .iter()
                .enumerate()
                .filter(|(i, entry)| {
                    entry.content_id.is_some()
                        && !entries.iter().enumerate().any(|(j, other)| {
                            *i != j && other.version.compare(&entry.version) == VvOrdering::After
                        })
                })
                .map(|(_, e)| e)
                .collect();
            if racing.len() < 2 {
                continue; // no genuine, still-live race on this path
            }

            for entry in &racing {
                let content_id = entry.content_id.expect("filtered to Some above");
                let Some(expected_bytes) = content_table.get(content_id) else { continue };
                // Review note (agmsg, 2026-07-08): check *per device*, not
                // a cross-device sum -- a duplicate on one device and a
                // matching absence on another would otherwise cancel out
                // in a summed total (`devices.len()` occurrences overall
                // looks "correct" even though one device has 2 copies and
                // another has 0). A per-device count > 1 is both sharper
                // and independent of whether the run has fully converged
                // yet.
                for (device_idx, (root, _)) in devices.iter().enumerate() {
                    let occurrences = count_matching_occurrences(root, path, expected_bytes);
                    if occurrences > 1 {
                        violations.push(Violation {
                            kind: ViolationKind::ConflictCopyAccounting,
                            path: Some(path.clone()),
                            content_ids: vec![content_id],
                            devices: vec![device_idx],
                            detail: format!(
                                "content_id {content_id} (from device {}'s write) appears \
                                 {occurrences} times on device {device_idx} alone -- implies a \
                                 duplicate conflict-copy name",
                                entry.device_idx
                            ),
                        });
                    }
                }
            }
        }

        violations
    }

    /// **No-corruption.** Every live file and every `(conflicted copy...)`
    /// sibling this oracle can find on any device must hash to a value
    /// present in `content_table` — a value nobody's recorded write
    /// produced is either a torn/partial write or genuinely mixed content.
    /// P0 scope: assumes Eager materialization (every P0 scenario's
    /// policy) — an `OnDemand` placeholder's legitimately-sparse content
    /// is out of scope until a scenario actually exercises that policy.
    pub fn check_no_corruption(
        &self,
        content_table: &ContentTable,
        devices: &[(&Path, &SyncState)],
    ) -> Vec<Violation> {
        // Opus review note: build the known-hash set once (O(1) per
        // lookup) rather than `ContentTable::contains_bytes`'s per-call
        // linear scan -- this runs once per file on every device.
        let known_hashes: HashSet<String> =
            content_table.iter().map(|(_, bytes)| content_hash(bytes)).collect();

        let mut violations = Vec::new();
        for (device_idx, (root, _state)) in devices.iter().enumerate() {
            let Ok(entries) = std::fs::read_dir(root) else { continue };
            for entry in entries.flatten() {
                let Ok(file_type) = entry.file_type() else { continue };
                if !file_type.is_file() {
                    continue; // P0 scope: flat candidate paths only, no dir recursion yet
                }
                let Ok(bytes) = std::fs::read(entry.path()) else { continue };
                let hash = content_hash(&bytes);
                if !known_hashes.contains(&hash) {
                    violations.push(Violation {
                        kind: ViolationKind::Corruption,
                        path: Some(entry.file_name().to_string_lossy().into_owned()),
                        content_ids: Vec::new(),
                        devices: vec![device_idx],
                        detail: format!(
                            "on-disk content (hash {hash}) matches no recorded write in this \
                             run's content table"
                        ),
                    });
                }
            }
        }
        violations
    }

    /// **Structural invariants — P0 scope: existence only.** Every
    /// non-deleted index row must have a real file on disk (a row
    /// claiming "live" with nothing backing it — a COR-6-class bug).
    ///
    /// Review note (agmsg, 2026-07-08): this does **not** yet check that
    /// the on-disk content-hash matches what the index/materialized state
    /// implies (would need to compare against `combined_block_hash` of
    /// the record's `blocks`, cross-referencing the block store, not just
    /// the index — deferred, not implemented), nor the reverse direction
    /// (a real file with no corresponding index row at all —
    /// `ViolationKind::StructuralOrphanIndexRow` is defined for this but
    /// has no producer yet). Both are real, valuable follow-up checks;
    /// this doc comment previously overclaimed them as already covered,
    /// which risked a false sense of oracle coverage — corrected here to
    /// describe only what's actually implemented.
    pub fn check_structural(
        &self,
        group_id: &str,
        devices: &[(&Path, &SyncState)],
    ) -> Vec<Violation> {
        let mut violations = Vec::new();
        for (device_idx, (root, state)) in devices.iter().enumerate() {
            let Ok(files) = state.list_files(group_id) else { continue };
            for record in files {
                if record.deleted {
                    continue;
                }
                let on_disk = root.join(&record.path);
                if !on_disk.exists() {
                    violations.push(Violation {
                        kind: ViolationKind::StructuralIndexDiskMismatch,
                        path: Some(record.path.clone()),
                        content_ids: Vec::new(),
                        devices: vec![device_idx],
                        detail: "index shows a live, non-deleted row with no file on disk"
                            .to_string(),
                    });
                }
            }
        }
        violations
    }

    /// **Convergence.** Every device in `devices` must agree on
    /// `name -> content-hash` for every live path any of them has (a
    /// `(conflicted copy...)` sibling is its own distinct name, so this
    /// naturally requires the same *set* of conflict copies too, not just
    /// the canonical path). Forward-compatible signature note: `devices`
    /// is the checked/expected-quiescent set — P0 always passes every
    /// device, but P2's fault injectors mean only the online/healed set is
    /// a legitimate quiescence point, so callers already pass a subset
    /// rather than this function assuming "all".
    pub fn check_convergence(&self, devices: &[(&Path, &SyncState)]) -> Vec<Violation> {
        if devices.len() < 2 {
            return Vec::new();
        }
        let snapshots: Vec<HashMap<String, String>> =
            devices.iter().map(|(root, _)| flat_hash_snapshot(root)).collect();
        let reference = &snapshots[0];
        let mut violations = Vec::new();
        for (device_idx, snapshot) in snapshots.iter().enumerate().skip(1) {
            if snapshot != reference {
                violations.push(Violation {
                    kind: ViolationKind::Convergence,
                    path: None,
                    content_ids: Vec::new(),
                    devices: vec![0, device_idx],
                    detail: format!(
                        "device 0 and device {device_idx} disagree: device0={reference:?} \
                         device{device_idx}={snapshot:?}"
                    ),
                });
            }
        }
        violations
    }

    /// **Convergence (recursive).** For nested paths from directory ops:
    /// identical in every respect to
    /// `check_convergence` except it walks subdirectories too, via
    /// `recursive_hash_snapshot` instead of `flat_hash_snapshot` — a new
    /// sibling method, not a rewrite, so `dst_two_device_chaos.rs`'s flat
    /// candidate-path scenario (and every other existing caller) keeps its
    /// exact current behavior unchanged. Any scenario that writes nested
    /// paths (`dir1/a.bin`) must call this variant instead: the flat one
    /// would only ever see top-level entries and silently ignore whole
    /// subtrees, false-passing a real divergence underneath a directory.
    pub fn check_convergence_recursive(&self, devices: &[(&Path, &SyncState)]) -> Vec<Violation> {
        if devices.len() < 2 {
            return Vec::new();
        }
        let snapshots: Vec<HashMap<String, String>> =
            devices.iter().map(|(root, _)| recursive_hash_snapshot(root)).collect();
        let reference = &snapshots[0];
        let mut violations = Vec::new();
        for (device_idx, snapshot) in snapshots.iter().enumerate().skip(1) {
            if snapshot != reference {
                violations.push(Violation {
                    kind: ViolationKind::Convergence,
                    path: None,
                    content_ids: Vec::new(),
                    devices: vec![0, device_idx],
                    detail: format!(
                        "device 0 and device {device_idx} disagree: device0={reference:?} \
                         device{device_idx}={snapshot:?}"
                    ),
                });
            }
        }
        violations
    }

    /// **No-loss (recursive).** Same causal-supersession logic as
    /// `check_no_loss`, but proves survival via `write_survives_anywhere_
    /// recursive` (checks the conflict-copy sibling in `path`'s own parent
    /// directory, wherever nested that is) rather than `write_survives_
    /// anywhere`'s root-only conflict-copy scan. Needed once a path's
    /// directory can itself have been renamed/moved out from under it —
    /// see this module's doc comment on why the flat scan is a real gap
    /// for nested paths, not just an unused generality.
    pub fn check_no_loss_recursive(
        &self,
        content_table: &ContentTable,
        devices: &[(&Path, &SyncState)],
    ) -> Vec<Violation> {
        let mut violations = Vec::new();

        for (path, entries) in &self.history {
            for (i, entry) in entries.iter().enumerate() {
                let superseded = entries.iter().enumerate().any(|(j, other)| {
                    if i == j {
                        return false;
                    }
                    other.version.compare(&entry.version) == VvOrdering::After
                });
                if superseded {
                    continue;
                }

                let Some(content_id) = entry.content_id else {
                    continue;
                };

                let Some(expected_bytes) = content_table.get(content_id) else {
                    violations.push(Violation {
                        kind: ViolationKind::NoLoss,
                        path: Some(path.clone()),
                        content_ids: vec![content_id],
                        devices: vec![entry.device_idx],
                        detail: format!(
                            "content_id {content_id} recorded for a write with no corresponding \
                             content_table entry -- scenario bug, not a product violation"
                        ),
                    });
                    continue;
                };

                let survives = devices.iter().any(|(root, _state)| {
                    write_survives_anywhere_recursive(root, path, expected_bytes)
                });
                if !survives {
                    violations.push(Violation {
                        kind: ViolationKind::NoLoss,
                        path: Some(path.clone()),
                        content_ids: vec![content_id],
                        devices: vec![entry.device_idx],
                        detail: format!(
                            "device {}'s write (content_id {content_id}) was never causally \
                             superseded but its content is not present, live or as a conflict \
                             copy, on any device (recursive search)",
                            entry.device_idx
                        ),
                    });
                }
            }
        }

        violations
    }

    /// **Conflict-copy accounting (recursive).** Same as `check_conflict_
    /// copy_accounting`, but counts occurrences via `count_matching_
    /// occurrences_recursive` so a duplicate conflict-copy nested under a
    /// directory is actually found instead of silently missed by a
    /// root-only scan.
    pub fn check_conflict_copy_accounting_recursive(
        &self,
        content_table: &ContentTable,
        devices: &[(&Path, &SyncState)],
        _group_id: &str,
    ) -> Vec<Violation> {
        let mut violations = Vec::new();

        for (path, entries) in &self.history {
            let racing: Vec<&HistoryEntry> = entries
                .iter()
                .enumerate()
                .filter(|(i, entry)| {
                    entry.content_id.is_some()
                        && !entries.iter().enumerate().any(|(j, other)| {
                            *i != j && other.version.compare(&entry.version) == VvOrdering::After
                        })
                })
                .map(|(_, e)| e)
                .collect();
            if racing.len() < 2 {
                continue;
            }

            for entry in &racing {
                let content_id = entry.content_id.expect("filtered to Some above");
                let Some(expected_bytes) = content_table.get(content_id) else { continue };
                for (device_idx, (root, _)) in devices.iter().enumerate() {
                    let occurrences =
                        count_matching_occurrences_recursive(root, path, expected_bytes);
                    if occurrences > 1 {
                        violations.push(Violation {
                            kind: ViolationKind::ConflictCopyAccounting,
                            path: Some(path.clone()),
                            content_ids: vec![content_id],
                            devices: vec![device_idx],
                            detail: format!(
                                "content_id {content_id} (from device {}'s write) appears \
                                 {occurrences} times on device {device_idx} alone (recursive \
                                 search) -- implies a duplicate conflict-copy name",
                                entry.device_idx
                            ),
                        });
                    }
                }
            }
        }

        violations
    }

    /// **No-corruption (recursive).** Same as `check_no_corruption`, but
    /// walks subdirectories (`walk_recursive`) instead of a flat top-level
    /// `read_dir`, so a corrupt/torn value nested under a directory ops
    /// scenario's tree is actually found.
    pub fn check_no_corruption_recursive(
        &self,
        content_table: &ContentTable,
        devices: &[(&Path, &SyncState)],
    ) -> Vec<Violation> {
        let known_hashes: HashSet<String> =
            content_table.iter().map(|(_, bytes)| content_hash(bytes)).collect();

        let mut violations = Vec::new();
        for (device_idx, (root, _state)) in devices.iter().enumerate() {
            let mut found = Vec::new();
            walk_recursive(root, root, &mut |rel_path, bytes| {
                found.push((rel_path, content_hash(bytes)));
            });
            for (rel_path, hash) in found {
                if !known_hashes.contains(&hash) {
                    violations.push(Violation {
                        kind: ViolationKind::Corruption,
                        path: Some(rel_path),
                        content_ids: Vec::new(),
                        devices: vec![device_idx],
                        detail: format!(
                            "on-disk content (hash {hash}) matches no recorded write in this \
                             run's content table (recursive search)"
                        ),
                    });
                }
            }
        }
        violations
    }
}

/// Review note (agmsg, 2026-07-08): flat, root-directory-only — NOT
/// recursive despite `write_survives_anywhere`/this scan sharing the same
/// non-recursive scope. P0's `CANDIDATE_PATHS` are all flat (no directory
/// ops yet), so this is a non-issue today, but it's a real gap before P3's
/// `Mkdir`/nested-path ops land: a conflict-copy sibling for a nested path
/// (`dir/a.txt`) appears in `dir/`, not `root`, so a flat scan would
/// falsely report non-convergence/loss for it. Named `flat_hash_snapshot`
/// (not `recursive_...`) precisely so it doesn't claim behavior it doesn't
/// have; fix alongside `write_survives_anywhere`/`count_matching_
/// occurrences` when P3 introduces nested paths.
fn flat_hash_snapshot(root: &Path) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let Ok(entries) = std::fs::read_dir(root) else { return out };
    for entry in entries.flatten() {
        let Ok(file_type) = entry.file_type() else { continue };
        if !file_type.is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if let Ok(bytes) = std::fs::read(entry.path()) {
            out.insert(name, content_hash(&bytes));
        }
    }
    out
}

/// True if `expected` bytes are present on `root`, either as the live
/// file at `path` or as a `(conflicted copy...)` sibling — generalizes
/// `dst_two_device_chaos.rs`'s own `write_survives` to be called against
/// an arbitrary device root from shared oracle code.
fn write_survives_anywhere(root: &Path, path: &str, expected: &[u8]) -> bool {
    let live = root.join(path);
    if std::fs::read(&live).map(|c| c == expected).unwrap_or(false) {
        return true;
    }
    let stem =
        Path::new(path).file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
    let Ok(entries) = std::fs::read_dir(root) else { return false };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with(&format!("{stem} ("))
            && name.contains("(conflicted copy")
            && std::fs::read(entry.path()).map(|c| c == expected).unwrap_or(false)
        {
            return true;
        }
    }
    false
}

fn count_matching_occurrences(root: &Path, path: &str, expected: &[u8]) -> usize {
    let mut count = 0;
    let live = root.join(path);
    if std::fs::read(&live).map(|c| c == expected).unwrap_or(false) {
        count += 1;
    }
    let stem =
        Path::new(path).file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
    if let Ok(entries) = std::fs::read_dir(root) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with(&format!("{stem} ("))
                && name.contains("(conflicted copy")
                && std::fs::read(entry.path()).map(|c| c == expected).unwrap_or(false)
            {
                count += 1;
            }
        }
    }
    count
}

/// Recursively walks `dir` (relative to
/// `root`, for building forward-slash-separated relative paths), invoking
/// `visit(relative_path, bytes)` for every regular file found. The
/// genuinely-recursive counterpart `flat_hash_snapshot`'s own doc comment
/// flags as missing before directory ops exist. Best-effort: an
/// unreadable directory/file is silently skipped (matches every other
/// disk-walk helper in this module — a transient race with a concurrent
/// writer is not itself an oracle failure).
fn walk_recursive(root: &Path, dir: &Path, visit: &mut dyn FnMut(String, &[u8])) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let Ok(file_type) = entry.file_type() else { continue };
        let path = entry.path();
        if file_type.is_dir() {
            walk_recursive(root, &path, visit);
        } else if file_type.is_file() {
            let Ok(rel) = path.strip_prefix(root) else { continue };
            let Ok(bytes) = std::fs::read(&path) else { continue };
            visit(rel.to_string_lossy().replace('\\', "/"), &bytes);
        }
    }
}

/// Recursive counterpart to `flat_hash_snapshot` — descends into
/// subdirectories so a nested path's (or a nested conflict-copy sibling's)
/// entry is actually captured. See `flat_hash_snapshot`'s doc comment for
/// why the flat version is a real gap once directory ops introduce nested
/// paths.
fn recursive_hash_snapshot(root: &Path) -> HashMap<String, String> {
    let mut out = HashMap::new();
    walk_recursive(root, root, &mut |rel_path, bytes| {
        out.insert(rel_path, content_hash(bytes));
    });
    out
}

/// Recursive counterpart to `write_survives_anywhere` — looks for a
/// `(conflicted copy...)` sibling in `path`'s own (possibly nested) parent
/// directory rather than assuming everything lives at `root`'s top level.
/// `conflict_copy_path` (`conflict.rs`) always preserves the original
/// path's directory prefix when naming a conflict copy, so this is the
/// correct (and only) directory to search — not a full-tree scan.
fn write_survives_anywhere_recursive(root: &Path, path: &str, expected: &[u8]) -> bool {
    let live = root.join(path);
    if std::fs::read(&live).map(|c| c == expected).unwrap_or(false) {
        return true;
    }
    let stem =
        Path::new(path).file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
    let parent_dir = match Path::new(path).parent() {
        Some(p) if p != Path::new("") => root.join(p),
        _ => root.to_path_buf(),
    };
    let Ok(entries) = std::fs::read_dir(&parent_dir) else { return false };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with(&format!("{stem} ("))
            && name.contains("(conflicted copy")
            && std::fs::read(entry.path()).map(|c| c == expected).unwrap_or(false)
        {
            return true;
        }
    }
    false
}

/// Recursive counterpart to `count_matching_occurrences` — same nested-
/// parent-directory search as `write_survives_anywhere_recursive`.
fn count_matching_occurrences_recursive(root: &Path, path: &str, expected: &[u8]) -> usize {
    let mut count = 0;
    let live = root.join(path);
    if std::fs::read(&live).map(|c| c == expected).unwrap_or(false) {
        count += 1;
    }
    let stem =
        Path::new(path).file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
    let parent_dir = match Path::new(path).parent() {
        Some(p) if p != Path::new("") => root.join(p),
        _ => root.to_path_buf(),
    };
    if let Ok(entries) = std::fs::read_dir(&parent_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.starts_with(&format!("{stem} ("))
                && name.contains("(conflicted copy")
                && std::fs::read(entry.path()).map(|c| c == expected).unwrap_or(false)
            {
                count += 1;
            }
        }
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;
    use yadorilink_sync_core::types::FileRecord;

    fn group_id() -> &'static str {
        "oracle-test-group"
    }

    fn setup() -> (SyncState, tempfile::TempDir) {
        let root = tempfile::tempdir().unwrap();
        let state = SyncState::open_in_memory().unwrap();
        state.add_link(&root.path().to_string_lossy(), group_id()).unwrap();
        (state, root)
    }

    fn vv(device: &str, count: u64) -> VersionVector {
        let mut v = VersionVector::new();
        for _ in 0..count {
            v.increment(device);
        }
        v
    }

    #[test]
    fn no_loss_passes_when_the_only_write_survives() {
        let (state_a, root_a) = setup();
        std::fs::write(root_a.path().join("a.txt"), b"hello").unwrap();

        let mut table = ContentTable::default();
        table.insert(1, b"hello".to_vec());

        let mut oracle = GlobalOracle::new();
        oracle.record_write("a.txt", 0, 1, vv("device-a", 1));

        let violations = oracle.check_no_loss(&table, &[(root_a.path(), &state_a)]);
        assert!(violations.is_empty(), "{violations:?}");
    }

    #[test]
    fn no_loss_is_silent_about_a_legitimately_superseded_write() {
        // device-a wrote "first" then "second" (causally later) -- only
        // "second" needs to survive; "first" disappearing is correct LWW
        // behavior, not data loss.
        let (state_a, root_a) = setup();
        std::fs::write(root_a.path().join("a.txt"), b"second").unwrap();

        let mut table = ContentTable::default();
        table.insert(1, b"first".to_vec());
        table.insert(2, b"second".to_vec());

        let mut oracle = GlobalOracle::new();
        oracle.record_write("a.txt", 0, 1, vv("device-a", 1));
        oracle.record_write("a.txt", 0, 2, vv("device-a", 2));

        let violations = oracle.check_no_loss(&table, &[(root_a.path(), &state_a)]);
        assert!(violations.is_empty(), "the superseded write must not be flagged: {violations:?}");
    }

    #[test]
    fn no_loss_flags_a_write_that_truly_vanished() {
        let (state_a, root_a) = setup();
        // Nothing written to disk at all -- simulating a genuinely lost write.

        let mut table = ContentTable::default();
        table.insert(1, b"hello".to_vec());

        let mut oracle = GlobalOracle::new();
        oracle.record_write("a.txt", 0, 1, vv("device-a", 1));

        let violations = oracle.check_no_loss(&table, &[(root_a.path(), &state_a)]);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].kind, ViolationKind::NoLoss);
    }

    #[test]
    fn no_loss_requires_both_sides_of_a_genuine_concurrent_race_to_survive() {
        let (state_a, root_a) = setup();
        // Both concurrent writes' content must be present -- one live,
        // one as a conflict copy.
        std::fs::write(root_a.path().join("a.txt"), b"from-a").unwrap();
        std::fs::write(root_a.path().join("a (conflicted copy, x).txt"), b"from-b").unwrap();

        let mut table = ContentTable::default();
        table.insert(1, b"from-a".to_vec());
        table.insert(2, b"from-b".to_vec());

        let mut oracle = GlobalOracle::new();
        // Concurrent: neither dominates the other.
        oracle.record_write("a.txt", 0, 1, vv("device-a", 1));
        oracle.record_write("a.txt", 1, 2, vv("device-b", 1));

        let violations = oracle.check_no_loss(&table, &[(root_a.path(), &state_a)]);
        assert!(violations.is_empty(), "{violations:?}");
    }

    // COR-3 (delete-vs-write race) coverage, added per review (agmsg,
    // 2026-07-08): `resolve_and_apply_conflict`'s documented outcome is
    // that a losing *delete* is dropped outright (never conflict-copied),
    // while a losing *write* against a concurrent delete still must
    // survive as a conflict copy -- these two tests each guard one
    // direction of that asymmetry, the highest-data-loss-risk path this
    // oracle exists to catch.

    #[test]
    fn no_loss_does_not_require_a_delete_to_survive_when_a_concurrent_write_wins() {
        // device-a deletes; device-b concurrently writes and wins the
        // conflict outright (COR-3's documented, correct outcome: the
        // delete is dropped, no conflict copy for it). Only the write's
        // content needs to survive; the oracle must not demand the delete
        // "survive" as an absence check that no `check_no_loss` branch
        // performs in the first place.
        let (state_a, root_a) = setup();
        std::fs::write(root_a.path().join("a.txt"), b"write-wins").unwrap();

        let mut table = ContentTable::default();
        table.insert(1, b"write-wins".to_vec());

        let mut oracle = GlobalOracle::new();
        oracle.record_delete("a.txt", 0, vv("device-a", 1)); // concurrent, loses
        oracle.record_write("a.txt", 1, 1, vv("device-b", 1)); // concurrent, wins

        let violations = oracle.check_no_loss(&table, &[(root_a.path(), &state_a)]);
        assert!(violations.is_empty(), "{violations:?}");
    }

    #[test]
    fn no_loss_flags_a_losing_write_against_a_concurrent_delete_that_never_survived() {
        // The asymmetric direction: a losing *write* against a concurrent
        // delete must still survive as a conflict copy (COR-3 only
        // exempts the delete side). If neither the live path nor any
        // conflict copy holds the write's content, that's a genuine loss.
        let (state_a, root_a) = setup();
        // Only the delete's effect is visible on disk -- nothing at all
        // for the concurrent write's content.

        let mut table = ContentTable::default();
        table.insert(1, b"lost-write-content".to_vec());

        let mut oracle = GlobalOracle::new();
        oracle.record_delete("a.txt", 0, vv("device-a", 1)); // concurrent, wins
        oracle.record_write("a.txt", 1, 1, vv("device-b", 1)); // concurrent, loses -- must still survive

        let violations = oracle.check_no_loss(&table, &[(root_a.path(), &state_a)]);
        assert_eq!(violations.len(), 1, "{violations:?}");
        assert_eq!(violations[0].kind, ViolationKind::NoLoss);
        assert_eq!(violations[0].devices, vec![1]);
    }

    #[test]
    fn no_loss_is_silent_when_a_write_is_superseded_by_a_later_delete() {
        // Not a race: device-a's write is causally-*before* a later
        // delete (by version vector, not concurrent) -- a legitimate LWW
        // supersession by a delete, same as being superseded by a later
        // write. Must not be flagged.
        let (state_a, root_a) = setup();
        // Nothing on disk -- the later delete's tombstone correctly left
        // no file behind.

        let mut table = ContentTable::default();
        table.insert(1, b"superseded-by-delete".to_vec());

        let mut oracle = GlobalOracle::new();
        oracle.record_write("a.txt", 0, 1, vv("device-a", 1));
        oracle.record_delete("a.txt", 0, vv("device-a", 2)); // causally later, dominates

        let violations = oracle.check_no_loss(&table, &[(root_a.path(), &state_a)]);
        assert!(violations.is_empty(), "the superseded write must not be flagged: {violations:?}");
    }

    #[test]
    fn no_corruption_flags_a_value_nobody_wrote() {
        let (state_a, root_a) = setup();
        std::fs::write(root_a.path().join("a.txt"), b"corrupted-third-value").unwrap();

        let mut table = ContentTable::default();
        table.insert(1, b"hello".to_vec());

        let oracle = GlobalOracle::new();
        let violations = oracle.check_no_corruption(&table, &[(root_a.path(), &state_a)]);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].kind, ViolationKind::Corruption);
    }

    #[test]
    fn no_corruption_passes_when_content_matches_the_table() {
        let (state_a, root_a) = setup();
        std::fs::write(root_a.path().join("a.txt"), b"hello").unwrap();

        let mut table = ContentTable::default();
        table.insert(1, b"hello".to_vec());

        let oracle = GlobalOracle::new();
        let violations = oracle.check_no_corruption(&table, &[(root_a.path(), &state_a)]);
        assert!(violations.is_empty(), "{violations:?}");
    }

    #[test]
    fn convergence_passes_when_devices_agree() {
        let (state_a, root_a) = setup();
        let (state_b, root_b) = setup();
        std::fs::write(root_a.path().join("a.txt"), b"same").unwrap();
        std::fs::write(root_b.path().join("a.txt"), b"same").unwrap();

        let oracle = GlobalOracle::new();
        let violations =
            oracle.check_convergence(&[(root_a.path(), &state_a), (root_b.path(), &state_b)]);
        assert!(violations.is_empty(), "{violations:?}");
    }

    #[test]
    fn convergence_flags_disagreement() {
        let (state_a, root_a) = setup();
        let (state_b, root_b) = setup();
        std::fs::write(root_a.path().join("a.txt"), b"one").unwrap();
        std::fs::write(root_b.path().join("a.txt"), b"different").unwrap();

        let oracle = GlobalOracle::new();
        let violations =
            oracle.check_convergence(&[(root_a.path(), &state_a), (root_b.path(), &state_b)]);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].kind, ViolationKind::Convergence);
    }

    #[test]
    fn structural_flags_a_live_index_row_with_no_file_on_disk() {
        let (state_a, root_a) = setup();
        state_a
            .upsert_file(
                group_id(),
                &FileRecord {
                    path: "ghost.txt".to_string(),
                    size: 0,
                    mtime_unix_nanos: 0,
                    version: VersionVector::new(),
                    blocks: Vec::new(),
                    deleted: false,
                },
            )
            .unwrap();

        let oracle = GlobalOracle::new();
        let violations = oracle.check_structural(group_id(), &[(root_a.path(), &state_a)]);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].kind, ViolationKind::StructuralIndexDiskMismatch);
    }
}
